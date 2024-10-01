use diesel::prelude::*;
use chrono::prelude::*;
use base64::prelude::*;
use diesel_async::{RunQueryDsl, AsyncConnection};
use rand::Rng;
use std::str::FromStr;

pub struct ValidatorManager {
    pub endpoint: tonic::transport::Endpoint,
}

#[mobc::async_trait]
impl mobc::Manager for ValidatorManager {
    type Connection = crate::cert_order::validator_client::ValidatorClient<tonic::transport::Channel>;
    type Error = tonic::transport::Error;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        crate::cert_order::validator_client::ValidatorClient::connect(self.endpoint.clone()).await
    }

    async fn check(&self, conn: Self::Connection) -> Result<Self::Connection, Self::Error> {
        Ok(conn)
    }
}

#[derive(Clone)]
enum ChallengeResponse {
    None,
    CSR(Vec<u8>)
}

#[derive(Clone)]
pub(crate) struct CA {
    pub db: crate::DBPool,
    pub validator: mobc::Pool<ValidatorManager>,
    pub issuing_cert_id: uuid::Uuid,
    pub signing_key: std::sync::Arc<openssl::pkey::PKey<openssl::pkey::Private>>,
    pub ct_logs: std::sync::Arc<Vec<crate::CTLog>>,
    pub http_client: std::sync::Arc<reqwest::Client>
}

impl CA {
    pub(crate) async fn get_db_conn(&self) -> Result<crate::DBConn, tonic::Status> {
        match self.db.get().await {
            Ok(c) => Ok(c),
            Err(e) => {
                warn!("Failed to get DB connection: {}", e);
                Err(tonic::Status::internal(""))
            }
        }
    }

    async fn get_order(&self, id: &[u8]) -> Result<crate::models::Order, tonic::Status> {
        let order_id = match uuid::Uuid::from_slice(&id) {
            Ok(i) => i,
            Err(_) => return Err(tonic::Status::new(tonic::Code::NotFound, "Requested order not found"))
        };

        let mut conn = self.get_db_conn().await?;
        let order: crate::models::Order = match handle_db_result(
            crate::schema::orders::dsl::orders.find(order_id)
                .get_result(&mut conn).await.optional()
        )? {
            Some(o) => o,
            None => return Err(tonic::Status::new(tonic::Code::NotFound, "Requested order not found"))
        };

        Ok(order)
    }

    async fn get_authorization(&self, id: &[u8]) -> Result<crate::models::Authorization, tonic::Status> {
        let authorization_id = match uuid::Uuid::from_slice(id) {
            Ok(i) => i,
            Err(_) => return Err(tonic::Status::new(tonic::Code::NotFound, "Requested authorization not found"))
        };

        let mut conn = self.get_db_conn().await?;
        let authorization: crate::models::Authorization = match handle_db_result(
            crate::schema::authorizations::dsl::authorizations.find(authorization_id)
                .get_result(&mut conn).await.optional()
        )? {
            Some(o) => o,
            None => return Err(tonic::Status::new(tonic::Code::NotFound, "Requested authorization not found"))
        };

        Ok(authorization)
    }

    async fn get_challenge(&self, id: &[u8], auth_id: &[u8]) -> Result<crate::models::AuthorizationChallenge, tonic::Status> {
        let challenge_id = match uuid::Uuid::from_slice(id) {
            Ok(i) => i,
            Err(_) => return Err(tonic::Status::new(tonic::Code::NotFound, "Requested challenge not found"))
        };
        let authorization_id = match uuid::Uuid::from_slice(auth_id) {
            Ok(i) => i,
            Err(_) => return Err(tonic::Status::new(tonic::Code::NotFound, "Requested challenge not found"))
        };

        let mut conn = self.get_db_conn().await?;
        let challenge: crate::models::AuthorizationChallenge = match handle_db_result(
            crate::schema::authorization_challenges::dsl::authorization_challenges
                .filter(
                    crate::schema::authorization_challenges::dsl::id.eq(challenge_id)
                )
                .filter(
                    crate::schema::authorization_challenges::dsl::authorization.eq(authorization_id)
                )
                .get_result(&mut conn).await.optional()
        )? {
            Some(o) => o,
            None => return Err(tonic::Status::new(tonic::Code::NotFound, "Requested challenge not found"))
        };

        Ok(challenge)
    }

    async fn complete_challenge_task(
        &self, mut challenge: crate::models::AuthorizationChallenge, thumbprint: String,
        response: ChallengeResponse
    ) -> Result<(), backoff::Error<String>> {
        let mut conn = self.db.get().await.map_err(|e| e.to_string())?;
        let mut authorization: crate::models::Authorization = crate::schema::authorizations::table
            .find(challenge.authorization).get_result(&mut conn).await.map_err(|e| e.to_string())?;

        let mut validator = self.validator.get().await.map_err(|e| e.to_string())?;

        match match challenge.type_ {
            crate::models::ChallengeType::Http01 | crate::models::ChallengeType::Dns01 |  crate::models::ChallengeType::TlsAlpn01 => {
                let req = crate::cert_order::KeyValidationRequest {
                    token: challenge.token.clone().unwrap_or_default(),
                    account_thumbprint: thumbprint,
                    identifier: Some(authorization.id_to_pb()),
                    hs_private_key: challenge.auth_key.clone().unwrap_or_default(),
                };
                match challenge.type_ {
                    crate::models::ChallengeType::Http01 => validator.validate_http01(req).await,
                    crate::models::ChallengeType::Dns01 => validator.validate_dns01(req).await,
                    crate::models::ChallengeType::TlsAlpn01 => validator.validate_tlsalpn01(req).await,
                    _ => unreachable!()
                }
            }
            crate::models::ChallengeType::OnionCsr01 => {
                let req = crate::cert_order::OnionCsrValidationRequest {
                    csr: match response {
                        ChallengeResponse::CSR(csr) => csr,
                        _ => return Ok(())
                    },
                    ca_nonce: challenge.nonce.clone().unwrap_or_default(),
                    identifier: Some(authorization.id_to_pb()),
                };
                validator.validate_onion_csr01(req).await
            }
        } {
            Ok(r) => {
                let res = r.into_inner();

                if res.valid {
                    challenge.validated_at = Some(Utc::now().naive_utc());
                    authorization.state = crate::models::AuthorizationState::Valid;
                } else {
                    challenge.error = res.error.map(|r| serde_json::to_value(r).unwrap());
                    authorization.state = crate::models::AuthorizationState::Invalid;
                }
            }
            Err(e) => {
                warn!("Challenge validation failed: {}", e);
                challenge.error = Some(serde_json::to_value(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::ServerInternalError.into(),
                        title: "Internal Server Error".to_string(),
                        status: 500,
                        detail: "Challenge verification unexpectedly failed".to_string(),
                        identifier: None,
                        instance: None,
                        sub_problems: vec![]
                    }]
                }).unwrap());
                authorization.state = crate::models::AuthorizationState::Invalid;
            }
        }

        conn.transaction(|mut conn| Box::pin(async move {
            diesel::update(&challenge).set(&challenge).execute(&mut conn).await?;
            diesel::update(&authorization).set(&authorization).execute(&mut conn).await?;
            Ok(())
        })).await.map_err(|e: diesel::result::Error| e.to_string())?;

        Ok(())
    }

    fn build_cert(
        builder: &mut openssl::x509::X509Builder,
        csr: &openssl::x509::X509Req,
        cert_id: uuid::Uuid,
        now: DateTime<Utc>,
        expiry: DateTime<Utc>,
        identifiers: &[crate::models::OrderIdentifier],
        issued_by: &crate::models::IssuingCert,
        issuer_cert: &openssl::x509::X509Ref,
    ) -> Result<(), String> {
        let cert_id_bn = openssl::bn::BigNum::from_slice(cert_id.as_bytes())
            .map_err(|e| format!("failed to make cert ID: {}", e))?;

        let issuer_name = issuer_cert.subject_name();
        let mut subject_name = openssl::x509::X509NameBuilder::new()
            .map_err(|e| format!("failed to build subject name: {}", e))?;
        let subject_name = subject_name.build();

        builder.set_version(2)
            .map_err(|e| format!("failed to set certificate version: {}", e))?;
        builder.set_pubkey(
            csr.public_key()
                .map_err(|e| format!("failed to get public key from CSR: {}", e))?.as_ref()
        ).map_err(|e| format!("failed to set public key: {}", e))?;
        builder.set_serial_number(
            cert_id_bn.to_asn1_integer()
                .map_err(|e| format!("failed to make serial number: {}", e))?.as_ref()
        ).map_err(|e| format!("failed to set serial number: {}", e))?;
        builder.set_not_before(
            openssl::asn1::Asn1Time::from_unix(now.timestamp())
                .map_err(|e| format!("failed to make not before: {}", e))?.as_ref()
        ).map_err(|e| format!("failed to set not before: {}", e))?;
        builder.set_not_after(
            openssl::asn1::Asn1Time::from_unix(expiry.timestamp())
                .map_err(|e| format!("failed to make not after: {}", e))?.as_ref()
        ).map_err(|e| format!("failed to set not after: {}", e))?;
        builder.set_issuer_name(&issuer_name)
            .map_err(|e| format!("failed to set issuer name: {}", e))?;
        builder.set_subject_name(&subject_name)
            .map_err(|e| format!("failed to set subject name: {}", e))?;

        let mut bc = openssl::x509::extension::BasicConstraints::new();
        bc.critical();
        let bc = bc.build()
            .map_err(|e| format!("failed to build basic constraints: {}", e))?;
        builder.append_extension(bc)
            .map_err(|e| format!("failed to add basic constraints: {}", e))?;

        let mut ku = openssl::x509::extension::KeyUsage::new();
        ku.critical();
        ku.digital_signature();
        ku.non_repudiation();
        ku.key_agreement();
        let ku = ku.build()
            .map_err(|e| format!("failed to build key usage: {}", e))?;
        builder.append_extension(ku)
            .map_err(|e| format!("failed to add key usage: {}", e))?;

        let mut eku = openssl::x509::extension::ExtendedKeyUsage::new();
        eku.server_auth();
        eku.client_auth();
        let eku = eku.build()
            .map_err(|e| format!("failed to build extended key usage: {}", e))?;
        builder.append_extension2(&eku)
            .map_err(|e| format!("failed to add extended key usage: {}", e))?;

        let mut san = openssl::x509::extension::SubjectAlternativeName::new();
        // RFC 5280 § 4.1.2.6 - If subject naming information is present only in the subjectAltName
        // extension then the subject name MUST be an empty sequence and the subjectAltName
        // extension MUST be critical.
        san.critical();
        for id in identifiers {
            match id.identifier_type {
                crate::models::IdentifierType::Dns => {
                    san.dns(&id.identifier);
                }
            }
        }
        let context = builder.x509v3_context(Some(&issuer_cert), None);
        let san = san.build(&context)
            .map_err(|e| format!("failed to build SANs: {}", e))?;
        builder.append_extension(san)
            .map_err(|e| format!("failed to add SANs: {}", e))?;

        let context = builder.x509v3_context(Some(&issuer_cert), None);
        let ski = openssl::x509::extension::SubjectKeyIdentifier::new()
            .build(&context)
            .map_err(|e| format!("failed to build SKI: {}", e))?;
        builder.append_extension(ski)
            .map_err(|e| format!("failed to add SKI: {}", e))?;

        let mut aki = openssl::x509::extension::AuthorityKeyIdentifier::new();
        aki.keyid(false);
        aki.issuer(false);
        let context = builder.x509v3_context(Some(&issuer_cert), None);
        let aki = aki.build(&context)
            .map_err(|e| format!("failed to build AKI: {}", e))?;
        builder.append_extension(aki)
            .map_err(|e| format!("failed to add AKI: {}", e))?;

        if let Some(crl_url) = &issued_by.crl_url {
            #[allow(deprecated)]
            let cdp = openssl::x509::X509Extension::new_nid(
                None,
                None,
                openssl::nid::Nid::CRL_DISTRIBUTION_POINTS,
                &format!("URI:{}", crl_url)
            ).map_err(|e| format!("failed to build CRL distribution points: {}", e))?;
            builder.append_extension(cdp)
                .map_err(|e| format!("failed to add CRL distribution points: {}", e))?;
        }

        let mut aia = vec![];
        if let Some(cert_url) = &issued_by.cert_url {
            aia.push(format!("caIssuers;URI:{}", cert_url));
        }
        for ocsp_url in &issued_by.ocsp_responder_url {
            if let Some(ocsp_url) = ocsp_url {
                aia.push(format!("OCSP;URI:{}", ocsp_url));
            }
        }
        if !aia.is_empty() {
            #[allow(deprecated)]
            let aia = openssl::x509::X509Extension::new_nid(
                None,
                None,
                openssl::nid::Nid::INFO_ACCESS,
                &aia.join(",")
            ).map_err(|e| format!("failed to build AIA: {}", e))?;
            builder.append_extension(aia)
                .map_err(|e|  format!("failed to add AIA: {}", e))?;
        }

        Ok(())
    }

    async fn sign_order_task(
        &self, mut order: crate::models::Order, account_uri: String,
        onion_caa: std::collections::HashMap<String, crate::cert_order::OnionCaa>
    ) -> Result<(), backoff::Error<String>> {
        let csr = match &order.csr {
            Some(csr) => csr,
            None => return Ok(())
        };

        let mut chain_bytes = vec![];
        let mut chain = vec![];

        let mut conn = self.db.get().await.map_err(|e| e.to_string())?;
        let mut issued_by = Some(self.issuing_cert_id);
        while let Some(id) = issued_by {
            let issuing_cert: crate::models::IssuingCert = crate::schema::issuing_certs::table
                .find(id).get_result(&mut conn).await.map_err(|e| e.to_string())?;
            chain_bytes.push(BASE64_STANDARD.encode(&issuing_cert.cert));
            issued_by = issuing_cert.issued_by;
            chain.push(issuing_cert);
        }

        let identifiers: Vec<crate::models::OrderIdentifier> = crate::schema::order_identifiers::table
            .filter(
                crate::schema::order_identifiers::dsl::order_id.eq(order.id)
            ).get_results(&mut conn).await.map_err(|e| e.to_string())?;

        if identifiers.len() == 0 {
            return Ok(());
        }

        let mut validator = self.validator.get().await.map_err(|e| e.to_string())?;

        for identifier in &identifiers {
            let authorization_id = match identifier.authorization {
                Some(id) => id,
                None => {
                    order.error = Some(serde_json::to_value(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::CaaError.into(),
                            title: "Unable to check CAA".to_string(),
                            status: 500,
                            detail: "Internal server error when checking CAA".to_string(),
                            identifier: None,
                            instance: None,
                            sub_problems: vec![]
                        }]
                    }).unwrap());
                    diesel::update(&order).set(&order).execute(&mut conn).await.map_err(|e| e.to_string())?;
                    return Ok(());
                }
            };

            let authorization_challenge: crate::models::AuthorizationChallenge =
                crate::schema::authorization_challenges::table.filter(
                    crate::schema::authorization_challenges::dsl::authorization.eq(&authorization_id)
                ).filter(
                    crate::schema::authorization_challenges::dsl::validated_at.is_not_null()
                ).get_result(&mut conn).await.map_err(|e| e.to_string())?;

            let onion_caa_set = if identifier.identifier_type == crate::models::IdentifierType::Dns &&
                identifier.identifier.ends_with(".onion") {
                let i = &identifier.identifier[..identifier.identifier.len() - ".onion".len()];
                let i = match i.rsplit_once(".") {
                    Some((_, i)) => i,
                    None => i
                };
                let i = format!("{}.onion", i);

                onion_caa.get(&i).map(|o| o.clone())
            } else {
                None
            };

            match validator.check_caa(crate::cert_order::CaaCheckRequest {
                validation_method: match authorization_challenge.type_ {
                    crate::models::ChallengeType::Http01 => crate::cert_order::ValidationMethod::Http01.into(),
                    crate::models::ChallengeType::Dns01 => crate::cert_order::ValidationMethod::Dns01.into(),
                    crate::models::ChallengeType::TlsAlpn01 => crate::cert_order::ValidationMethod::TlsAlpn01.into(),
                    crate::models::ChallengeType::OnionCsr01 => crate::cert_order::ValidationMethod::OnionCsr01.into(),
                },
                identifier: Some(identifier.to_pb()),
                account_uri: Some(account_uri.clone()),
                hs_private_key: authorization_challenge.auth_key.unwrap_or_default(),
                onion_caa: onion_caa_set
            }).await {
                Ok(r) => {
                    let r = r.into_inner();
                    if !r.valid {
                        order.error = Some(serde_json::to_value(r.error).unwrap());
                        diesel::update(&order).set(&order).execute(&mut conn).await.map_err(|e| e.to_string())?;
                        return Ok(());
                    }
                },
                Err(e) => {
                    warn!("CAA check failed: {}", e);
                    order.error = Some(serde_json::to_value(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::ServerInternalError.into(),
                            title: "Internal Server Error".to_string(),
                            status: 500,
                            detail: "CAA check unexpectedly failed".to_string(),
                            identifier: None,
                            instance: None,
                            sub_problems: vec![]
                        }]
                    }).unwrap());
                    diesel::update(&order).set(&order).execute(&mut conn).await.map_err(|e| e.to_string())?;
                    return Ok(());
                }
            }
        }

        let cert_id = uuid::Uuid::new_v4();
        let now = Utc::now();
        let expiry = now + chrono::Duration::days(90);
        let csr = openssl::x509::X509Req::from_der(csr)
            .map_err(|e| format!("failed to load CSR: {}", e))?;
        let issuer_cert = openssl::x509::X509::from_der(&chain[0].cert)
            .map_err(|e| format!("failed to load issuer certificate: {}", e))?;

        let issuer_pub_key = issuer_cert.public_key()
            .map_err(|e| format!("failed to load issuer public key: {}", e))?;
        let signing_hash = match issuer_pub_key.id() {
            openssl::pkey::Id::RSA => openssl::hash::MessageDigest::sha512(),
            openssl::pkey::Id::EC => {
                let ec_key = issuer_pub_key.ec_key().unwrap();
                match ec_key.group().order_bits() {
                    256 => openssl::hash::MessageDigest::sha256(),
                    384 => openssl::hash::MessageDigest::sha384(),
                    512 => openssl::hash::MessageDigest::sha512(),
                    _ => {
                        order.error = Some(serde_json::to_value(crate::cert_order::ErrorResponse {
                            errors: vec![crate::cert_order::Error {
                                error_type: crate::cert_order::ErrorType::BadCsrError.into(),
                                title: "Invalid key".to_string(),
                                status: 400,
                                detail: format!("unsupported ECDSA key size: {}", ec_key.group().order_bits()),
                                identifier: None,
                                instance: None,
                                sub_problems: vec![]
                            }]
                        }).unwrap());
                        diesel::update(&order).set(&order).execute(&mut conn).await.map_err(|e| e.to_string())?;
                        return Ok(());
                    }
                }
            },
            _ => {
                order.error = Some(serde_json::to_value(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::BadCsrError.into(),
                        title: "Invalid key".to_string(),
                        status: 400,
                        detail: format!("unsupported issuer public key type: {:?}", issuer_pub_key.id()),
                        identifier: None,
                        instance: None,
                        sub_problems: vec![]
                    }]
                }).unwrap());
                diesel::update(&order).set(&order).execute(&mut conn).await.map_err(|e| e.to_string())?;
                return Ok(())
            }
        };

        let mut builder = openssl::x509::X509Builder::new()
            .map_err(|e| format!("failed to build builder: {}", e))?;
        Self::build_cert(
            &mut builder, &csr, cert_id, now, expiry, &identifiers, &chain[0],
            &issuer_cert
        )?;

        let poison = openssl::x509::X509Extension::new_from_der(
            &openssl::asn1::Asn1Object::from_str("1.3.6.1.4.1.11129.2.4.3").unwrap(),
            true,
            &openssl::asn1::Asn1OctetString::new_from_bytes(&[0x05, 0x00]).unwrap()
        ).map_err(|e| format!("failed to build PreCert Poison: {}", e))?;
        builder.append_extension(poison)
            .map_err(|e| format!("failed to add PreCert Poison: {}", e))?;

        builder.sign(&self.signing_key, signing_hash)
            .map_err(|e| format!("failed to sign PreCert: {}", e))?;

        let pre_cert = builder.build();
        let pre_cert_bytes = pre_cert.to_der()
            .map_err(|e| format!("failed to encode PreCert: {}", e))?;

        let ct_logs = self.ct_logs.iter().filter_map(|ct_log| {
            match &ct_log.expiry_range {
                Some(er) => {
                    if er.start <= expiry && expiry < er.end {
                        Some(&ct_log.url)
                    } else {
                        None
                    }
                },
                None => Some(&ct_log.url)
            }
        }).collect::<Vec<_>>();

        let mut pre_chain = vec![BASE64_STANDARD.encode(pre_cert_bytes)];
        pre_chain.append(&mut chain_bytes.clone());
        let add_pre_chain = crate::sct::CTAddChain {
            chain: pre_chain
        };
        let mut scts = crate::sct::SCTList::new();
        for log in &ct_logs {
            match self.http_client.post(log.join("ct/v1/add-pre-chain").unwrap())
                .json(&add_pre_chain)
                .send().await.and_then(|r| r.error_for_status()) {
                Ok(r) => {
                    let resp = r.text().await
                        .map_err(|e| format!("failed to get SCT response: {}", e))?;
                    let sct: crate::sct::JsonSCT = serde_json::from_str(&resp)
                        .map_err(|e| format!("failed to parse SCT response: {}, got: {}", e, resp))?;
                    scts.push(
                        sct.parse()
                            .map_err(|e| format!("failed to parse SCT response: {}", e))?
                    );
                },
                Err(e) => {
                    warn!("Failed to submit pre-certificate to {}: {}", log, e);
                    return Err(backoff::Error::transient(e.to_string()));
                }
            }
        }

        let mut builder = openssl::x509::X509Builder::new()
            .map_err(|e| format!("failed to build builder: {}", e))?;
        Self::build_cert(
            &mut builder, &csr, cert_id, now, expiry, &identifiers, &chain[0],
            &issuer_cert
        )?;

        let scts_asn1 = scts.encode_asn1();
        let scts_ext = openssl::x509::X509Extension::new_from_der(
            &openssl::asn1::Asn1Object::from_str("1.3.6.1.4.1.11129.2.4.2").unwrap(),
            false,
            &openssl::asn1::Asn1OctetString::new_from_bytes(&scts_asn1).unwrap()
        ).map_err(|e| format!("failed to build SCT list: {}", e))?;
        builder.append_extension(scts_ext)
            .map_err(|e| format!("failed to add SCT list: {}", e))?;

        builder.sign(&self.signing_key, signing_hash)
            .map_err(|e| format!("failed to sign certificate: {}", e))?;

        let ee_cert = builder.build();
        let ee_cert_bytes = ee_cert.to_der()
            .map_err(|e| format!("failed to encode certificate: {}", e))?;

        let mut ee_chain = vec![BASE64_STANDARD.encode(&ee_cert_bytes)];
        ee_chain.append(&mut chain_bytes.clone());
        let add_ee_chain = crate::sct::CTAddChain {
            chain: ee_chain
        };
        for log in &ct_logs {
            match self.http_client.post(log.join("ct/v1/add-chain").unwrap())
                .json(&add_ee_chain)
                .send().await.map(|r| r.error_for_status()) {
                Ok(_) => {},
                Err(e) => {
                    warn!("Failed to submit certificate to {}: {}", log, e);
                    return Err(backoff::Error::transient(e.to_string()));
                }
            }
        }

        let certificate = crate::models::Certificate {
            id: cert_id,
            acme_account_id: order.acme_account_id.clone(),
            ee_cert: ee_cert_bytes,
            issued_at: now.naive_utc(),
            issued_by: self.issuing_cert_id,
            revoked: false,
            revocation_reason: None,
            revocation_timestamp: None,
            invalidity_date: None,
        };
        order.certificate = Some(certificate.id);
        let certificate_identifiers = identifiers.iter().map(|i| {
            crate::models::CertificateIdentifier {
                id: uuid::Uuid::new_v4(),
                certificate_id: certificate.id,
                identifier_type: i.identifier_type,
                identifier: i.identifier.clone(),
            }
        }).collect::<Vec<_>>();

        conn.transaction(|mut conn| Box::pin(async move {
            diesel::insert_into(crate::schema::certificate::table)
                .values(&certificate).execute(&mut conn).await?;
            diesel::insert_into(crate::schema::certificate_identifiers::table)
                .values(&certificate_identifiers).execute(&mut conn).await?;
            diesel::update(&order).set(&order).execute(&mut conn).await?;
            Ok(())
        })).await.map_err(|e: diesel::result::Error| e.to_string())?;

        Ok(())
    }

    fn check_identifier(
        identifier: crate::cert_order::Identifier,
    ) -> Result<(crate::models::IdentifierType, String), crate::cert_order::Error> {
        let onion_zone = trust_dns_proto::rr::Name::from_ascii("onion.").unwrap();

        match crate::cert_order::IdentifierType::from_i32(identifier.id_type) {
            Some(crate::cert_order::IdentifierType::DnsIdentifier) => {
                let name = match trust_dns_proto::rr::Name::from_ascii(&identifier.identifier) {
                    Ok(name) => name.to_lowercase(),
                    Err(_) => {
                        return Err(crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::RejectedIdentifierError.into(),
                            status: 400,
                            title: "Invalid identifier".to_string(),
                            detail: format!("'{}' is not a valid DNS name", identifier.identifier),
                            identifier: Some(identifier),
                            instance: None,
                            sub_problems: vec![]
                        });
                    }
                };

                for l in name.iter() {
                    if l.contains(&b'*') && l != b"*" {
                        return Err(crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::RejectedIdentifierError.into(),
                            status: 400,
                            title: "Unsupported identifier".to_string(),
                            detail: "Partial wildcard identifiers are not supported".to_string(),
                            identifier: Some(identifier),
                            instance: None,
                            sub_problems: vec![]
                        });
                    }
                }

                if !onion_zone.zone_of(&name) {
                    return Err(crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::RejectedIdentifierError.into(),
                        status: 400,
                        title: "Unsupported identifier".to_string(),
                        detail: "Only certificates for .onion domains are supported".to_string(),
                        identifier: Some(identifier),
                        instance: None,
                        sub_problems: vec![]
                    })
                }

                Ok((crate::models::IdentifierType::Dns, identifier.identifier))
            },
            _ => {
                Err(crate::cert_order::Error {
                    error_type: crate::cert_order::ErrorType::UnsupportedIdentifierError.into(),
                    status: 400,
                    title: "Unsupported identifier".to_string(),
                    detail: format!("'{}' is not an identifier we support", identifier.identifier),
                    identifier: Some(identifier),
                    instance: None,
                    sub_problems: vec![]
                })
            }
        }
    }

    fn make_challenges(
        authorization: uuid::Uuid,
        identifier_type: crate::models::IdentifierType, identifier: &str
    ) -> Vec<crate::models::AuthorizationChallenge> {
        let mut rng = rand::thread_rng();
        let mut challenges = vec![];

        let mut auth_key = [0u8; 32];
        rng.fill(&mut auth_key);

        match identifier_type {
            crate::models::IdentifierType::Dns => {
                let is_wildcard = identifier.contains('*');

                if !is_wildcard {
                    let mut http_01_tok = [0u8; 32];
                    rng.fill(&mut http_01_tok);
                    challenges.push(crate::models::AuthorizationChallenge {
                        id: uuid::Uuid::new_v4(),
                        authorization,
                        validated_at: None,
                        processing: false,
                        error: None,
                        type_: crate::models::ChallengeType::Http01,
                        token: Some(BASE64_URL_SAFE_NO_PAD.encode(&http_01_tok)),
                        auth_key: Some(auth_key.to_vec()),
                        nonce: None,
                    });

                    let mut tls_alpn_01_tok = [0u8; 32];
                    rng.fill(&mut tls_alpn_01_tok);
                    challenges.push(crate::models::AuthorizationChallenge {
                        id: uuid::Uuid::new_v4(),
                        authorization,
                        validated_at: None,
                        processing: false,
                        error: None,
                        type_: crate::models::ChallengeType::TlsAlpn01,
                        token: Some(BASE64_URL_SAFE_NO_PAD.encode(&tls_alpn_01_tok)),
                        auth_key: Some(auth_key.to_vec()),
                        nonce: None,
                    });
                }

                let mut onion_csr_01_nonce = [0u8; 16];
                rng.fill(&mut onion_csr_01_nonce);
                challenges.push(crate::models::AuthorizationChallenge {
                    id: uuid::Uuid::new_v4(),
                    authorization,
                    validated_at: None,
                    processing: false,
                    error: None,
                    type_: crate::models::ChallengeType::OnionCsr01,
                    token: None,
                    auth_key: Some(auth_key.to_vec()),
                    nonce: Some(onion_csr_01_nonce.to_vec())
                });
            }
        }

        challenges
    }
}

pub(crate) fn handle_db_result<O>(res: QueryResult<O>) -> Result<O, tonic::Status> {
    match res {
        Ok(res) => Ok(res),
        Err(e) => {
            warn!("Failed to execute DB query: {}", e);
            return Err(tonic::Status::internal(""));
        }
    }
}

#[tonic::async_trait]
impl crate::cert_order::ca_server::Ca for CA {
    async fn validate_eab(
        &self, _request: tonic::Request<crate::cert_order::ValidateEabRequest>
    ) -> Result<tonic::Response<crate::cert_order::ValidateEabResponse>, tonic::Status> {
        Ok(tonic::Response::new(crate::cert_order::ValidateEabResponse {
            valid: false,
        }))
    }

    async fn create_order(
        &self, request: tonic::Request<crate::cert_order::CreateOrderRequest>
    ) -> Result<tonic::Response<crate::cert_order::OrderResponse>, tonic::Status> {
        let request = request.into_inner();
        let now = Utc::now();
        let expiry = (now + chrono::Duration::days(1)).naive_utc();

        let order = crate::models::Order {
            id: uuid::Uuid::new_v4(),
            acme_account_id: request.account_id.clone(),
            expires_at: expiry.clone(),
            csr: None,
            certificate: None,
            error: None,
        };

        let mut errors = vec![];
        let mut identifiers = vec![];

        for identifier in request.identifiers {
            match Self::check_identifier(identifier) {
                Ok((t, i)) => identifiers.push(crate::models::OrderIdentifier {
                    id: uuid::Uuid::new_v4(),
                    order_id: order.id,
                    identifier_type: t,
                    identifier: i,
                    authorization: None,
                }),
                Err(e) => errors.push(e),
            }
        }

        if request.not_before.is_some() {
            errors.push(crate::cert_order::Error {
                error_type: crate::cert_order::ErrorType::MalformedError.into(),
                status: 400,
                title: "Unsupported request".to_string(),
                detail: "'notBefore' is not supported by this server".to_string(),
                identifier: None,
                instance: None,
                sub_problems: vec![]
            });
        }
        if request.not_after.is_some() {
            errors.push(crate::cert_order::Error {
                error_type: crate::cert_order::ErrorType::MalformedError.into(),
                status: 400,
                title: "Unsupported request".to_string(),
                detail: "'notAfter' is not supported by this server".to_string(),
                identifier: None,
                instance: None,
                sub_problems: vec![]
            });
        }

        if !errors.is_empty() {
            return Ok(tonic::Response::new(crate::cert_order::OrderResponse {
                result: Some(crate::cert_order::order_response::Result::Error(
                    crate::cert_order::ErrorResponse {
                        errors
                    }
                ))
            }));
        }

        let mut conn = self.get_db_conn().await?;

        let mut authorizations = vec![];
        let mut existing_authorizations = vec![];
        let mut challenges = vec![];

        'outer: for identifier in &mut identifiers {
            let account_authorizations: Vec<crate::models::Authorization> =
                handle_db_result(crate::schema::authorizations::table
                    .filter(
                        crate::schema::authorizations::dsl::acme_account_id.eq(&request.account_id)
                    ).filter(
                    crate::schema::authorizations::dsl::identifier.eq(&identifier.identifier)
                ).filter(
                    crate::schema::authorizations::dsl::identifier_type.eq(identifier.identifier_type)
                ).get_results(&mut conn).await)?;

            for ea in account_authorizations {
                let s = ea.pb_status();
                if s == crate::cert_order::AuthorizationStatus::AuthorizationValid ||
                    s == crate::cert_order::AuthorizationStatus::AuthorizationPending {
                    identifier.authorization = Some(ea.id);
                    existing_authorizations.push(ea);
                    continue 'outer;
                }
            }

            let authorization = crate::models::Authorization {
                id: uuid::Uuid::new_v4(),
                acme_account_id: request.account_id.clone(),
                state: crate::models::AuthorizationState::Pending,
                expires_at: expiry.clone(),
                deactivated: false,
                revoked: false,
                identifier_type: identifier.identifier_type,
                identifier: identifier.identifier.clone()
            };
            identifier.authorization = Some(authorization.id);

            challenges.append(&mut Self::make_challenges(
                authorization.id, identifier.identifier_type, &identifier.identifier,
            ));
            authorizations.push(authorization);
        }

        let order = handle_db_result(conn.transaction(|mut conn| Box::pin(async move {
            diesel::insert_into(crate::schema::orders::dsl::orders)
                .values(&order).execute(&mut conn).await?;
            for authorization in &authorizations {
                diesel::insert_into(crate::schema::authorizations::dsl::authorizations)
                    .values(authorization).execute(&mut conn).await?;
                diesel::insert_into(crate::schema::order_authorization::dsl::order_authorization)
                    .values(&crate::models::OrderAuthorization {
                        id: uuid::Uuid::new_v4(),
                        order: order.id,
                        authorization: authorization.id,
                    }).execute(&mut conn).await?;
            }
            for identifier in &identifiers {
                diesel::insert_into(crate::schema::order_identifiers::dsl::order_identifiers)
                    .values(identifier).execute(&mut conn).await?;
            }
            for authorization in &existing_authorizations {
                diesel::insert_into(crate::schema::order_authorization::dsl::order_authorization)
                    .values(&crate::models::OrderAuthorization {
                        id: uuid::Uuid::new_v4(),
                        order: order.id,
                        authorization: authorization.id,
                    }).execute(&mut conn).await?;
            }
            for challenge in &challenges {
                diesel::insert_into(crate::schema::authorization_challenges::dsl::authorization_challenges)
                    .values(challenge).execute(&mut conn).await?;
            }
            Ok(order)
        })).await)?;

        Ok(tonic::Response::new(crate::cert_order::OrderResponse {
            result: Some(crate::cert_order::order_response::Result::Order(
                handle_db_result(order.to_pb(&mut conn).await)?
            ))
        }))
    }

    async fn get_order(
        &self, request: tonic::Request<crate::cert_order::IdRequest>
    ) -> Result<tonic::Response<crate::cert_order::Order>, tonic::Status> {
        let request = request.into_inner();
        let order = self.get_order(&request.id).await?;
        let mut conn = self.get_db_conn().await?;
        Ok(tonic::Response::new(handle_db_result(order.to_pb(&mut conn).await)?))
    }

    async fn finalize_order(
        &self, request: tonic::Request<crate::cert_order::FinalizeOrderRequest>
    ) -> Result<tonic::Response<crate::cert_order::OrderResponse>, tonic::Status> {
        let request = request.into_inner();
        let mut order = self.get_order(&request.id).await?;
        let mut conn = self.get_db_conn().await?;

        let authorizations = handle_db_result(order.authorizations(&mut conn).await)?;
        if order.pb_status(&authorizations) != crate::cert_order::OrderStatus::OrderReady {
            return Ok(tonic::Response::new(crate::cert_order::OrderResponse {
                result: Some(crate::cert_order::order_response::Result::Error(
                    crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::OrderNotReadyError.into(),
                            status: 403,
                            title: "Order not ready".to_string(),
                            detail: "Some authorizations are still pending".to_string(),
                            identifier: None,
                            instance: None,
                            sub_problems: vec![]
                        }]
                    }
                ))
            }));
        }

        let req = match openssl::x509::X509Req::from_der(&request.csr) {
            Ok(r) => r,
            Err(_) => return Ok(tonic::Response::new(crate::cert_order::OrderResponse {
                result: Some(crate::cert_order::order_response::Result::Error(
                    crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::MalformedError.into(),
                            status: 400,
                            title: "Malformed CSR".to_string(),
                            detail: "CSR could not be parsed".to_string(),
                            identifier: None,
                            instance: None,
                            sub_problems: vec![]
                        }]
                    }
                ))
            }))
        };

        let public_key = match req.public_key() {
            Ok(k) => k,
            Err(_) => return Ok(tonic::Response::new(crate::cert_order::OrderResponse {
                result: Some(crate::cert_order::order_response::Result::Error(
                    crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::MalformedError.into(),
                            status: 400,
                            title: "Malformed CSR".to_string(),
                            detail: "CSR contains an invalid public key".to_string(),
                            identifier: None,
                            instance: None,
                            sub_problems: vec![]
                        }]
                    }
                ))
            }))
        };

        if !match req.verify(&public_key) {
            Ok(r) => r,
            Err(_) => return Ok(tonic::Response::new(crate::cert_order::OrderResponse {
                result: Some(crate::cert_order::order_response::Result::Error(
                    crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::MalformedError.into(),
                            status: 400,
                            title: "Malformed CSR".to_string(),
                            detail: "CSR signature could not be verified".to_string(),
                            identifier: None,
                            instance: None,
                            sub_problems: vec![]
                        }]
                    }
                ))
            }))
        } {
            return Ok(tonic::Response::new(crate::cert_order::OrderResponse {
                result: Some(crate::cert_order::order_response::Result::Error(
                    crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::MalformedError.into(),
                            status: 400,
                            title: "Malformed CSR".to_string(),
                            detail: "CSR not signed by inner public key".to_string(),
                            identifier: None,
                            instance: None,
                            sub_problems: vec![]
                        }]
                    }
                ))
            }));
        }

        order.csr = Some(match req.to_der() {
            Ok(d) => d,
            Err(_) => return Err(tonic::Status::internal(""))
        });

        handle_db_result(diesel::update(&order).set(&order).execute(&mut conn).await)?;

        let t_order = order.clone();
        let t_self = self.clone();
        tokio::task::spawn(async move {
            let _ = backoff::future::retry(backoff::ExponentialBackoff::default(), || async {
                t_self.sign_order_task(
                    t_order.clone(), request.account_uri.clone(), request.onion_caa.clone()
                ).await.map_err(|e| {
                    warn!("Failed to sign order: {}", e);
                    e
                })
            }).await;
        });

        Ok(tonic::Response::new(crate::cert_order::OrderResponse {
            result: Some(crate::cert_order::order_response::Result::Order(
                handle_db_result(order.to_pb(&mut conn).await)?
            ))
        }))
    }

    async fn create_authorization(
        &self, request: tonic::Request<crate::cert_order::CreateAuthorizationRequest>
    ) -> Result<tonic::Response<crate::cert_order::AuthorizationResponse>, tonic::Status> {
        let request = request.into_inner();
        let now = Utc::now();
        let expiry = (now + chrono::Duration::days(1)).naive_utc();

        let (identifier_type, identifier) = match Self::check_identifier(request.identifier.unwrap()) {
            Ok(r) => r,
            Err(e) => return Ok(tonic::Response::new(crate::cert_order::AuthorizationResponse {
                result: Some(crate::cert_order::authorization_response::Result::Error(
                    crate::cert_order::ErrorResponse {
                        errors: vec![e]
                    }
                ))
            }))
        };

        let authorization_id = uuid::Uuid::new_v4();
        let challenges = Self::make_challenges(
            authorization_id, identifier_type, &identifier,
        );
        let authorization = crate::models::Authorization {
            id: authorization_id,
            acme_account_id: request.account_id.clone(),
            state: crate::models::AuthorizationState::Pending,
            expires_at: expiry.clone(),
            deactivated: false,
            revoked: false,
            identifier_type,
            identifier,
        };

        let mut conn = self.get_db_conn().await?;

        let authorization = handle_db_result(conn.transaction(|mut conn| Box::pin(async move {
            diesel::insert_into(crate::schema::authorizations::dsl::authorizations)
                .values(&authorization).execute(&mut conn).await?;
            for challenge in &challenges {
                diesel::insert_into(crate::schema::authorization_challenges::dsl::authorization_challenges)
                    .values(challenge).execute(&mut conn).await?;
            }
            Ok(authorization)
        })).await)?;

        Ok(tonic::Response::new(crate::cert_order::AuthorizationResponse {
            result: Some(crate::cert_order::authorization_response::Result::Authorization(
                handle_db_result(authorization.to_pb(&mut conn).await)?
            ))
        }))
    }

    async fn get_authorization(
        &self, request: tonic::Request<crate::cert_order::IdRequest>
    ) -> Result<tonic::Response<crate::cert_order::Authorization>, tonic::Status> {
        let request = request.into_inner();
        let authorization = self.get_authorization(&request.id).await?;
        let mut conn = self.get_db_conn().await?;
        Ok(tonic::Response::new(handle_db_result(authorization.to_pb(&mut conn).await)?))
    }

    async fn deactivate_authorization(
        &self, request: tonic::Request<crate::cert_order::IdRequest>
    ) -> Result<tonic::Response<crate::cert_order::AuthorizationResponse>, tonic::Status> {
        let request = request.into_inner();
        let mut authorization = self.get_authorization(&request.id).await?;
        let mut conn = self.get_db_conn().await?;

        authorization.deactivated = true;

        handle_db_result(diesel::update(&authorization).set(&authorization).execute(&mut conn).await)?;

        Ok(tonic::Response::new(crate::cert_order::AuthorizationResponse {
            result: Some(crate::cert_order::authorization_response::Result::Authorization(
                handle_db_result(authorization.to_pb(&mut conn).await)?
            ))
        }))
    }

    async fn get_challenge(
        &self, request: tonic::Request<crate::cert_order::ChallengeIdRequest>
    ) -> Result<tonic::Response<crate::cert_order::Challenge>, tonic::Status> {
        let request = request.into_inner();
        let challenge = self.get_challenge(&request.id, &request.auth_id).await?;
        Ok(tonic::Response::new(challenge.to_pb()))
    }

    async fn complete_challenge(
        &self, request: tonic::Request<crate::cert_order::CompleteChallengeRequest>
    ) -> Result<tonic::Response<crate::cert_order::ChallengeResponse>, tonic::Status> {
        let request = request.into_inner();
        let mut challenge = self.get_challenge(&request.id, &request.auth_id).await?;

        if challenge.pb_status() != crate::cert_order::ChallengeStatus::ChallengePending {
            return Ok(tonic::Response::new(crate::cert_order::ChallengeResponse {
                result: Some(crate::cert_order::challenge_response::Result::Error(
                    crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::MalformedError.into(),
                            status: 400,
                            title: "Invalid request".to_string(),
                            detail: "Challenge not in a pending state".to_string(),
                            identifier: None,
                            instance: None,
                            sub_problems: vec![]
                        }]
                    }
                ))
            }));
        }

        let mut conn = self.get_db_conn().await?;
        let authorization: crate::models::Authorization = handle_db_result(crate::schema::authorizations::table
            .find(challenge.authorization).get_result(&mut conn).await)?;

        if authorization.pb_status() != crate::cert_order::AuthorizationStatus::AuthorizationPending {
            return Ok(tonic::Response::new(crate::cert_order::ChallengeResponse {
                result: Some(crate::cert_order::challenge_response::Result::Error(
                    crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::MalformedError.into(),
                            status: 400,
                            title: "Invalid request".to_string(),
                            detail: "Authorization not in a pending state".to_string(),
                            identifier: None,
                            instance: None,
                            sub_problems: vec![]
                        }]
                    }
                ))
            }));
        }

        challenge.processing = true;

        handle_db_result(diesel::update(&challenge).set(&challenge).execute(&mut conn).await)?;

        let response = match request.response {
            None => ChallengeResponse::None,
            Some(crate::cert_order::complete_challenge_request::Response::Csr(csr)) => ChallengeResponse::CSR(csr)
        };

        let t_challenge = challenge.clone();
        let t_self = self.clone();
        tokio::task::spawn(async move {
            let _ = backoff::future::retry(backoff::ExponentialBackoff::default(), || async {
                t_self.complete_challenge_task(
                    t_challenge.clone(), request.account_thumbprint.clone(), response.clone()
                ).await.map_err(|e| {
                    warn!("Failed to process challenge response: {}", e);
                    e
                })
            }).await;
        });

        Ok(tonic::Response::new(crate::cert_order::ChallengeResponse {
            result: Some(crate::cert_order::challenge_response::Result::Challenge(challenge.to_pb()))
        }))
    }

    async fn get_certificate(
        &self, request: tonic::Request<crate::cert_order::IdRequest>
    ) -> Result<tonic::Response<crate::cert_order::CertificateChainResponse>, tonic::Status> {
        let request = request.into_inner();
        let certificate_id = match uuid::Uuid::from_slice(&request.id) {
            Ok(i) => i,
            Err(_) => return Err(tonic::Status::new(tonic::Code::NotFound, "Requested certificate not found"))
        };

        let mut conn = self.get_db_conn().await?;
        let certificate: crate::models::Certificate = match handle_db_result(
            crate::schema::certificate::dsl::certificate.find(certificate_id)
                .get_result(&mut conn).await.optional()
        )? {
            Some(o) => o,
            None => return Err(tonic::Status::new(tonic::Code::NotFound, "Requested certificate not found"))
        };

        let mut certs = vec![certificate.ee_cert];
        let mut issued_by = Some(certificate.issued_by);
        while let Some(id) = issued_by {
            let issuing_cert: crate::models::IssuingCert = handle_db_result(
                crate::schema::issuing_certs::dsl::issuing_certs.find(id)
                    .get_result(&mut conn).await
            )?;
            certs.push(issuing_cert.cert.clone());
            issued_by = issuing_cert.issued_by;
        }

        Ok(tonic::Response::new(crate::cert_order::CertificateChainResponse {
            primary_chain: Some(crate::cert_order::CertificateChain {
                certificates: certs
            }),
            alternative_chains: vec![]
        }))
    }

    async fn revoke_certificate(
        &self, request: tonic::Request<crate::cert_order::RevokeCertRequest>
    ) -> Result<tonic::Response<crate::cert_order::RevokeCertResponse>, tonic::Status> {
        let request = request.into_inner();
        let issuer_id = match uuid::Uuid::from_str(&request.issuer_id) {
            Ok(i) => i,
            Err(_) => return Err(tonic::Status::new(tonic::Code::NotFound, "Requested issuer not found"))
        };
        let certificate_id = match uuid::Uuid::from_slice(&request.serial_number) {
            Ok(i) => i,
            Err(_) => return Err(tonic::Status::new(tonic::Code::NotFound, "Requested certificate not found"))
        };

        let mut conn = self.get_db_conn().await?;
        let mut certificate: crate::models::Certificate = match handle_db_result(
            crate::schema::certificate::table
                .filter(
                    crate::schema::certificate::dsl::id.eq(certificate_id)
                )
                .filter(
                    crate::schema::certificate::dsl::issued_by.eq(issuer_id)
                )
                .get_result(&mut conn).await.optional()
        )? {
            Some(o) => o,
            None => return Err(tonic::Status::new(tonic::Code::NotFound, "Requested certificate not found"))
        };

        if !request.authz_checked && certificate.acme_account_id != request.account_id {
            let certificate_identifiers: Vec<crate::models::CertificateIdentifier> =
                handle_db_result(crate::schema::certificate_identifiers::table
                .filter(
                    crate::schema::certificate_identifiers::dsl::certificate_id.eq(&certificate.id)
                ).get_results(&mut conn).await)?;

            for ci in &certificate_identifiers {
                let authorizations: Vec<crate::models::Authorization> =
                    handle_db_result(crate::schema::authorizations::table
                    .filter(
                        crate::schema::authorizations::dsl::acme_account_id.eq(&request.account_id)
                    ).filter(
                        crate::schema::authorizations::dsl::identifier.eq(&ci.identifier)
                    ).filter(
                        crate::schema::authorizations::dsl::identifier_type.eq(ci.identifier_type)
                    ).get_results(&mut conn).await)?;

                if !authorizations.iter().any(|a| {
                    a.pb_status() != crate::cert_order::AuthorizationStatus::AuthorizationValid
                }) {
                    return Ok(tonic::Response::new(crate::cert_order::RevokeCertResponse {
                        error: Some(crate::cert_order::ErrorResponse {
                            errors: vec![crate::cert_order::Error {
                                error_type: crate::cert_order::ErrorType::UnauthorizedError.into(),
                                status: 403,
                                title: "Unauthorized".to_string(),
                                detail: "Your account is not authorized to revoke this certificate".to_string(),
                                identifier: None,
                                instance: None,
                                sub_problems: vec![]
                            }]
                        })
                    }))
                }
            }
        }

        let revocation_reason = match request.revocation_reason {
            Some(r) => match r {
                // Unspecified
                0 |
                // Key Compromise
                1 |
                // Affiliation changed
                3 |
                // Superseded
                4 |
                // Cessation of operation
                5 => r,
                o => return Ok(tonic::Response::new(crate::cert_order::RevokeCertResponse {
                    error: Some(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::BadRevocationReasonError.into(),
                            status: 403,
                            title: "Unsupported revocation reason".to_string(),
                            detail: format!("Revocation reason code {} is not supported", o),
                            identifier: None,
                            instance: None,
                            sub_problems: vec![]
                        }]
                    })
                }))
            },
            None => 0,
        };

        certificate.revoked = true;
        certificate.revocation_reason = Some(revocation_reason as i16);
        certificate.revocation_timestamp = Some(Utc::now().naive_utc());

        handle_db_result(diesel::update(&certificate).set(&certificate).execute(&mut conn).await)?;

        Ok(tonic::Response::new(crate::cert_order::RevokeCertResponse {
            error: None
        }))
    }
}