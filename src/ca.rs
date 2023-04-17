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
pub struct CA {
    pub db: crate::DBPool,
    pub validator: mobc::Pool<ValidatorManager>
}

impl CA {
    async fn get_db_conn(&self) -> Result<crate::DBConn, tonic::Status> {
        match self.db.get().await {
            Ok(c) => Ok(c),
            Err(e) => {
                warn!("Failed to get DB connection: {}", e);
                return Err(tonic::Status::internal(""));
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
        &self, mut challenge: crate::models::AuthorizationChallenge, thumbprint: String, account_uri: String
    ) -> Result<(), backoff::Error<String>> {
        let mut conn = self.db.get().await.map_err(|e| e.to_string())?;
        let mut authorization: crate::models::Authorization = match crate::schema::authorizations::dsl::authorizations
            .find(challenge.authorization).get_result(&mut conn).await.optional().map_err(|e| e.to_string())? {
            Some(o) => o,
            None => return Err(backoff::Error::Permanent("Requested authorization not found".to_string()))
        };

        let req = crate::cert_order::KeyValidationRequest {
            token: challenge.token.clone().unwrap_or_default(),
            account_thumbprint: thumbprint,
            identifier: Some(authorization.id_to_pb()),
            account_uri: Some(account_uri),
            hs_private_key: vec![],
        };

        let mut validator = self.validator.get().await.map_err(|e| e.to_string())?;

        match match challenge.type_ {
            crate::models::ChallengeType::Http01 => validator.validate_http01(req).await,
            crate::models::ChallengeType::Dns01 => validator.validate_dns01(req).await,
            crate::models::ChallengeType::TlsAlpn01 => validator.validate_tlsalpn01(req).await,
            crate::models::ChallengeType::OnionCsr01 => {
                // TODO: implement
                return Ok(())
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
}

fn handle_db_result<O>(res: QueryResult<O>) -> Result<O, tonic::Status> {
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
        };

        let mut errors = vec![];
        let mut identifiers = vec![];

        let onion_zone = trust_dns_proto::rr::Name::from_ascii("onion.").unwrap();

        'outer: for identifier in request.identifiers {
            match crate::cert_order::IdentifierType::from_i32(identifier.id_type) {
                Some(crate::cert_order::IdentifierType::DnsIdentifier) => {
                    let name = match trust_dns_proto::rr::Name::from_ascii(&identifier.identifier) {
                        Ok(name) => name.to_lowercase(),
                        Err(_) => {
                            errors.push(crate::cert_order::Error {
                                error_type: crate::cert_order::ErrorType::RejectedIdentifierError.into(),
                                status: 400,
                                title: "Invalid identifier".to_string(),
                                detail: format!("'{}' is not a valid DNS name", identifier.identifier),
                                identifier: Some(identifier),
                                instance: None,
                                sub_problems: vec![]
                            });
                            continue;
                        }
                    };

                    for l in name.iter() {
                        if l.contains(&b'*') {
                            errors.push(crate::cert_order::Error {
                                error_type: crate::cert_order::ErrorType::RejectedIdentifierError.into(),
                                status: 400,
                                title: "Unsupported identifier".to_string(),
                                detail: "Wildcard identifiers are not supported".to_string(),
                                identifier: Some(identifier),
                                instance: None,
                                sub_problems: vec![]
                            });
                            continue 'outer;
                        }
                    }

                    if !onion_zone.zone_of(&name) {
                        errors.push(crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::RejectedIdentifierError.into(),
                            status: 400,
                            title: "Unsupported identifier".to_string(),
                            detail: "Only certificates for .onion domains are supported".to_string(),
                            identifier: Some(identifier),
                            instance: None,
                            sub_problems: vec![]
                        });
                        continue;
                    }

                    identifiers.push(crate::models::OrderIdentifier {
                        id: uuid::Uuid::new_v4(),
                        order_id: order.id,
                        identifier_type: crate::models::IdentifierType::Dns,
                        identifier: identifier.identifier
                    });
                },
                _ => {
                    errors.push(crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::UnsupportedIdentifierError.into(),
                        status: 400,
                        title: "Unsupported identifier".to_string(),
                        detail: format!("'{}' is not an identifier we support", identifier.identifier),
                        identifier: Some(identifier),
                        instance: None,
                        sub_problems: vec![]
                    });
                }
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

        let mut authorizations = vec![];
        let mut challenges = vec![];

        for identifier in &identifiers {
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

            let mut rng = rand::thread_rng();

            let mut http_01_tok = [0u8; 32];
            rng.fill(&mut http_01_tok);
            let challenge_http_01 = crate::models::AuthorizationChallenge {
                id: uuid::Uuid::new_v4(),
                authorization: authorization.id,
                validated_at: None,
                processing: false,
                error: None,
                type_: crate::models::ChallengeType::Http01,
                token: Some(BASE64_URL_SAFE_NO_PAD.encode(&http_01_tok)),
            };

            let mut tls_alpn_01_tok = [0u8; 32];
            rng.fill(&mut tls_alpn_01_tok);
            let challenge_tls_alpn_01 = crate::models::AuthorizationChallenge {
                id: uuid::Uuid::new_v4(),
                authorization: authorization.id,
                validated_at: None,
                processing: false,
                error: None,
                type_: crate::models::ChallengeType::TlsAlpn01,
                token: Some(BASE64_URL_SAFE_NO_PAD.encode(&tls_alpn_01_tok)),
            };

            authorizations.push(authorization);
            challenges.push(challenge_http_01);
            challenges.push(challenge_tls_alpn_01);
        }

        let mut conn = self.get_db_conn().await?;

        let order = handle_db_result(conn.transaction(|mut conn| Box::pin(async move {
            diesel::insert_into(crate::schema::orders::dsl::orders)
                .values(&order).execute(&mut conn).await?;
            for identifier in &identifiers {
                diesel::insert_into(crate::schema::order_identifiers::dsl::order_identifiers)
                    .values(identifier).execute(&mut conn).await?;
            }
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

        // TODO: sign order in the background

        Ok(tonic::Response::new(crate::cert_order::OrderResponse {
            result: Some(crate::cert_order::order_response::Result::Order(
                handle_db_result(order.to_pb(&mut conn).await)?
            ))
        }))
    }

    async fn create_authorization(
        &self, _request: tonic::Request<crate::cert_order::CreateAuthorizationRequest>
    ) -> Result<tonic::Response<crate::cert_order::AuthorizationResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("Authorizations may only be created by an creating an order"))
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

        let t_challenge = challenge.clone();
        let t_self = self.clone();
        tokio::task::spawn(async move {
            let _ = backoff::future::retry(backoff::ExponentialBackoff::default(), || async {
                t_self.complete_challenge_task(
                    t_challenge.clone(), request.account_thumbprint.clone(), request.account_uri.clone()
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