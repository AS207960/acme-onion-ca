use super::schema::*;
use diesel::prelude::*;
use chrono::prelude::*;
use diesel_async::RunQueryDsl;

#[derive(DbEnum, Debug, PartialEq, Eq, Copy, Clone)]
pub enum AuthorizationState {
    Pending,
    Valid,
    Invalid
}

#[derive(DbEnum, Debug, PartialEq, Eq, Copy, Clone)]
pub enum ChallengeType {
    #[db_rename = "http-01"]
    Http01,
    #[db_rename = "dns-01"]
    Dns01,
    #[db_rename = "tls-alpn-01"]
    TlsAlpn01,
    #[db_rename = "onion-csr-01"]
    OnionCsr01
}

#[derive(DbEnum, Debug, PartialEq, Eq, Copy, Clone)]
pub enum IdentifierType {
    Dns,
}

#[derive(Insertable, Queryable, Identifiable, Debug, Clone)]
#[diesel(table_name = issuing_certs)]
pub struct IssuingCert {
    pub id: uuid::Uuid,
    pub issued_by: Option<uuid::Uuid>,
    pub name: String,
    pub cert: Vec<u8>,
    pub crl_url: Option<String>,
    pub cert_url: Option<String>,
    pub ocsp_responder_url: Vec<Option<String>>
}

#[derive(Insertable, Queryable, Identifiable, AsChangeset, Debug, Clone)]
#[diesel(table_name = certificate)]
pub struct Certificate {
    pub id: uuid::Uuid,
    pub acme_account_id: String,
    pub ee_cert: Vec<u8>,
    pub issued_at: NaiveDateTime,
    pub issued_by: uuid::Uuid,
    pub revoked: bool,
    pub revocation_reason: Option<i16>,
    pub revocation_timestamp: Option<NaiveDateTime>,
    pub invalidity_date: Option<NaiveDateTime>
}

#[derive(Insertable, Queryable, Identifiable, Debug, Clone)]
#[diesel(table_name = certificate_identifiers)]
pub struct CertificateIdentifier {
    pub id: uuid::Uuid,
    pub certificate_id: uuid::Uuid,
    pub identifier_type: IdentifierType,
    pub identifier: String,
}

#[derive(Insertable, Queryable, Identifiable, AsChangeset, Debug, Clone)]
#[diesel(table_name = orders)]
pub struct Order {
    pub id: uuid::Uuid,
    pub acme_account_id: String,
    pub expires_at: NaiveDateTime,
    pub csr: Option<Vec<u8>>,
    pub certificate: Option<uuid::Uuid>,
    pub error: Option<serde_json::Value>,
}

#[derive(Insertable, Queryable, Identifiable, Debug, Clone)]
#[diesel(table_name = order_identifiers)]
pub struct OrderIdentifier {
    pub id: uuid::Uuid,
    pub order_id: uuid::Uuid,
    pub identifier_type: IdentifierType,
    pub identifier: String,
    pub authorization: Option<uuid::Uuid>,
}

#[derive(Insertable, Queryable, Identifiable, AsChangeset, Debug, Clone)]
#[diesel(table_name = authorizations)]
pub struct Authorization {
    pub id: uuid::Uuid,
    pub acme_account_id: String,
    pub state: AuthorizationState,
    pub expires_at: NaiveDateTime,
    pub deactivated: bool,
    pub revoked: bool,
    pub identifier_type: IdentifierType,
    pub identifier: String,
}

#[derive(Insertable, Queryable, Identifiable, AsChangeset, Debug, Clone)]
#[diesel(table_name = authorization_challenges)]
pub struct AuthorizationChallenge {
    pub id: uuid::Uuid,
    pub authorization: uuid::Uuid,
    pub validated_at: Option<NaiveDateTime>,
    pub processing: bool,
    pub error: Option<serde_json::Value>,
    pub type_: ChallengeType,
    pub token: Option<String>,
    pub auth_key: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

#[derive(Insertable, Queryable, Identifiable, Debug, Clone)]
#[diesel(table_name = order_authorization)]
pub struct OrderAuthorization {
    pub id: uuid::Uuid,
    pub order: uuid::Uuid,
    pub authorization: uuid::Uuid,
}

impl Order {
    fn get_expires_at(&self) -> prost_wkt_types::Timestamp {
        let t = Utc.from_utc_datetime(&self.expires_at);

        prost_wkt_types::Timestamp {
            seconds: t.timestamp(),
            nanos: t.timestamp_subsec_nanos() as i32,
        }
    }

    pub async fn authorizations(&self, conn: &mut crate::DBConn) -> QueryResult<Vec<crate::models::Authorization>> {
        Ok(authorizations::dsl::authorizations.inner_join(
            order_authorization::dsl::order_authorization
        ).filter(
            order_authorization::dsl::order.eq(&self.id)
        ).get_results::<(Authorization, OrderAuthorization)>(conn).await?
            .into_iter().map(|a| a.0).collect::<Vec<_>>())
    }

    pub fn pb_status(&self, authorizations: &[Authorization]) -> crate::cert_order::OrderStatus {
        if self.certificate.is_some() {
            crate::cert_order::OrderStatus::OrderValid
        } else if self.error.is_some() {
            crate::cert_order::OrderStatus::OrderInvalid
        } else if self.csr.is_some() {
            crate::cert_order::OrderStatus::OrderProcessing
        } else if self.expires_at <= Utc::now().naive_utc() {
            crate::cert_order::OrderStatus::OrderInvalid
        } else if authorizations.iter().all(|a| a.pb_status() == crate::cert_order::AuthorizationStatus::AuthorizationValid) {
            crate::cert_order::OrderStatus::OrderReady
        } else if authorizations.iter().any(|a| {
            let s = a.pb_status();
            s == crate::cert_order::AuthorizationStatus::AuthorizationRevoked ||
            s == crate::cert_order::AuthorizationStatus::AuthorizationDeactivated ||
            s == crate::cert_order::AuthorizationStatus::AuthorizationInvalid ||
            s == crate::cert_order::AuthorizationStatus::AuthorizationExpired
        }) {
            crate::cert_order::OrderStatus::OrderInvalid
        } else {
            crate::cert_order::OrderStatus::OrderPending
        }
    }

    pub async fn to_pb(&self, conn: &mut crate::DBConn) -> QueryResult<crate::cert_order::Order> {
        let authorizations = self.authorizations(conn).await?;
        let identifiers = order_identifiers::dsl::order_identifiers.filter(
            order_identifiers::dsl::order_id.eq(&self.id)
        ).get_results::<OrderIdentifier>(conn).await?;

        Ok(crate::cert_order::Order {
            id: self.id.as_bytes().to_vec(),
            identifiers: identifiers.into_iter().map(|i| i.to_pb()).collect(),
            not_before: None,
            not_after: None,
            expires: Some(self.get_expires_at()),
            status: self.pb_status(&authorizations).into(),
            authorizations: authorizations.iter().map(|a| a.id.as_bytes().to_vec()).collect(),
            certificate_id: self.certificate.map(|i| i.as_bytes().to_vec()),
            error: self.error.clone().and_then(|e| serde_json::from_value(e).ok()),
        })
    }
}

impl OrderIdentifier {
    pub fn to_pb(&self) -> crate::cert_order::Identifier {
        crate::cert_order::Identifier {
            identifier: self.identifier.clone(),
            id_type: match self.identifier_type {
                IdentifierType::Dns => crate::cert_order::IdentifierType::DnsIdentifier
            }.into()
        }
    }
}

impl Authorization {
    fn get_expires_at(&self) -> prost_wkt_types::Timestamp {
        let t = Utc.from_utc_datetime(&self.expires_at);

        prost_wkt_types::Timestamp {
            seconds: t.timestamp(),
            nanos: t.timestamp_subsec_nanos() as i32,
        }
    }

    pub fn pb_status(&self) -> crate::cert_order::AuthorizationStatus {
        if self.revoked {
            crate::cert_order::AuthorizationStatus::AuthorizationRevoked
        } else if self.deactivated {
            crate::cert_order::AuthorizationStatus::AuthorizationDeactivated
        } else if self.expires_at <= Utc::now().naive_utc() {
            crate::cert_order::AuthorizationStatus::AuthorizationExpired
        } else if self.state == AuthorizationState::Invalid {
            crate::cert_order::AuthorizationStatus::AuthorizationInvalid
        } else if self.state == AuthorizationState::Valid {
            crate::cert_order::AuthorizationStatus::AuthorizationValid
        } else {
            crate::cert_order::AuthorizationStatus::AuthorizationPending
        }
    }

    pub async fn to_pb(&self, conn: &mut crate::DBConn) -> QueryResult<crate::cert_order::Authorization> {
        let challenges = authorization_challenges::dsl::authorization_challenges.filter(
            authorization_challenges::dsl::authorization.eq(&self.id)
        ).get_results::<AuthorizationChallenge>(conn).await?;

        Ok(crate::cert_order::Authorization {
            id: self.id.as_bytes().to_vec(),
            status: self.pb_status().into(),
            expires: Some(self.get_expires_at()),
            identifier: Some(self.id_to_pb()),
            challenges: challenges.into_iter().map(|i| i.to_pb()).collect(),
            wildcard: None
        })
    }

    pub fn id_to_pb(&self) -> crate::cert_order::Identifier {
        crate::cert_order::Identifier {
            identifier: self.identifier.clone(),
            id_type: match self.identifier_type {
                IdentifierType::Dns => crate::cert_order::IdentifierType::DnsIdentifier
            }.into()
        }
    }
}

impl AuthorizationChallenge {
    pub fn pb_status(&self) -> crate::cert_order::ChallengeStatus {
        if self.error.is_some() {
            crate::cert_order::ChallengeStatus::ChallengeInvalid
        } else if self.validated_at.is_some() {
            crate::cert_order::ChallengeStatus::ChallengeValid
        } else if self.processing {
            crate::cert_order::ChallengeStatus::ChallengeProcessing
        } else {
            crate::cert_order::ChallengeStatus::ChallengePending
        }
    }

    pub fn to_pb(&self) -> crate::cert_order::Challenge {
        crate::cert_order::Challenge {
            id: self.id.as_bytes().to_vec(),
            r#type: match self.type_ {
                ChallengeType::Http01 => crate::cert_order::ChallengeType::ChallengeHttp01,
                ChallengeType::Dns01 => crate::cert_order::ChallengeType::ChallengeDns01,
                ChallengeType::TlsAlpn01 => crate::cert_order::ChallengeType::ChallengeTlsalpn01,
                ChallengeType::OnionCsr01 => crate::cert_order::ChallengeType::ChallengeOnionCsr01,
            }.into(),
            status: self.pb_status().into(),
            validated: self.validated_at.map(|t| {
                let t = Utc.from_utc_datetime(&t);

                prost_wkt_types::Timestamp {
                    seconds: t.timestamp(),
                    nanos: t.timestamp_subsec_nanos() as i32,
                }
            }),
            error: self.error.clone().and_then(|e| serde_json::from_value(e).ok()),
            token: self.token.clone(),
            auth_key: match &self.auth_key {
                Some(ak) => {
                    let ak = TryInto::<[u8; 32]>::try_into(ak.as_slice()).unwrap();
                    let priv_key = x25519_dalek::StaticSecret::from(ak);
                    let pub_key = x25519_dalek::PublicKey::from(&priv_key);
                    pub_key.as_bytes().to_vec()
                },
                None => vec![]
            },
            nonce: match &self.nonce {
                Some(n) => n.to_vec(),
                None => vec![]
            },
        }
    }
}