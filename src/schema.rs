// @generated automatically by Diesel CLI.

diesel::table! {
    authorization_challenges (id) {
        id -> Uuid,
        authorization -> Uuid,
        validated_at -> Nullable<Timestamp>,
        processing -> Bool,
        error -> Nullable<Jsonb>,
        #[sql_name = "type"]
        type_ -> crate::models::ChallengeTypeMapping,
        token -> Nullable<Varchar>,
        auth_key -> Nullable<Bytea>,
        nonce -> Nullable<Bytea>,
    }
}

diesel::table! {
    authorizations (id) {
        id -> Uuid,
        acme_account_id -> Varchar,
        state -> crate::models::AuthorizationStateMapping,
        expires_at -> Timestamp,
        deactivated -> Bool,
        revoked -> Bool,
        identifier_type -> crate::models::IdentifierTypeMapping,
        identifier -> Text,
    }
}

diesel::table! {
    certificate (id) {
        id -> Uuid,
        acme_account_id -> Varchar,
        ee_cert -> Bytea,
        issued_at -> Timestamp,
        issued_by -> Uuid,
        revoked -> Bool,
        revocation_reason -> Nullable<Int2>,
        revocation_timestamp -> Nullable<Timestamp>,
        invalidity_date -> Nullable<Timestamp>,
    }
}

diesel::table! {
    certificate_identifiers (id) {
        id -> Uuid,
        certificate_id -> Uuid,
        identifier_type -> crate::models::IdentifierTypeMapping,
        identifier -> Text,
    }
}

diesel::table! {
    issuing_certs (id) {
        id -> Uuid,
        issued_by -> Nullable<Uuid>,
        name -> Varchar,
        cert -> Bytea,
        crl_url -> Nullable<Text>,
        cert_url -> Nullable<Text>,
        ocsp_responder_url -> Array<Nullable<Text>>,
    }
}

diesel::table! {
    order_authorization (id) {
        id -> Uuid,
        order -> Uuid,
        authorization -> Uuid,
    }
}

diesel::table! {
    order_identifiers (id) {
        id -> Uuid,
        order_id -> Uuid,
        identifier_type -> crate::models::IdentifierTypeMapping,
        identifier -> Text,
        authorization -> Nullable<Uuid>,
    }
}

diesel::table! {
    orders (id) {
        id -> Uuid,
        acme_account_id -> Varchar,
        expires_at -> Timestamp,
        csr -> Nullable<Bytea>,
        certificate -> Nullable<Uuid>,
        error -> Nullable<Jsonb>,
    }
}

diesel::joinable!(authorization_challenges -> authorizations (authorization));
diesel::joinable!(certificate -> issuing_certs (issued_by));
diesel::joinable!(certificate_identifiers -> certificate (certificate_id));
diesel::joinable!(order_authorization -> authorizations (authorization));
diesel::joinable!(order_authorization -> orders (order));
diesel::joinable!(order_identifiers -> orders (order_id));
diesel::joinable!(orders -> certificate (certificate));

diesel::allow_tables_to_appear_in_same_query!(
    authorization_challenges,
    authorizations,
    certificate,
    certificate_identifiers,
    issuing_certs,
    order_authorization,
    order_identifiers,
    orders,
);
