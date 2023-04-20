create table issuing_certs
(
    id                 uuid primary key not null,
    issued_by          uuid             null,
    name               varchar(255)     not null,
    cert               bytea            not null,
    crl_url            text             null,
    cert_url           text             null,
    ocsp_responder_url text             null
);

alter table issuing_certs
    add foreign key (issued_by) references issuing_certs (id);

create type identifier_type as enum ('dns');

create table certificate
(
    id                   uuid primary key not null,
    acme_account_id      varchar(255)     not null,
    ee_cert              bytea            not null,
    issued_at            timestamp        not null,
    issued_by            uuid             not null references issuing_certs (id) on update cascade,
    revoked              boolean          not null,
    revocation_reason    smallint         null,
    revocation_timestamp timestamp        null,
    invalidity_date      timestamp        null
);

create table certificate_identifiers
(
    id              uuid primary key not null,
    certificate_id  uuid             not null references certificate (id) on update cascade on delete cascade,
    identifier_type identifier_type  not null,
    identifier      text             not null
);

create table orders
(
    id              uuid primary key                 not null,
    acme_account_id varchar(255)                     not null,
    expires_at      timestamp                        not null,
    csr             bytea                            null,
    certificate     uuid references certificate (id) null
);

create table order_identifiers
(
    id              uuid primary key not null,
    order_id        uuid             not null references orders (id) on update cascade on delete cascade,
    identifier_type identifier_type  not null,
    identifier      text             not null
);

create type authorization_state as enum ('pending', 'valid', 'invalid');

create table authorizations
(
    id              uuid primary key    not null,
    acme_account_id varchar(255)        not null,
    state           authorization_state not null,
    expires_at      timestamp           not null,
    deactivated     bool                not null,
    revoked         bool                not null,
    identifier_type identifier_type     not null,
    identifier      text                not null
);

create type challenge_type as enum ('http-01', 'dns-01', 'tls-alpn-01', 'onion-csr-01');

create table authorization_challenges
(
    id              uuid primary key not null,
    "authorization" uuid             not null references authorizations (id) on update cascade on delete cascade,
    validated_at    timestamp        null,
    processing      bool             not null,
    error           jsonb            null,
    type            challenge_type   not null,
    token           varchar(255)     null
);

create table order_authorization
(
    id              uuid primary key not null,
    "order"         uuid             not null references orders (id) on update cascade on delete cascade,
    "authorization" uuid             not null references authorizations (id) on update cascade on delete cascade
);