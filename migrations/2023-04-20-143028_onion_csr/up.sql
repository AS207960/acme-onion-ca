alter table authorization_challenges add column auth_key bytea null;
alter table authorization_challenges add constraint auth_key_length check (octet_length(auth_key) = 32);
alter table authorization_challenges add column nonce bytea null;