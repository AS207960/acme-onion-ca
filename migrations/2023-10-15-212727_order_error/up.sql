alter table orders add column error jsonb null;
alter table order_identifiers add column "authorization" uuid null references authorizations (id) on update cascade on delete cascade;