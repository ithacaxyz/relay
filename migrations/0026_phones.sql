create table phones (
    address bytea not null,
    phone text not null,
    verification_sid text not null,
    verified_at timestamp,
    attempts int not null default 0,
    created_at timestamp not null default now()
);

-- only allow a phone number once per account to prevent spam
create unique index idx_address_phone on phones (address, phone);

-- index for looking up verified phone numbers
create index idx_phone_verified on phones (phone, verified_at);