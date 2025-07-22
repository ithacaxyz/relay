create table emails (
    address bytea not null unique,
    email text not null,
    token varchar(255) not null,
    verified_at timestamp,
    created_at timestamp not null default now ()
);

-- only allow an email address once per account to prevent spam
create unique index idx_address_email on emails (address, email);
