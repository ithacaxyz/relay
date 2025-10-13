-- Create table for storing historical USD prices for assets
-- Timestamps are normalized to minute boundaries (seconds set to 0)
create table historical_usd_prices (
    asset_uid text not null,
    timestamp bigint not null,
    usd_price double precision not null,
    primary key (asset_uid, timestamp)
);
