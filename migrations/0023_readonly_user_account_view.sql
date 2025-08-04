-- Create a view that shows account address, email (if exists), and verification status
CREATE OR REPLACE VIEW account_emails_view AS
SELECT 
    encode(a.address, 'hex') as account_address,
    e.email,
    CASE 
        WHEN e.verified_at IS NOT NULL THEN true
        WHEN e.email IS NOT NULL THEN false
        ELSE NULL
    END as email_verified
FROM accounts a
LEFT JOIN emails e ON a.address = e.address;

-- Create readonly user (Note: password should be changed in production)
-- The user creation might fail if it already exists, so we use DO block for conditional creation
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'readonly_user') THEN
        CREATE USER readonly_user WITH PASSWORD 'changeme_in_production';
    END IF;
END
$$;

-- Revoke all default permissions from readonly_user
REVOKE ALL ON DATABASE postgres FROM readonly_user;
REVOKE ALL ON SCHEMA public FROM readonly_user;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM readonly_user;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM readonly_user;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM readonly_user;

-- Grant connect to database
GRANT CONNECT ON DATABASE postgres TO readonly_user;

-- Grant usage on schema
GRANT USAGE ON SCHEMA public TO readonly_user;

-- Grant SELECT permission ONLY on the account_emails_view
GRANT SELECT ON account_emails_view TO readonly_user;