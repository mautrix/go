-- v8: Add expired field to cross signing keys
ALTER TABLE crypto_cross_signing_keys ADD COLUMN first_seen_key CHAR(43);
UPDATE crypto_cross_signing_keys SET first_seen_key=key;
-- only: postgres
ALTER TABLE crypto_cross_signing_keys ALTER COLUMN first_seen_key SET NOT NULL;
