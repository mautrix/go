-- v10: Add metadata for detecting when megolm sessions are safe to delete
ALTER TABLE crypto_megolm_inbound_session ADD COLUMN ratchet_safety jsonb;
ALTER TABLE crypto_megolm_inbound_session ADD COLUMN received_at timestamp;
ALTER TABLE crypto_megolm_inbound_session ADD COLUMN max_age BIGINT;
ALTER TABLE crypto_megolm_inbound_session ADD COLUMN max_messages INTEGER;
ALTER TABLE crypto_megolm_inbound_session ADD COLUMN is_scheduled BOOLEAN NOT NULL DEFAULT false;
