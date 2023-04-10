-- v10: Add flag for megolm sessions to mark them as safe to delete
ALTER TABLE crypto_megolm_inbound_session ADD COLUMN ratchet_safety jsonb;
ALTER TABLE crypto_megolm_inbound_session ADD COLUMN received_at timestamp;
ALTER TABLE crypto_megolm_inbound_session ADD COLUMN max_age BIGINT;
ALTER TABLE crypto_megolm_inbound_session ADD COLUMN max_messages INTEGER;
