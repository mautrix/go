-- v5: Switch from VARCHAR(255) to TEXT
-- only: postgres

ALTER TABLE crypto_account ALTER COLUMN device_id TYPE TEXT;
ALTER TABLE crypto_account ALTER COLUMN account_id TYPE TEXT;

ALTER TABLE crypto_device ALTER COLUMN user_id TYPE TEXT;
ALTER TABLE crypto_device ALTER COLUMN device_id TYPE TEXT;
ALTER TABLE crypto_device ALTER COLUMN name TYPE TEXT;

ALTER TABLE crypto_megolm_inbound_session ALTER COLUMN room_id TYPE TEXT;
ALTER TABLE crypto_megolm_inbound_session ALTER COLUMN account_id TYPE TEXT;
ALTER TABLE crypto_megolm_inbound_session ALTER COLUMN withheld_code TYPE TEXT;

ALTER TABLE crypto_megolm_outbound_session ALTER COLUMN room_id TYPE TEXT;
ALTER TABLE crypto_megolm_outbound_session ALTER COLUMN account_id TYPE TEXT;

ALTER TABLE crypto_message_index ALTER COLUMN event_id TYPE TEXT;

ALTER TABLE crypto_olm_session ALTER COLUMN account_id TYPE TEXT;

ALTER TABLE crypto_tracked_user ALTER COLUMN user_id TYPE TEXT;

ALTER TABLE crypto_cross_signing_keys ALTER COLUMN user_id TYPE TEXT;
ALTER TABLE crypto_cross_signing_keys ALTER COLUMN usage TYPE TEXT;

ALTER TABLE crypto_cross_signing_signatures ALTER COLUMN signed_user_id TYPE TEXT;
ALTER TABLE crypto_cross_signing_signatures ALTER COLUMN signed_key TYPE TEXT;
ALTER TABLE crypto_cross_signing_signatures ALTER COLUMN signer_user_id TYPE TEXT;
ALTER TABLE crypto_cross_signing_signatures ALTER COLUMN signer_key TYPE TEXT;
ALTER TABLE crypto_cross_signing_signatures ALTER COLUMN signature TYPE TEXT;
