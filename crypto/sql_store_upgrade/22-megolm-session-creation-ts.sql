-- v22 (compatible with v20+): Store the sender-provided creation timestamp for megolm sessions
ALTER TABLE crypto_megolm_inbound_session ADD COLUMN session_creation_ts timestamp;
