-- v21 (compatible with v20+): Add shared history flag for megolm sessions
ALTER TABLE crypto_megolm_inbound_session ADD COLUMN shared_history BOOLEAN;
ALTER TABLE crypto_megolm_outbound_session ADD COLUMN shared_history BOOLEAN;
