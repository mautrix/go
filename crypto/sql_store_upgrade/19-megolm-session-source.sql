-- v19 (compatible with v15+): Store megolm session source
ALTER TABLE crypto_megolm_inbound_session ADD COLUMN key_source TEXT NOT NULL DEFAULT '';
