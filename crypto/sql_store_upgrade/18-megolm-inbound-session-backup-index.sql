-- v18 (compatible with v15+): Add an index to the megolm_inbound_session table to make finding sessions to backup faster
CREATE INDEX crypto_megolm_inbound_session_backup_idx ON crypto_megolm_inbound_session(account_id, key_backup_version) WHERE session IS NOT NULL;
