-- v16 (compatible with v15+): Add index to crypto_olm_sessions to speedup lookups by sender_key
CREATE INDEX crypto_olm_session_sender_key_idx ON crypto_olm_session (account_id, sender_key);
