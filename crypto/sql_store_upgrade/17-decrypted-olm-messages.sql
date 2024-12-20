-- v17 (compatible with v15+): Add table for decrypted Olm message hashes
CREATE TABLE crypto_olm_message_hash (
	account_id   TEXT   NOT NULL,
	received_at  BIGINT NOT NULL,
	message_hash bytea  NOT NULL PRIMARY KEY,

	CONSTRAINT crypto_olm_message_hash_account_fkey FOREIGN KEY (account_id)
		REFERENCES crypto_account (account_id) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX crypto_olm_message_hash_account_idx ON crypto_olm_message_hash (account_id);
