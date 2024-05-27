-- v15: Fix crypto_secrets table
CREATE TABLE crypto_secrets_new (
	account_id TEXT  NOT NULL,
	name       TEXT  NOT NULL,
	secret     bytea NOT NULL,

	PRIMARY KEY (account_id, name)
);

INSERT INTO crypto_secrets_new (account_id, name, secret)
SELECT '', name, secret
FROM crypto_secrets;

DROP TABLE crypto_secrets;

ALTER TABLE crypto_secrets_new RENAME TO crypto_secrets;

-- only: sqlite
UPDATE crypto_secrets SET account_id=(SELECT account_id FROM crypto_account ORDER BY rowid DESC LIMIT 1);
-- only: postgres
UPDATE crypto_secrets SET account_id=(SELECT account_id FROM crypto_account LIMIT 1);
