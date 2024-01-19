-- v12 (compatible with v9+): Add crypto_secrets table
CREATE TABLE IF NOT EXISTS crypto_secrets (
	name   TEXT  PRIMARY KEY NOT NULL,
	secret bytea NOT NULL
);
