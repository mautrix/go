-- v4: Add tables for cross-signing keys
CREATE TABLE IF NOT EXISTS crypto_cross_signing_keys (
	user_id VARCHAR(255) NOT NULL,
	usage   VARCHAR(20)  NOT NULL,
	key     CHAR(43)     NOT NULL,
	PRIMARY KEY (user_id, usage)
);

CREATE TABLE IF NOT EXISTS crypto_cross_signing_signatures (
	signed_user_id VARCHAR(255) NOT NULL,
	signed_key     VARCHAR(255) NOT NULL,
	signer_user_id VARCHAR(255) NOT NULL,
	signer_key     VARCHAR(255) NOT NULL,
	signature      CHAR(88)     NOT NULL,
	PRIMARY KEY (signed_user_id, signed_key, signer_user_id, signer_key)
)
