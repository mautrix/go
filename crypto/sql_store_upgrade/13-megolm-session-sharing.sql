-- v13 (compatible with v9+): Add crypto_megolm_outbound_session_shared table

CREATE TABLE IF NOT EXISTS crypto_megolm_outbound_session_shared (
	user_id      TEXT     NOT NULL,
	identity_key CHAR(43) NOT NULL,
	session_id   CHAR(43) NOT NULL,

	PRIMARY KEY (user_id, identity_key, session_id)
);
