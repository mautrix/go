-- v0 -> v14 (compatible with v9+): Latest revision
CREATE TABLE IF NOT EXISTS crypto_account (
	account_id         TEXT    PRIMARY KEY,
	device_id          TEXT    NOT NULL,
	shared             BOOLEAN NOT NULL,
	sync_token         TEXT    NOT NULL,
	account            bytea   NOT NULL,
	key_backup_version TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS crypto_message_index (
	sender_key CHAR(43),
	session_id CHAR(43),
	"index"    INTEGER,
	event_id   TEXT   NOT NULL,
	timestamp  BIGINT NOT NULL,
	PRIMARY KEY (sender_key, session_id, "index")
);

CREATE TABLE IF NOT EXISTS crypto_tracked_user (
	user_id          TEXT PRIMARY KEY,
	devices_outdated BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS crypto_device (
	user_id      TEXT,
	device_id    TEXT,
	identity_key CHAR(43) NOT NULL,
	signing_key  CHAR(43) NOT NULL,
	trust        SMALLINT NOT NULL,
	deleted      BOOLEAN  NOT NULL,
	name         TEXT     NOT NULL,
	PRIMARY KEY (user_id, device_id)
);

CREATE TABLE IF NOT EXISTS crypto_olm_session (
	account_id     TEXT,
	session_id     CHAR(43),
	sender_key     CHAR(43)  NOT NULL,
	session        bytea     NOT NULL,
	created_at     timestamp NOT NULL,
	last_decrypted timestamp NOT NULL,
	last_encrypted timestamp NOT NULL,
	PRIMARY KEY (account_id, session_id)
);

CREATE TABLE IF NOT EXISTS crypto_megolm_inbound_session (
	account_id         TEXT,
	session_id         CHAR(43),
	sender_key         CHAR(43) NOT NULL,
	signing_key        CHAR(43),
	room_id            TEXT     NOT NULL,
	session            bytea,
	forwarding_chains  bytea,
	withheld_code      TEXT,
	withheld_reason    TEXT,
	ratchet_safety     jsonb,
	received_at        timestamp,
	max_age            BIGINT,
	max_messages       INTEGER,
	is_scheduled       BOOLEAN NOT NULL DEFAULT false,
	key_backup_version TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (account_id, session_id)
);

CREATE TABLE IF NOT EXISTS crypto_megolm_outbound_session (
	account_id    TEXT,
	room_id       TEXT,
	session_id    CHAR(43)  NOT NULL UNIQUE,
	session       bytea     NOT NULL,
	shared        BOOLEAN   NOT NULL,
	max_messages  INTEGER   NOT NULL,
	message_count INTEGER   NOT NULL,
	max_age       BIGINT    NOT NULL,
	created_at    timestamp NOT NULL,
	last_used     timestamp NOT NULL,
	PRIMARY KEY (account_id, room_id)
);

CREATE TABLE IF NOT EXISTS crypto_megolm_outbound_session_shared (
	user_id      TEXT     NOT NULL,
	identity_key CHAR(43) NOT NULL,
	session_id   CHAR(43) NOT NULL,

	PRIMARY KEY (user_id, identity_key, session_id)
);

CREATE TABLE IF NOT EXISTS crypto_cross_signing_keys (
	user_id TEXT,
	usage   TEXT,
	key     CHAR(43) NOT NULL,

	first_seen_key CHAR(43) NOT NULL,

	PRIMARY KEY (user_id, usage)
);

CREATE TABLE IF NOT EXISTS crypto_cross_signing_signatures (
	signed_user_id TEXT,
	signed_key     TEXT,
	signer_user_id TEXT,
	signer_key     TEXT,
	signature      CHAR(88) NOT NULL,
	PRIMARY KEY (signed_user_id, signed_key, signer_user_id, signer_key)
);

CREATE TABLE IF NOT EXISTS crypto_secrets (
	name   TEXT  PRIMARY KEY NOT NULL,
	secret bytea NOT NULL
);
