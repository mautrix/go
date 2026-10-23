-- v23 (compatible with v23+): Key received megolm sessions by room ID
CREATE TABLE crypto_megolm_inbound_session_new (
	account_id         TEXT     NOT NULL,
	session_id         CHAR(43) NOT NULL,
	sender_key         CHAR(43) NOT NULL,
	signing_key        CHAR(43),
	room_id            TEXT     NOT NULL,
	session            bytea,
	forwarding_chains  bytea,
	shared_history     BOOLEAN,
	withheld_code      TEXT,
	withheld_reason    TEXT,
	ratchet_safety     jsonb,
	received_at        timestamp,
	max_age            BIGINT,
	max_messages       INTEGER,
	is_scheduled       BOOLEAN NOT NULL DEFAULT false,
	key_backup_version TEXT NOT NULL DEFAULT '',
	key_source         TEXT NOT NULL DEFAULT '',
	source_user        TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (account_id, room_id, session_id)
);
INSERT INTO crypto_megolm_inbound_session_new (
	account_id, session_id, sender_key, signing_key, room_id, "session", forwarding_chains, shared_history,
	withheld_code, withheld_reason, ratchet_safety, received_at, max_age, max_messages, is_scheduled,
	key_backup_version, key_source, source_user
)
SELECT
	account_id, session_id, sender_key, signing_key, room_id, "session", forwarding_chains, shared_history,
	withheld_code, withheld_reason, ratchet_safety, received_at, max_age, max_messages, is_scheduled,
	key_backup_version, key_source, source_user
FROM crypto_megolm_inbound_session;
DROP TABLE crypto_megolm_inbound_session;
ALTER TABLE crypto_megolm_inbound_session_new RENAME TO crypto_megolm_inbound_session;
CREATE INDEX crypto_megolm_inbound_session_backup_idx ON crypto_megolm_inbound_session(account_id, key_backup_version) WHERE session IS NOT NULL;
