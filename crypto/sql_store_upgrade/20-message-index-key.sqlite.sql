-- v20 (compatible with v20+): Remove sender_key from crypto_message_index
CREATE TABLE IF NOT EXISTS new_crypto_message_index (
	session_id CHAR(43),
	"index"    INTEGER,
	event_id   TEXT   NOT NULL,
	timestamp  BIGINT NOT NULL,
	PRIMARY KEY (session_id, "index")
);

INSERT INTO new_crypto_message_index (session_id, "index", event_id, timestamp)
SELECT session_id, "index", event_id, timestamp FROM crypto_message_index;

DROP TABLE crypto_message_index;
ALTER TABLE new_crypto_message_index RENAME TO crypto_message_index;
