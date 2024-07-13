-- v8: Drop relates_to column in messages
-- transaction: off
PRAGMA foreign_keys = OFF;
BEGIN;

CREATE TABLE message_new (
	rowid      INTEGER PRIMARY KEY,

	bridge_id        TEXT    NOT NULL,
	id               TEXT    NOT NULL,
	part_id          TEXT    NOT NULL,
	mxid             TEXT    NOT NULL,

	room_id          TEXT    NOT NULL,
	room_receiver    TEXT    NOT NULL,
	sender_id        TEXT    NOT NULL,
	timestamp        BIGINT  NOT NULL,
	thread_root_id   TEXT,
	reply_to_id      TEXT,
	reply_to_part_id TEXT,
	metadata         jsonb   NOT NULL,

	CONSTRAINT message_room_fkey FOREIGN KEY (bridge_id, room_id, room_receiver)
		REFERENCES portal (bridge_id, id, receiver)
		ON DELETE CASCADE ON UPDATE CASCADE,
	CONSTRAINT message_sender_fkey FOREIGN KEY (bridge_id, sender_id)
		REFERENCES ghost (bridge_id, id)
		ON DELETE CASCADE ON UPDATE CASCADE,
	CONSTRAINT message_real_pkey UNIQUE (bridge_id, room_receiver, id, part_id)
);

INSERT INTO message_new (rowid, bridge_id, id, part_id, mxid, room_id, room_receiver, sender_id, timestamp, metadata)
SELECT rowid, bridge_id, id, part_id, mxid, room_id, room_receiver, sender_id, timestamp, metadata
FROM message;

DROP TABLE message;
ALTER TABLE message_new RENAME TO message;

PRAGMA foreign_key_check;
COMMIT;
PRAGMA foreign_keys = ON;
