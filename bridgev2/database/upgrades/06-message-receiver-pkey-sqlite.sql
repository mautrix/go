-- v6 (compatible with v1+): Add room_receiver to message unique key (SQLite)
-- transaction: off
-- only: sqlite

PRAGMA foreign_keys = OFF;
BEGIN;

CREATE TABLE message_new (
	rowid         INTEGER PRIMARY KEY,

	bridge_id     TEXT   NOT NULL,
	id            TEXT   NOT NULL,
	part_id       TEXT   NOT NULL,
	mxid          TEXT   NOT NULL,

	room_id       TEXT   NOT NULL,
	room_receiver TEXT   NOT NULL,
	sender_id     TEXT   NOT NULL,
	timestamp     BIGINT NOT NULL,
	relates_to    BIGINT,
	metadata      jsonb  NOT NULL,

	CONSTRAINT message_relation_fkey FOREIGN KEY (relates_to)
		REFERENCES message (rowid) ON DELETE SET NULL,
	CONSTRAINT message_room_fkey FOREIGN KEY (bridge_id, room_id, room_receiver)
		REFERENCES portal (bridge_id, id, receiver)
		ON DELETE CASCADE ON UPDATE CASCADE,
	CONSTRAINT message_sender_fkey FOREIGN KEY (bridge_id, sender_id)
		REFERENCES ghost (bridge_id, id)
		ON DELETE CASCADE ON UPDATE CASCADE,
	CONSTRAINT message_real_pkey UNIQUE (bridge_id, room_receiver, id, part_id)
);

INSERT INTO message_new (rowid, bridge_id, id, part_id, mxid, room_id, room_receiver, sender_id, timestamp, relates_to, metadata)
SELECT rowid, bridge_id, id, part_id, mxid, room_id, room_receiver, sender_id, timestamp, relates_to, metadata
FROM message;

DROP TABLE message;
ALTER TABLE message_new RENAME TO message;

CREATE TABLE reaction_new (
	bridge_id       TEXT   NOT NULL,
	message_id      TEXT   NOT NULL,
	message_part_id TEXT   NOT NULL,
	sender_id       TEXT   NOT NULL,
	emoji_id        TEXT   NOT NULL,
	room_id         TEXT   NOT NULL,
	room_receiver   TEXT   NOT NULL,
	mxid            TEXT   NOT NULL,

	timestamp       BIGINT NOT NULL,
	metadata        jsonb  NOT NULL,

	PRIMARY KEY (bridge_id, room_receiver, message_id, message_part_id, sender_id, emoji_id),
	CONSTRAINT reaction_room_fkey FOREIGN KEY (bridge_id, room_id, room_receiver)
		REFERENCES portal (bridge_id, id, receiver)
		ON DELETE CASCADE ON UPDATE CASCADE,
	CONSTRAINT reaction_message_fkey FOREIGN KEY (bridge_id, room_receiver, message_id, message_part_id)
		REFERENCES message (bridge_id, room_receiver, id, part_id)
		ON DELETE CASCADE ON UPDATE CASCADE,
	CONSTRAINT reaction_sender_fkey FOREIGN KEY (bridge_id, sender_id)
		REFERENCES ghost (bridge_id, id)
		ON DELETE CASCADE ON UPDATE CASCADE
);

INSERT INTO reaction_new
SELECT bridge_id, message_id, message_part_id, sender_id, emoji_id, room_id, room_receiver, mxid, timestamp, metadata
FROM reaction;

DROP TABLE reaction;
ALTER TABLE reaction_new RENAME TO reaction;

PRAGMA foreign_key_check;
COMMIT;
PRAGMA foreign_keys = ON;
