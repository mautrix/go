-- v4 (compatible with v1+): Add relay column for portals (SQLite)
-- transaction: off
-- only: sqlite

PRAGMA foreign_keys = OFF;
BEGIN;

CREATE TABLE user_login_new (
	bridge_id  TEXT  NOT NULL,
	user_mxid  TEXT  NOT NULL,
	id         TEXT  NOT NULL,
	space_room TEXT,
	metadata   jsonb NOT NULL,

	PRIMARY KEY (bridge_id, id),
	CONSTRAINT user_login_user_fkey FOREIGN KEY (bridge_id, user_mxid)
		REFERENCES "user" (bridge_id, mxid)
		ON DELETE CASCADE ON UPDATE CASCADE
);

INSERT INTO user_login_new
SELECT bridge_id, user_mxid, id, space_room, metadata
FROM user_login;

DROP TABLE user_login;
ALTER TABLE user_login_new RENAME TO user_login;


CREATE TABLE user_portal_new (
    bridge_id       TEXT    NOT NULL,
    user_mxid       TEXT    NOT NULL,
    login_id        TEXT    NOT NULL,
    portal_id       TEXT    NOT NULL,
    portal_receiver TEXT    NOT NULL,
    in_space        BOOLEAN NOT NULL,
    preferred       BOOLEAN NOT NULL,
    last_read       BIGINT,

    PRIMARY KEY (bridge_id, user_mxid, login_id, portal_id, portal_receiver),
    CONSTRAINT user_portal_user_login_fkey FOREIGN KEY (bridge_id, login_id)
        REFERENCES user_login (bridge_id, id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT user_portal_portal_fkey FOREIGN KEY (bridge_id, portal_id, portal_receiver)
        REFERENCES portal (bridge_id, id, receiver)
        ON DELETE CASCADE ON UPDATE CASCADE
);

INSERT INTO user_portal_new
SELECT bridge_id, user_mxid, login_id, portal_id, portal_receiver, in_space, preferred, last_read
FROM user_portal;

DROP TABLE user_portal;
ALTER TABLE user_portal_new RENAME TO user_portal;

CREATE TABLE portal_new (
	bridge_id       TEXT    NOT NULL,
	id              TEXT    NOT NULL,
	receiver        TEXT    NOT NULL,
	mxid            TEXT,

	parent_id       TEXT,
	-- This is not accessed by the bridge, it's only used for the portal parent foreign key.
	-- Parent groups are probably never DMs, so they don't need a receiver.
	parent_receiver TEXT    NOT NULL DEFAULT '',

	relay_bridge_id TEXT,
	relay_login_id  TEXT,

	name            TEXT    NOT NULL,
	topic           TEXT    NOT NULL,
	avatar_id       TEXT    NOT NULL,
	avatar_hash     TEXT    NOT NULL,
	avatar_mxc      TEXT    NOT NULL,
	name_set        BOOLEAN NOT NULL,
	avatar_set      BOOLEAN NOT NULL,
	topic_set       BOOLEAN NOT NULL,
	in_space        BOOLEAN NOT NULL,
	metadata        jsonb   NOT NULL,

	PRIMARY KEY (bridge_id, id, receiver),
	CONSTRAINT portal_parent_fkey FOREIGN KEY (bridge_id, parent_id, parent_receiver)
		-- Deletes aren't allowed to cascade here:
		-- children should be re-parented or cleaned up manually
		REFERENCES portal (bridge_id, id, receiver) ON UPDATE CASCADE,
	CONSTRAINT portal_relay_fkey FOREIGN KEY (relay_bridge_id, relay_login_id)
		REFERENCES user_login (bridge_id, id)
		ON DELETE SET NULL ON UPDATE CASCADE
);

INSERT INTO portal_new
SELECT bridge_id, id, receiver, mxid, parent_id, parent_receiver, NULL, NULL,
	   name, topic, avatar_id, avatar_hash, avatar_mxc, name_set, avatar_set, topic_set, in_space, metadata
FROM portal;

DROP TABLE portal;
ALTER TABLE portal_new RENAME TO portal;

PRAGMA foreign_key_check;
COMMIT;
PRAGMA foreign_keys = ON;
