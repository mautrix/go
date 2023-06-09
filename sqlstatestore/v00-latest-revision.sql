-- v0 -> v5: Latest revision

CREATE TABLE mx_registrations (
	user_id TEXT PRIMARY KEY
);

-- only: postgres
CREATE TYPE membership AS ENUM ('join', 'leave', 'invite', 'ban', 'knock');

CREATE TABLE mx_user_profile (
	room_id     TEXT,
	user_id     TEXT,
	membership  membership NOT NULL,
	displayname TEXT NOT NULL DEFAULT '',
	avatar_url  TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (room_id, user_id)
);

CREATE TABLE mx_room_state (
	room_id      TEXT PRIMARY KEY,
	power_levels jsonb,
	encryption   jsonb
);
