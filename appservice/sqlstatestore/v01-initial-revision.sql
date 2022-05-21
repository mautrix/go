-- v1: Initial revision

CREATE TABLE mx_registrations (
	user_id TEXT PRIMARY KEY
);

CREATE TABLE mx_user_profile (
	room_id     TEXT,
	user_id     TEXT,
	membership  TEXT NOT NULL,
	displayname TEXT,
	avatar_url  TEXT,
	PRIMARY KEY (room_id, user_id)
);

CREATE TABLE mx_room_state (
	room_id      TEXT PRIMARY KEY,
	power_levels jsonb
);
