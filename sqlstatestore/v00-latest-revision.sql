-- v0 -> v7 (compatible with v3+): Latest revision

CREATE TABLE mx_registrations (
	user_id TEXT PRIMARY KEY
);

-- only: postgres
CREATE TYPE membership AS ENUM ('join', 'leave', 'invite', 'ban', 'knock');

CREATE TABLE mx_user_profile (
	room_id       TEXT,
	user_id       TEXT,
	membership    membership NOT NULL,
	displayname   TEXT       NOT NULL DEFAULT '',
	avatar_url    TEXT       NOT NULL DEFAULT '',

	name_skeleton bytea,

	PRIMARY KEY (room_id, user_id)
);

CREATE INDEX mx_user_profile_membership_idx ON mx_user_profile (room_id, membership);
CREATE INDEX mx_user_profile_name_skeleton_idx ON mx_user_profile (room_id, name_skeleton);

CREATE TABLE mx_room_state (
	room_id         TEXT PRIMARY KEY,
	power_levels    jsonb,
	encryption      jsonb,
	members_fetched BOOLEAN NOT NULL DEFAULT false
);
