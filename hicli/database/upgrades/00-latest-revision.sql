-- v0 -> v1: Latest revision
CREATE TABLE account (
	user_id        TEXT NOT NULL PRIMARY KEY,
	device_id      TEXT NOT NULL,
	access_token   TEXT NOT NULL,
	homeserver_url TEXT NOT NULL,

	next_batch     TEXT NOT NULL
) STRICT;

CREATE TABLE room (
	room_id           TEXT    NOT NULL PRIMARY KEY,
	creation_content  TEXT,

	name              TEXT,
	avatar            TEXT,
	topic             TEXT,
	lazy_load_summary TEXT,

	encryption_event  TEXT,
	has_member_list   INTEGER NOT NULL DEFAULT false,

	prev_batch        TEXT
) STRICT;
CREATE INDEX room_type_idx ON room (creation_content ->> 'type');

CREATE TABLE account_data (
	user_id TEXT NOT NULL,
	type    TEXT NOT NULL,
	content TEXT NOT NULL,

	PRIMARY KEY (user_id, type)
) STRICT;

CREATE TABLE room_account_data (
	user_id TEXT NOT NULL,
	room_id TEXT NOT NULL,
	type    TEXT NOT NULL,
	content TEXT NOT NULL,

	PRIMARY KEY (user_id, room_id, type),
	CONSTRAINT room_account_data_room_fkey FOREIGN KEY (room_id) REFERENCES room (room_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE event (
	rowid             INTEGER PRIMARY KEY,

	room_id           TEXT    NOT NULL,
	event_id          TEXT    NOT NULL,
	sender            TEXT    NOT NULL,
	type              TEXT    NOT NULL,
	state_key         TEXT,
	timestamp         INTEGER NOT NULL,

	content           TEXT    NOT NULL,
	decrypted         TEXT,
	decrypted_type    TEXT,
	unsigned          TEXT    NOT NULL,

	redacted_by       TEXT,
	relates_to        TEXT,

	megolm_session_id TEXT,
	decryption_error  TEXT,

	CONSTRAINT event_id_unique_key UNIQUE (event_id),
	CONSTRAINT event_room_fkey FOREIGN KEY (room_id) REFERENCES room (room_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX event_room_id_idx ON event (room_id);
CREATE INDEX event_redacted_by_idx ON event (room_id, redacted_by);
CREATE INDEX event_relates_to_idx ON event (room_id, relates_to);
CREATE INDEX event_megolm_session_id_idx ON event (room_id, megolm_session_id);

CREATE TABLE session_request (
	room_id        TEXT    NOT NULL,
	session_id     TEXT    NOT NULL,
	sender         TEXT    NOT NULL,
	min_index      INTEGER NOT NULL,
	backup_checked INTEGER NOT NULL DEFAULT false,
	request_sent   INTEGER NOT NULL DEFAULT false,

	PRIMARY KEY (session_id),
	CONSTRAINT session_request_queue_room_fkey FOREIGN KEY (room_id) REFERENCES room (room_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE timeline (
	rowid       INTEGER PRIMARY KEY,
	room_id     TEXT    NOT NULL,
	event_rowid INTEGER NOT NULL,

	CONSTRAINT timeline_room_fkey FOREIGN KEY (room_id) REFERENCES room (room_id) ON DELETE CASCADE,
	CONSTRAINT timeline_event_fkey FOREIGN KEY (event_rowid) REFERENCES event (rowid) ON DELETE CASCADE
) STRICT;
CREATE INDEX timeline_room_id_idx ON timeline (room_id);

CREATE TABLE current_state (
	room_id     TEXT    NOT NULL,
	event_type  TEXT    NOT NULL,
	state_key   TEXT    NOT NULL,
	event_rowid INTEGER NOT NULL,

	membership TEXT,

	PRIMARY KEY (room_id, event_type, state_key),
	CONSTRAINT current_state_room_fkey FOREIGN KEY (room_id) REFERENCES room (room_id) ON DELETE CASCADE,
	CONSTRAINT current_state_event_fkey FOREIGN KEY (event_rowid) REFERENCES event (rowid)
) STRICT, WITHOUT ROWID;
