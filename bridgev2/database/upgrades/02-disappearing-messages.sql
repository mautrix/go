-- v2 (compatible with v1+): Add disappearing messages table
CREATE TABLE disappearing_message (
	bridge_id    TEXT   NOT NULL,
	mx_room      TEXT   NOT NULL,
	mxid         TEXT   NOT NULL,
	type         TEXT   NOT NULL,
	timer        BIGINT NOT NULL,
	disappear_at BIGINT,

	PRIMARY KEY (bridge_id, mxid)
);
