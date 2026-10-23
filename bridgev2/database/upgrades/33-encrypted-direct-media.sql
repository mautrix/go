-- v33 (compatible with v9+): Add table for encrypted direct media
CREATE TABLE encrypted_direct_media (
	bridge_id   TEXT NOT NULL,
	media_id    TEXT NOT NULL,
	floe_key    TEXT,
	floe_header TEXT,
	handled_at  BIGINT,

	PRIMARY KEY (bridge_id, media_id)
);
