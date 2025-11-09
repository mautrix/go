-- v24 (compatible with v9+): Custom URLs for public media
CREATE TABLE public_media (
	bridge_id TEXT   NOT NULL,
	public_id TEXT   NOT NULL,
	mxc       TEXT   NOT NULL,
	keys      jsonb,
	mimetype  TEXT,
	expiry    BIGINT,

	PRIMARY KEY (bridge_id, public_id)
);
