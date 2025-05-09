-- v23 (compatible with v9+): Add media table

CREATE TABLE media (
	bridge_id TEXT NOT NULL,
	id        TEXT NOT NULL,
	metadata  jsonb NOT NULL,

	PRIMARY KEY (bridge_id, id)
);
