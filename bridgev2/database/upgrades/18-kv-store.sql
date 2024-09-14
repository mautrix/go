-- v18 (compatible with v9+): Add generic key-value store
CREATE TABLE kv_store (
	bridge_id TEXT NOT NULL,
	key       TEXT NOT NULL,
	value     TEXT NOT NULL,

	PRIMARY KEY (bridge_id, key)
);
