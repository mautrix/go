-- v31 (compatible with v9+): Persist view-limited media opens
CREATE TABLE view_limited_message (
    bridge_id TEXT NOT NULL,
    mxid TEXT NOT NULL,
    limit_json TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    request TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'ready',
    viewed_at BIGINT NOT NULL DEFAULT 0,
    type TEXT NOT NULL DEFAULT '',
    disappear_at BIGINT,
    PRIMARY KEY (bridge_id, mxid),
    FOREIGN KEY (bridge_id, mxid) REFERENCES message (bridge_id, mxid) ON DELETE CASCADE ON UPDATE CASCADE
);
