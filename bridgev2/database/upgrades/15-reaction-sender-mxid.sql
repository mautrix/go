-- v15 (compatible with v9+): Save sender MXID for reactions
ALTER TABLE reaction ADD COLUMN sender_mxid TEXT NOT NULL DEFAULT '';
