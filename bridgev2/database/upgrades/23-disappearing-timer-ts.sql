-- v23 (compatible with v9+): Add event timestamp for disappearing messages
ALTER TABLE disappearing_message ADD COLUMN timestamp BIGINT NOT NULL DEFAULT 0;
