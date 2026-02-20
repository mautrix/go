-- v27 (compatible with v9+): Add column for extra ghost profile metadata
ALTER TABLE ghost ADD COLUMN extra_profile jsonb;
