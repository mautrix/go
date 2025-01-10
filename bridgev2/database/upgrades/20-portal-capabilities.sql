-- v20 (compatible with v9+): Add portal capability state
ALTER TABLE portal ADD COLUMN cap_state jsonb;
