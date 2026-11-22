-- v34 (compatible with v9+): Store internal media ID for encrypted direct media in database
ALTER TABLE encrypted_direct_media ADD COLUMN internal_id bytea;
