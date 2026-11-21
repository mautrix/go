-- v34 (compatible with v9+): Add remote_media_id column to encrypted_direct_media
ALTER TABLE encrypted_direct_media ADD COLUMN remote_media_id bytea;
