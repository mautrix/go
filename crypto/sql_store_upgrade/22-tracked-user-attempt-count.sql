-- v22 (compatible with v20+): Track number of device list fetch attempts
ALTER TABLE crypto_tracked_user ADD COLUMN last_attempt BIGINT;
ALTER TABLE crypto_tracked_user ADD COLUMN error_count INTEGER;
