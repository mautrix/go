-- v11: Add devices_outdated field to crypto_tracked_user
ALTER TABLE crypto_tracked_user ADD COLUMN devices_outdated BOOLEAN NOT NULL DEFAULT FALSE;
