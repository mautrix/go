-- v14 (compatible with v9+): Add key_backup_version column to account and igs

ALTER TABLE crypto_account ADD COLUMN key_backup_version TEXT NOT NULL DEFAULT '';
ALTER TABLE crypto_megolm_inbound_session ADD COLUMN key_backup_version TEXT NOT NULL DEFAULT '';
