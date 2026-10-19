-- v12 (compatible with v3+): Track MSC4350 impersonatable devices of appservice users
ALTER TABLE mx_registrations ADD COLUMN impersonator_device_id TEXT;
ALTER TABLE mx_registrations ADD COLUMN impersonator_signing_key TEXT;
