-- v34 (compatible with v9+): Store last bridged remote mute and tag in user portals
ALTER TABLE user_portal ADD COLUMN muted_until BIGINT;
ALTER TABLE user_portal ADD COLUMN tag TEXT;
