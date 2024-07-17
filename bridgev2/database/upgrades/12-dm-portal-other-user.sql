-- v12 (compatible with v9+): Save other user ID in DM portals
ALTER TABLE portal ADD COLUMN other_user_id TEXT;
