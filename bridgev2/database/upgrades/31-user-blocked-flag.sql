-- v31 (compatible with v9+): Flag for DM portals where the other user is blocked
ALTER TABLE portal ADD COLUMN user_blocked BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX portal_blocked_idx ON portal (bridge_id, receiver, id) WHERE user_blocked = true;
