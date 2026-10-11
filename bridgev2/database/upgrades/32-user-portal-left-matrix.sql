-- v32 (compatible with v9+): Flag for portals the user left on Matrix without leaving on the remote network
ALTER TABLE user_portal ADD COLUMN left_matrix BOOLEAN NOT NULL DEFAULT false;
