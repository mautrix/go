-- v14 (compatible with v9+): Save whether name is custom in portals
ALTER TABLE portal ADD COLUMN name_is_custom BOOLEAN NOT NULL DEFAULT false;
