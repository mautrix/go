-- v25 (compatible with v9+): Flag for message request portals
ALTER TABLE portal ADD COLUMN message_request BOOLEAN NOT NULL DEFAULT false;
