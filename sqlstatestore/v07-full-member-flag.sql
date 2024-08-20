-- v7 (compatible with v3+): Add flag for whether the full member list has been fetched
ALTER TABLE mx_room_state ADD COLUMN members_fetched BOOLEAN NOT NULL DEFAULT false;
