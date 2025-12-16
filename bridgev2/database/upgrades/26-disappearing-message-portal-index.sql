-- v26 (compatible with v9+): Add room index for disappearing message table and portal parents
CREATE INDEX disappearing_message_portal_idx ON disappearing_message (bridge_id, mx_room);
CREATE INDEX portal_parent_idx ON portal (bridge_id, parent_id, parent_receiver);
