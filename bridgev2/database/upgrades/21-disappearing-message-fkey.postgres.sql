-- v21 (compatible with v9+): Add foreign key constraint from disappearing_message.mx_room to portals.mxid
CREATE UNIQUE INDEX portal_bridge_mxid_idx ON portal (bridge_id, mxid);
DELETE FROM disappearing_message WHERE mx_room NOT IN (SELECT mxid FROM portal WHERE mxid IS NOT NULL);
ALTER TABLE disappearing_message
    ADD CONSTRAINT disappearing_message_portal_fkey
    FOREIGN KEY (bridge_id, mx_room)
    REFERENCES portal (bridge_id, mxid)
    ON DELETE CASCADE;
