-- v11: Add indexes for some foreign keys
CREATE INDEX message_room_idx ON message (bridge_id, room_id, room_receiver);
CREATE INDEX reaction_room_idx ON reaction (bridge_id, room_id, room_receiver);
CREATE INDEX user_portal_portal_idx ON user_portal (bridge_id, portal_id, portal_receiver);
CREATE INDEX user_portal_login_idx ON user_portal (bridge_id, login_id);
