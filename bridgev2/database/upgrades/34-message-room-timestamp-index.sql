-- v34 (compatible with v9+): Add timestamp index for messages in rooms
CREATE INDEX message_room_timestamp_idx ON message (bridge_id, room_id, room_receiver, timestamp);
