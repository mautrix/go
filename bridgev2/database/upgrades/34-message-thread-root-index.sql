-- v34 (compatible with v9+): Add index for finding messages in threads
CREATE INDEX message_thread_root_idx ON message (bridge_id, room_receiver, thread_root_id);
