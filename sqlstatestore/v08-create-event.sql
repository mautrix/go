-- v8 (compatible with v3+): Add create event to room state table
ALTER TABLE mx_room_state ADD COLUMN create_event jsonb;
