-- v4: Store room encryption configuration
ALTER TABLE mx_room_state ADD COLUMN encryption jsonb;
