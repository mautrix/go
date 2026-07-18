-- v11 (compatible with v3+): Add history visibility to room state table
ALTER TABLE mx_room_state ADD COLUMN history_visibility jsonb;
