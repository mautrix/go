-- v10 (compatible with v3+): Add join rules to room state table
ALTER TABLE mx_room_state ADD COLUMN join_rules jsonb;
