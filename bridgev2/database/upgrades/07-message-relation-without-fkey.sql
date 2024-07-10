-- v7: Add new relation columns to messages
ALTER TABLE message ADD COLUMN thread_root_id TEXT;
ALTER TABLE message ADD COLUMN reply_to_id TEXT;
ALTER TABLE message ADD COLUMN reply_to_part_id TEXT;
