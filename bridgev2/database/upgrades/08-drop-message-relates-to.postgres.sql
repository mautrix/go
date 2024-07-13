-- v8: Drop relates_to column in messages
-- transaction: off
ALTER TABLE message DROP COLUMN relates_to;
