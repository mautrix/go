-- v22 (compatible with v9+): Add message send transaction ID column
ALTER TABLE message ADD COLUMN send_txn_id TEXT;
-- only: postgres
ALTER TABLE message ADD CONSTRAINT message_txn_id_unique UNIQUE (bridge_id, room_receiver, send_txn_id);
-- only: sqlite
CREATE UNIQUE INDEX message_txn_id_unique ON message (bridge_id, room_receiver, send_txn_id);
