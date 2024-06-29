-- v5 (compatible with v1+): Add room_receiver to message unique key (Postgres)
-- only: postgres
ALTER TABLE reaction DROP CONSTRAINT reaction_message_fkey;
ALTER TABLE reaction DROP CONSTRAINT reaction_pkey1;
ALTER TABLE reaction ADD PRIMARY KEY (bridge_id, room_receiver, message_id, message_part_id, sender_id, emoji_id);
ALTER TABLE message DROP CONSTRAINT message_real_pkey;
ALTER TABLE message ADD CONSTRAINT message_real_pkey UNIQUE (bridge_id, room_receiver, id, part_id);
ALTER TABLE reaction ADD CONSTRAINT reaction_message_fkey FOREIGN KEY (bridge_id, room_receiver, message_id, message_part_id)
	REFERENCES message (bridge_id, room_receiver, id, part_id)
	ON DELETE CASCADE ON UPDATE CASCADE;
