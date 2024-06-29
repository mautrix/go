-- v3 (compatible with v1+): Add relay column for portals (Postgres)
-- only: postgres
ALTER TABLE portal ADD COLUMN relay_bridge_id TEXT;
ALTER TABLE portal ADD COLUMN relay_login_id TEXT;
ALTER TABLE user_portal DROP CONSTRAINT user_portal_user_login_fkey;
ALTER TABLE user_login DROP CONSTRAINT user_login_pkey;
ALTER TABLE user_login ADD CONSTRAINT user_login_pkey PRIMARY KEY (bridge_id, id);
ALTER TABLE user_portal ADD CONSTRAINT user_portal_user_login_fkey FOREIGN KEY (bridge_id, login_id)
	REFERENCES user_login (bridge_id, id)
	ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE portal ADD CONSTRAINT portal_relay_fkey FOREIGN KEY (relay_bridge_id, relay_login_id)
	REFERENCES user_login (bridge_id, id)
	ON DELETE CASCADE ON UPDATE CASCADE;
