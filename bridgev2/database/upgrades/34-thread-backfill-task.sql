-- v34 (compatible with v9+): Add table for deferred thread backfill
CREATE TABLE thread_backfill_task (
	bridge_id            TEXT    NOT NULL,
	portal_id            TEXT    NOT NULL,
	portal_receiver      TEXT    NOT NULL,
	thread_root_id       TEXT    NOT NULL,
	user_login_id        TEXT    NOT NULL,
	mark_read            BOOLEAN NOT NULL,
	queued_at            BIGINT  NOT NULL,
	next_dispatch_min_ts BIGINT  NOT NULL,

	PRIMARY KEY (bridge_id, portal_id, portal_receiver, thread_root_id),
	CONSTRAINT thread_backfill_task_portal_fkey FOREIGN KEY (bridge_id, portal_id, portal_receiver)
		REFERENCES portal (bridge_id, id, receiver)
		ON DELETE CASCADE ON UPDATE CASCADE,
	CONSTRAINT thread_backfill_task_user_login_fkey FOREIGN KEY (bridge_id, user_login_id)
		REFERENCES user_login (bridge_id, id)
		ON DELETE CASCADE ON UPDATE CASCADE
);
