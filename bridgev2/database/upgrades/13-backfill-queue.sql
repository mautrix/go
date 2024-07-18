-- v13 (compatible with v9+): Add backfill queue
CREATE TABLE backfill_task (
	bridge_id            TEXT    NOT NULL,
	portal_id            TEXT    NOT NULL,
	portal_receiver      TEXT    NOT NULL,
	user_login_id        TEXT    NOT NULL,

	batch_count          INTEGER NOT NULL,
	is_done              BOOLEAN NOT NULL,
	cursor               TEXT,
	oldest_message_id    TEXT,
	dispatched_at        BIGINT,
	completed_at         BIGINT,
	next_dispatch_min_ts BIGINT  NOT NULL,

	PRIMARY KEY (bridge_id, portal_id, portal_receiver),
	CONSTRAINT backfill_queue_portal_fkey FOREIGN KEY (bridge_id, portal_id, portal_receiver)
		REFERENCES portal (bridge_id, id, receiver)
		ON DELETE CASCADE ON UPDATE CASCADE
);
