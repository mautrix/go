-- v28 (compatible with v9+): Add separate queue_done flag for backfill queue
ALTER TABLE backfill_task ADD COLUMN queue_done BOOLEAN NOT NULL DEFAULT false;
UPDATE backfill_task SET queue_done=true WHERE is_done=true;
