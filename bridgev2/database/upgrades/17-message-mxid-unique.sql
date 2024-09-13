-- v17 (compatible with v9+): Add unique constraint for message and reaction mxids
DELETE FROM message WHERE mxid IN (SELECT mxid FROM message GROUP BY mxid HAVING COUNT(*) > 1);
-- only: postgres for next 2 lines
ALTER TABLE message ADD CONSTRAINT message_mxid_unique UNIQUE (bridge_id, mxid);
ALTER TABLE reaction ADD CONSTRAINT reaction_mxid_unique UNIQUE (bridge_id, mxid);
-- only: sqlite for next 2 lines
CREATE UNIQUE INDEX message_mxid_unique ON message (bridge_id, mxid);
CREATE UNIQUE INDEX reaction_mxid_unique ON reaction (bridge_id, mxid);
