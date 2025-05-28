-- v21 (compatible with v9+): Add foreign key constraint from disappearing_message.mx_room to portals.mxid
CREATE UNIQUE INDEX portal_bridge_mxid_idx ON portal (bridge_id, mxid);
CREATE TABLE disappearing_message_new (
    bridge_id    TEXT   NOT NULL,
    mx_room      TEXT   NOT NULL,
    mxid         TEXT   NOT NULL,
    type         TEXT   NOT NULL,
    timer        BIGINT NOT NULL,
    disappear_at BIGINT,

    PRIMARY KEY (bridge_id, mxid),
    CONSTRAINT disappearing_message_portal_fkey
        FOREIGN KEY (bridge_id, mx_room)
        REFERENCES portal (bridge_id, mxid)
        ON DELETE CASCADE
);

WITH portal_mxids AS (SELECT mxid FROM portal WHERE mxid IS NOT NULL)
INSERT INTO disappearing_message_new (bridge_id, mx_room, mxid, type, timer, disappear_at)
SELECT bridge_id, mx_room, mxid, type, timer, disappear_at
FROM disappearing_message WHERE mx_room IN portal_mxids;

DROP TABLE disappearing_message;
ALTER TABLE disappearing_message_new RENAME TO disappearing_message;
