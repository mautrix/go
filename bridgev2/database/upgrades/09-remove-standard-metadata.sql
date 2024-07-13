-- v9: Move standard metadata to separate columns
ALTER TABLE message ADD COLUMN sender_mxid TEXT NOT NULL DEFAULT '';
UPDATE message SET sender_mxid=COALESCE((metadata->>'sender_mxid'), '');

ALTER TABLE message ADD COLUMN edit_count INTEGER NOT NULL DEFAULT 0;
UPDATE message SET edit_count=COALESCE(CAST((metadata->>'edit_count') AS INTEGER), 0);

ALTER TABLE portal ADD COLUMN disappear_type TEXT;
UPDATE portal SET disappear_type=(metadata->>'disappear_type');

ALTER TABLE portal ADD COLUMN disappear_timer BIGINT;
-- only: postgres
UPDATE portal SET disappear_timer=(metadata->>'disappear_timer')::BIGINT;
-- only: sqlite
UPDATE portal SET disappear_timer=CAST(metadata->>'disappear_timer' AS INTEGER);

ALTER TABLE portal ADD COLUMN room_type TEXT NOT NULL DEFAULT '';
UPDATE portal SET room_type='dm' WHERE CAST(metadata->>'is_direct' AS BOOLEAN) IS true;
UPDATE portal SET room_type='space' WHERE CAST(metadata->>'is_space' AS BOOLEAN) IS true;

ALTER TABLE reaction ADD COLUMN emoji TEXT NOT NULL DEFAULT '';
UPDATE reaction SET emoji=COALESCE((metadata->>'emoji'), '');

ALTER TABLE user_login ADD COLUMN remote_name TEXT NOT NULL DEFAULT '';
UPDATE user_login SET remote_name=COALESCE((metadata->>'remote_name'), '');

ALTER TABLE ghost ADD COLUMN contact_info_set BOOLEAN NOT NULL DEFAULT false;
UPDATE ghost SET contact_info_set=COALESCE(CAST((metadata->>'contact_info_set') AS BOOLEAN), false);

ALTER TABLE ghost ADD COLUMN is_bot BOOLEAN NOT NULL DEFAULT false;
UPDATE ghost SET is_bot=COALESCE(CAST((metadata->>'is_bot') AS BOOLEAN), false);

ALTER TABLE ghost ADD COLUMN identifiers jsonb NOT NULL DEFAULT '[]';
UPDATE ghost SET identifiers=COALESCE((metadata->'identifiers'), '[]');

-- only: postgres until "end only"
ALTER TABLE message ALTER COLUMN sender_mxid DROP DEFAULT;
ALTER TABLE message ALTER COLUMN edit_count DROP DEFAULT;
ALTER TABLE portal ALTER COLUMN room_type DROP DEFAULT;
ALTER TABLE reaction ALTER COLUMN emoji DROP DEFAULT;
ALTER TABLE user_login ALTER COLUMN remote_name DROP DEFAULT;
ALTER TABLE ghost ALTER COLUMN contact_info_set DROP DEFAULT;
ALTER TABLE ghost ALTER COLUMN is_bot DROP DEFAULT;
ALTER TABLE ghost ALTER COLUMN identifiers DROP DEFAULT;
-- end only postgres
