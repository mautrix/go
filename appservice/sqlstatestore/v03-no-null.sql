-- v3: Disable nulls in mx_user_profile

UPDATE mx_user_profile SET displayname='' WHERE displayname IS NULL;
UPDATE mx_user_profile SET avatar_url='' WHERE avatar_url IS NULL;

-- only: postgres for next 4 lines
ALTER TABLE mx_user_profile ALTER COLUMN displayname SET DEFAULT '';
ALTER TABLE mx_user_profile ALTER COLUMN displayname SET NOT NULL;
ALTER TABLE mx_user_profile ALTER COLUMN avatar_url SET DEFAULT '';
ALTER TABLE mx_user_profile ALTER COLUMN avatar_url SET NOT NULL;
