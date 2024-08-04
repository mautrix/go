-- v16 (compatible with v9+): Save remote profile in user logins
ALTER TABLE user_login ADD COLUMN remote_profile jsonb;
