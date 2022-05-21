-- v2: Use enum for membership field on Postgres
-- only: postgres

CREATE TYPE membership AS ENUM ('join', 'leave', 'invite', 'ban', 'knock');
ALTER TABLE mx_user_profile ALTER COLUMN membership TYPE membership USING LOWER(membership)::membership;
