-- v23 (compatible with v23+): Key received megolm sessions by room ID
ALTER TABLE crypto_megolm_inbound_session DROP CONSTRAINT crypto_megolm_inbound_session_pkey;
ALTER TABLE crypto_megolm_inbound_session ADD PRIMARY KEY (account_id, room_id, session_id);
