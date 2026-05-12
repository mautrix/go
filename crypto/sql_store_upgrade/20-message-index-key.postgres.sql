-- v20 (compatible with v20+): Remove sender_key from crypto_message_index
ALTER TABLE crypto_message_index DROP CONSTRAINT crypto_message_index_pkey;
ALTER TABLE crypto_message_index DROP COLUMN sender_key;
ALTER TABLE crypto_message_index ADD PRIMARY KEY (session_id, "index")
