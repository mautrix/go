-- v9: Change outbound megolm session max_age column to milliseconds
UPDATE crypto_megolm_outbound_session SET max_age=max_age/1000000;
