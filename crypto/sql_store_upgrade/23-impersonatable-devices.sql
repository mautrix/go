-- v23 (compatible with v20+): MSC4350 impersonatable devices
CREATE TABLE crypto_impersonatable_device (
	account_id           TEXT NOT NULL,
	user_id              TEXT NOT NULL,
	device_id            TEXT NOT NULL,
	impersonator_ed25519 TEXT NOT NULL,

	PRIMARY KEY (account_id, user_id)
);
