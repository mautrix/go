-- v7: Update trust state values
UPDATE crypto_device SET trust=300 WHERE trust=1; -- verified
UPDATE crypto_device SET trust=-100 WHERE trust=2; -- blacklisted
UPDATE crypto_device SET trust=0 WHERE trust=3; -- ignored -> unset
