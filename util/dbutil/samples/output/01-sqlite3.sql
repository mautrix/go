CREATE TABLE foo (
	key INTEGER PRIMARY KEY,

	data JSONB NOT NULL
);

CREATE TRIGGER test AFTER INSERT ON foo WHEN NEW.data->>'action' = 'delete' BEGIN
	DELETE FROM test WHERE key <= NEW.data->>'index';
END;
-- end only sqlite
