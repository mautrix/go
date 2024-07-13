-- v10 (compatible with v9+): Fix Signal portal revisions
UPDATE portal
SET metadata=json_set(metadata, '$.revision', CAST(json_extract(metadata, '$.revision') AS INTEGER))
WHERE json_type(metadata, '$.revision')='text';
