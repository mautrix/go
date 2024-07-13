-- v10 (compatible with v9+): Fix Signal portal revisions
UPDATE portal
SET metadata=jsonb_set(metadata, '{revision}', CAST((metadata->>'revision') AS jsonb))
WHERE jsonb_typeof(metadata->'revision')='string';
