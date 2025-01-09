-- v19 (compatible with v9+): Add double puppeted state to messages
ALTER TABLE messages ADD COLUMN is_double_puppeted BOOLEAN NOT NULL;
