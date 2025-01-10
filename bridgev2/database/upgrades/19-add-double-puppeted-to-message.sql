-- v19 (compatible with v9+): Add double puppeted state to messages
ALTER TABLE message ADD COLUMN double_puppeted BOOLEAN;
