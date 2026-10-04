-- Channel kinds are defined in code (notify::Registry), so adding one shouldn't need
-- a migration. Rows whose kind is no longer registered fail delivery with a clear error.
ALTER TABLE channels DROP CONSTRAINT channels_kind_check;

-- Recipient confirmation for channels that need it (email to someone else).
-- Only the sha256 of the one-time token is stored.
ALTER TABLE channels
    ADD COLUMN verify_token_hash bytea UNIQUE,
    ADD COLUMN verify_sent_at timestamptz;

-- Delivery history per channel, newest first.
CREATE INDEX notifications_channel_id_created_at_idx ON notifications (channel_id, created_at DESC);
DROP INDEX notifications_channel_id_idx;
