ALTER TABLE users ADD COLUMN email_verified_at timestamptz;

-- One-time links mailed to account holders. Only the sha256 of the token is stored.
CREATE TABLE user_tokens (
    token_hash bytea PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose    text NOT NULL CHECK (purpose IN ('verify_email', 'reset_password')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);
-- Cooldown check ("was one sent in the last minute?") and cleanup per user.
CREATE INDEX user_tokens_user_id_purpose_created_at_idx ON user_tokens (user_id, purpose, created_at DESC);
CREATE INDEX user_tokens_expires_at_idx ON user_tokens (expires_at);
