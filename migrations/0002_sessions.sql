ALTER TABLE users ADD CONSTRAINT users_email_length CHECK (length(email) <= 254);

CREATE TABLE sessions (
    -- sha256 of the cookie value; the raw token is never stored.
    token_hash   bytea PRIMARY KEY,
    user_id      uuid NOT NULL,
    -- Active org. Must be one the user belongs to; dropping the membership kills the session.
    org_id       uuid NOT NULL,
    csrf_token   text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    FOREIGN KEY (user_id, org_id) REFERENCES memberships (user_id, org_id) ON DELETE CASCADE
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
