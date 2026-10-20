-- Org-scoped keys for the REST API. Only a SHA-256 of the key is stored; the key
-- itself is shown once, when it's created.
CREATE TABLE api_keys (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    token_hash   bytea NOT NULL UNIQUE,
    -- The key's first characters, so people can tell their keys apart.
    prefix       text NOT NULL,
    scope        text NOT NULL CHECK (scope IN ('read', 'write')),
    created_by   uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    expires_at   timestamptz
);
CREATE INDEX api_keys_org_id_idx ON api_keys (org_id, created_at);
