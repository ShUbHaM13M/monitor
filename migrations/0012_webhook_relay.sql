-- Webhook relay: a webhook check can forward every accepted delivery to the
-- org's own server, at least once, in order, with retries.
ALTER TABLE checks
    ADD COLUMN relay_url        text CHECK (length(relay_url) <= 2000),
    -- Signs forwarded requests (X-Monitor-Signature). Sealed with SECRET_KEY.
    ADD COLUMN relay_secret_enc bytea,
    -- Forward attempts that failed since the last success.
    ADD COLUMN relay_failures   integer NOT NULL DEFAULT 0,
    ADD CONSTRAINT checks_relay_check CHECK (relay_url IS NULL OR kind = 'webhook');

CREATE TABLE relay_deliveries (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    check_id        uuid NOT NULL REFERENCES checks (id) ON DELETE CASCADE,
    method          text NOT NULL,
    -- [[name, value], …] to pass on (hop-by-hop and credential headers dropped).
    headers         jsonb NOT NULL,
    body            bytea NOT NULL CHECK (octet_length(body) <= 1048576),
    source_ip       inet,
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'sending', 'delivered', 'failed')),
    attempts        integer NOT NULL DEFAULT 0,
    -- For 'sending', the lease expiry.
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_attempt_at timestamptz,
    last_status     smallint,
    last_error      text,
    received_at     timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    CHECK ((status IN ('delivered', 'failed')) = (finished_at IS NOT NULL))
);
-- The queue: each check's oldest unfinished delivery is its head.
CREATE INDEX relay_deliveries_queue_idx ON relay_deliveries (check_id, id)
    WHERE status IN ('pending', 'sending');
CREATE INDEX relay_deliveries_check_idx ON relay_deliveries (check_id, id DESC);
CREATE INDEX relay_deliveries_finished_idx ON relay_deliveries (finished_at)
    WHERE finished_at IS NOT NULL;

-- A failing relay is its own incident, alongside (not instead of) an outage of
-- the check itself: allow one open incident of each sort per check.
ALTER TABLE incidents DROP CONSTRAINT incidents_reason_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_reason_check
    CHECK (reason IN ('missed', 'failed', 'hung', 'http_down', 'http_slow', 'slow_run', 'fast_run',
                      'relay_failing'));
DROP INDEX incidents_open_check_key;
CREATE UNIQUE INDEX incidents_open_check_key ON incidents (check_id, (reason = 'relay_failing'))
    WHERE resolved_at IS NULL;

ALTER TABLE notifications DROP CONSTRAINT notifications_event_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_event_check
    CHECK (event IN ('down', 'up', 'fail', 'anomaly', 'relay_down', 'relay_up'));
