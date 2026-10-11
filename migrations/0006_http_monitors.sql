-- Response-time limit: slower responses count as failures. NULL = no limit.
ALTER TABLE http_monitors
    ADD COLUMN max_latency_ms integer CHECK (max_latency_ms > 0),
    -- Latest result, denormalised so the list doesn't need to read http_results.
    ADD COLUMN last_status_code smallint,
    ADD COLUMN last_latency_ms integer,
    ADD COLUMN last_error text;

CREATE INDEX http_monitors_org_id_created_at_idx ON http_monitors (org_id, created_at);

ALTER TABLE incidents DROP CONSTRAINT incidents_reason_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_reason_check
    CHECK (reason IN ('missed', 'failed', 'hung', 'http_down', 'http_slow'));
