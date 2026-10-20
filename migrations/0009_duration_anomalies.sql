-- Alert when a run takes far longer, or far less time, than it usually does.
ALTER TABLE checks ADD COLUMN duration_alerts boolean NOT NULL DEFAULT true;

-- Anomalies are recorded as incidents that open and resolve at once: they show
-- in the history and carry the alert, but the check stays up.
ALTER TABLE incidents DROP CONSTRAINT incidents_reason_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_reason_check
    CHECK (reason IN ('missed', 'failed', 'hung', 'http_down', 'http_slow', 'slow_run', 'fast_run'));

ALTER TABLE notifications DROP CONSTRAINT notifications_event_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_event_check
    CHECK (event IN ('down', 'up', 'fail', 'anomaly'));

-- The baseline query: a check's recent timed runs, newest first.
CREATE INDEX pings_check_id_timed_idx ON pings (check_id, created_at DESC)
    WHERE duration_ms IS NOT NULL;
