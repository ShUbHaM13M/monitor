-- Per-account login throttling: counts attempts that haven't (yet) succeeded.
-- After 5, the account is locked for 1 minute, doubling per further failure up
-- to an hour. A successful login or password reset clears both.
ALTER TABLE users
    ADD COLUMN failed_logins integer NOT NULL DEFAULT 0 CHECK (failed_logins >= 0),
    ADD COLUMN locked_until  timestamptz;

-- Plan limits. NULL means the server-wide default (PLAN_* settings); set a value
-- to give one org more or less.
ALTER TABLE orgs
    ADD COLUMN max_checks                integer CHECK (max_checks >= 0),
    ADD COLUMN max_monitors              integer CHECK (max_monitors >= 0),
    ADD COLUMN max_channels              integer CHECK (max_channels >= 0),
    ADD COLUMN min_monitor_interval_secs integer CHECK (min_monitor_interval_secs > 0);
