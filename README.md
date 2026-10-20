# Monitor

Cron / heartbeat, webhook and HTTP uptime monitoring with email, Slack, Discord and webhook
alerts, a REST API, and a `monitor-run` job wrapper.
Rust (axum + sqlx + askama) with server-rendered pages and htmx, backed by PostgreSQL.

## Development

```sh
cp .env.example .env
sed -i "s|^SECRET_KEY=$|SECRET_KEY=$(cargo run -q -- gen-key)|" .env   # fill in SECRET_KEY
docker compose up -d          # Postgres on :5432, Mailpit on :1025 (UI: http://localhost:8025)
cargo run -- migrate          # apply migrations (also done at startup when AUTO_MIGRATE=true)
cargo run                     # web + workers on http://localhost:3000
```

Queries are checked at compile time by `sqlx::query!` against the database in `DATABASE_URL`.
After changing a query or migration, refresh the offline metadata and commit `.sqlx/`:

```sh
cargo install sqlx-cli --no-default-features --features postgres,rustls   # once
cargo sqlx migrate run
cargo sqlx prepare -- --all-targets
```

Builds without a database (CI, Docker) use the committed metadata: `SQLX_OFFLINE=true cargo build`.

## Tests

```sh
docker compose up -d
cargo test      # integration tests create a throwaway database per test via #[sqlx::test]
```

Alert tests deliver to a wiremock server and to Mailpit, so both containers must be up.

## Commands

| Command | Runs |
|---|---|
| `monitor all` (default) | web server and background workers in one process |
| `monitor serve` | web server only (dashboard + ping ingest) |
| `monitor worker` | background workers only (scheduler, prober, notifier) |
| `monitor migrate` | apply pending migrations and exit |
| `monitor gen-key` | print a new random `SECRET_KEY` |
| `monitor healthcheck` | exit 0 if the local server answers `/healthz` (for container health checks) |

All settings are flags or environment variables; see `monitor --help` and `.env.example`.

| Setting | Notes |
|---|---|
| `SECRET_KEY` | Required. Encrypts channel configs (webhook URLs, secrets) at rest. Losing it makes existing channels unreadable. |
| `SMTP_URL`, `SMTP_FROM` | Enable email channels. `smtp://localhost:1025` is Mailpit; use `smtps://user:pass@host` in production. |
| `ALLOW_PRIVATE_TARGETS` | Lets webhooks reach localhost/private IPs. Dev only: enabling it in production allows SSRF. |
| `TRUSTED_PROXIES` | Comma-separated IPs/CIDRs of your reverse proxies. Only their `X-Forwarded-For` is believed, read from the right; unset means the TCP peer is the client. |
| `METRICS_ADDR` | Serve Prometheus metrics at `/metrics` on this address. Keep it private; off when unset. |
| `PLAN_MAX_CHECKS`, `PLAN_MAX_MONITORS`, `PLAN_MAX_CHANNELS`, `PLAN_MIN_INTERVAL_SECS` | Default plan limits (100, 20, 10, 30 s). Override one org with `UPDATE orgs SET max_checks = 500 WHERE …`. |

## Deploying

`Dockerfile` builds one binary, with templates, static files and migrations embedded, into a
distroless image that runs as a non-root user. No database is needed at build time: it uses the
committed `.sqlx/`. `deploy/` runs it behind
Caddy with automatic HTTPS:

```sh
cd deploy
cp .env.example .env        # DOMAIN, POSTGRES_PASSWORD, SECRET_KEY, SMTP_URL
docker compose up -d --build
```

The stack is Postgres, a one-shot `migrate` container, the app (`monitor all`), and Caddy, the
only service with published ports. Caddy has a fixed address that is the app's only trusted
proxy. On `SIGTERM` the app stops taking connections, finishes in-flight requests and the
current worker ticks, then exits. Several `monitor worker` processes can run side by side.

**Hardening built in:**
- **Rate limits** (per process): pings and webhook deliveries per token (burst 60, then 1/s)
  and per client (burst 300, then 20/s), answered with `429` and `Retry-After`. Login, signup,
  password reset and confirmation forms are limited per client address.
- **Login throttling** (in Postgres, so it holds across instances): from the 5th unsuccessful
  attempt an account locks for 1 minute, doubling up to an hour. A successful login or a
  password reset clears it.
- **Retention:** each check keeps its newest 100 pings and none older than 30 days (a ping that
  caused an incident is kept with it). Uptime results keep 7 days and hourly rollups 90 days.
  Delivered or abandoned alerts keep 90 days. Cleanup runs hourly.
- **Plan limits** per org, checked inside the creating transaction so concurrent requests can't
  overshoot.
- **Headers:** a strict Content-Security-Policy (no inline script or style, no `eval`; htmx is
  configured to match), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: same-origin`, and
  HSTS when `BASE_URL` is HTTPS.

**Metrics** (`METRICS_ADDR`): `http_requests_total` and `http_request_duration_seconds` by route
template; `pings_total`, `probes_total`, `alerts_total`, `logins_total`, `rate_limited_total`;
`worker_tick_duration_seconds` and `worker_tick_errors_total`; and, read from the database at
scrape time, `checks` and `http_monitors` by status, `incidents_open`, `alerts_queued`,
`alerts_overdue` (should be zero: the notifier is behind) and the connection pool size.

## Layout

```
migrations/   SQL migrations (embedded into the binary)
templates/    askama templates; partials/ are htmx fragments
static/       CSS, vendored htmx and app.js (local times, copy buttons, tab title), embedded in release builds
src/
  auth/       passwords, sessions, CSRF, CurrentUser/OrgId extractors
  config.rs   CLI / env configuration
  db/         pool, migrations, queries (tenant data always scoped by OrgId)
  domain/     pure logic: schedules (cron + tz), ping signals, run-time anomalies, time formatting
  web/        router, handlers, ping ingest (/p/{token}), REST API (web/api), static assets
  notify/     alert channels: the ChannelKind trait, registry, built-in kinds, SSRF-safe HTTP
  crypto.rs   encryption at rest for channel configs
  worker/     background loops: deadline scheduler, HTTP prober, rollups, alert notifier, cleanup
              (work is claimed with FOR UPDATE SKIP LOCKED, so workers can scale out)
cli/          monitor-run, the job wrapper (its own small crate in the workspace)
```

## Dashboard

`/dashboard` is the overview. It shows a one-line verdict (down, alerts at risk, or all
good), status counts that link to the filtered lists, what's down right now, alert-delivery
problems (no channels, unconfirmed channels, alerts that gave up after every retry in the last
24 hours) and recently resolved incidents. `/incidents` has the full history for the org, 50
per page. The Checks and Uptime lists put problems first and can be filtered by status and
searched; the filter is kept in the URL.

Pages refresh with htmx polling every 10 seconds, paused while the tab is hidden. The nav
badge keeps polling in hidden tabs and mirrors the down count into the tab title and favicon.
`static/app.js` shows times in the viewer's timezone and adds copy buttons to snippets.
Without JavaScript, times are shown in UTC and the snippets are plain selectable text.

## Accounts

Signing up emails a confirmation link, and the dashboard shows a banner (with "Resend")
until it's confirmed. "Forgot password?" on the login page emails a reset link. It is valid
for 1 hour, works once, and logs the user out everywhere. Both kinds of link open a page
with a button rather than acting on the GET, because mail scanners prefetch links. Tokens
are stored hashed, and each kind can be sent at most once a minute per account. Without
`SMTP_URL` there is no banner and no reset.

## Webhook monitors

A check of kind *webhook* gets a URL, `POST /w/{token}`, to give to a service such as
Stripe, GitHub or Shopify. Every delivery counts as a heartbeat, so the usual schedule,
grace period and missed-ping alerts apply: "Stripe should hit us at least hourly."

- **Signatures (optional, recommended):** Stripe (`Stripe-Signature`, with a 5-minute
  replay window), GitHub (`X-Hub-Signature-256`), Shopify (`X-Shopify-Hmac-Sha256`), or a
  generic HMAC-SHA256 of the body in a header you name. They are verified over the raw
  body with a constant-time compare. The signing secret is encrypted with `SECRET_KEY`,
  and the endpoint fails closed if it can't be read.
- **Bad signatures** get `401`. They don't count as heartbeats, and they appear in the
  delivery log as *rejected*, with the reason.
- **Delivery log:** method, headers (credentials such as `Authorization` and `Cookie`
  redacted) and the first 10 KB of the body.
- **Separate tokens:** a webhook token doesn't work on `/p/` and a ping token doesn't work
  on `/w/`, so the ping URL can't bypass verification.

## Uptime monitors

An HTTP monitor requests a URL every 30s to 1h. A check passes when:
- the status matches (any 2xx/3xx by default, or an exact code),
- the response contains a given text (optional),
- and it answers within a time limit (optional; slower counts as a failure).

After N failed checks in a row (default 2) the monitor goes down, opens an incident and
alerts. The first passing check after that resolves the incident and sends a recovery.

How it works:
- **Prober:** the worker claims due monitors with `FOR UPDATE SKIP LOCKED`, by moving
  `next_run_at` one interval ahead, and probes up to 50 at once. New monitors start at a
  random point in their first interval, so they don't all fire together.
- **Requests:** made with the same SSRF-guarded client as webhooks (no private
  addresses, no redirects). Request headers are encrypted at rest.
- **Latency:** time to response headers. Hourly rollups (count, failures, avg, p50,
  p95) are refreshed every minute and drive the uptime % and charts.
- **Retention:** raw results are kept for 7 days, hourly rollups for 90.

## Alerts

When a check goes down (missed ping, run never finished), fails (`/fail` or a non-zero
exit code) or recovers, an alert row is written to the `notifications` outbox **in the same
transaction** as the state change. The notifier worker delivers it, retrying with
exponential backoff (30s doubling to 1h, 8 attempts) and dead-lettering permanent failures.
Each channel's page shows its delivery history.

- Alerts only go to confirmed channels. An email channel needs a confirmation link
  unless it's addressed to your own, already confirmed, account email.
- A recovery goes only to the channels that were told about that outage.

Built-in channels: **Email** (needs `SMTP_URL`), **Slack** and **Discord** (incoming-webhook
URLs, treated as secrets and checked to point at Slack or Discord), and a signed **Webhook**.

### Unusual run times

A check whose job pings `/start` gets its runs timed. Once it has 8 timed successful runs,
each new run is compared with the median of the last 20. The check stays up either way, but
an *anomaly* alert goes out when:
- a run takes at least twice the median, at least a minute longer, and longer than any recent
  run;
- a run that usually takes at least a minute finishes in under a fifth of the median, and
  faster than any recent run. A backup that "succeeds" in 3 seconds probably did nothing.

Each anomaly is recorded as a single-run incident. The check page shows the typical run time,
and the check form can switch these alerts off.

## Running jobs with `monitor-run`

`cli/` builds `monitor-run`, a small wrapper for cron jobs:

```sh
cargo build --release -p monitor-run      # target/release/monitor-run
monitor-run --url https://monitor.example.com/p/<token> -- /usr/local/bin/backup.sh --full
```

It pings `/start`, runs the command with its output passed through as usual, and then reports
the exit code with the last 10 KB of output. Options:
- `--timeout SECONDS` kills the job's whole process group and reports exit code 124.
- `--no-start` skips the `/start` ping.
- `--tail BYTES` changes how much output is sent.
- `--quiet` silences warnings.
- `MONITOR_URL` can be used instead of `--url`.

SIGTERM, SIGHUP and SIGINT are passed on to the job, so stopping the wrapper still reports how
the job ended. If Monitor is unreachable the job runs anyway (each report is retried 3 times),
and `monitor-run` always exits with the job's own exit code.

## REST API

Create a key under **API** in the dashboard. It is shown once, stored hashed, and is either
read-only or read-write, with an optional expiry. Send it as `Authorization: Bearer mon_…`.
Requests are limited to bursts of 120, then 10 per second, per key.

| Method | Path | |
|---|---|---|
| `GET`, `POST` | `/api/v1/checks` | list; create |
| `GET`, `PUT`, `DELETE` | `/api/v1/checks/{id}` | read; replace; delete |
| `POST` | `/api/v1/checks/{id}/pause`, `/resume` | |
| `GET` | `/api/v1/checks/{id}/pings?limit=50` | newest first |
| `GET`, `POST` | `/api/v1/monitors` | list; create |
| `GET`, `PUT`, `DELETE` | `/api/v1/monitors/{id}` | |
| `POST` | `/api/v1/monitors/{id}/pause`, `/resume` | |
| `GET` | `/api/v1/monitors/{id}/results?limit=50` | |
| `GET` | `/api/v1/channels` | ids to use in `channels` (channels are added in the dashboard) |
| `GET` | `/api/v1/incidents?state=open\|resolved&limit=50` | page with `before` + `before_id` |

```sh
curl -X POST https://monitor.example.com/api/v1/checks \
  -H "Authorization: Bearer $MONITOR_KEY" -H "Content-Type: application/json" \
  -d '{"name": "Nightly backup", "schedule": {"cron": "0 2 * * *", "tz": "Europe/Berlin"}, "grace": 1800}'
```

How request bodies work:
- **Units.** Durations are in seconds.
- **Schedule.** `schedule` is either `{"every": 3600}` or `{"cron": "…", "tz": "…"}`.
- **Check kinds.** A webhook check takes `"kind": "webhook"` plus
  `"signature": {"scheme": "stripe", "secret": "…"}`.
- **Monitors.** Monitors take `url`, `method`, `interval` (30, 60, 300, 900, 1800 or 3600),
  `timeout`, `expected_status`, `body_contains`, `max_latency_ms`, `fail_threshold`, `headers`
  (an object) and `body`.
- **Validation.** Bodies go through the same validation as the dashboard forms, and unknown
  fields are rejected.
- **`PUT`.** It replaces the whole definition, except that omitted `channels`, monitor
  `headers` and webhook `secret` are kept as they are.

What comes back:
- **Secrets.** Header values and signing secrets are never returned.
- **Errors.** They look like `{"error": {"code": "invalid", "message": "…"}}`, with code
  `unauthorized` (401), `read_only_key` (403), `plan_limit` (403), `not_found` (404),
  `invalid` (422) or `rate_limited` (429).

### Adding a channel

Channel types are plugins. Everything else is generic: the form, encrypted storage,
delivery queue, retries, confirmation flow and delivery history. To add one, e.g. WhatsApp:

1. Create `src/notify/channels/whatsapp.rs` implementing `notify::ChannelKind`:
   - `id()` → `"whatsapp"`: stored in the database, never change it.
   - `fields()` → `[Field { name: "phone", input: Input::Text, .. }]`: the form is built from this.
   - `validate()` → normalise the number and return the config JSON.
   - `summary()` → e.g. a masked number; never reveal secrets.
   - `send()` → call the provider API (Twilio/Meta). Return `SendError::Retryable` for
     timeouts, 429s and 5xx, and `SendError::Permanent` for anything that will never work.
   - `verification()` / `send_verification()` → confirm the number before alerting it. Phone
     channels will want a one-time code (`Verification::Code`, to be added next to `Link`).
2. Add the provider credentials to `Config` (e.g. `TWILIO_*`), and register the kind in
   `Registry::from_config` when they're set.

No migration and no template are needed.
