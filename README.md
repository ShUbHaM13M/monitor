# Monitor

Cron / heartbeat, webhook and HTTP uptime monitoring with email and webhook alerts.
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

All settings are flags or environment variables; see `monitor --help` and `.env.example`.

| Setting | Notes |
|---|---|
| `SECRET_KEY` | Required. Encrypts channel configs (webhook URLs, secrets) at rest. Losing it makes existing channels unreadable. |
| `SMTP_URL`, `SMTP_FROM` | Enable email channels. `smtp://localhost:1025` is Mailpit; use `smtps://user:pass@host` in production. |
| `ALLOW_PRIVATE_TARGETS` | Lets webhooks reach localhost/private IPs. Dev only: enabling it in production allows SSRF. |

## Layout

```
migrations/   SQL migrations (embedded into the binary)
templates/    askama templates; partials/ are htmx fragments
static/       CSS, vendored htmx and app.js (local times, copy buttons, tab title), embedded in release builds
src/
  auth/       passwords, sessions, CSRF, CurrentUser/OrgId extractors
  config.rs   CLI / env configuration
  db/         pool, migrations, queries (tenant data always scoped by OrgId)
  domain/     pure logic: schedules (cron + tz), ping signals, time formatting
  web/        router, handlers, ping ingest (/p/{token}), error type, static assets
  notify/     alert channels: the ChannelKind trait, registry, built-in kinds, SSRF-safe HTTP
  crypto.rs   encryption at rest for channel configs
  worker/     background loops: deadline scheduler, HTTP prober, rollups, alert notifier, cleanup
              (work is claimed with FOR UPDATE SKIP LOCKED, so workers can scale out)
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
