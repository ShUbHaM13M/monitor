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
static/       CSS and vendored htmx, embedded in release builds
src/
  auth/       passwords, sessions, CSRF, CurrentUser/OrgId extractors
  config.rs   CLI / env configuration
  db/         pool, migrations, queries (tenant data always scoped by OrgId)
  domain/     pure logic: schedules (cron + tz), ping signals, time formatting
  web/        router, handlers, ping ingest (/p/{token}), error type, static assets
  notify/     alert channels: the ChannelKind trait, registry, built-in kinds, SSRF-safe HTTP
  crypto.rs   encryption at rest for channel configs
  worker/     background loops: deadline scheduler, alert notifier, session cleanup
              (work is claimed with FOR UPDATE SKIP LOCKED, so workers can scale out)
```

## Alerts

When a check goes down (missed ping, run never finished), fails (`/fail` or a non-zero
exit code) or recovers, an alert row is written to the `notifications` outbox **in the same
transaction** as the state change. The notifier worker delivers it, retrying with
exponential backoff (30s doubling to 1h, 8 attempts) and dead-lettering permanent failures.
Each channel's page shows its delivery history.

- Alerts only go to confirmed channels. An email channel addressed to anyone other than you
  must be confirmed through a link first.
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
