# Monitor

Cron / heartbeat, webhook and HTTP uptime monitoring with email, Slack and Discord alerts.
Rust (axum + sqlx + askama) with server-rendered pages and htmx, backed by PostgreSQL.

## Development

```sh
cp .env.example .env
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

## Commands

| Command | Runs |
|---|---|
| `monitor all` (default) | web server and background workers in one process |
| `monitor serve` | web server only (dashboard + ping ingest) |
| `monitor worker` | background workers only (scheduler, prober, notifier) |
| `monitor migrate` | apply pending migrations and exit |

All settings are flags or environment variables; see `monitor --help` and `.env.example`.

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
  worker/     background loops: deadline scheduler, session cleanup
              (work is claimed with FOR UPDATE SKIP LOCKED, so workers can scale out)
```
