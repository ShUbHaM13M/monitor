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
  config.rs   CLI / env configuration
  db/         pool, migrations, queries
  web/        router, handlers, error type, static assets
  worker/     background loops (Postgres FOR UPDATE SKIP LOCKED for work claiming)
```
