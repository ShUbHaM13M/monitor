//! Prometheus metrics. Counters and histograms are recorded where things happen
//! (`metrics::counter!` etc.); gauges that describe stored state are read from
//! Postgres at scrape time. Served on `METRICS_ADDR`, never on the public port.

use std::net::SocketAddr;
use std::time::Instant;

use axum::Router;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use sqlx::PgPool;
use tokio_util::sync::CancellationToken;

/// Latency buckets in seconds, for requests and probes.
const BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// Installs the global recorder. Call once, at startup.
pub fn install() -> anyhow::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(Matcher::Suffix("_seconds".into()), BUCKETS)?
        .install_recorder()?;
    Ok(handle)
}

#[derive(Clone)]
struct MetricsState {
    handle: PrometheusHandle,
    db: PgPool,
}

pub fn router(handle: PrometheusHandle, db: PgPool) -> Router {
    Router::new()
        .route("/metrics", get(render))
        .with_state(MetricsState { handle, db })
}

pub async fn serve(
    addr: SocketAddr,
    handle: PrometheusHandle,
    db: PgPool,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "metrics listening");
    axum::serve(listener, router(handle, db))
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await?;
    Ok(())
}

async fn render(State(st): State<MetricsState>) -> Response {
    if let Err(err) = record_gauges(&st.db).await {
        // Still serve the counters; the stale gauges say when they were last set.
        tracing::warn!(error = %err, "could not refresh gauges");
        metrics::counter!("metrics_gauge_errors_total").increment(1);
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        st.handle.render(),
    )
        .into_response()
}

async fn record_gauges(db: &PgPool) -> sqlx::Result<()> {
    metrics::gauge!("db_pool_connections").set(f64::from(db.size()));
    metrics::gauge!("db_pool_idle_connections").set(db.num_idle() as f64);

    // Every known status is set, so a status that drops to zero reads 0
    // rather than keeping its last value.
    let rows = sqlx::query!(
        r#"SELECT s.status AS "status!", count(c.id) AS "n!"
           FROM unnest(ARRAY['new','up','started','down','paused']) AS s(status)
           LEFT JOIN checks c ON c.status = s.status
           GROUP BY s.status"#
    )
    .fetch_all(db)
    .await?;
    for r in rows {
        metrics::gauge!("checks", "status" => r.status).set(r.n as f64);
    }
    let rows = sqlx::query!(
        r#"SELECT s.status AS "status!", count(m.id) AS "n!"
           FROM unnest(ARRAY['new','up','down','paused']) AS s(status)
           LEFT JOIN http_monitors m ON m.status = s.status
           GROUP BY s.status"#
    )
    .fetch_all(db)
    .await?;
    for r in rows {
        metrics::gauge!("http_monitors", "status" => r.status).set(r.n as f64);
    }
    let q = sqlx::query!(
        r#"SELECT count(*) AS "queued!",
                  count(*) FILTER (WHERE next_attempt_at < now() - interval '1 minute') AS "overdue!"
           FROM notifications WHERE status IN ('pending', 'sending')"#
    )
    .fetch_one(db)
    .await?;
    metrics::gauge!("alerts_queued").set(q.queued as f64);
    // Alerts that should have gone out a minute ago: the notifier is stuck or slow.
    metrics::gauge!("alerts_overdue").set(q.overdue as f64);
    let open: i64 =
        sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM incidents WHERE resolved_at IS NULL"#)
            .fetch_one(db)
            .await?;
    metrics::gauge!("incidents_open").set(open as f64);
    Ok(())
}

/// Request count and latency by route template (`/checks/{id}`, not the real
/// path, so the label set stays small).
pub async fn track_http(req: Request, next: Next) -> Response {
    let started = Instant::now();
    let method = req.method().as_str().to_owned();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "unmatched".to_owned(), |p| p.as_str().to_owned());
    let res = next.run(req).await;
    let status = res.status().as_u16().to_string();
    metrics::counter!("http_requests_total", "method" => method.clone(), "route" => route.clone(), "status" => status)
        .increment(1);
    metrics::histogram!("http_request_duration_seconds", "method" => method, "route" => route)
        .record(started.elapsed().as_secs_f64());
    res
}
