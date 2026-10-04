use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::db::checks::CheckStatus;
use crate::db::{incidents, notifications};
use crate::notify::{Alert, AlertEvent};

const BATCH: i64 = 100;

/// Flips every overdue `up`/`started` check to `down` and opens an incident for it.
/// Returns how many checks were flipped.
///
/// Rows are claimed with `FOR UPDATE SKIP LOCKED`, so several workers can run this
/// at once, and a check being pinged right now (row locked by ingest) is skipped
/// and re-evaluated on the next tick.
pub async fn tick(db: &PgPool, base_url: &str) -> anyhow::Result<u64> {
    let mut total = 0;
    loop {
        let mut tx = db.begin().await?;
        let due = sqlx::query!(
            r#"SELECT id, org_id, name, status AS "status: CheckStatus", next_expected_at,
                      last_ping_at, last_start_at
               FROM checks
               WHERE status IN ('up', 'started') AND alert_after <= now()
               ORDER BY alert_after
               LIMIT $1
               FOR UPDATE SKIP LOCKED"#,
            BATCH,
        )
        .fetch_all(&mut *tx)
        .await?;
        if due.is_empty() {
            break;
        }

        let ids: Vec<_> = due.iter().map(|c| c.id).collect();
        sqlx::query!(
            "UPDATE checks SET status = 'down', updated_at = now() WHERE id = ANY($1)",
            &ids,
        )
        .execute(&mut *tx)
        .await?;

        for check in &due {
            let (reason, label, detail) = if check.status == CheckStatus::Started {
                (
                    "hung",
                    "Run never finished",
                    format!(
                        "Run started {} and did not finish in time.",
                        fmt_time(check.last_start_at)
                    ),
                )
            } else {
                (
                    "missed",
                    "Missed ping",
                    format!(
                        "Expected a ping by {}. Last ping {}.",
                        fmt_time(check.next_expected_at),
                        fmt_time(check.last_ping_at)
                    ),
                )
            };
            let opened =
                incidents::open_for_check(&mut tx, check.org_id, check.id, reason, &detail, None)
                    .await?;
            if let Some(incident_id) = opened {
                let mut alert = Alert::new(AlertEvent::Down, check.id, &check.name, base_url);
                alert.reason = Some(label.into());
                alert.detail = Some(detail);
                notifications::enqueue_for_check(&mut tx, incident_id, check.id, &alert).await?;
            }
        }
        tx.commit().await?;

        let flipped = due.len() as u64;
        total += flipped;
        tracing::info!(flipped, "checks marked down");
        if flipped < BATCH as u64 {
            break;
        }
    }
    Ok(total)
}

fn fmt_time(t: Option<DateTime<Utc>>) -> String {
    t.map_or_else(
        || "never".to_owned(),
        |t| t.format("%Y-%m-%d %H:%M UTC").to_string(),
    )
}
