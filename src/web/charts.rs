//! Geometry for the server-rendered SVG charts on the uptime pages. Templates only
//! draw what's computed here; colours come from CSS variables (`.viz` in app.css).

use chrono::{DateTime, TimeDelta, Timelike, Utc};

const HOURS: i64 = 24;

/// The 24 hourly buckets ending with the current hour, oldest first.
fn hour_slots(now: DateTime<Utc>) -> Vec<DateTime<Utc>> {
    let this_hour = now
        .with_minute(0)
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(now);
    (0..HOURS)
        .rev()
        .map(|back| this_hour - TimeDelta::hours(back))
        .collect()
}

/// Round `max` up to 1, 2 or 5 × 10ⁿ, so axis ticks are clean numbers.
pub fn nice_ceiling(max: f64) -> f64 {
    if max <= 0.0 {
        return 1.0;
    }
    let magnitude = 10f64.powf(max.log10().floor());
    let step = [1.0, 2.0, 5.0, 10.0]
        .into_iter()
        .find(|m| m * magnitude >= max)
        .unwrap_or(10.0);
    step * magnitude
}

/// An SVG path through the points, broken wherever a value is missing (hours
/// with no data aren't interpolated across).
pub fn broken_path(points: &[Option<(f64, f64)>]) -> String {
    let mut path = String::new();
    let mut pen_down = false;
    for point in points {
        match point {
            Some((x, y)) => {
                path.push_str(&format!(
                    "{}{x:.1},{y:.1} ",
                    if pen_down { "L" } else { "M" }
                ));
                pen_down = true;
            }
            None => pen_down = false,
        }
    }
    path.trim_end().to_owned()
}

/// Points with no neighbour on either side: a path can't show them, so they get a dot.
fn isolated(points: &[Option<(f64, f64)>]) -> Vec<(f64, f64)> {
    (0..points.len())
        .filter_map(|i| {
            let before = i.checked_sub(1).and_then(|j| points[j]).is_some();
            let after = points.get(i + 1).copied().flatten().is_some();
            match points[i] {
                Some(p) if !before && !after => Some(p),
                _ => None,
            }
        })
        .collect()
}

// ───────────────────────────── sparkline ─────────────────────────────

pub struct Sparkline {
    pub width: u32,
    pub height: u32,
    pub path: String,
    pub dots: Vec<(f64, f64)>,
    /// The latest point, drawn in the accent colour.
    pub end: Option<(f64, f64)>,
    /// Accessible summary (also the hover tooltip).
    pub summary: String,
}

/// 24h of hourly average latency. `points` are (hour, avg ms), any order.
pub fn sparkline(points: &[(DateTime<Utc>, i32)], now: DateTime<Utc>) -> Option<Sparkline> {
    if points.is_empty() {
        return None;
    }
    let (width, height, pad) = (120u32, 28u32, 4.0);
    let slots = hour_slots(now);
    let values: Vec<Option<i32>> = slots
        .iter()
        .map(|slot| points.iter().find(|(h, _)| h == slot).map(|(_, v)| *v))
        .collect();
    let max = values.iter().flatten().copied().max().unwrap_or(1).max(1) as f64;
    let min = values.iter().flatten().copied().min().unwrap_or(0) as f64;
    let step = (f64::from(width) - 2.0 * pad) / (HOURS - 1) as f64;
    // Scaled between min and max: a sparkline shows shape, not magnitude.
    let span = (max - min).max(1.0);
    let coords: Vec<Option<(f64, f64)>> = values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            v.map(|v| {
                let x = pad + i as f64 * step;
                let y = pad + (1.0 - (f64::from(v) - min) / span) * (f64::from(height) - 2.0 * pad);
                (x, y)
            })
        })
        .collect();
    let latest = values.iter().rev().flatten().next().copied();
    Some(Sparkline {
        width,
        height,
        path: broken_path(&coords),
        dots: isolated(&coords),
        end: coords.iter().rev().flatten().next().copied(),
        summary: format!(
            "Average latency per hour, last 24 hours: {} to {} ms, latest {} ms",
            min as i64,
            max as i64,
            latest.unwrap_or_default()
        ),
    })
}

// ───────────────────────────── latency chart ─────────────────────────────

pub struct HourInput {
    pub hour: DateTime<Utc>,
    pub avg_ms: Option<i32>,
    pub p95_ms: Option<i32>,
    pub checks: i32,
    pub failed: i32,
}

pub struct Tick {
    pub pos: f64,
    pub label: String,
}

pub struct Column {
    pub x: f64,
    pub center: f64,
    pub width: f64,
    /// Tooltip and table text.
    pub hour: String,
    pub avg: String,
    pub p95: String,
    pub checks: i32,
    pub failed: i32,
}

pub struct EndLabel {
    pub x: f64,
    pub y: f64,
    pub text: String,
}

pub struct LatencyChart {
    pub width: f64,
    pub height: f64,
    pub plot_left: f64,
    pub plot_right: f64,
    pub plot_top: f64,
    pub plot_bottom: f64,
    pub avg_path: String,
    pub p95_path: String,
    pub avg_dots: Vec<(f64, f64)>,
    pub p95_dots: Vec<(f64, f64)>,
    pub avg_end: Option<EndLabel>,
    pub p95_end: Option<EndLabel>,
    pub y_ticks: Vec<Tick>,
    pub x_ticks: Vec<Tick>,
    /// Hours with failed checks, marked under the baseline.
    pub failures: Vec<(f64, i32)>,
    pub columns: Vec<Column>,
}

pub fn latency_chart(input: &[HourInput], now: DateTime<Utc>) -> Option<LatencyChart> {
    if input.iter().all(|h| h.checks == 0) {
        return None;
    }
    let (width, height) = (720.0, 240.0);
    let (left, right, top, bottom) = (52.0, width - 72.0, 12.0, height - 44.0);
    let slots = hour_slots(now);
    let slot_w = (right - left) / HOURS as f64;
    let rows: Vec<Option<&HourInput>> = slots
        .iter()
        .map(|slot| input.iter().find(|h| h.hour == *slot))
        .collect();

    let max = rows
        .iter()
        .flatten()
        .flat_map(|h| [h.avg_ms, h.p95_ms])
        .flatten()
        .max()
        .unwrap_or(0);
    let y_max = nice_ceiling(f64::from(max) * 1.1);
    let y = |ms: i32| bottom - f64::from(ms) / y_max * (bottom - top);
    let center = |i: usize| left + (i as f64 + 0.5) * slot_w;

    let series = |pick: fn(&HourInput) -> Option<i32>| -> Vec<Option<(f64, f64)>> {
        rows.iter()
            .enumerate()
            .map(|(i, row)| row.and_then(pick).map(|ms| (center(i), y(ms))))
            .collect()
    };
    let avg = series(|h| h.avg_ms);
    let p95 = series(|h| h.p95_ms);

    let end_label =
        |points: &[Option<(f64, f64)>], pick: fn(&HourInput) -> Option<i32>, name: &str| {
            let i = points.iter().rposition(Option::is_some)?;
            let (x, py) = points[i]?;
            let ms = rows[i].and_then(pick)?;
            Some(EndLabel {
                x: x + 8.0,
                y: py + 4.0,
                text: format!("{name} {ms} ms"),
            })
        };
    let mut avg_end = end_label(&avg, |h| h.avg_ms, "avg");
    let mut p95_end = end_label(&p95, |h| h.p95_ms, "p95");
    // Converging lines: drop both end labels rather than nudge them off their
    // lines; the legend and the hover/table carry the values.
    if let (Some(a), Some(p)) = (&avg_end, &p95_end)
        && (a.y - p.y).abs() < 14.0
    {
        avg_end = None;
        p95_end = None;
    }

    let y_ticks = (0..=4)
        .map(|i| {
            let ms = y_max * f64::from(i) / 4.0;
            Tick {
                pos: bottom - ms / y_max * (bottom - top),
                label: format!("{} ms", ms.round() as i64),
            }
        })
        .collect();
    let x_ticks = slots
        .iter()
        .enumerate()
        .filter(|(_, t)| t.hour() % 6 == 0)
        .map(|(i, t)| Tick {
            pos: center(i),
            label: t.format("%H:00").to_string(),
        })
        .collect();

    let fmt = |v: Option<i32>| v.map_or_else(|| "—".to_owned(), |ms| format!("{ms} ms"));
    let columns = slots
        .iter()
        .enumerate()
        .map(|(i, slot)| {
            let row = rows[i];
            Column {
                x: left + i as f64 * slot_w,
                center: center(i),
                width: slot_w,
                hour: slot.format("%H:00 UTC").to_string(),
                avg: fmt(row.and_then(|h| h.avg_ms)),
                p95: fmt(row.and_then(|h| h.p95_ms)),
                checks: row.map_or(0, |h| h.checks),
                failed: row.map_or(0, |h| h.failed),
            }
        })
        .collect::<Vec<_>>();
    let failures = columns
        .iter()
        .filter(|c| c.failed > 0)
        .map(|c| (c.center, c.failed))
        .collect();

    Some(LatencyChart {
        width,
        height,
        plot_left: left,
        plot_right: right,
        plot_top: top,
        plot_bottom: bottom,
        avg_path: broken_path(&avg),
        p95_path: broken_path(&p95),
        avg_dots: isolated(&avg),
        p95_dots: isolated(&p95),
        avg_end,
        p95_end,
        y_ticks,
        x_ticks,
        failures,
        columns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(h: u32, m: u32) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&format!("2026-10-06T{h:02}:{m:02}:00Z"))
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn nice_ceilings() {
        assert_eq!(nice_ceiling(0.0), 1.0);
        assert_eq!(nice_ceiling(87.0), 100.0);
        assert_eq!(nice_ceiling(120.0), 200.0);
        assert_eq!(nice_ceiling(2100.0), 5000.0);
        assert_eq!(nice_ceiling(5000.0), 5000.0);
    }

    #[test]
    fn paths_break_at_gaps() {
        let pts = [
            Some((0.0, 1.0)),
            Some((1.0, 2.0)),
            None,
            Some((3.0, 4.0)),
            Some((4.0, 5.0)),
        ];
        assert_eq!(broken_path(&pts), "M0.0,1.0 L1.0,2.0 M3.0,4.0 L4.0,5.0");
        let lone = [
            None,
            Some((1.0, 1.0)),
            None,
            Some((3.0, 3.0)),
            Some((4.0, 4.0)),
        ];
        assert_eq!(isolated(&lone), vec![(1.0, 1.0)]);
    }

    #[test]
    fn slots_end_at_the_current_hour() {
        let slots = hour_slots(at(14, 37));
        assert_eq!(slots.len(), 24);
        assert_eq!(slots[23], at(14, 0));
        assert_eq!(slots[0], at(14, 0) - TimeDelta::hours(23));
    }

    #[test]
    fn sparkline_scales_between_min_and_max() {
        let now = at(14, 10);
        let s = sparkline(&[(at(13, 0), 100), (at(14, 0), 300)], now).unwrap();
        assert!(s.path.starts_with('M'));
        let (_, end_y) = s.end.unwrap();
        assert!((end_y - 4.0).abs() < 0.01, "max sits at the top");
        assert!(s.summary.contains("100 to 300 ms, latest 300 ms"));
        assert!(sparkline(&[], now).is_none());
    }

    #[test]
    fn latency_chart_axes_and_failures() {
        let now = at(14, 10);
        let input = [
            HourInput {
                hour: at(12, 0),
                avg_ms: Some(80),
                p95_ms: Some(400),
                checks: 120,
                failed: 0,
            },
            HourInput {
                hour: at(13, 0),
                avg_ms: Some(90),
                p95_ms: Some(420),
                checks: 120,
                failed: 3,
            },
            HourInput {
                hour: at(14, 0),
                avg_ms: None,
                p95_ms: None,
                checks: 20,
                failed: 20,
            },
        ];
        let c = latency_chart(&input, now).unwrap();
        assert_eq!(c.y_ticks.last().unwrap().label, "500 ms", "420 × 1.1 → 500");
        assert_eq!(c.failures.len(), 2);
        assert_eq!(c.columns.len(), 24);
        assert_eq!(c.columns[23].avg, "—");
        assert_eq!(c.columns[22].failed, 3);
        assert!(c.x_ticks.iter().any(|t| t.label == "12:00"));
        // Lines far apart: both end labels shown.
        assert_eq!(c.avg_end.as_ref().unwrap().text, "avg 90 ms");
        assert_eq!(c.p95_end.as_ref().unwrap().text, "p95 420 ms");
        assert!(latency_chart(&[], now).is_none());
    }
}
