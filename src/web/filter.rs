use axum::http::{HeaderMap, HeaderValue};
use serde::Deserialize;

/// `?status=down&q=backup` on the Checks and Uptime lists. Lists are small per
/// org, so filtering and sorting happen in Rust on the full list.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ListQuery {
    pub status: String,
    pub q: String,
}

/// A status filter chip: "Down 2".
pub struct Chip {
    pub value: &'static str,
    pub label: &'static str,
    pub count: usize,
    pub selected: bool,
}

impl ListQuery {
    /// Case-insensitive substring match on any of `fields`.
    pub fn matches_text(&self, fields: &[&str]) -> bool {
        let needle = self.q.trim().to_lowercase();
        needle.is_empty() || fields.iter().any(|f| f.to_lowercase().contains(&needle))
    }

    /// Chips for `statuses` (in display order), counting items that pass the
    /// text search. Empty statuses are hidden unless selected; "All" always shows.
    pub fn chips<'a>(
        &self,
        statuses: &[(&'static str, &'static str)],
        matching: impl Iterator<Item = &'a str> + Clone,
    ) -> Vec<Chip> {
        let all = Chip {
            value: "",
            label: "All",
            count: matching.clone().count(),
            selected: !statuses.iter().any(|(v, _)| *v == self.status),
        };
        let by_status = statuses.iter().filter_map(|&(value, label)| {
            let count = matching.clone().filter(|s| *s == value).count();
            let selected = self.status == value;
            (count > 0 || selected).then_some(Chip {
                value,
                label,
                count,
                selected,
            })
        });
        std::iter::once(all).chain(by_status).collect()
    }

    /// Whether `status` passes the status filter. Unknown values show everything.
    pub fn matches_status(&self, status: &str, statuses: &[(&'static str, &'static str)]) -> bool {
        self.status == status || !statuses.iter().any(|(v, _)| *v == self.status)
    }

    /// The list's own URL with this filter, for the address bar.
    pub fn url(&self, path: &str) -> String {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if !self.status.is_empty() {
            query.append_pair("status", &self.status);
        }
        if !self.q.trim().is_empty() {
            query.append_pair("q", self.q.trim());
        }
        let query = query.finish();
        if query.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{query}")
        }
    }
}

/// When the filter form (`form_id`) made the request, keep the address bar in
/// step so reloading or sharing the page keeps the filter. The periodic refresh
/// leaves it alone.
pub fn replace_url(
    headers: &HeaderMap,
    form_id: &str,
    url: &str,
) -> Option<(&'static str, HeaderValue)> {
    let from_form = headers
        .get("HX-Trigger")
        .is_some_and(|v| v.as_bytes() == form_id.as_bytes());
    from_form
        .then(|| HeaderValue::from_str(url).ok())
        .flatten()
        .map(|v| ("HX-Replace-Url", v))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUSES: &[(&str, &str)] = &[("down", "Down"), ("up", "Up"), ("paused", "Paused")];

    fn query(status: &str, q: &str) -> ListQuery {
        ListQuery {
            status: status.into(),
            q: q.into(),
        }
    }

    #[test]
    fn chips_count_and_hide_empty_statuses() {
        let items = ["up", "down", "up"];
        let chips = query("", "").chips(STATUSES, items.iter().copied());
        let summary: Vec<_> = chips
            .iter()
            .map(|c| (c.label, c.count, c.selected))
            .collect();
        assert_eq!(
            summary,
            [("All", 3, true), ("Down", 1, false), ("Up", 2, false)]
        );

        // A selected status stays visible even when nothing matches it.
        let chips = query("paused", "").chips(STATUSES, items.iter().copied());
        assert!(
            chips
                .iter()
                .any(|c| c.value == "paused" && c.selected && c.count == 0)
        );
        assert!(!chips[0].selected);
    }

    #[test]
    fn unknown_status_means_all() {
        let q = query("bogus", "");
        assert!(q.matches_status("up", STATUSES));
        assert!(q.chips(STATUSES, ["up"].into_iter())[0].selected);
        assert!(!query("down", "").matches_status("up", STATUSES));
    }

    #[test]
    fn text_search_is_case_insensitive() {
        assert!(query("", "BACK").matches_text(&["Nightly backup"]));
        assert!(query("", "  ").matches_text(&["anything"]));
        assert!(!query("", "api").matches_text(&["Nightly backup", "example.com"]));
    }

    #[test]
    fn urls_round_trip_the_filter() {
        assert_eq!(query("", "").url("/checks"), "/checks");
        assert_eq!(
            query("down", " db & co ").url("/checks"),
            "/checks?status=down&q=db+%26+co"
        );
    }
}
