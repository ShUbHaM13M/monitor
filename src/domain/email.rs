/// A deliberately loose email check: one `@`, a non-empty local part, a dotted
/// domain and no whitespace. Real validation is whether mail arrives.
pub fn is_valid(email: &str) -> bool {
    email.len() <= 254
        && !email.chars().any(char::is_whitespace)
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
                && !domain.contains('@')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        assert!(is_valid("ops@example.com"));
        for bad in [
            "",
            "ops",
            "ops@",
            "@example.com",
            "ops@example",
            "o ps@example.com",
            "a@b@c.com",
            "ops@.com",
        ] {
            assert!(!is_valid(bad), "{bad:?} should be rejected");
        }
    }
}
