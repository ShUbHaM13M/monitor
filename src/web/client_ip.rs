use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::HeaderMap;
use axum::http::request::Parts;
use ipnet::IpNet;

use super::AppState;

/// The address of whoever sent the request. Behind a trusted reverse proxy this
/// comes from `X-Forwarded-For`; otherwise it's the TCP peer. `None` only when
/// the server wasn't started with connect info (in-process tests).
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub Option<IpAddr>);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Infallible> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip());
        Ok(Self(resolve(
            &state.config.trusted_proxies,
            peer,
            &parts.headers,
        )))
    }
}

/// Walks `X-Forwarded-For` from the right, skipping trusted proxies, and returns
/// the first address not under our control. Anything left of that is whatever
/// the client chose to send, so it's never believed.
pub fn resolve(trusted: &[IpNet], peer: Option<IpAddr>, headers: &HeaderMap) -> Option<IpAddr> {
    let mut client = canonical(peer?);
    if !is_trusted(trusted, client) {
        return Some(client);
    }
    let hops: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .collect();
    for hop in hops.iter().rev() {
        let Ok(ip) = hop.trim().parse::<IpAddr>() else {
            // Garbage: stop at the last address a trusted proxy vouched for.
            break;
        };
        client = canonical(ip);
        if !is_trusted(trusted, client) {
            break;
        }
    }
    Some(client)
}

fn is_trusted(trusted: &[IpNet], ip: IpAddr) -> bool {
    trusted.iter().any(|net| net.contains(&ip))
}

/// `::ffff:1.2.3.4` (dual-stack sockets) is the IPv4 address it wraps.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn xff(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for v in values {
            headers.append("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        }
        headers
    }

    fn proxies() -> Vec<IpNet> {
        vec![
            "10.0.0.0/8".parse().unwrap(),
            "127.0.0.1/32".parse().unwrap(),
        ]
    }

    #[test]
    fn untrusted_peers_are_the_client_whatever_they_claim() {
        let headers = xff(&["1.2.3.4"]);
        assert_eq!(
            resolve(&proxies(), Some(ip("203.0.113.9")), &headers),
            Some(ip("203.0.113.9"))
        );
        assert_eq!(
            resolve(&[], Some(ip("127.0.0.1")), &headers),
            Some(ip("127.0.0.1"))
        );
        assert_eq!(resolve(&proxies(), None, &headers), None);
    }

    #[test]
    fn trusted_proxies_are_skipped_from_the_right() {
        // The client prepended a fake hop; our proxies appended the real ones.
        let headers = xff(&["6.6.6.6, 198.51.100.7", "10.1.2.3"]);
        assert_eq!(
            resolve(&proxies(), Some(ip("127.0.0.1")), &headers),
            Some(ip("198.51.100.7"))
        );
    }

    #[test]
    fn garbage_or_missing_header_falls_back_to_the_nearest_proxy() {
        assert_eq!(
            resolve(&proxies(), Some(ip("10.0.0.5")), &HeaderMap::new()),
            Some(ip("10.0.0.5"))
        );
        let headers = xff(&["nonsense, 10.9.9.9"]);
        assert_eq!(
            resolve(&proxies(), Some(ip("10.0.0.5")), &headers),
            Some(ip("10.9.9.9"))
        );
    }

    #[test]
    fn mapped_ipv4_is_normalised() {
        let headers = xff(&["::ffff:198.51.100.7"]);
        assert_eq!(
            resolve(&proxies(), Some(ip("::ffff:127.0.0.1")), &headers),
            Some(ip("198.51.100.7"))
        );
    }
}
