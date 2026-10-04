//! Outbound HTTP for user-supplied URLs (webhook channels now, HTTP monitors later),
//! guarded against SSRF: requests can't reach loopback, private or metadata addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{StatusCode, Url, redirect};

use super::kind::SendError;

const TIMEOUT: Duration = Duration::from_secs(10);

/// An HTTP client for untrusted URLs. Unless `allow_private` is set, hostnames are
/// resolved by a resolver that drops non-public addresses; redirects aren't followed
/// (they could point anywhere) and proxies from the environment are ignored (they'd
/// bypass the resolver).
pub fn client(allow_private: bool) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .timeout(TIMEOUT)
        .connect_timeout(TIMEOUT)
        .redirect(redirect::Policy::none())
        .no_proxy()
        .user_agent(concat!("Monitor/", env!("CARGO_PKG_VERSION")));
    if !allow_private {
        builder = builder.dns_resolver(PublicOnlyResolver);
    }
    builder.build().expect("build HTTP client")
}

/// Parses a user-supplied URL: http(s) only, with a host, and a literal IP must be
/// public. (Hostnames are checked at connect time by the resolver.)
pub fn parse_url(raw: &str, allow_private: bool) -> Result<Url, String> {
    let url = Url::parse(raw.trim())
        .map_err(|_| "Enter a full URL, starting with https://.".to_owned())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("Only http:// and https:// URLs are supported.".into());
    }
    let Some(host) = url.host() else {
        return Err("The URL needs a host name.".into());
    };
    if !allow_private {
        let ip = match host {
            url::Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
            url::Host::Domain(domain) if domain.eq_ignore_ascii_case("localhost") => {
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
            }
            url::Host::Domain(_) => None,
        };
        if ip.is_some_and(|ip| !is_public(ip)) {
            return Err("Private, loopback and reserved addresses aren't allowed.".into());
        }
    }
    Ok(url)
}

/// Maps an HTTP response status to a delivery outcome.
pub fn classify(status: StatusCode) -> Result<(), SendError> {
    if status.is_success() {
        Ok(())
    } else if status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
    {
        Err(SendError::Retryable(format!("HTTP {status}")))
    } else {
        Err(SendError::Permanent(format!("HTTP {status}")))
    }
}

/// Maps a transport error (DNS, connect, timeout) to a delivery outcome.
pub fn transport_error(err: reqwest::Error) -> SendError {
    // Walk the source chain so the resolver's message ("resolves only to private…")
    // reaches the user instead of a generic "error sending request".
    let mut msg = err.to_string();
    let mut source = std::error::Error::source(&err);
    while let Some(inner) = source {
        msg = format!("{msg}: {inner}");
        source = inner.source();
    }
    if msg.contains(BLOCKED) {
        SendError::Permanent(msg)
    } else {
        SendError::Retryable(msg)
    }
}

const BLOCKED: &str = "resolves only to private or reserved addresses";

struct PublicOnlyResolver;

impl Resolve for PublicOnlyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .filter(|addr| is_public(addr.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(format!("{host} {BLOCKED}").into());
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Whether `ip` is a globally routable unicast address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(v4) => is_public_v4(v4),
            None => is_public_v6(ip),
        },
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local() // 169.254/16, incl. cloud metadata
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..128).contains(&b)) // 100.64/10 carrier-grade NAT
        || (a == 192 && b == 0 && c == 0) // 192.0.0/24 IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19)) // 198.18/15 benchmarking
        || a >= 240) // 240/4 reserved
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (first & 0xffc0) == 0xfe80 // fe80::/10 link local
        || first == 0x2001 && ip.segments()[1] == 0x0db8 // 2001:db8::/32 documentation
        || ip.segments()[..6] == [0x64, 0xff9b, 0, 0, 0, 0]) // NAT64 could reach v4 privates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_private_and_reserved_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip} should be blocked");
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip} should be allowed");
        }
    }

    #[test]
    fn url_rules() {
        assert!(parse_url("https://hooks.example.com/x", false).is_ok());
        assert!(parse_url("ftp://example.com", false).is_err());
        assert!(parse_url("not a url", false).is_err());
        assert!(parse_url("http://127.0.0.1:8080/hook", false).is_err());
        assert!(parse_url("http://[::1]/hook", false).is_err());
        assert!(parse_url("http://localhost/hook", false).is_err());
        assert!(parse_url("http://169.254.169.254/latest", false).is_err());
        assert!(parse_url("http://127.0.0.1:8080/hook", true).is_ok());
    }

    #[test]
    fn status_classification() {
        assert!(classify(StatusCode::NO_CONTENT).is_ok());
        for retry in [408, 429, 500, 502, 503] {
            assert!(matches!(
                classify(StatusCode::from_u16(retry).unwrap()),
                Err(SendError::Retryable(_))
            ));
        }
        for permanent in [400, 401, 403, 404, 410] {
            assert!(matches!(
                classify(StatusCode::from_u16(permanent).unwrap()),
                Err(SendError::Permanent(_))
            ));
        }
    }

    #[tokio::test]
    async fn resolver_refuses_hosts_that_resolve_privately() {
        let client = client(false);
        let err = client.get("http://localhost:9/").send().await.unwrap_err();
        assert!(matches!(transport_error(err), SendError::Permanent(msg) if msg.contains(BLOCKED)));
    }
}
