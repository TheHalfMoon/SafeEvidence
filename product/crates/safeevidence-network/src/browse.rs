//! Governed HTTPS URL validation, SSRF IP filtering, and scripted browse transport
//! (`ADM-0015` / `T05`, `TA-21`).
//!
//! Adapted from `AbdulazizShehri/MedScale` (`crates/medscale-network/src/browse.rs`)
//! under Apache-2.0 (`ADR-0004`), with `ureq` removed to preserve `TA-29` zero-HTTP-client
//! workspace invariants.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::Duration;

use safeevidence_contracts::network::{
    BrowseDenyReason, URL_MAX_CHARS, is_dns_host_name, is_unambiguous_url_path,
};

/// A URL that passed `validate_url`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedUrl {
    pub url: String,
    pub host: String,
    pub path: String,
}

/// Parses and validates a governed HTTPS URL (`https://`, port 443, canonical DNS host, no IP
/// literals, no userinfo, no dot/backslash/encoded-slash path ambiguity).
pub fn validate_url(raw: &str) -> Result<ValidatedUrl, BrowseDenyReason> {
    let raw = raw.trim();
    if raw.is_empty() || raw.chars().count() > URL_MAX_CHARS {
        return Err(BrowseDenyReason::MalformedUrl);
    }
    if raw.chars().any(|c| c.is_whitespace() || c.is_control()) || raw.contains('#') {
        return Err(BrowseDenyReason::MalformedUrl);
    }
    let lower = raw.to_ascii_lowercase();
    let rest = if lower.starts_with("https://") {
        &raw["https://".len()..]
    } else if lower.contains("://") || lower.starts_with("//") {
        return Err(BrowseDenyReason::SchemeNotHttps);
    } else {
        return Err(BrowseDenyReason::MalformedUrl);
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.contains('@') {
        return Err(BrowseDenyReason::MalformedUrl);
    }
    if authority.starts_with('[') {
        return Err(BrowseDenyReason::IpLiteralHost);
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if let Some(port) = port
        && port != "443"
    {
        return Err(BrowseDenyReason::PortNotAllowed);
    }
    let host = host.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host).to_owned();
    if host.parse::<IpAddr>().is_ok() || looks_numeric_host(&host) {
        return Err(BrowseDenyReason::IpLiteralHost);
    }
    if !is_dns_host_name(&host) {
        return Err(BrowseDenyReason::MalformedUrl);
    }
    let path = if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_owned()
    };
    if !is_unambiguous_url_path(&path) {
        return Err(BrowseDenyReason::MalformedUrl);
    }
    Ok(ValidatedUrl {
        url: format!("https://{host}{path}"),
        host,
        path,
    })
}

fn looks_numeric_host(host: &str) -> bool {
    host.split('.').all(|label| {
        !label.is_empty()
            && (label.bytes().all(|b| b.is_ascii_digit())
                || (label.starts_with("0x") && label[2..].bytes().all(|b| b.is_ascii_hexdigit())))
    })
}

/// Resolves a `Location` header against `current` without following it automatically.
#[must_use]
pub fn resolve_redirect(current: &ValidatedUrl, location: &str) -> String {
    let location = location.trim();
    if location.starts_with('/') && !location.starts_with("//") {
        format!("https://{}{}", current.host, location)
    } else {
        location.to_owned()
    }
}

/// True for every IPv4/IPv6 address that governed egress must never connect to (loopback, RFC1918,
/// link-local / cloud metadata `169.254.169.254`, CGNAT, multicast, broadcast, documentation,
/// benchmarking, reserved, unspecified, IPv6 unique/link/site-local, 6to4, Teredo, NAT64, and
/// IPv4-mapped/compatible forms).
#[must_use]
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => forbidden_v4(v4),
        IpAddr::V6(v6) => forbidden_v6(v6),
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240
}

fn forbidden_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return forbidden_v4(v4);
    }
    let s = ip.segments();
    if s[0] == 0x2002 {
        let v4 = Ipv4Addr::new(
            (s[1] >> 8) as u8,
            (s[1] & 0xff) as u8,
            (s[2] >> 8) as u8,
            (s[2] & 0xff) as u8,
        );
        return forbidden_v4(v4);
    }
    if (s[0] == 0x2001 && s[1] == 0) || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1) {
        return true;
    }
    if s[..6] == [0, 0, 0, 0, 0, 0] || (s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0]) {
        let v4 = Ipv4Addr::new(
            (s[6] >> 8) as u8,
            (s[6] & 0xff) as u8,
            (s[7] >> 8) as u8,
            (s[7] & 0xff) as u8,
        );
        return ip.is_unspecified() || ip.is_loopback() || forbidden_v4(v4);
    }
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        || (s[0] == 0x2001 && s[1] == 0x0db8)
}

/// Filters candidate resolved socket addresses down to strictly public endpoints; fails with
/// `BrowseDenyReason::ForbiddenResolvedIp` if none survive (defeating DNS-rebinding to internal IPs).
pub fn filter_public_socket_addrs(
    addrs: &[SocketAddr],
) -> Result<Vec<SocketAddr>, BrowseDenyReason> {
    let kept: Vec<SocketAddr> = addrs
        .iter()
        .copied()
        .filter(|a| !is_forbidden_ip(a.ip()))
        .collect();
    if kept.is_empty() {
        Err(BrowseDenyReason::ForbiddenResolvedIp)
    } else {
        Ok(kept)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowseHttpResponse {
    pub status: u16,
    pub location: Option<String>,
    pub content_type: String,
    pub www_authenticate: bool,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowseTransportError {
    ForbiddenAddress,
    Timeout,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowseFileResponse {
    pub status: u16,
    pub location: Option<String>,
    pub file_len: u64,
}

pub trait BrowseTransport: Send + Sync {
    fn get(
        &self,
        url: &ValidatedUrl,
        max_body_bytes: usize,
        timeout: Duration,
    ) -> Result<BrowseHttpResponse, BrowseTransportError>;

    fn get_to_file(
        &self,
        url: &ValidatedUrl,
        resume_from: u64,
        max_total_bytes: u64,
        path: &std::path::Path,
        timeout: Duration,
    ) -> Result<BrowseFileResponse, BrowseTransportError> {
        let _ = (url, resume_from, max_total_bytes, path, timeout);
        Err(BrowseTransportError::Failed)
    }
}

/// Deterministic offline scripted transport for testing redirects, size caps, and resumable pack
/// downloads without opening sockets.
#[derive(Debug, Default)]
pub struct ScriptedBrowseTransport {
    steps: Mutex<VecDeque<Result<BrowseHttpResponse, BrowseTransportError>>>,
}

impl ScriptedBrowseTransport {
    #[must_use]
    pub fn with_steps(
        steps: impl IntoIterator<Item = Result<BrowseHttpResponse, BrowseTransportError>>,
    ) -> Self {
        Self {
            steps: Mutex::new(steps.into_iter().collect()),
        }
    }
}

impl BrowseTransport for ScriptedBrowseTransport {
    fn get(
        &self,
        _url: &ValidatedUrl,
        max_body_bytes: usize,
        _timeout: Duration,
    ) -> Result<BrowseHttpResponse, BrowseTransportError> {
        let mut guard = self
            .steps
            .lock()
            .map_err(|_| BrowseTransportError::Failed)?;
        let mut resp = guard
            .pop_front()
            .unwrap_or(Err(BrowseTransportError::Failed))?;
        if resp.body.len() > max_body_bytes.saturating_add(1) {
            resp.body.truncate(max_body_bytes.saturating_add(1));
        }
        Ok(resp)
    }

    fn get_to_file(
        &self,
        url: &ValidatedUrl,
        resume_from: u64,
        max_total_bytes: u64,
        path: &std::path::Path,
        timeout: Duration,
    ) -> Result<BrowseFileResponse, BrowseTransportError> {
        use std::io::{Read as _, Write as _};
        let resp = self.get(url, usize::MAX / 2, timeout)?;
        let append = resp.status == 206 && resume_from > 0;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .truncate(!append)
            .open(path)
            .map_err(|_| BrowseTransportError::Failed)?;
        let start = if append { resume_from } else { 0 };
        let budget = max_total_bytes.saturating_add(1).saturating_sub(start);
        let mut cursor = std::io::Cursor::new(&resp.body).take(budget);
        let mut buf = Vec::new();
        cursor
            .read_to_end(&mut buf)
            .map_err(|_| BrowseTransportError::Failed)?;
        file.write_all(&buf)
            .map_err(|_| BrowseTransportError::Failed)?;
        file.flush().map_err(|_| BrowseTransportError::Failed)?;
        Ok(BrowseFileResponse {
            status: resp.status,
            location: resp.location,
            file_len: start + buf.len() as u64,
        })
    }
}
