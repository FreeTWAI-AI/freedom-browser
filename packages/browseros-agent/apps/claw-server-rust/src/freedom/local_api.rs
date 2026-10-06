// Freedom modification (AGPL-3.0-or-later §5(a) prominent notice).
// Added 2026-10-06. Managed-mode guard for the 自由工坊 neo client.
// Not part of upstream BrowserOS.

//! Loopback-only Freedom local API gate.
//!
//! The listener address is IPv4 localhost. `/freedom/v1/*` also requires an
//! allowlisted `Host`, an absent or allowlisted `Origin`, the per-process native
//! token, and a single-use nonce. The native token is not a member credential.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::http::{HeaderMap, header};
use rand::RngCore;

use super::FreedomRuntime;

pub const CODE_PEER: &str = "freedom_peer_denied";
pub const CODE_HOST: &str = "freedom_host_denied";
pub const CODE_ORIGIN: &str = "freedom_origin_denied";
pub const CODE_TOKEN: &str = "freedom_token_denied";
pub const CODE_NONCE_MISSING: &str = "freedom_nonce_missing";
pub const CODE_NONCE_REPLAYED: &str = "freedom_nonce_replayed";

const MSG_PEER: &str = "只接受本機連線";
const MSG_HOST: &str = "不允許這個 Host";
const MSG_ORIGIN: &str = "不允許這個來源";
const MSG_TOKEN: &str = "本機憑證無效";
const MSG_NONCE_MISSING: &str = "缺少單次 nonce";
const MSG_NONCE_REPLAYED: &str = "這個 nonce 已經用過";

const HEADER_TOKEN: &str = "x-freedom-native-token";
const HEADER_NONCE: &str = "x-freedom-nonce";
const NONCE_CAP: usize = 4096;
const NONCE_MAX_LEN: usize = 128;
const TOKEN_MAX_LEN: usize = 512;

/// Inserted only after [`authorize`] succeeds. Handlers must not run without it.
#[derive(Debug, Clone, Copy)]
pub struct FreedomLocalAuth;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalError {
    Peer,
    Host,
    Origin,
    Token,
    NonceMissing,
    NonceReplayed,
}

impl LocalError {
    #[must_use]
    pub fn status(self) -> axum::http::StatusCode {
        match self {
            Self::Token => axum::http::StatusCode::UNAUTHORIZED,
            _ => axum::http::StatusCode::FORBIDDEN,
        }
    }

    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Peer => CODE_PEER,
            Self::Host => CODE_HOST,
            Self::Origin => CODE_ORIGIN,
            Self::Token => CODE_TOKEN,
            Self::NonceMissing => CODE_NONCE_MISSING,
            Self::NonceReplayed => CODE_NONCE_REPLAYED,
        }
    }

    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::Peer => MSG_PEER,
            Self::Host => MSG_HOST,
            Self::Origin => MSG_ORIGIN,
            Self::Token => MSG_TOKEN,
            Self::NonceMissing => MSG_NONCE_MISSING,
            Self::NonceReplayed => MSG_NONCE_REPLAYED,
        }
    }
}

impl std::fmt::Display for LocalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

/// 32 random bytes, hex encoded. Generated per process, never logged here.
pub(crate) fn generate_native_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

/// IPv4 loopback only. This is the only address the managed listener may bind.
#[must_use]
pub fn loopback_bind_addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// Rejects `0.0.0.0`, non-loopback addresses, and any address other than
/// `127.0.0.1`. IPv6 loopback is not a bind target for this process.
pub fn refuse_non_loopback(addr: SocketAddr) -> Result<(), LocalError> {
    if addr.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) {
        Ok(())
    } else {
        Err(LocalError::Peer)
    }
}

/// Peer, host, origin, native token, then single-use nonce.
/// A failing token check does not consume the nonce.
pub fn authorize(
    runtime: &FreedomRuntime,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
) -> Result<(), LocalError> {
    if !peer.is_some_and(|addr| addr.is_loopback()) {
        return Err(LocalError::Peer);
    }
    if !host_allowed(headers, runtime.bound_port()) {
        return Err(LocalError::Host);
    }
    if !origin_allowed(headers, runtime.bound_port()) {
        return Err(LocalError::Origin);
    }
    let presented = header_str(headers, HEADER_TOKEN).unwrap_or("");
    if presented.is_empty()
        || presented.len() > TOKEN_MAX_LEN
        || !constant_time_eq(presented, runtime.native_token())
    {
        return Err(LocalError::Token);
    }
    let nonce = header_str(headers, HEADER_NONCE).unwrap_or("");
    consume_nonce(runtime, nonce)
}

pub(crate) fn host_allowed(headers: &HeaderMap, port: u16) -> bool {
    if port == 0 {
        return false;
    }
    let Some(raw) = header_str(headers, header::HOST.as_str()) else {
        return false;
    };
    let Some((host, port_text)) = raw.rsplit_once(':') else {
        return false;
    };
    let host_ok = host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost");
    host_ok && port_text == port.to_string()
}

pub(crate) fn origin_allowed(headers: &HeaderMap, port: u16) -> bool {
    let Some(raw) = header_str(headers, header::ORIGIN.as_str()) else {
        return true;
    };
    if port == 0 || raw.is_empty() {
        return false;
    }
    let port_text = port.to_string();
    raw == format!("http://127.0.0.1:{port_text}") || raw == format!("http://localhost:{port_text}")
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn consume_nonce(runtime: &FreedomRuntime, nonce: &str) -> Result<(), LocalError> {
    if nonce.is_empty() || nonce.len() > NONCE_MAX_LEN {
        return Err(LocalError::NonceMissing);
    }
    let mut jar = runtime
        .nonce_jar()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if jar.contains(nonce) || jar.len() >= NONCE_CAP {
        return Err(LocalError::NonceReplayed);
    }
    jar.insert(nonce.to_string());
    Ok(())
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut diff = left.len() ^ right.len();
    let width = left.len().max(right.len());
    for index in 0..width {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::{LocalError, authorize, loopback_bind_addr, refuse_non_loopback};
    use crate::freedom::{ClosedVerifier, FreedomRuntime};
    use axum::http::{HeaderMap, HeaderValue};
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::PathBuf,
        sync::Arc,
    };

    fn runtime() -> Arc<FreedomRuntime> {
        FreedomRuntime::managed(
            9200,
            PathBuf::from("/tmp/freedom-managed-profile"),
            Arc::new(ClosedVerifier),
        )
    }

    fn headers(token: &str, nonce: &str, host: &str, origin: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-freedom-native-token",
            HeaderValue::from_str(token).unwrap_or_else(|_| panic!("token header")),
        );
        headers.insert(
            "x-freedom-nonce",
            HeaderValue::from_str(nonce).unwrap_or_else(|_| panic!("nonce header")),
        );
        headers.insert(
            "host",
            HeaderValue::from_str(host).unwrap_or_else(|_| panic!("host header")),
        );
        if let Some(origin) = origin {
            headers.insert(
                "origin",
                HeaderValue::from_str(origin).unwrap_or_else(|_| panic!("origin header")),
            );
        }
        headers
    }

    #[test]
    fn bind_helper_is_ipv4_localhost_and_rejects_unspecified() {
        let addr = loopback_bind_addr(9200);
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(refuse_non_loopback(addr).is_ok());
        let unspecified = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 9200));
        assert_eq!(refuse_non_loopback(unspecified), Err(LocalError::Peer));
        let public = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 9200));
        assert_eq!(refuse_non_loopback(public), Err(LocalError::Peer));
    }

    #[test]
    fn authorize_accepts_loopback_and_rejects_each_negative() {
        let runtime = runtime();
        let token = runtime.native_token().to_string();
        let peer = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let ok = headers(&token, "nonce-1", "127.0.0.1:9200", None);
        assert!(authorize(&runtime, &ok, peer).is_ok());
        let replay = headers(
            &token,
            "nonce-1",
            "localhost:9200",
            Some("http://127.0.0.1:9200"),
        );
        assert_eq!(
            authorize(&runtime, &replay, peer),
            Err(LocalError::NonceReplayed)
        );
        let wrong_host = headers(&token, "nonce-2", "evil.example:9200", None);
        assert_eq!(
            authorize(&runtime, &wrong_host, peer),
            Err(LocalError::Host)
        );
        let wrong_origin = headers(
            &token,
            "nonce-3",
            "127.0.0.1:9200",
            Some("http://evil.example"),
        );
        assert_eq!(
            authorize(&runtime, &wrong_origin, peer),
            Err(LocalError::Origin)
        );
        let missing_nonce = headers(&token, "", "127.0.0.1:9200", None);
        assert_eq!(
            authorize(&runtime, &missing_nonce, peer),
            Err(LocalError::NonceMissing)
        );
        let wrong_token = headers("not-the-token", "nonce-4", "127.0.0.1:9200", None);
        assert_eq!(
            authorize(&runtime, &wrong_token, peer),
            Err(LocalError::Token)
        );
        let after_bad_token = headers(&token, "nonce-4", "127.0.0.1:9200", None);
        assert!(authorize(&runtime, &after_bad_token, peer).is_ok());
        let public = Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let public_headers = headers(&token, "nonce-5", "127.0.0.1:9200", None);
        assert_eq!(
            authorize(&runtime, &public_headers, public),
            Err(LocalError::Peer)
        );
        let unspecified = Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let unspecified_headers = headers(&token, "nonce-6", "127.0.0.1:9200", None);
        assert_eq!(
            authorize(&runtime, &unspecified_headers, unspecified),
            Err(LocalError::Peer)
        );
        assert_eq!(authorize(&runtime, &ok, None), Err(LocalError::Peer));
    }
}
