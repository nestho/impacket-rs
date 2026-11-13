//! Pure-Rust network transport abstraction supporting direct TCP, SOCKS5 (RFC 1928/1929),
//! and HTTP CONNECT (RFC 7231) proxy tunneling with zero external dependencies.
//!
//! Provides `TransportStream` which wraps a connected `std::net::TcpStream` and transparently
//! handles proxy handshakes. This enables static `musl` binaries to traverse proxies without
//! relying on `LD_PRELOAD`-based tools such as `proxychains4`.

use std::fmt;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream, ToSocketAddrs};
use std::ops::{Deref, DerefMut};
use std::time::Duration;

use crate::{encode_base64, CoreError, SecretString, TargetSpec};

/// Supported proxy protocol types.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProxyType {
    /// SOCKS5 protocol per RFC 1928 / RFC 1929.
    Socks5,
    /// HTTP tunneling proxy using the `CONNECT` method per RFC 7231 §4.3.6.
    HttpConnect,
}

impl fmt::Display for ProxyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socks5 => write!(f, "SOCKS5"),
            Self::HttpConnect => write!(f, "HTTP CONNECT"),
        }
    }
}

/// Authentication credentials for proxy connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyAuth {
    pub username: String,
    pub password: SecretString,
}

impl ProxyAuth {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: SecretString::new(password.into()),
        }
    }
}

/// Configuration for routing connections through a network proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    pub proxy_type: ProxyType,
    pub host: String,
    pub port: u16,
    pub auth: Option<ProxyAuth>,
}

impl ProxyConfig {
    /// Parses a proxy URL string:
    /// - `socks5://[user:pass@]host[:port]`
    /// - `socks5h://[user:pass@]host[:port]` (remote DNS resolution)
    /// - `http://[user:pass@]host[:port]`
    pub fn parse(proxy_url: &str) -> Result<Self, CoreError> {
        let trimmed = proxy_url.trim();
        if trimmed.is_empty() {
            return Err(CoreError::ProxyError("Proxy URL cannot be empty".into()));
        }

        let (scheme, rest) = trimmed.split_once("://").ok_or_else(|| {
            CoreError::ProxyError(format!(
                "Invalid proxy URL '{}': missing protocol scheme ('socks5://' or 'http://')",
                trimmed
            ))
        })?;

        let (proxy_type, default_port) = match scheme.to_ascii_lowercase().as_str() {
            "socks5" | "socks5h" => (ProxyType::Socks5, 1080),
            "http" | "https" => (ProxyType::HttpConnect, 8080),
            other => {
                return Err(CoreError::ProxyError(format!(
                    "Unsupported proxy scheme '{}': only socks5 and http are supported",
                    other
                )));
            }
        };

        let (auth_part, host_port_part) = match rest.rsplit_once('@') {
            Some((auth, host_port)) => (Some(auth), host_port),
            None => (None, rest),
        };

        let auth = if let Some(a) = auth_part {
            let (u, p) = match a.split_once(':') {
                Some((u, p)) => (u, p),
                None => (a, ""),
            };
            Some(ProxyAuth::new(u, p))
        } else {
            None
        };

        let (host, port) = if host_port_part.starts_with('[') {
            // IPv6 address syntax [fe80::1]:port
            let end_bracket = host_port_part.find(']').ok_or_else(|| {
                CoreError::ProxyError(format!(
                    "Invalid IPv6 proxy address '{}': missing closing bracket ']'",
                    host_port_part
                ))
            })?;
            let ipv6_str = &host_port_part[1..end_bracket];
            let remainder = &host_port_part[end_bracket + 1..];
            let port = if let Some(p_str) = remainder.strip_prefix(':') {
                p_str
                    .parse::<u16>()
                    .map_err(|e| CoreError::ProxyError(format!("Invalid proxy port: {}", e)))?
            } else {
                default_port
            };
            (ipv6_str.to_string(), port)
        } else {
            match host_port_part.split_once(':') {
                Some((h, p_str)) => {
                    let port = p_str
                        .parse::<u16>()
                        .map_err(|e| CoreError::ProxyError(format!("Invalid proxy port: {}", e)))?;
                    (h.to_string(), port)
                }
                None => (host_port_part.to_string(), default_port),
            }
        };

        if host.is_empty() {
            return Err(CoreError::ProxyError("Proxy host cannot be empty".into()));
        }

        Ok(Self {
            proxy_type,
            host,
            port,
            auth,
        })
    }

    /// Checks environment variables (`ALL_PROXY`, `all_proxy`, `HTTPS_PROXY`, `https_proxy`,
    /// `HTTP_PROXY`, `http_proxy`) to automatically configure a proxy.
    pub fn from_env() -> Option<Self> {
        let vars = [
            "ALL_PROXY",
            "all_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
        ];
        for var in &vars {
            if let Ok(val) = std::env::var(var) {
                let trimmed = val.trim();
                if !trimmed.is_empty() {
                    if let Ok(config) = Self::parse(trimmed) {
                        return Some(config);
                    }
                }
            }
        }
        None
    }

    /// Formats the proxy configuration back into a standard URL string.
    pub fn to_url(&self) -> String {
        let scheme = match self.proxy_type {
            ProxyType::Socks5 => "socks5",
            ProxyType::HttpConnect => "http",
        };
        match &self.auth {
            Some(auth) => format!(
                "{}://{}:{}@{}:{}",
                scheme,
                auth.username,
                auth.password.expose_secret(),
                self.host,
                self.port
            ),
            None => format!("{}://{}:{}", scheme, self.host, self.port),
        }
    }
}

/// A connected stream to a network target, either direct or via a proxy tunnel.
///
/// Implements `Read`, `Write`, and dereferences to `TcpStream` for full compatibility
/// with existing protocol client implementations.
#[derive(Debug)]
pub struct TransportStream {
    inner: TcpStream,
    target_host: String,
    target_port: u16,
    proxied_via: Option<String>,
}

impl TransportStream {
    /// Connects to a target host and port, routing through a proxy if configured.
    pub fn connect(
        target_host: &str,
        target_port: u16,
        timeout: Duration,
        proxy: Option<&ProxyConfig>,
    ) -> Result<Self, CoreError> {
        match proxy {
            Some(p) => Self::connect_proxied(target_host, target_port, timeout, p),
            None => Self::connect_direct(target_host, target_port, timeout),
        }
    }

    /// Connects to a target specified by a `TargetSpec` using default port and optional proxy.
    pub fn connect_target(
        spec: &TargetSpec,
        default_port: u16,
        timeout: Duration,
    ) -> Result<Self, CoreError> {
        let host = spec.effective_target_ip();
        let port = spec.effective_port(default_port);
        let proxy = spec.proxy.as_ref();
        Self::connect(host, port, timeout, proxy)
    }

    /// Direct TCP connection without proxy, supporting IPv4 and IPv6 dual-stack resolution.
    fn connect_direct(
        target_host: &str,
        target_port: u16,
        timeout: Duration,
    ) -> Result<Self, CoreError> {
        let clean_host = target_host.trim_start_matches('[').trim_end_matches(']');
        let addr_str = if clean_host.contains(':') {
            format!("[{}]:{}", clean_host, target_port)
        } else {
            format!("{}:{}", clean_host, target_port)
        };
        let addrs = addr_str.to_socket_addrs().map_err(|e| {
            CoreError::IoError(format!("Failed to resolve target '{}': {}", addr_str, e))
        })?;

        let mut last_err = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(Self {
                        inner: stream,
                        target_host: target_host.to_string(),
                        target_port,
                        proxied_via: None,
                    });
                }
                Err(e) => last_err = Some(e),
            }
        }

        Err(CoreError::IoError(format!(
            "Failed to connect to target '{}:{}': {}",
            target_host,
            target_port,
            last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "No reachable address resolved".into())
        )))
    }

    /// Establishes connection through a configured SOCKS5 or HTTP CONNECT proxy.
    fn connect_proxied(
        target_host: &str,
        target_port: u16,
        timeout: Duration,
        proxy: &ProxyConfig,
    ) -> Result<Self, CoreError> {
        let clean_proxy_host = proxy.host.trim_start_matches('[').trim_end_matches(']');
        let proxy_addr_str = if clean_proxy_host.contains(':') {
            format!("[{}]:{}", clean_proxy_host, proxy.port)
        } else {
            format!("{}:{}", clean_proxy_host, proxy.port)
        };
        let proxy_addrs = proxy_addr_str.to_socket_addrs().map_err(|e| {
            CoreError::ProxyError(format!(
                "Failed to resolve proxy server '{}': {}",
                proxy_addr_str, e
            ))
        })?;

        let mut stream_opt = None;
        let mut last_err = None;
        for addr in proxy_addrs {
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    stream_opt = Some(s);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }

        let mut stream = stream_opt.ok_or_else(|| {
            CoreError::ProxyError(format!(
                "Failed to connect to proxy server '{}:{}': {}",
                proxy.host,
                proxy.port,
                last_err
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "No reachable address".into())
            ))
        })?;

        // Set handshake timeout
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));

        match proxy.proxy_type {
            ProxyType::Socks5 => {
                socks5_handshake(&mut stream, target_host, target_port, proxy.auth.as_ref())?;
            }
            ProxyType::HttpConnect => {
                http_connect_handshake(&mut stream, target_host, target_port, proxy.auth.as_ref())?;
            }
        }

        Ok(Self {
            inner: stream,
            target_host: target_host.to_string(),
            target_port,
            proxied_via: Some(proxy.to_url()),
        })
    }

    pub fn target_host(&self) -> &str {
        &self.target_host
    }

    pub fn target_port(&self) -> u16 {
        self.target_port
    }

    pub fn is_proxied(&self) -> bool {
        self.proxied_via.is_some()
    }

    pub fn proxied_via(&self) -> Option<&str> {
        self.proxied_via.as_deref()
    }

    pub fn into_inner(self) -> TcpStream {
        self.inner
    }

    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            inner: self.inner.try_clone()?,
            target_host: self.target_host.clone(),
            target_port: self.target_port,
            proxied_via: self.proxied_via.clone(),
        })
    }
}

impl Deref for TransportStream {
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TransportStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Read for TransportStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for TransportStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

// ============================================================================
// Internal Handshake Engines (SOCKS5 & HTTP CONNECT)
// ============================================================================

/// Executes the RFC 1928 / RFC 1929 SOCKS5 greeting, authentication, and connection negotiation.
fn socks5_handshake(
    stream: &mut TcpStream,
    target_host: &str,
    target_port: u16,
    auth: Option<&ProxyAuth>,
) -> Result<(), CoreError> {
    // 1. Send version & authentication methods
    let greeting = match auth {
        Some(_) => vec![0x05, 0x02, 0x00, 0x02], // Methods: No Auth (0x00) & User/Pass (0x02)
        None => vec![0x05, 0x01, 0x00],          // Method: No Auth (0x00)
    };
    stream
        .write_all(&greeting)
        .map_err(|e| CoreError::ProxyError(format!("SOCKS5 greeting send failed: {}", e)))?;
    stream
        .flush()
        .map_err(|e| CoreError::ProxyError(format!("SOCKS5 greeting flush failed: {}", e)))?;

    // 2. Read server method choice (2 bytes: [VER, METHOD])
    let mut resp = [0u8; 2];
    stream
        .read_exact(&mut resp)
        .map_err(|e| CoreError::ProxyError(format!("SOCKS5 method reply read failed: {}", e)))?;

    if resp[0] != 0x05 {
        return Err(CoreError::ProxyError(format!(
            "Invalid SOCKS version in server reply: expected 0x05, got 0x{:02X}",
            resp[0]
        )));
    }

    match resp[1] {
        0x00 => {
            // No authentication required
        }
        0x02 => {
            // Username/Password authentication (RFC 1929)
            let credentials = auth.ok_or_else(|| {
                CoreError::ProxyError(
                    "SOCKS5 proxy requested username/password auth, but no credentials provided"
                        .into(),
                )
            })?;

            let u_bytes = credentials.username.as_bytes();
            let p_bytes = credentials.password.as_bytes();

            if u_bytes.len() > 255 || p_bytes.len() > 255 {
                return Err(CoreError::ProxyError(
                    "SOCKS5 username or password exceeds 255 bytes".into(),
                ));
            }

            let mut auth_pkt = Vec::with_capacity(3 + u_bytes.len() + p_bytes.len());
            auth_pkt.push(0x01); // Subnegotiation version 1
            auth_pkt.push(u_bytes.len() as u8);
            auth_pkt.extend_from_slice(u_bytes);
            auth_pkt.push(p_bytes.len() as u8);
            auth_pkt.extend_from_slice(p_bytes);

            stream
                .write_all(&auth_pkt)
                .map_err(|e| CoreError::ProxyError(format!("SOCKS5 auth send failed: {}", e)))?;
            stream
                .flush()
                .map_err(|e| CoreError::ProxyError(format!("SOCKS5 auth flush failed: {}", e)))?;

            let mut auth_resp = [0u8; 2];
            stream
                .read_exact(&mut auth_resp)
                .map_err(|e| CoreError::ProxyError(format!("SOCKS5 auth reply read failed: {}", e)))?;

            if auth_resp[1] != 0x00 {
                return Err(CoreError::ProxyError(format!(
                    "SOCKS5 authentication rejected by proxy (status 0x{:02X})",
                    auth_resp[1]
                )));
            }
        }
        0xFF => {
            return Err(CoreError::ProxyError(
                "SOCKS5 proxy rejected authentication methods (0xFF: no acceptable methods)".into(),
            ));
        }
        other => {
            return Err(CoreError::ProxyError(format!(
                "Unsupported SOCKS5 authentication method requested by server: 0x{:02X}",
                other
            )));
        }
    }

    // 3. Send SOCKS5 CONNECT command
    // Format: [VER=0x05, CMD=0x01, RSV=0x00, ATYP, DST.ADDR, DST.PORT (2 bytes BE)]
    let mut req = Vec::with_capacity(32);
    req.push(0x05); // Version 5
    req.push(0x01); // CMD: CONNECT
    req.push(0x00); // Reserved

    // Determine address type
    let clean_target = target_host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ipv4) = clean_target.parse::<Ipv4Addr>() {
        req.push(0x01); // ATYP: IPv4
        req.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = clean_target.parse::<Ipv6Addr>() {
        req.push(0x04); // ATYP: IPv6
        req.extend_from_slice(&ipv6.octets());
    } else {
        // Domain Name (ATYP: 0x03) - resolves remotely on proxy to prevent DNS leaks!
        let host_bytes = clean_target.as_bytes();
        if host_bytes.len() > 255 {
            return Err(CoreError::ProxyError(
                "Target hostname exceeds maximum SOCKS5 length (255 bytes)".into(),
            ));
        }
        req.push(0x03);
        req.push(host_bytes.len() as u8);
        req.extend_from_slice(host_bytes);
    }

    req.extend_from_slice(&target_port.to_be_bytes());

    stream
        .write_all(&req)
        .map_err(|e| CoreError::ProxyError(format!("SOCKS5 connect request failed: {}", e)))?;
    stream
        .flush()
        .map_err(|e| CoreError::ProxyError(format!("SOCKS5 connect flush failed: {}", e)))?;

    // 4. Read server reply: [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
    let mut reply_header = [0u8; 4];
    stream
        .read_exact(&mut reply_header)
        .map_err(|e| CoreError::ProxyError(format!("SOCKS5 connect reply read failed: {}", e)))?;

    if reply_header[0] != 0x05 {
        return Err(CoreError::ProxyError(format!(
            "Invalid SOCKS version in connect reply: expected 0x05, got 0x{:02X}",
            reply_header[0]
        )));
    }

    let rep = reply_header[1];
    if rep != 0x00 {
        let reason = match rep {
            0x01 => "General SOCKS server failure",
            0x02 => "Connection not allowed by ruleset",
            0x03 => "Network unreachable",
            0x04 => "Host unreachable",
            0x05 => "Connection refused by destination host",
            0x06 => "TTL expired",
            0x07 => "Command not supported",
            0x08 => "Address type not supported",
            _ => "Unknown SOCKS5 error code",
        };
        return Err(CoreError::ProxyError(format!(
            "SOCKS5 connection to '{}:{}' failed (REP 0x{:02X}): {}",
            target_host, target_port, rep, reason
        )));
    }

    // Read bound address and port to consume the full SOCKS reply frame
    let atyp = reply_header[3];
    match atyp {
        0x01 => {
            // IPv4: 4 bytes addr + 2 bytes port
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).map_err(|e| {
                CoreError::ProxyError(format!("SOCKS5 bound IPv4 read failed: {}", e))
            })?;
        }
        0x03 => {
            // Domain name: 1 byte len + N bytes + 2 bytes port
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).map_err(|e| {
                CoreError::ProxyError(format!("SOCKS5 bound domain len read failed: {}", e))
            })?;
            let domain_len = len_buf[0] as usize;
            let mut domain_and_port = vec![0u8; domain_len + 2];
            stream.read_exact(&mut domain_and_port).map_err(|e| {
                CoreError::ProxyError(format!("SOCKS5 bound domain read failed: {}", e))
            })?;
        }
        0x04 => {
            // IPv6: 16 bytes addr + 2 bytes port
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).map_err(|e| {
                CoreError::ProxyError(format!("SOCKS5 bound IPv6 read failed: {}", e))
            })?;
        }
        other => {
            return Err(CoreError::ProxyError(format!(
                "Invalid ATYP in SOCKS5 connect response: 0x{:02X}",
                other
            )));
        }
    }

    // SOCKS5 tunnel established successfully!
    Ok(())
}

/// Executes the RFC 7231 §4.3.6 HTTP `CONNECT` tunneling handshake.
fn http_connect_handshake(
    stream: &mut TcpStream,
    target_host: &str,
    target_port: u16,
    auth: Option<&ProxyAuth>,
) -> Result<(), CoreError> {
    let clean_target = target_host.trim_start_matches('[').trim_end_matches(']');
    let host_header = if clean_target.contains(':') {
        format!("[{}]:{}", clean_target, target_port)
    } else {
        format!("{}:{}", clean_target, target_port)
    };
    let mut req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: impacket-rs\r\nProxy-Connection: Keep-Alive\r\n",
        host_header, host_header
    );

    if let Some(credentials) = auth {
        let auth_payload = format!(
            "{}:{}",
            credentials.username,
            credentials.password.expose_secret()
        );
        let b64 = encode_base64(auth_payload.as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", b64));
    }

    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .map_err(|e| CoreError::ProxyError(format!("HTTP CONNECT request failed: {}", e)))?;
    stream
        .flush()
        .map_err(|e| CoreError::ProxyError(format!("HTTP CONNECT flush failed: {}", e)))?;

    // Read HTTP response headers byte-by-byte or small chunk until "\r\n\r\n"
    let mut response_bytes = Vec::with_capacity(512);
    let mut byte_buf = [0u8; 1];

    while response_bytes.len() < 8192 {
        stream
            .read_exact(&mut byte_buf)
            .map_err(|e| CoreError::ProxyError(format!("HTTP CONNECT reply read failed: {}", e)))?;
        response_bytes.push(byte_buf[0]);

        if response_bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let response_str = String::from_utf8_lossy(&response_bytes);
    let status_line = response_str
        .lines()
        .next()
        .ok_or_else(|| CoreError::ProxyError("Empty HTTP response from proxy".into()))?;

    // Check status code: "HTTP/1.1 200 ..." or "HTTP/1.0 200 ..."
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(CoreError::ProxyError(format!(
            "Malformed HTTP status line from proxy: '{}'",
            status_line
        )));
    }

    let status_code = parts[1]
        .parse::<u16>()
        .map_err(|e| CoreError::ProxyError(format!("Invalid HTTP status code: {}", e)))?;

    if status_code != 200 {
        return Err(CoreError::ProxyError(format!(
            "HTTP CONNECT to '{}:{}' rejected by proxy: '{}'",
            target_host, target_port, status_line
        )));
    }

    // HTTP tunnel established successfully!
    Ok(())
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn test_proxy_config_parse_socks5() {
        let p = ProxyConfig::parse("socks5://127.0.0.1:1080").unwrap();
        assert_eq!(p.proxy_type, ProxyType::Socks5);
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 1080);
        assert!(p.auth.is_none());

        let p_auth = ProxyConfig::parse("socks5://admin:SuperSecret@10.0.0.1:9050").unwrap();
        assert_eq!(p_auth.proxy_type, ProxyType::Socks5);
        assert_eq!(p_auth.host, "10.0.0.1");
        assert_eq!(p_auth.port, 9050);
        let auth = p_auth.auth.unwrap();
        assert_eq!(auth.username, "admin");
        assert_eq!(auth.password.expose_secret(), "SuperSecret");
    }

    #[test]
    fn test_proxy_config_parse_http() {
        let p = ProxyConfig::parse("http://proxy.corp.internal:8080").unwrap();
        assert_eq!(p.proxy_type, ProxyType::HttpConnect);
        assert_eq!(p.host, "proxy.corp.internal");
        assert_eq!(p.port, 8080);

        let p_default_port = ProxyConfig::parse("http://proxy.corp.internal").unwrap();
        assert_eq!(p_default_port.port, 8080);
    }

    #[test]
    fn test_proxy_config_parse_ipv6() {
        let p = ProxyConfig::parse("socks5://[::1]:1080").unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 1080);
    }

    #[test]
    fn test_socks5_handshake_mock_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();

            // 1. Read greeting [0x05, 0x01, 0x00]
            let mut greeting = [0u8; 3];
            socket.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);

            // 2. Respond method choice [0x05, 0x00]
            socket.write_all(&[0x05, 0x00]).unwrap();

            // 3. Read connect request
            let mut req_hdr = [0u8; 4];
            socket.read_exact(&mut req_hdr).unwrap();
            assert_eq!(req_hdr, [0x05, 0x01, 0x00, 0x03]); // Domain name

            let mut len = [0u8; 1];
            socket.read_exact(&mut len).unwrap();
            let mut domain = vec![0u8; len[0] as usize];
            socket.read_exact(&mut domain).unwrap();
            assert_eq!(String::from_utf8(domain).unwrap(), "target.domain.local");

            let mut port_bytes = [0u8; 2];
            socket.read_exact(&mut port_bytes).unwrap();
            assert_eq!(u16::from_be_bytes(port_bytes), 445);

            // 4. Send success reply [0x05, 0x00, 0x00, 0x01, 127.0.0.1, 445]
            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xBD])
                .unwrap();

            // Echo test
            let mut payload = [0u8; 4];
            socket.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"PING");
            socket.write_all(b"PONG").unwrap();
        });

        let proxy = ProxyConfig {
            proxy_type: ProxyType::Socks5,
            host: "127.0.0.1".into(),
            port,
            auth: None,
        };

        let mut stream = TransportStream::connect(
            "target.domain.local",
            445,
            Duration::from_secs(5),
            Some(&proxy),
        )
        .unwrap();

        assert!(stream.is_proxied());
        stream.write_all(b"PING").unwrap();
        stream.flush().unwrap();

        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"PONG");

        handle.join().unwrap();
    }

    #[test]
    fn test_http_connect_handshake_mock_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());

            // Read CONNECT request line
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.starts_with("CONNECT 192.168.1.100:389 HTTP/1.1"));

            // Drain headers until empty line
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
            }

            // Send 200 Connection Established
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .unwrap();

            // Echo payload
            let mut buf = [0u8; 5];
            socket.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"HELLO");
            socket.write_all(b"WORLD").unwrap();
        });

        let proxy = ProxyConfig {
            proxy_type: ProxyType::HttpConnect,
            host: "127.0.0.1".into(),
            port,
            auth: None,
        };

        let mut stream = TransportStream::connect(
            "192.168.1.100",
            389,
            Duration::from_secs(5),
            Some(&proxy),
        )
        .unwrap();

        assert!(stream.is_proxied());
        stream.write_all(b"HELLO").unwrap();
        stream.flush().unwrap();

        let mut reply = [0u8; 5];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"WORLD");

        handle.join().unwrap();
    }
}
