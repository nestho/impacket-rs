//! `kkdcp`: `[MS-KKDCP]` Kerberos Key Distribution Center (KDC) Proxy Protocol client (`RFC 7874`).
//!
//! Tunnels Kerberos network exchanges (`AS-REQ`, `TGS-REQ`) over HTTPS (port 443) through
//! a Microsoft KDC Proxy or RD Gateway service, bypassing perimeter firewalls blocking TCP/UDP 88.

use crate::{KdcAsResponse, Krb5AsReq};
use impacket_core::CoreError;
use std::io::{Read, Write};

/// MS-KKDCP Default Proxy HTTP URL Path.
pub const DEFAULT_KKDCP_PATH: &str = "/KdcProxy";

/// Default HTTPS port used for KDC Proxy services.
pub const DEFAULT_KKDCP_PORT: u16 = 443;

/// `[MS-KKDCP] 2.2.2 KDC_PROXY_MESSAGE`: Length-prefixed Kerberos message container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcProxyMessage {
    /// Raw Kerberos protocol PDU (e.g. DER-encoded `AS-REQ` or `AS-REP`).
    pub kerb_message: Vec<u8>,
    /// Optional target realm / domain name hint.
    pub target_domain: Option<String>,
    /// Domain Controller locator hint flags.
    pub dclocator_hint: u32,
}

impl KdcProxyMessage {
    /// Creates a new proxy message wrapping raw Kerberos PDU bytes.
    pub fn new(kerb_message: Vec<u8>) -> Self {
        Self {
            kerb_message,
            target_domain: None,
            dclocator_hint: 0,
        }
    }

    /// Creates a new proxy message with target domain hint.
    pub fn with_domain(kerb_message: Vec<u8>, domain: impl Into<String>) -> Self {
        Self {
            kerb_message,
            target_domain: Some(domain.into()),
            dclocator_hint: 0,
        }
    }

    /// Serializes into MS-KKDCP wire bytes:
    /// `[4 bytes little-endian ulLength][kerb_message bytes]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.kerb_message.len());
        buf.extend_from_slice(&(self.kerb_message.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.kerb_message);
        buf
    }

    /// Parses wire bytes into a `KdcProxyMessage`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 4 {
            return Err(CoreError::ProtocolError(
                "KKDCP message too short: less than 4 bytes".into(),
            ));
        }
        let length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + length {
            return Err(CoreError::ProtocolError(format!(
                "KKDCP message payload truncated: expected {} bytes, got {}",
                length,
                data.len() - 4
            )));
        }
        let kerb_message = data[4..4 + length].to_vec();
        Ok(Self {
            kerb_message,
            target_domain: None,
            dclocator_hint: 0,
        })
    }

    /// Builds a standard HTTP/1.1 POST request payload for KKDCP.
    pub fn build_http_request(&self, host: &str, path: &str) -> Vec<u8> {
        let body = self.to_bytes();
        let headers = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Kerberos-KdcProxy-Client/1.0\r\n\
             Content-Type: application/kerberos\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            path,
            host,
            body.len()
        );
        let mut req = headers.into_bytes();
        req.extend_from_slice(&body);
        req
    }
}

/// Parses an HTTP response containing an MS-KKDCP reply body.
pub fn parse_http_kkdcp_response(resp: &[u8]) -> Result<KdcProxyMessage, CoreError> {
    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| {
            CoreError::ProtocolError("Incomplete HTTP response: missing CRLF CRLF".into())
        })?;

    let header_str = String::from_utf8_lossy(&resp[..header_end]);
    let status_line = header_str
        .lines()
        .next()
        .ok_or_else(|| CoreError::ProtocolError("Missing HTTP status line".into()))?;

    if !status_line.contains(" 200 ") {
        return Err(CoreError::ProtocolError(format!(
            "KKDCP HTTP proxy error: {}",
            status_line
        )));
    }

    let body = &resp[header_end + 4..];
    KdcProxyMessage::from_bytes(body)
}

/// Sans-I/O: Sends an AS-REQ wrapped in MS-KKDCP over a transport stream (HTTP/HTTPS) and parses the reply.
pub fn send_as_req_kkdcp_over_stream<R: Read, W: Write>(
    req: &Krb5AsReq,
    host: &str,
    path: &str,
    rx: &mut R,
    tx: &mut W,
) -> Result<KdcAsResponse, CoreError> {
    let raw_as_req = req.to_der_bytes(false);
    let proxy_msg = KdcProxyMessage::with_domain(raw_as_req, &req.realm);
    let http_req = proxy_msg.build_http_request(host, path);

    tx.write_all(&http_req)
        .map_err(|e| CoreError::IoError(format!("Failed sending KKDCP HTTP request: {}", e)))?;
    tx.flush()
        .map_err(|e| CoreError::IoError(format!("Failed flushing KKDCP stream: {}", e)))?;

    let mut response_bytes = Vec::new();
    rx.read_to_end(&mut response_bytes)
        .map_err(|e| CoreError::IoError(format!("Failed reading KKDCP HTTP response: {}", e)))?;

    let proxy_reply = parse_http_kkdcp_response(&response_bytes)?;
    KdcAsResponse::from_der_bytes(&proxy_reply.kerb_message, &req.realm, &req.username)
}

/// Connects to a KDC Proxy over TCP and executes an AS-REQ exchange via MS-KKDCP.
pub fn send_as_req_kkdcp_live(
    proxy_host: &str,
    proxy_port: u16,
    path: &str,
    req: &Krb5AsReq,
    timeout: std::time::Duration,
) -> Result<KdcAsResponse, CoreError> {
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
    let addr_str = format!("{}:{}", proxy_host, proxy_port);
    let sock_addr: SocketAddr = addr_str
        .to_socket_addrs()
        .map_err(|e| CoreError::ProtocolError(format!("Failed resolving KDC proxy {}: {}", addr_str, e)))?
        .next()
        .ok_or_else(|| CoreError::ProtocolError(format!("No IP resolved for KDC proxy {}", addr_str)))?;

    let stream = TcpStream::connect_timeout(&sock_addr, timeout)
        .map_err(|e| CoreError::IoError(format!("Failed connecting to KDC proxy {}: {}", addr_str, e)))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let mut rx = stream.try_clone().map_err(|e| CoreError::IoError(e.to_string()))?;
    let mut tx = stream;
    send_as_req_kkdcp_over_stream(req, proxy_host, path, &mut rx, &mut tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KrbErrorCode;
    use impacket_core::AdCompatProfile;
    use std::io::Cursor;

    #[test]
    fn test_kkdcp_message_serialization_roundtrip() {
        let fake_as_req = vec![0x6a, 0x10, 0x01, 0x02, 0x03, 0x04];
        let msg = KdcProxyMessage::with_domain(fake_as_req.clone(), "CORP.LOCAL");
        let wire = msg.to_bytes();

        assert_eq!(u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]), 6);
        assert_eq!(&wire[4..], &fake_as_req[..]);

        let parsed = KdcProxyMessage::from_bytes(&wire).unwrap();
        assert_eq!(parsed.kerb_message, fake_as_req);
    }

    #[test]
    fn test_kkdcp_http_request_and_response_roundtrip() {
        let fake_as_req = vec![0x6a, 0x04, 0xAA, 0xBB];
        let msg = KdcProxyMessage::new(fake_as_req);
        let http_bytes = msg.build_http_request("kdcproxy.corp.local", "/KdcProxy");

        let http_str = String::from_utf8_lossy(&http_bytes);
        assert!(http_str.starts_with("POST /KdcProxy HTTP/1.1\r\n"));
        assert!(http_str.contains("Host: kdcproxy.corp.local\r\n"));
        assert!(http_str.contains("Content-Type: application/kerberos\r\n"));
        assert!(http_str.contains("Content-Length: 8\r\n"));

        // Build mock HTTP response containing KRB-ERROR
        let krb_err = KdcAsResponse::build_krb_error_der(
            KrbErrorCode::KDC_ERR_PREAUTH_REQUIRED,
            "CORP.LOCAL",
            false,
        );
        let proxy_reply = KdcProxyMessage::new(krb_err);
        let body = proxy_reply.to_bytes();
        let http_resp = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/kerberos\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        let mut full_resp = http_resp;
        full_resp.extend_from_slice(&body);

        let parsed_msg = parse_http_kkdcp_response(&full_resp).unwrap();
        assert_eq!(parsed_msg.kerb_message.len(), proxy_reply.kerb_message.len());

        let req = Krb5AsReq::new("CORP.LOCAL", "testuser", AdCompatProfile::UniversalAuto);
        let mut rx = Cursor::new(full_resp);
        let mut tx = Vec::new();
        let resp = send_as_req_kkdcp_over_stream(&req, "kdcproxy.corp.local", "/KdcProxy", &mut rx, &mut tx).unwrap();

        match resp {
            KdcAsResponse::Error { error_code, realm } => {
                assert_eq!(error_code, KrbErrorCode::KDC_ERR_PREAUTH_REQUIRED);
                assert_eq!(realm.as_deref(), Some("CORP.LOCAL"));
            }
            _ => panic!("Expected KRB-ERROR"),
        }
    }
}
