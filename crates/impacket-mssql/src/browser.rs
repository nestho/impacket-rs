//! `browser`: `[MC-SQLR]` SQL Server Resolution Protocol client (`impacket/examples/mssqlinstance.py`).
//!
//! Queries the Microsoft SQL Server Browser Service over UDP port 1434 to discover
//! running MSSQL instances, instance names, cluster configurations, versions, and TCP ports.

use impacket_core::CoreError;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

pub const SQLR_DEFAULT_PORT: u16 = 1434;
pub const CLNT_UCAST_EX: u8 = 0x02;
pub const CLNT_UCAST_INST: u8 = 0x03;
pub const SVR_RESP: u8 = 0x05;

/// An SQL Server instance discovered via SQL Server Resolution Protocol (`[MC-SQLR]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlBrowserInstance {
    pub server_name: String,
    pub instance_name: String,
    pub is_clustered: bool,
    pub version: String,
    pub tcp_port: Option<u16>,
    pub named_pipe: Option<String>,
    pub raw_properties: HashMap<String, String>,
}

/// Parses an `[MC-SQLR]` `SVR_RESP` packet (0x05 + 2-byte length + semicolon-delimited string).
pub fn parse_sql_browser_response(data: &[u8]) -> Result<Vec<SqlBrowserInstance>, CoreError> {
    if data.is_empty() {
        return Err(CoreError::BufferUnderflow { needed: 3, available: 0 });
    }
    if data[0] != SVR_RESP {
        return Err(CoreError::ProtocolError(format!(
            "Invalid SQL Browser response token {:#x} (expected 0x05)",
            data[0]
        )));
    }
    if data.len() < 3 {
        return Err(CoreError::BufferUnderflow { needed: 3, available: data.len() });
    }
    let resp_len = u16::from_le_bytes([data[1], data[2]]) as usize;
    let payload = if data.len() >= 3 + resp_len {
        &data[3..3 + resp_len]
    } else {
        &data[3..]
    };

    let text = std::str::from_utf8(payload)
        .map_err(|e| CoreError::ProtocolError(format!("Invalid UTF-8 in SQL Browser response: {}", e)))?;

    parse_sql_browser_text(text)
}

/// Parses semicolon-delimited instance text from `[MC-SQLR]`.
pub fn parse_sql_browser_text(text: &str) -> Result<Vec<SqlBrowserInstance>, CoreError> {
    let mut instances = Vec::new();
    // Double semicolon or separate instance blocks
    let tokens: Vec<&str> = text.split(';').collect();
    let mut current_map: HashMap<String, String> = HashMap::new();

    let mut i = 0;
    while i + 1 < tokens.len() {
        let key = tokens[i].trim();
        let val = tokens[i + 1].trim();
        if key.is_empty() {
            i += 1;
            continue;
        }

        // When a new ServerName appears and we already have fields, push current instance
        if key.eq_ignore_ascii_case("ServerName") && !current_map.is_empty() {
            if let Some(inst) = instance_from_map(&current_map) {
                instances.push(inst);
            }
            current_map.clear();
        }

        current_map.insert(key.to_string(), val.to_string());
        i += 2;
    }

    if !current_map.is_empty() {
        if let Some(inst) = instance_from_map(&current_map) {
            instances.push(inst);
        }
    }

    Ok(instances)
}

fn instance_from_map(map: &HashMap<String, String>) -> Option<SqlBrowserInstance> {
    let server_name = map.get("ServerName").cloned().unwrap_or_default();
    let instance_name = map.get("InstanceName").cloned().unwrap_or_else(|| "MSSQLSERVER".to_string());
    let is_clustered = map
        .get("IsClustered")
        .map(|v| v.eq_ignore_ascii_case("Yes") || v == "1")
        .unwrap_or(false);
    let version = map.get("Version").cloned().unwrap_or_default();
    let tcp_port = map.get("tcp").and_then(|p| p.parse::<u16>().ok());
    let named_pipe = map.get("np").cloned();

    Some(SqlBrowserInstance {
        server_name,
        instance_name,
        is_clustered,
        version,
        tcp_port,
        named_pipe,
        raw_properties: map.clone(),
    })
}

/// Sends a CLNT_UCAST_EX probe over UDP to `host:port` and returns discovered SQL Server instances.
pub fn query_sql_instances_udp(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<SqlBrowserInstance>, CoreError> {
    let addr_str = format!("{}:{}", host, port);
    let remote_addr: SocketAddr = addr_str
        .to_socket_addrs()
        .map_err(|e| CoreError::ProtocolError(format!("Failed resolving {}: {}", addr_str, e)))?
        .next()
        .ok_or_else(|| CoreError::ProtocolError(format!("No address found for {}", addr_str)))?;

    let bind_addr = if remote_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let socket = UdpSocket::bind(bind_addr)
        .map_err(|e| CoreError::ProtocolError(format!("Failed binding UDP socket: {}", e)))?;

    socket.set_read_timeout(Some(timeout)).ok();
    socket.set_write_timeout(Some(timeout)).ok();

    // Send CLNT_UCAST_EX (0x02)
    socket
        .send_to(&[CLNT_UCAST_EX], remote_addr)
        .map_err(|e| CoreError::ProtocolError(format!("Failed sending SQL Browser probe: {}", e)))?;

    let mut buf = vec![0u8; 4096];
    let (n, _) = socket
        .recv_from(&mut buf)
        .map_err(|e| CoreError::ProtocolError(format!("Timeout waiting for SQL Browser reply: {}", e)))?;

    buf.truncate(n);
    parse_sql_browser_response(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sql_browser_response_single_instance() {
        let text = "ServerName;DC01;InstanceName;SQLEXPRESS;IsClustered;No;Version;15.0.2000.5;tcp;1433;np;\\\\DC01\\pipe\\MSSQL$SQLEXPRESS\\sql\\query;;";
        let text_bytes = text.as_bytes();
        let mut pkt = Vec::new();
        pkt.push(SVR_RESP);
        pkt.extend_from_slice(&(text_bytes.len() as u16).to_le_bytes());
        pkt.extend_from_slice(text_bytes);

        let instances = parse_sql_browser_response(&pkt).unwrap();
        assert_eq!(instances.len(), 1);
        let inst = &instances[0];
        assert_eq!(inst.server_name, "DC01");
        assert_eq!(inst.instance_name, "SQLEXPRESS");
        assert!(!inst.is_clustered);
        assert_eq!(inst.version, "15.0.2000.5");
        assert_eq!(inst.tcp_port, Some(1433));
        assert_eq!(
            inst.named_pipe.as_deref(),
            Some(r"\\DC01\pipe\MSSQL$SQLEXPRESS\sql\query")
        );
    }

    #[test]
    fn test_parse_sql_browser_multiple_instances() {
        let text = "ServerName;PROD01;InstanceName;MSSQLSERVER;IsClustered;Yes;Version;14.0.1000.169;tcp;1433;;ServerName;PROD01;InstanceName;ANALYTICS;IsClustered;No;Version;14.0.1000.169;tcp;1435;;";
        let instances = parse_sql_browser_text(text).unwrap();
        assert_eq!(instances.len(), 2);
        assert_eq!(instances[0].instance_name, "MSSQLSERVER");
        assert!(instances[0].is_clustered);
        assert_eq!(instances[0].tcp_port, Some(1433));
        assert_eq!(instances[1].instance_name, "ANALYTICS");
        assert!(!instances[1].is_clustered);
        assert_eq!(instances[1].tcp_port, Some(1435));
    }
}
