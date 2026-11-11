//! `server`: Cross-protocol relay target orchestrator and listener coordinator (`impacket/examples/ntlmrelayx`).

use impacket_core::CoreError;
use crate::session::{NtlmRelaySession, RelayProtocol};

/// Configuration of a target service for NTLM authentication relaying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTarget {
    pub protocol: RelayProtocol,
    pub host: String,
    pub port: u16,
}

impl RelayTarget {
    pub fn new(protocol: RelayProtocol, host: impl Into<String>, port: u16) -> Self {
        Self {
            protocol,
            host: host.into(),
            port,
        }
    }

    /// Parses a target URL string like `smb://192.168.1.10`, `ldap://dc01.corp.local`, `http://srv01`.
    pub fn parse(url: &str) -> Result<Self, CoreError> {
        let trimmed = url.trim();
        let (proto, rest) = if let Some((p, r)) = trimmed.split_once("://") {
            (p, r)
        } else {
            ("smb", trimmed)
        };

        let protocol = match proto.to_lowercase().as_str() {
            "http" => RelayProtocol::Http,
            "smb" => RelayProtocol::Smb,
            "ldap" => RelayProtocol::Ldap,
            "mssql" => RelayProtocol::Mssql,
            other => {
                return Err(CoreError::ProtocolError(format!(
                    "Unsupported relay protocol: {}",
                    other
                )))
            }
        };

        let (host, port) = if let Some((h, p_str)) = rest.split_once(':') {
            let port_num: u16 = p_str
                .split('/')
                .next()
                .unwrap_or(p_str)
                .parse()
                .map_err(|_| CoreError::ProtocolError("Invalid port number".into()))?;
            (h.to_string(), port_num)
        } else {
            let default_port = match protocol {
                RelayProtocol::Http => 80,
                RelayProtocol::Smb => 445,
                RelayProtocol::Ldap => 389,
                RelayProtocol::Mssql => 1433,
            };
            let h = rest.split('/').next().unwrap_or(rest);
            (h.to_string(), default_port)
        };

        Ok(Self {
            protocol,
            host,
            port,
        })
    }
}

/// Orchestrator for incoming connections and target relay sessions.
#[derive(Debug, Clone)]
pub struct RelayEngine {
    pub targets: Vec<RelayTarget>,
    pub listen_protocol: RelayProtocol,
    pub remove_mic: bool,
    pub remove_channel_bindings: bool,
}

impl RelayEngine {
    pub fn new(listen_protocol: RelayProtocol, targets: Vec<RelayTarget>) -> Self {
        Self {
            targets,
            listen_protocol,
            remove_mic: true,
            remove_channel_bindings: true,
        }
    }

    /// Creates a new relay session for an incoming client targeting the next available target.
    pub fn create_session(&self, target_index: usize) -> Result<NtlmRelaySession, CoreError> {
        let target = self
            .targets
            .get(target_index)
            .ok_or_else(|| CoreError::ProtocolError("No relay target available".into()))?;

        let mut session = NtlmRelaySession::new(self.listen_protocol, target.protocol);
        session.strip_mic = self.remove_mic;
        session.strip_channel_bindings = self.remove_channel_bindings;
        Ok(session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_target_url_parser() {
        let t1 = RelayTarget::parse("smb://10.0.0.1").unwrap();
        assert_eq!(t1.protocol, RelayProtocol::Smb);
        assert_eq!(t1.host, "10.0.0.1");
        assert_eq!(t1.port, 445);

        let t2 = RelayTarget::parse("ldap://dc01.corp.local:389").unwrap();
        assert_eq!(t2.protocol, RelayProtocol::Ldap);
        assert_eq!(t2.host, "dc01.corp.local");
        assert_eq!(t2.port, 389);

        let t3 = RelayTarget::parse("http://web.corp.local:8080/endpoint").unwrap();
        assert_eq!(t3.protocol, RelayProtocol::Http);
        assert_eq!(t3.host, "web.corp.local");
        assert_eq!(t3.port, 8080);
    }

    #[test]
    fn test_relay_engine_session_creation() {
        let targets = vec![
            RelayTarget::parse("smb://192.168.1.10").unwrap(),
            RelayTarget::parse("ldap://192.168.1.2").unwrap(),
        ];
        let engine = RelayEngine::new(RelayProtocol::Http, targets);
        let s0 = engine.create_session(0).unwrap();
        assert_eq!(s0.client_protocol, RelayProtocol::Http);
        assert_eq!(s0.target_protocol, RelayProtocol::Smb);

        let s1 = engine.create_session(1).unwrap();
        assert_eq!(s1.client_protocol, RelayProtocol::Http);
        assert_eq!(s1.target_protocol, RelayProtocol::Ldap);
    }
}
