//! `server`: Cross-protocol relay target orchestrator and listener coordinator (`impacket/examples/ntlmrelayx`).

use impacket_core::CoreError;
use crate::session::{NtlmRelaySession, RelayProtocol};

/// Configuration of a target service for NTLM authentication relaying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTarget {
    pub protocol: RelayProtocol,
    pub user_filter: Option<String>,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl RelayTarget {
    pub fn new(protocol: RelayProtocol, host: impl Into<String>, port: u16) -> Self {
        Self {
            protocol,
            user_filter: None,
            host: host.into(),
            port,
            path: "/".to_string(),
        }
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user_filter = Some(user.into());
        self
    }

    /// Parses a target URL string like:
    /// - `smb://192.168.1.10`
    /// - `smb://Administrator@192.168.1.10`
    /// - `smb://CONTOSO\Administrator@192.168.1.10`
    /// - `ldap://dc01.corp.local`
    /// - `http://srv01:8080/endpoint`
    /// - `adcs://ca01/certsrv`
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
            "rpc" => RelayProtocol::Rpc,
            "winrm" => RelayProtocol::Winrm,
            "adcs" => RelayProtocol::Adcs,
            other => {
                return Err(CoreError::ProtocolError(format!(
                    "Unsupported relay protocol: {}",
                    other
                )))
            }
        };

        // Separate host:port and path
        let (raw_host_port, path) = if let Some((hp, p)) = rest.split_once('/') {
            (hp, format!("/{}", p))
        } else {
            (rest, "/".to_string())
        };

        // Extract user filter if present (e.g. user@host or DOMAIN\user@host)
        let (user_filter, host_port) = if let Some((user, hp)) = raw_host_port.split_once('@') {
            (Some(user.to_string()), hp)
        } else {
            (None, raw_host_port)
        };

        let (host, port) = if let Some((h, p_str)) = host_port.split_once(':') {
            let port_num: u16 = p_str
                .parse()
                .map_err(|_| CoreError::ProtocolError("Invalid port number".into()))?;
            (h.to_string(), port_num)
        } else {
            let default_port = match protocol {
                RelayProtocol::Http => 80,
                RelayProtocol::Smb => 445,
                RelayProtocol::Ldap => 389,
                RelayProtocol::Mssql => 1433,
                RelayProtocol::Rpc => 135,
                RelayProtocol::Winrm => 5985,
                RelayProtocol::Adcs => 80,
            };
            (host_port.to_string(), default_port)
        };

        Ok(Self {
            protocol,
            user_filter,
            host,
            port,
            path,
        })
    }

    /// Evaluates whether an incoming authenticated user/domain matches this target's filter.
    pub fn matches_user(&self, domain: &str, username: &str) -> bool {
        let Some(filter) = &self.user_filter else {
            return true;
        };

        let filter_clean = filter.trim();
        if filter_clean.is_empty() || filter_clean == "*" {
            return true;
        }

        let full_name = if domain.is_empty() {
            username.to_string()
        } else {
            format!("{}\\{}", domain, username)
        };

        if filter_clean.contains('\\') {
            filter_clean.eq_ignore_ascii_case(&full_name)
        } else {
            filter_clean.eq_ignore_ascii_case(username)
        }
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

    /// Returns the indices of all targets matching the authenticated user and domain.
    pub fn matching_target_indices(&self, domain: &str, username: &str) -> Vec<usize> {
        self.targets
            .iter()
            .enumerate()
            .filter(|(_, target)| target.matches_user(domain, username))
            .map(|(i, _)| i)
            .collect()
    }

    /// Selects the next unexhausted target matching the user.
    pub fn next_target_for_user(
        &self,
        domain: &str,
        username: &str,
        used_indices: &[usize],
    ) -> Option<usize> {
        self.matching_target_indices(domain, username)
            .into_iter()
            .find(|idx| !used_indices.contains(idx))
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
        assert_eq!(t1.user_filter, None);

        let t2 = RelayTarget::parse("ldap://dc01.corp.local:389").unwrap();
        assert_eq!(t2.protocol, RelayProtocol::Ldap);
        assert_eq!(t2.host, "dc01.corp.local");
        assert_eq!(t2.port, 389);

        let t3 = RelayTarget::parse("http://web.corp.local:8080/endpoint").unwrap();
        assert_eq!(t3.protocol, RelayProtocol::Http);
        assert_eq!(t3.host, "web.corp.local");
        assert_eq!(t3.port, 8080);
        assert_eq!(t3.path, "/endpoint");

        let t4 = RelayTarget::parse("rpc://192.168.1.10").unwrap();
        assert_eq!(t4.protocol, RelayProtocol::Rpc);
        assert_eq!(t4.port, 135);

        let t5 = RelayTarget::parse("winrm://srv01.corp.local").unwrap();
        assert_eq!(t5.protocol, RelayProtocol::Winrm);
        assert_eq!(t5.port, 5985);

        let t6 = RelayTarget::parse("adcs://ca01.corp.local/certsrv/certfnsh.asp").unwrap();
        assert_eq!(t6.protocol, RelayProtocol::Adcs);
        assert_eq!(t6.port, 80);
        assert_eq!(t6.path, "/certsrv/certfnsh.asp");
    }

    #[test]
    fn test_relay_target_user_filter_parsing_and_matching() {
        let t1 = RelayTarget::parse(r"smb://CONTOSO\Administrator@192.168.1.50").unwrap();
        assert_eq!(t1.user_filter, Some(r"CONTOSO\Administrator".to_string()));
        assert_eq!(t1.host, "192.168.1.50");
        assert!(t1.matches_user("CONTOSO", "Administrator"));
        assert!(t1.matches_user("contoso", "administrator"));
        assert!(!t1.matches_user("CONTOSO", "Guest"));

        let t2 = RelayTarget::parse("ldap://admin@dc01.corp.local:389").unwrap();
        assert_eq!(t2.user_filter, Some("admin".to_string()));
        assert!(t2.matches_user("ANY_DOMAIN", "admin"));
        assert!(t2.matches_user("", "admin"));
        assert!(!t2.matches_user("ANY_DOMAIN", "user1"));
    }

    #[test]
    fn test_relay_engine_multi_target_user_routing() {
        let targets = vec![
            RelayTarget::parse(r"smb://CORP\Alice@192.168.1.10").unwrap(),
            RelayTarget::parse(r"ldap://Bob@192.168.1.20").unwrap(),
            RelayTarget::parse("http://192.168.1.30").unwrap(), // wildcard
        ];
        let engine = RelayEngine::new(RelayProtocol::Smb, targets);

        // Alice matches target 0 and target 2
        let alice_targets = engine.matching_target_indices("CORP", "Alice");
        assert_eq!(alice_targets, vec![0, 2]);

        // First target for Alice is 0
        let next_0 = engine.next_target_for_user("CORP", "Alice", &[]);
        assert_eq!(next_0, Some(0));

        // When 0 is used, next target for Alice is 2
        let next_1 = engine.next_target_for_user("CORP", "Alice", &[0]);
        assert_eq!(next_1, Some(2));

        // When 0 and 2 are used, exhausted
        let next_none = engine.next_target_for_user("CORP", "Alice", &[0, 2]);
        assert_eq!(next_none, None);

        // Bob matches target 1 and 2
        let bob_targets = engine.matching_target_indices("CORP", "Bob");
        assert_eq!(bob_targets, vec![1, 2]);
    }
}
