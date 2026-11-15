//! `socks`: SOCKS multiplexer and active relayed session pool (`impacket/examples/ntlmrelayx/servers/socksserver.py`).
//!
//! Maintains a registry of active authenticated sessions created through NTLM relaying,
//! enabling post-relay interaction, session switching, and SOCKS proxy dispatching.

use std::sync::atomic::{AtomicU32, Ordering};
use crate::server::RelayTarget;
use crate::session::RelayProtocol;

/// Metadata for an active relayed session held in the SOCKS pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayedSession {
    pub id: u32,
    pub target: RelayTarget,
    pub identity: String,
    pub is_admin: bool,
    pub created_at_unix: u64,
}

impl RelayedSession {
    pub fn new(id: u32, target: RelayTarget, identity: impl Into<String>, is_admin: bool) -> Self {
        Self {
            id,
            target,
            identity: identity.into(),
            is_admin,
            created_at_unix: 0,
        }
    }
}

/// Thread-safe registry and multiplexer pool for relayed sessions.
#[derive(Debug, Default)]
pub struct SocksRelayPool {
    sessions: Vec<RelayedSession>,
    next_id: AtomicU32,
}

impl SocksRelayPool {
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
            next_id: AtomicU32::new(1),
        }
    }

    /// Registers a newly authenticated relayed session into the pool.
    pub fn register_session(
        &mut self,
        target: RelayTarget,
        identity: impl Into<String>,
        is_admin: bool,
    ) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let session = RelayedSession::new(id, target, identity, is_admin);
        self.sessions.push(session);
        id
    }

    /// Returns a reference to a session by ID.
    pub fn get_session(&self, id: u32) -> Option<&RelayedSession> {
        self.sessions.iter().find(|s| s.id == id)
    }

    /// Removes a session from the pool by ID.
    pub fn remove_session(&mut self, id: u32) -> bool {
        let len_before = self.sessions.len();
        self.sessions.retain(|s| s.id != id);
        self.sessions.len() < len_before
    }

    /// Lists all currently active sessions.
    pub fn list_sessions(&self) -> &[RelayedSession] {
        &self.sessions
    }

    /// Finds the first active session matching a given host and username.
    pub fn find_session(&self, host: &str, user: &str) -> Option<&RelayedSession> {
        self.sessions.iter().find(|s| {
            s.target.host.eq_ignore_ascii_case(host) && s.identity.eq_ignore_ascii_case(user)
        })
    }

    /// Formats the session table for interactive CLI output (`sessions` command).
    pub fn format_table(&self) -> String {
        if self.sessions.is_empty() {
            return "No active relayed sessions in SOCKS pool.".to_string();
        }

        let mut out = String::new();
        out.push_str("ID   Protocol  Target                User/Identity                   Admin\n");
        out.push_str("---  --------  --------------------  ------------------------------  -----\n");
        for s in &self.sessions {
            let target_str = format!("{}:{}", s.target.host, s.target.port);
            let admin_str = if s.is_admin { "TRUE" } else { "FALSE" };
            out.push_str(&format!(
                "{:<4} {:<9} {:<21} {:<31} {}\n",
                s.id,
                s.target.protocol.name(),
                target_str,
                s.identity,
                admin_str
            ));
        }
        out
    }
}

/// SOCKS proxy connection dispatch decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksDispatchResult<'a> {
    SessionMatched(&'a RelayedSession),
    NoMatchingSession,
    DirectPassthrough,
}

impl SocksRelayPool {
    /// Evaluates incoming SOCKS destination request against active relayed sessions.
    pub fn dispatch(&self, dest_host: &str, dest_port: u16) -> SocksDispatchResult<'_> {
        let proto = match dest_port {
            445 => RelayProtocol::Smb,
            389 | 636 => RelayProtocol::Ldap,
            1433 => RelayProtocol::Mssql,
            80 | 443 | 8080 => RelayProtocol::Http,
            135 => RelayProtocol::Rpc,
            5985 | 5986 => RelayProtocol::Winrm,
            _ => return SocksDispatchResult::DirectPassthrough,
        };

        if let Some(s) = self
            .sessions
            .iter()
            .find(|s| s.target.protocol == proto && s.target.host.eq_ignore_ascii_case(dest_host))
        {
            SocksDispatchResult::SessionMatched(s)
        } else {
            SocksDispatchResult::NoMatchingSession
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks_pool_lifecycle() {
        let mut pool = SocksRelayPool::new();
        let t1 = RelayTarget::parse("smb://10.0.0.1").unwrap();
        let id1 = pool.register_session(t1, "CORP\\admin", true);
        assert_eq!(id1, 1);

        let t2 = RelayTarget::parse("mssql://10.0.0.2").unwrap();
        let id2 = pool.register_session(t2, "CORP\\sql_svc", false);
        assert_eq!(id2, 2);

        assert_eq!(pool.list_sessions().len(), 2);
        assert!(pool.get_session(id1).unwrap().is_admin);
        assert!(!pool.get_session(id2).unwrap().is_admin);

        let table = pool.format_table();
        assert!(table.contains("CORP\\admin"));
        assert!(table.contains("CORP\\sql_svc"));
        assert!(table.contains("SMB"));
        assert!(table.contains("MSSQL"));

        assert!(pool.remove_session(id1));
        assert_eq!(pool.list_sessions().len(), 1);
        assert!(pool.get_session(id1).is_none());
    }

    #[test]
    fn test_socks_dispatch_matching() {
        let mut pool = SocksRelayPool::new();
        let t1 = RelayTarget::parse("smb://192.168.1.50").unwrap();
        pool.register_session(t1, "CORP\\dc01$", true);

        // Matching target
        match pool.dispatch("192.168.1.50", 445) {
            SocksDispatchResult::SessionMatched(s) => {
                assert_eq!(s.identity, "CORP\\dc01$");
            }
            _ => panic!("Expected matched session"),
        }

        // Port with no registered session
        match pool.dispatch("192.168.1.50", 1433) {
            SocksDispatchResult::NoMatchingSession => {}
            _ => panic!("Expected NoMatchingSession"),
        }

        // Unrelated port
        match pool.dispatch("8.8.8.8", 53) {
            SocksDispatchResult::DirectPassthrough => {}
            _ => panic!("Expected DirectPassthrough"),
        }
    }
}
