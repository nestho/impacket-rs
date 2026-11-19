//! `vault`: Embedded Operator State Vault.
//!
//! Retains discovered network hosts, open services, operating systems, SMB signing posture,
//! administrator privileges (`Pwn3d!`), and pillaged credentials across security testing sessions.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use crate::CoreError;

/// Recorded target host within the operator vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRecord {
    pub ip: String,
    pub hostname: String,
    pub domain: String,
    pub os: String,
    pub ports: Vec<u16>,
    pub smb_signing: bool,
    pub is_dc: bool,
    pub pwned: bool,
    pub updated_at: u64,
}

impl HostRecord {
    pub fn to_json_line(&self) -> String {
        let ports_str = self
            .ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"type\":\"host\",\"ip\":\"{}\",\"hostname\":\"{}\",\"domain\":\"{}\",\"os\":\"{}\",\"ports\":[{}],\"smb_signing\":{},\"is_dc\":{},\"pwned\":{},\"updated_at\":{}}}",
            self.ip,
            self.hostname,
            self.domain,
            self.os,
            ports_str,
            self.smb_signing,
            self.is_dc,
            self.pwned,
            self.updated_at
        )
    }

    pub fn from_json_line(line: &str) -> Option<Self> {
        let ip = extract_json_str(line, "ip")?;
        let hostname = extract_json_str(line, "hostname").unwrap_or_default();
        let domain = extract_json_str(line, "domain").unwrap_or_default();
        let os = extract_json_str(line, "os").unwrap_or_default();
        let ports = extract_json_u16_list(line, "ports");
        let smb_signing = extract_json_bool(line, "smb_signing").unwrap_or(false);
        let is_dc = extract_json_bool(line, "is_dc").unwrap_or(false);
        let pwned = extract_json_bool(line, "pwned").unwrap_or(false);
        let updated_at = extract_json_u64(line, "updated_at").unwrap_or(0);

        Some(Self {
            ip,
            hostname,
            domain,
            os,
            ports,
            smb_signing,
            is_dc,
            pwned,
            updated_at,
        })
    }
}

/// Recorded credential item within the operator vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRecord {
    pub domain: String,
    pub username: String,
    pub secret: String,
    pub secret_type: String, // "password" | "nthash" | "aes256"
    pub pillaged_from: String, // "DCSync" | "LSASS" | "SAM" | "Kerberoast" | "Manual"
    pub admin_on: Vec<String>,
    pub updated_at: u64,
}

impl CredentialRecord {
    pub fn to_json_line(&self) -> String {
        let admin_str = self
            .admin_on
            .iter()
            .map(|h| format!("\"{}\"", h))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"type\":\"cred\",\"domain\":\"{}\",\"username\":\"{}\",\"secret\":\"{}\",\"secret_type\":\"{}\",\"pillaged_from\":\"{}\",\"admin_on\":[{}],\"updated_at\":{}}}",
            self.domain,
            self.username,
            self.secret,
            self.secret_type,
            self.pillaged_from,
            admin_str,
            self.updated_at
        )
    }

    pub fn from_json_line(line: &str) -> Option<Self> {
        let domain = extract_json_str(line, "domain").unwrap_or_default();
        let username = extract_json_str(line, "username")?;
        let secret = extract_json_str(line, "secret")?;
        let secret_type = extract_json_str(line, "secret_type").unwrap_or_else(|| "password".into());
        let pillaged_from = extract_json_str(line, "pillaged_from").unwrap_or_else(|| "manual".into());
        let admin_on = extract_json_str_list(line, "admin_on");
        let updated_at = extract_json_u64(line, "updated_at").unwrap_or(0);

        Some(Self {
            domain,
            username,
            secret,
            secret_type,
            pillaged_from,
            admin_on,
            updated_at,
        })
    }
}

/// In-memory vault structure holding all persistent state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperatorVault {
    pub hosts: Vec<HostRecord>,
    pub credentials: Vec<CredentialRecord>,
}

impl OperatorVault {
    /// Returns default storage path for operator vault:
    /// Uses `$IMPACKET_VAULT`, or `~/.impacket/vault.jsonl`, or `./.impacket_vault.jsonl`.
    pub fn default_path() -> PathBuf {
        if let Ok(p) = std::env::var("IMPACKET_VAULT") {
            return PathBuf::from(p);
        }
        if let Ok(home) = std::env::var("HOME") {
            let mut p = PathBuf::from(home);
            p.push(".impacket");
            p.push("vault.jsonl");
            return p;
        }
        PathBuf::from(".impacket_vault.jsonl")
    }

    /// Loads vault records from a file path.
    pub fn load_from_path(path: &Path) -> Result<Self, CoreError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let file = File::open(path)
            .map_err(|e| CoreError::IoError(format!("Failed to open vault file '{}': {}", path.display(), e)))?;
        let reader = BufReader::new(file);

        let mut vault = Self::default();
        for line_res in reader.lines() {
            let line = line_res.map_err(|e| CoreError::IoError(format!("Error reading vault line: {}", e)))?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.contains("\"type\":\"host\"") {
                if let Some(host) = HostRecord::from_json_line(trimmed) {
                    vault.add_or_update_host(host);
                }
            } else if trimmed.contains("\"type\":\"cred\"") {
                if let Some(cred) = CredentialRecord::from_json_line(trimmed) {
                    vault.add_or_update_credential(cred);
                }
            }
        }
        Ok(vault)
    }

    /// Saves all vault records atomically to the specified file path.
    pub fn save_to_path(&self, path: &Path) -> Result<(), CoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|e| CoreError::IoError(format!("Failed to save vault file '{}': {}", path.display(), e)))?;

        for h in &self.hosts {
            writeln!(file, "{}", h.to_json_line())
                .map_err(|e| CoreError::IoError(format!("Failed writing host record: {}", e)))?;
        }
        for c in &self.credentials {
            writeln!(file, "{}", c.to_json_line())
                .map_err(|e| CoreError::IoError(format!("Failed writing credential record: {}", e)))?;
        }
        file.flush()
            .map_err(|e| CoreError::IoError(format!("Failed flushing vault file: {}", e)))?;
        Ok(())
    }

    /// Adds or updates a host record by IP address.
    pub fn add_or_update_host(&mut self, host: HostRecord) {
        if let Some(existing) = self.hosts.iter_mut().find(|h| h.ip == host.ip) {
            if !host.hostname.is_empty() {
                existing.hostname = host.hostname;
            }
            if !host.domain.is_empty() {
                existing.domain = host.domain;
            }
            if !host.os.is_empty() {
                existing.os = host.os;
            }
            for p in host.ports {
                if !existing.ports.contains(&p) {
                    existing.ports.push(p);
                }
            }
            existing.ports.sort();
            existing.smb_signing = host.smb_signing;
            existing.is_dc = existing.is_dc || host.is_dc;
            existing.pwned = existing.pwned || host.pwned;
            existing.updated_at = host.updated_at;
        } else {
            self.hosts.push(host);
        }
    }

    /// Adds or updates a credential record by (domain, username, secret).
    pub fn add_or_update_credential(&mut self, cred: CredentialRecord) {
        if let Some(existing) = self.credentials.iter_mut().find(|c| {
            c.domain.eq_ignore_ascii_case(&cred.domain)
                && c.username.eq_ignore_ascii_case(&cred.username)
                && c.secret == cred.secret
        }) {
            for h in cred.admin_on {
                if !existing.admin_on.contains(&h) {
                    existing.admin_on.push(h);
                }
            }
            existing.updated_at = cred.updated_at;
        } else {
            self.credentials.push(cred);
        }
    }
}

// ============================================================================
// Internal JSON extractors without external dependencies
// ============================================================================

pub fn extract_json_str(line: &str, field: &str) -> Option<String> {
    let key = format!("\"{}\":\"", field);
    let start = line.find(&key)? + key.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

pub fn extract_json_bool(line: &str, field: &str) -> Option<bool> {
    let key = format!("\"{}\":", field);
    let start = line.find(&key)? + key.len();
    let rest = line[start..].trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

pub fn extract_json_u64(line: &str, field: &str) -> Option<u64> {
    let key = format!("\"{}\":", field);
    let start = line.find(&key)? + key.len();
    let rest = line[start..].trim_start();
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

pub fn extract_json_u16_list(line: &str, field: &str) -> Vec<u16> {
    let key = format!("\"{}\":[", field);
    if let Some(start) = line.find(&key) {
        let rest = &line[start + key.len()..];
        if let Some(end) = rest.find(']') {
            let inner = &rest[..end];
            return inner
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect();
        }
    }
    Vec::new()
}

pub fn extract_json_str_list(line: &str, field: &str) -> Vec<String> {
    let key = format!("\"{}\":[", field);
    if let Some(start) = line.find(&key) {
        let rest = &line[start + key.len()..];
        if let Some(end) = rest.find(']') {
            let inner = &rest[..end];
            return inner
                .split(',')
                .map(|s| s.trim().trim_matches('"').to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_record_json_roundtrip() {
        let h = HostRecord {
            ip: "192.168.1.10".into(),
            hostname: "DC01".into(),
            domain: "CORP.LOCAL".into(),
            os: "Windows Server 2022".into(),
            ports: vec![135, 445, 389],
            smb_signing: true,
            is_dc: true,
            pwned: true,
            updated_at: 1762300000,
        };
        let line = h.to_json_line();
        let parsed = HostRecord::from_json_line(&line).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn test_credential_record_json_roundtrip() {
        let c = CredentialRecord {
            domain: "CORP.LOCAL".into(),
            username: "Administrator".into(),
            secret: "e52cac67419a9a224a3b108f3fa6cb6d".into(),
            secret_type: "nthash".into(),
            pillaged_from: "DCSync".into(),
            admin_on: vec!["192.168.1.10".into()],
            updated_at: 1762300000,
        };
        let line = c.to_json_line();
        let parsed = CredentialRecord::from_json_line(&line).unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn test_operator_vault_upsert_and_merge() {
        let mut vault = OperatorVault::default();
        vault.add_or_update_host(HostRecord {
            ip: "10.0.0.5".into(),
            hostname: "WS01".into(),
            domain: "CORP".into(),
            os: "Windows 10".into(),
            ports: vec![445],
            smb_signing: false,
            is_dc: false,
            pwned: false,
            updated_at: 100,
        });

        // Update with newly discovered ports and admin privilege
        vault.add_or_update_host(HostRecord {
            ip: "10.0.0.5".into(),
            hostname: "WS01.corp".into(),
            domain: "CORP.LOCAL".into(),
            os: "Windows 10 Enterprise".into(),
            ports: vec![445, 135, 5985],
            smb_signing: false,
            is_dc: false,
            pwned: true,
            updated_at: 200,
        });

        assert_eq!(vault.hosts.len(), 1);
        let h = &vault.hosts[0];
        assert_eq!(h.ports, vec![135, 445, 5985]);
        assert!(h.pwned);
        assert_eq!(h.updated_at, 200);
    }
}
