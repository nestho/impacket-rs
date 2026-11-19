//! High-concurrency Active Directory multi-protocol port prober.
//!
//! Scans targets for open Windows/AD protocol ports (SMB, RPC, LDAP, LDAPS, Kerberos,
//! MSSQL, WinRM, ADWS) across large CIDR blocks using a worker pool with zero external dependencies.

use std::fmt;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::net::TargetList;

/// Standard Active Directory and Windows Enterprise Ports.
pub mod ports {
    pub const SMB: u16 = 445;
    pub const RPC: u16 = 135;
    pub const LDAP: u16 = 389;
    pub const LDAPS: u16 = 636;
    pub const KERBEROS: u16 = 88;
    pub const MSSQL: u16 = 1433;
    pub const WINRM_HTTP: u16 = 5985;
    pub const WINRM_HTTPS: u16 = 5986;
    pub const ADWS: u16 = 9389;

    /// Default ports scanned during Active Directory network discovery.
    pub const AD_DEFAULT_PORTS: [u16; 9] = [
        SMB, RPC, LDAP, LDAPS, KERBEROS, MSSQL, WINRM_HTTP, WINRM_HTTPS, ADWS,
    ];

    /// Returns human-readable protocol label for a port.
    pub fn port_label(port: u16) -> &'static str {
        match port {
            SMB => "SMB",
            RPC => "MSRPC",
            LDAP => "LDAP",
            LDAPS => "LDAPS",
            KERBEROS => "Kerberos",
            MSSQL => "MSSQL",
            WINRM_HTTP => "WinRM-HTTP",
            WINRM_HTTPS => "WinRM-HTTPS",
            ADWS => "ADWS",
            _ => "Unknown",
        }
    }
}

/// Configuration parameters for the multi-protocol prober.
#[derive(Debug, Clone)]
pub struct ProberConfig {
    /// Ports to probe per target.
    pub ports: Vec<u16>,
    /// Connection timeout per port attempt.
    pub timeout: Duration,
    /// Number of concurrent worker threads.
    pub concurrency: usize,
}

impl Default for ProberConfig {
    fn default() -> Self {
        Self {
            ports: ports::AD_DEFAULT_PORTS.to_vec(),
            timeout: Duration::from_millis(500),
            concurrency: 100,
        }
    }
}

impl ProberConfig {
    /// Create config with custom ports and timeout.
    pub fn new(ports: Vec<u16>, timeout_ms: u64, concurrency: usize) -> Self {
        Self {
            ports,
            timeout: Duration::from_millis(timeout_ms),
            concurrency: concurrency.clamp(1, 1000),
        }
    }
}

/// A discovered live network host with open Active Directory / Windows ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredHost {
    pub ip: IpAddr,
    pub open_ports: Vec<u16>,
    pub rtt_ms: u64,
}

impl DiscoveredHost {
    /// True if the host is likely a Domain Controller (Kerberos or LDAP open).
    #[inline]
    pub fn is_domain_controller(&self) -> bool {
        self.open_ports.contains(&ports::KERBEROS) || self.open_ports.contains(&ports::LDAP)
    }

    /// True if SMB (TCP 445) is open.
    #[inline]
    pub fn has_smb(&self) -> bool {
        self.open_ports.contains(&ports::SMB)
    }

    /// True if MSRPC (TCP 135) is open.
    #[inline]
    pub fn has_rpc(&self) -> bool {
        self.open_ports.contains(&ports::RPC)
    }

    /// True if LDAP or LDAPS is open.
    #[inline]
    pub fn has_ldap(&self) -> bool {
        self.open_ports.contains(&ports::LDAP) || self.open_ports.contains(&ports::LDAPS)
    }

    /// True if WinRM (5985 or 5986) is open.
    #[inline]
    pub fn has_winrm(&self) -> bool {
        self.open_ports.contains(&ports::WINRM_HTTP)
            || self.open_ports.contains(&ports::WINRM_HTTPS)
    }

    /// True if MSSQL (1433) is open.
    #[inline]
    pub fn has_mssql(&self) -> bool {
        self.open_ports.contains(&ports::MSSQL)
    }
}

impl fmt::Display for DiscoveredHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ports_str: Vec<String> = self
            .open_ports
            .iter()
            .map(|&p| format!("{}:{}", p, ports::port_label(p)))
            .collect();

        let dc_tag = if self.is_domain_controller() {
            " [Domain Controller]"
        } else {
            ""
        };

        write!(
            f,
            "{:<15} ({:>3}ms) -> [{}] {}",
            self.ip,
            self.rtt_ms,
            ports_str.join(", "),
            dc_tag
        )
    }
}

/// Probe a single IP address across the specified ports.
pub fn probe_host(ip: IpAddr, target_ports: &[u16], timeout: Duration) -> Option<DiscoveredHost> {
    let mut open_ports = Vec::new();
    let start = Instant::now();

    for &port in target_ports {
        let addr = SocketAddr::new(ip, port);
        if let Ok(_stream) = TcpStream::connect_timeout(&addr, timeout) {
            open_ports.push(port);
        }
    }

    if open_ports.is_empty() {
        None
    } else {
        Some(DiscoveredHost {
            ip,
            open_ports,
            rtt_ms: start.elapsed().as_millis() as u64,
        })
    }
}

/// Scan a list of IP targets using a high-concurrency worker pool.
pub fn probe_targets(targets: &TargetList, config: &ProberConfig) -> Vec<DiscoveredHost> {
    let all_ips: Vec<IpAddr> = targets.iter().collect();
    if all_ips.is_empty() {
        return Vec::new();
    }

    let ip_index = Arc::new(AtomicUsize::new(0));
    let total_ips = all_ips.len();
    let all_ips = Arc::new(all_ips);
    let ports = Arc::new(config.ports.clone());
    let timeout = config.timeout;

    let worker_count = config.concurrency.min(total_ips);
    let (tx, rx) = channel();

    thread::scope(|s| {
        for _ in 0..worker_count {
            let tx = tx.clone();
            let all_ips = Arc::clone(&all_ips);
            let ip_index = Arc::clone(&ip_index);
            let ports = Arc::clone(&ports);

            s.spawn(move || loop {
                let idx = ip_index.fetch_add(1, Ordering::Relaxed);
                if idx >= total_ips {
                    break;
                }
                let ip = all_ips[idx];
                if let Some(host) = probe_host(ip, &ports, timeout) {
                    let _ = tx.send(host);
                }
            });
        }
        drop(tx);
    });

    let mut results = Vec::new();
    while let Ok(host) = rx.recv() {
        results.push(host);
    }

    results.sort_by_key(|h| match h.ip {
        IpAddr::V4(v4) => (0, u128::from(u32::from(v4))),
        IpAddr::V6(v6) => (1, u128::from(v6)),
    });

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_ports_label() {
        assert_eq!(ports::port_label(445), "SMB");
        assert_eq!(ports::port_label(135), "MSRPC");
        assert_eq!(ports::port_label(88), "Kerberos");
        assert_eq!(ports::port_label(389), "LDAP");
        assert_eq!(ports::port_label(1433), "MSSQL");
    }

    #[test]
    fn test_probe_host_live_mock() {
        // Bind an ephemeral TCP listener on 127.0.0.1
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Get a port that is definitely closed by binding and dropping
        let closed_port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };

        let host = probe_host(
            "127.0.0.1".parse().unwrap(),
            &[port, closed_port],
            Duration::from_millis(300),
        )
        .expect("should find open port");

        assert!(host.open_ports.contains(&port));
        assert!(!host.open_ports.contains(&closed_port));
        assert_eq!(host.ip, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_probe_targets_with_mock() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let closed_port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };

        let targets = TargetList::parse("127.0.0.1").unwrap();
        let config = ProberConfig {
            ports: vec![port, closed_port],
            timeout: Duration::from_millis(200),
            concurrency: 4,
        };

        let results = probe_targets(&targets, &config);
        assert_eq!(results.len(), 1);
        assert!(results[0].open_ports.contains(&port));
        assert!(!results[0].open_ports.contains(&closed_port));
    }
}
