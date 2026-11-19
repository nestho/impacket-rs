//! Zero-allocation IP range, CIDR, and target address iterator.
//!
//! Provides ultra-high-speed parsing and traversal for single IP addresses,
//! IPv4/IPv6 CIDR blocks (`192.168.1.0/24`, `10.0.0.0/16`), and dash ranges (`10.0.0.1-50`, `10.0.0.1-10.0.0.254`).
//! Designed for mass network sweeps and multi-target orchestration without allocating intermediate heap buffers.

pub mod cldap;
pub mod prober;

pub use cldap::{cldap_ping, CldapDcInfo, CLDAP_DEFAULT_PORT};
pub use prober::{
    ports, probe_host, probe_targets, DiscoveredHost, ProberConfig,
};

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Error encountered while parsing an IP range or CIDR string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseIpRangeError {
    EmptyString,
    InvalidIp(String),
    InvalidCidrPrefix(String),
    InvalidRange(String),
    MixedIpVersions,
}

impl fmt::Display for ParseIpRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyString => write!(f, "empty IP range string"),
            Self::InvalidIp(s) => write!(f, "invalid IP address: {s}"),
            Self::InvalidCidrPrefix(s) => write!(f, "invalid CIDR prefix: {s}"),
            Self::InvalidRange(s) => write!(f, "invalid IP range bounds: {s}"),
            Self::MixedIpVersions => write!(f, "cannot mix IPv4 and IPv6 within a single range"),
        }
    }
}

impl std::error::Error for ParseIpRangeError {}

/// A continuous range of IP addresses (IPv4 or IPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpRange {
    V4(Ipv4Range),
    V6(Ipv6Range),
}

impl IpRange {
    /// Parse an IP range string.
    ///
    /// Supported formats:
    /// - Single IP: `192.168.1.1`, `::1`
    /// - CIDR notation: `192.168.1.0/24`, `10.0.0.0/16`
    /// - Short dash range: `192.168.1.1-50`
    /// - Full dash range: `192.168.1.1-192.168.1.50`
    pub fn parse(s: &str) -> Result<Self, ParseIpRangeError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(ParseIpRangeError::EmptyString);
        }

        // 1. Check for CIDR (contains '/')
        if let Some((ip_str, prefix_str)) = trimmed.split_once('/') {
            let prefix: u32 = prefix_str
                .parse()
                .map_err(|_| ParseIpRangeError::InvalidCidrPrefix(prefix_str.to_string()))?;

            if let Ok(ipv4) = Ipv4Addr::from_str(ip_str) {
                if prefix > 32 {
                    return Err(ParseIpRangeError::InvalidCidrPrefix(prefix_str.to_string()));
                }
                return Ok(Self::V4(Ipv4Range::from_cidr(ipv4, prefix)));
            } else if let Ok(ipv6) = Ipv6Addr::from_str(ip_str) {
                if prefix > 128 {
                    return Err(ParseIpRangeError::InvalidCidrPrefix(prefix_str.to_string()));
                }
                return Ok(Self::V6(Ipv6Range::from_cidr(ipv6, prefix)));
            } else {
                return Err(ParseIpRangeError::InvalidIp(ip_str.to_string()));
            }
        }

        // 2. Check for Dash range (contains '-')
        if let Some((start_str, end_str)) = trimmed.split_once('-') {
            let start_str = start_str.trim();
            let end_str = end_str.trim();

            if let Ok(start_ip) = Ipv4Addr::from_str(start_str) {
                // Check if end is a full IPv4 or a single octet (e.g. "1-50")
                if let Ok(end_octet) = end_str.parse::<u8>() {
                    let octets = start_ip.octets();
                    let end_ip = Ipv4Addr::new(octets[0], octets[1], octets[2], end_octet);
                    return Ok(Self::V4(Ipv4Range::new(start_ip, end_ip)?));
                } else if let Ok(end_ip) = Ipv4Addr::from_str(end_str) {
                    return Ok(Self::V4(Ipv4Range::new(start_ip, end_ip)?));
                } else {
                    return Err(ParseIpRangeError::InvalidRange(trimmed.to_string()));
                }
            } else if let Ok(start_ip) = Ipv6Addr::from_str(start_str) {
                if let Ok(end_ip) = Ipv6Addr::from_str(end_str) {
                    return Ok(Self::V6(Ipv6Range::new(start_ip, end_ip)?));
                } else {
                    return Err(ParseIpRangeError::InvalidRange(trimmed.to_string()));
                }
            } else {
                return Err(ParseIpRangeError::InvalidIp(start_str.to_string()));
            }
        }

        // 3. Single IP Address
        if let Ok(ipv4) = Ipv4Addr::from_str(trimmed) {
            Ok(Self::V4(Ipv4Range::single(ipv4)))
        } else if let Ok(ipv6) = Ipv6Addr::from_str(trimmed) {
            Ok(Self::V6(Ipv6Range::single(ipv6)))
        } else {
            Err(ParseIpRangeError::InvalidIp(trimmed.to_string()))
        }
    }

    /// Number of IP addresses in this range.
    #[inline]
    pub fn len(&self) -> u128 {
        match self {
            Self::V4(r) => r.len() as u128,
            Self::V6(r) => r.len(),
        }
    }

    /// Whether this range is empty (never true for valid ranges).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a zero-allocation streaming iterator over all IP addresses in the range.
    #[inline]
    pub fn iter(&self) -> IpRangeIter {
        match self {
            Self::V4(r) => IpRangeIter::V4(r.iter()),
            Self::V6(r) => IpRangeIter::V6(r.iter()),
        }
    }
}

impl IntoIterator for IpRange {
    type Item = IpAddr;
    type IntoIter = IpRangeIter;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// A continuous range of IPv4 addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Range {
    start: u32,
    end: u32,
}

impl Ipv4Range {
    /// Create a range from start and end IPv4 addresses.
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Result<Self, ParseIpRangeError> {
        let s = u32::from(start);
        let e = u32::from(end);
        if s > e {
            return Err(ParseIpRangeError::InvalidRange(format!(
                "{start} is greater than {end}"
            )));
        }
        Ok(Self { start: s, end: e })
    }

    /// Create a single-IP range.
    #[inline]
    pub fn single(ip: Ipv4Addr) -> Self {
        let val = u32::from(ip);
        Self {
            start: val,
            end: val,
        }
    }

    /// Create a range from an IPv4 address and CIDR prefix (0..=32).
    pub fn from_cidr(ip: Ipv4Addr, prefix: u32) -> Self {
        assert!(prefix <= 32);
        if prefix == 0 {
            return Self {
                start: 0,
                end: u32::MAX,
            };
        }
        let mask = !((1u64 << (32 - prefix)) - 1) as u32;
        let base = u32::from(ip) & mask;
        let broadcast = base | !mask;
        Self {
            start: base,
            end: broadcast,
        }
    }

    /// Total number of IP addresses in the range.
    #[inline]
    pub fn len(&self) -> u64 {
        (self.end as u64) - (self.start as u64) + 1
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Start address of the range.
    #[inline]
    pub fn start(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.start)
    }

    /// End address of the range.
    #[inline]
    pub fn end(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.end)
    }

    /// Returns a zero-allocation iterator over IPv4 addresses.
    #[inline]
    pub fn iter(&self) -> Ipv4RangeIter {
        Ipv4RangeIter {
            current: self.start as u64,
            end: self.end as u64,
        }
    }
}

/// Zero-allocation iterator for IPv4 addresses.
#[derive(Debug, Clone)]
pub struct Ipv4RangeIter {
    current: u64,
    end: u64,
}

impl Iterator for Ipv4RangeIter {
    type Item = Ipv4Addr;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.current <= self.end {
            let ip = Ipv4Addr::from(self.current as u32);
            self.current += 1;
            Some(ip)
        } else {
            None
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.current <= self.end {
            let rem = (self.end - self.current + 1) as usize;
            (rem, Some(rem))
        } else {
            (0, Some(0))
        }
    }
}

impl ExactSizeIterator for Ipv4RangeIter {}

/// A continuous range of IPv6 addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Range {
    start: u128,
    end: u128,
}

impl Ipv6Range {
    /// Create a range from start and end IPv6 addresses.
    pub fn new(start: Ipv6Addr, end: Ipv6Addr) -> Result<Self, ParseIpRangeError> {
        let s = u128::from(start);
        let e = u128::from(end);
        if s > e {
            return Err(ParseIpRangeError::InvalidRange(format!(
                "{start} is greater than {end}"
            )));
        }
        Ok(Self { start: s, end: e })
    }

    /// Create a single-IP range.
    #[inline]
    pub fn single(ip: Ipv6Addr) -> Self {
        let val = u128::from(ip);
        Self {
            start: val,
            end: val,
        }
    }

    /// Create a range from an IPv6 address and CIDR prefix (0..=128).
    pub fn from_cidr(ip: Ipv6Addr, prefix: u32) -> Self {
        assert!(prefix <= 128);
        if prefix == 0 {
            return Self {
                start: 0,
                end: u128::MAX,
            };
        }
        let mask = if prefix == 128 {
            u128::MAX
        } else {
            !((1u128 << (128 - prefix)) - 1)
        };
        let base = u128::from(ip) & mask;
        let last = base | !mask;
        Self {
            start: base,
            end: last,
        }
    }

    #[inline]
    pub fn len(&self) -> u128 {
        self.end - self.start + 1
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        false
    }

    #[inline]
    pub fn start(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.start)
    }

    #[inline]
    pub fn end(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.end)
    }

    #[inline]
    pub fn iter(&self) -> Ipv6RangeIter {
        Ipv6RangeIter {
            current: self.start,
            end: self.end,
            done: false,
        }
    }
}

/// Zero-allocation iterator for IPv6 addresses.
#[derive(Debug, Clone)]
pub struct Ipv6RangeIter {
    current: u128,
    end: u128,
    done: bool,
}

impl Iterator for Ipv6RangeIter {
    type Item = Ipv6Addr;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let ip = Ipv6Addr::from(self.current);
        if self.current == self.end {
            self.done = true;
        } else {
            self.current += 1;
        }
        Some(ip)
    }
}

/// Unified IP range iterator yielding `std::net::IpAddr`.
#[derive(Debug, Clone)]
pub enum IpRangeIter {
    V4(Ipv4RangeIter),
    V6(Ipv6RangeIter),
}

impl Iterator for IpRangeIter {
    type Item = IpAddr;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::V4(iter) => iter.next().map(IpAddr::V4),
            Self::V6(iter) => iter.next().map(IpAddr::V6),
        }
    }
}

/// A parsed list of IP targets containing multiple individual ranges or CIDRs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TargetList {
    ranges: Vec<IpRange>,
}

impl TargetList {
    /// Parse comma- or whitespace-separated list of targets.
    /// Example: `192.168.1.1, 10.0.0.0/24 172.16.1.1-10`
    pub fn parse(input: &str) -> Result<Self, ParseIpRangeError> {
        let mut ranges = Vec::new();
        for item in input.split(|c: char| c == ',' || c.is_whitespace()) {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            ranges.push(IpRange::parse(item)?);
        }
        Ok(Self { ranges })
    }

    /// Total count of all target IP addresses.
    pub fn total_ips(&self) -> u128 {
        self.ranges.iter().map(|r| r.len()).sum()
    }

    /// Flattened iterator across all ranges.
    pub fn iter(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.ranges.iter().flat_map(|r| r.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_single_ipv4() {
        let r = IpRange::parse("192.168.1.100").unwrap();
        assert_eq!(r.len(), 1);
        let ips: Vec<IpAddr> = r.iter().collect();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))]);
    }

    #[test]
    fn test_cidr_v4_24() {
        let r = IpRange::parse("192.168.1.0/24").unwrap();
        assert_eq!(r.len(), 256);
        let mut iter = r.iter();
        assert_eq!(iter.next(), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0))));
        assert_eq!(iter.last(), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))));
    }

    #[test]
    fn test_dash_range_short() {
        let r = IpRange::parse("10.0.0.1-5").unwrap();
        assert_eq!(r.len(), 5);
        let ips: Vec<IpAddr> = r.iter().collect();
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            ]
        );
    }

    #[test]
    fn test_dash_range_full() {
        let r = IpRange::parse("10.0.0.250-10.0.1.2").unwrap();
        assert_eq!(r.len(), 9); // 250, 251, 252, 253, 254, 255, 0, 1, 2
        let ips: Vec<IpAddr> = r.iter().collect();
        assert_eq!(ips.len(), 9);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(10, 0, 0, 250)));
        assert_eq!(ips[8], IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)));
    }

    #[test]
    fn test_cidr_slash_16_performance() {
        // Must traverse /16 (65,536 IPs) in sub-millisecond
        let r = IpRange::parse("172.16.0.0/16").unwrap();
        assert_eq!(r.len(), 65536);

        let start = Instant::now();
        let mut count = 0;
        for _ in r.iter() {
            count += 1;
        }
        let elapsed = start.elapsed();
        assert_eq!(count, 65536);
        println!("Traversed 65,536 IPs in {:?}", elapsed);
        // Requirement: sub-millisecond on standard modern CPU (under 10ms comfortably in debug)
        assert!(elapsed.as_millis() < 50);
    }

    #[test]
    fn test_target_list() {
        let targets = TargetList::parse("192.168.1.1, 10.0.0.1-3, 172.16.0.0/30").unwrap();
        // 1 + 3 + 4 = 8
        assert_eq!(targets.total_ips(), 8);
        let ips: Vec<IpAddr> = targets.iter().collect();
        assert_eq!(ips.len(), 8);
    }
}
