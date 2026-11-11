//! `[MS-DNSP]`: Active Directory Integrated DNS Protocol & `dnsRecord` Binary Codec.
//!
//! Implements Microsoft `[MS-DNSP]` Section 2.3.2.2 `DNS_RPC_RECORD` binary structure used
//! by Active Directory Integrated DNS for storing DNS records in the `dnsRecord` LDAP attribute
//! of `dnsNode` directory objects (`impacket/examples/dnstool.py`).
//!
//! Supports record types:
//! - `A` (IPv4, 0x0001)
//! - `NS` (Name Server, 0x0002)
//! - `CNAME` (Canonical Name, 0x0005)
//! - `SOA` (Start of Authority, 0x0006)
//! - `PTR` (Pointer, 0x000c)
//! - `MX` (Mail Exchange, 0x000f)
//! - `TXT` (Text strings, 0x0010)
//! - `AAAA` (IPv6, 0x001c)
//! - `SRV` (Service location, 0x0021)
//! - `Tombstone` (Deleted record, 0x0000)

use impacket_core::CoreError;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::asn1::{
    filter_and, filter_equality, AttributeModification, LdapAttribute, ModifyOperation,
    SearchScope,
};
use crate::client::LdapClient;

/// Standard Microsoft DNS Record Types per `[MS-DNSP]` Section 2.2.2.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsRecordType {
    Tombstone = 0x0000,
    A = 0x0001,
    Ns = 0x0002,
    Cname = 0x0005,
    Soa = 0x0006,
    Ptr = 0x000c,
    Mx = 0x000f,
    Txt = 0x0010,
    Aaaa = 0x001c,
    Srv = 0x0021,
    Unknown(u16),
}

impl DnsRecordType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0x0000 => DnsRecordType::Tombstone,
            0x0001 => DnsRecordType::A,
            0x0002 => DnsRecordType::Ns,
            0x0005 => DnsRecordType::Cname,
            0x0006 => DnsRecordType::Soa,
            0x000c => DnsRecordType::Ptr,
            0x000f => DnsRecordType::Mx,
            0x0010 => DnsRecordType::Txt,
            0x001c => DnsRecordType::Aaaa,
            0x0021 => DnsRecordType::Srv,
            other => DnsRecordType::Unknown(other),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            DnsRecordType::Tombstone => 0x0000,
            DnsRecordType::A => 0x0001,
            DnsRecordType::Ns => 0x0002,
            DnsRecordType::Cname => 0x0005,
            DnsRecordType::Soa => 0x0006,
            DnsRecordType::Ptr => 0x000c,
            DnsRecordType::Mx => 0x000f,
            DnsRecordType::Txt => 0x0010,
            DnsRecordType::Aaaa => 0x001c,
            DnsRecordType::Srv => 0x0021,
            DnsRecordType::Unknown(other) => other,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            DnsRecordType::Tombstone => "TOMBSTONE",
            DnsRecordType::A => "A",
            DnsRecordType::Ns => "NS",
            DnsRecordType::Cname => "CNAME",
            DnsRecordType::Soa => "SOA",
            DnsRecordType::Ptr => "PTR",
            DnsRecordType::Mx => "MX",
            DnsRecordType::Txt => "TXT",
            DnsRecordType::Aaaa => "AAAA",
            DnsRecordType::Srv => "SRV",
            DnsRecordType::Unknown(_) => "UNKNOWN",
        }
    }

    pub fn parse_str(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "A" => Some(DnsRecordType::A),
            "NS" => Some(DnsRecordType::Ns),
            "CNAME" => Some(DnsRecordType::Cname),
            "SOA" => Some(DnsRecordType::Soa),
            "PTR" => Some(DnsRecordType::Ptr),
            "MX" => Some(DnsRecordType::Mx),
            "TXT" => Some(DnsRecordType::Txt),
            "AAAA" => Some(DnsRecordType::Aaaa),
            "SRV" => Some(DnsRecordType::Srv),
            "TOMBSTONE" => Some(DnsRecordType::Tombstone),
            _ => None,
        }
    }
}

/// Record ranking constants per `[MS-DNSP]` Section 2.2.2.1.1.
pub const RANK_ZONE: u8 = 0xf0;
pub const RANK_ZONE_FILE: u8 = 0xe0;
pub const RANK_CACHE_BIT: u8 = 0x20;
pub const RANK_ROOT_HINT: u8 = 0x00;

/// Aging and behavior flags per `[MS-DNSP]` Section 2.2.2.1.1.
pub const DNS_RPC_FLAG_AGING_ON: u16 = 0x0002;
pub const DNS_RPC_RECORD_VERSION: u8 = 0x05;

/// Specific record payload per `[MS-DNSP]` Section 2.2.2.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordData {
    Tombstone,
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Ptr(String),
    Ns(String),
    Txt(Vec<String>),
    Mx {
        preference: u16,
        exchange: String,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Raw {
        record_type: u16,
        data: Vec<u8>,
    },
}

/// Represents an Active Directory `[MS-DNSP]` binary `dnsRecord` (`DNS_RPC_RECORD`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRpcRecord {
    pub record_type: DnsRecordType,
    pub version: u8,
    pub rank: u8,
    pub flags: u16,
    pub serial: u32,
    pub ttl_seconds: u32,
    pub reserved: u32,
    pub timestamp: u32,
    pub data: DnsRecordData,
}

impl DnsRpcRecord {
    /// Creates a standard Type A (IPv4) record.
    pub fn new_a(ip: Ipv4Addr, ttl: u32, serial: u32) -> Self {
        Self {
            record_type: DnsRecordType::A,
            version: DNS_RPC_RECORD_VERSION,
            rank: RANK_ZONE,
            flags: 0,
            serial,
            ttl_seconds: ttl,
            reserved: 0,
            timestamp: 0,
            data: DnsRecordData::A(ip),
        }
    }

    /// Creates a standard Type AAAA (IPv6) record.
    pub fn new_aaaa(ip: Ipv6Addr, ttl: u32, serial: u32) -> Self {
        Self {
            record_type: DnsRecordType::Aaaa,
            version: DNS_RPC_RECORD_VERSION,
            rank: RANK_ZONE,
            flags: 0,
            serial,
            ttl_seconds: ttl,
            reserved: 0,
            timestamp: 0,
            data: DnsRecordData::Aaaa(ip),
        }
    }

    /// Creates a standard Type CNAME record.
    pub fn new_cname(target: &str, ttl: u32, serial: u32) -> Self {
        Self {
            record_type: DnsRecordType::Cname,
            version: DNS_RPC_RECORD_VERSION,
            rank: RANK_ZONE,
            flags: 0,
            serial,
            ttl_seconds: ttl,
            reserved: 0,
            timestamp: 0,
            data: DnsRecordData::Cname(target.to_string()),
        }
    }

    /// Creates a standard Type PTR record.
    pub fn new_ptr(target: &str, ttl: u32, serial: u32) -> Self {
        Self {
            record_type: DnsRecordType::Ptr,
            version: DNS_RPC_RECORD_VERSION,
            rank: RANK_ZONE,
            flags: 0,
            serial,
            ttl_seconds: ttl,
            reserved: 0,
            timestamp: 0,
            data: DnsRecordData::Ptr(target.to_string()),
        }
    }

    /// Creates a standard Type TXT record.
    pub fn new_txt(texts: &[&str], ttl: u32, serial: u32) -> Self {
        Self {
            record_type: DnsRecordType::Txt,
            version: DNS_RPC_RECORD_VERSION,
            rank: RANK_ZONE,
            flags: 0,
            serial,
            ttl_seconds: ttl,
            reserved: 0,
            timestamp: 0,
            data: DnsRecordData::Txt(texts.iter().map(|s| s.to_string()).collect()),
        }
    }

    /// Creates a standard Type SRV record.
    pub fn new_srv(priority: u16, weight: u16, port: u16, target: &str, ttl: u32, serial: u32) -> Self {
        Self {
            record_type: DnsRecordType::Srv,
            version: DNS_RPC_RECORD_VERSION,
            rank: RANK_ZONE,
            flags: 0,
            serial,
            ttl_seconds: ttl,
            reserved: 0,
            timestamp: 0,
            data: DnsRecordData::Srv {
                priority,
                weight,
                port,
                target: target.to_string(),
            },
        }
    }

    /// Creates an AD DNS tombstone record.
    pub fn new_tombstone(serial: u32, timestamp: u32) -> Self {
        Self {
            record_type: DnsRecordType::Tombstone,
            version: DNS_RPC_RECORD_VERSION,
            rank: RANK_ROOT_HINT,
            flags: 0,
            serial,
            ttl_seconds: 0,
            reserved: 0,
            timestamp,
            data: DnsRecordData::Tombstone,
        }
    }

    /// Serializes the record into `[MS-DNSP]` Section 2.3.2.2 binary wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Encode specific payload first to compute DataLength
        let mut data_buf = Vec::new();
        match &self.data {
            DnsRecordData::Tombstone => {}
            DnsRecordData::A(ip) => {
                data_buf.extend_from_slice(&ip.octets());
            }
            DnsRecordData::Aaaa(ip) => {
                data_buf.extend_from_slice(&ip.octets());
            }
            DnsRecordData::Cname(name) | DnsRecordData::Ptr(name) | DnsRecordData::Ns(name) => {
                data_buf.extend_from_slice(&encode_dns_rpc_name(name));
            }
            DnsRecordData::Txt(strings) => {
                // Count of strings (1 byte) followed by each counted string
                data_buf.push(strings.len() as u8);
                for s in strings {
                    let bytes = s.as_bytes();
                    let len = bytes.len().min(255) as u8;
                    data_buf.push(len);
                    data_buf.extend_from_slice(&bytes[..len as usize]);
                }
            }
            DnsRecordData::Mx { preference, exchange } => {
                data_buf.extend_from_slice(&preference.to_le_bytes());
                data_buf.extend_from_slice(&encode_dns_rpc_name(exchange));
            }
            DnsRecordData::Srv { priority, weight, port, target } => {
                data_buf.extend_from_slice(&priority.to_le_bytes());
                data_buf.extend_from_slice(&weight.to_le_bytes());
                data_buf.extend_from_slice(&port.to_le_bytes());
                data_buf.extend_from_slice(&encode_dns_rpc_name(target));
            }
            DnsRecordData::Raw { data, .. } => {
                data_buf.extend_from_slice(data);
            }
        }

        // Header is 24 bytes total; DataLength (2 bytes) covers from wType to end of data:
        // wType(2) + bVersion(1) + bRank(1) + wFlags(2) + dwSerial(4) + dwTtlSeconds(4) + dwReserved(4) + dwTimeStamp(4) = 22 bytes.
        let data_len = (22 + data_buf.len()) as u16;

        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&self.record_type.to_u16().to_le_bytes());
        buf.push(self.version);
        buf.push(self.rank);
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf.extend_from_slice(&self.serial.to_le_bytes());
        // [MS-DNSP] Section 2.3.2.2: dwTtlSeconds is in big-endian (network byte order)!
        buf.extend_from_slice(&self.ttl_seconds.to_be_bytes());
        buf.extend_from_slice(&self.reserved.to_le_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&data_buf);

        buf
    }

    /// Parses an `[MS-DNSP]` Section 2.3.2.2 binary record from slice.
    pub fn parse(slice: &[u8]) -> Result<Self, CoreError> {
        if slice.len() < 24 {
            return Err(CoreError::BufferUnderflow {
                needed: 24,
                available: slice.len(),
            });
        }

        let data_len = u16::from_le_bytes([slice[0], slice[1]]) as usize;
        let record_type_u16 = u16::from_le_bytes([slice[2], slice[3]]);
        let record_type = DnsRecordType::from_u16(record_type_u16);
        let version = slice[4];
        let rank = slice[5];
        let flags = u16::from_le_bytes([slice[6], slice[7]]);
        let serial = u32::from_le_bytes([slice[8], slice[9], slice[10], slice[11]]);
        // dwTtlSeconds in network byte order:
        let ttl_seconds = u32::from_be_bytes([slice[12], slice[13], slice[14], slice[15]]);
        let reserved = u32::from_le_bytes([slice[16], slice[17], slice[18], slice[19]]);
        let timestamp = u32::from_le_bytes([slice[20], slice[21], slice[22], slice[23]]);

        let payload_len = if data_len >= 22 {
            data_len - 22
        } else {
            0
        };

        let end_idx = (24 + payload_len).min(slice.len());
        let payload = &slice[24..end_idx];

        let data = match record_type {
            DnsRecordType::Tombstone => DnsRecordData::Tombstone,
            DnsRecordType::A => {
                if payload.len() >= 4 {
                    DnsRecordData::A(Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]))
                } else {
                    DnsRecordData::Raw {
                        record_type: record_type_u16,
                        data: payload.to_vec(),
                    }
                }
            }
            DnsRecordType::Aaaa => {
                if payload.len() >= 16 {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&payload[..16]);
                    DnsRecordData::Aaaa(Ipv6Addr::from(octets))
                } else {
                    DnsRecordData::Raw {
                        record_type: record_type_u16,
                        data: payload.to_vec(),
                    }
                }
            }
            DnsRecordType::Cname => {
                let name = decode_dns_rpc_name(payload).unwrap_or_else(|_| String::new());
                DnsRecordData::Cname(name)
            }
            DnsRecordType::Ptr => {
                let name = decode_dns_rpc_name(payload).unwrap_or_else(|_| String::new());
                DnsRecordData::Ptr(name)
            }
            DnsRecordType::Ns => {
                let name = decode_dns_rpc_name(payload).unwrap_or_else(|_| String::new());
                DnsRecordData::Ns(name)
            }
            DnsRecordType::Txt => {
                if !payload.is_empty() {
                    let mut strings = Vec::new();
                    let count = payload[0] as usize;
                    let mut offset = 1;
                    for _ in 0..count {
                        if offset >= payload.len() {
                            break;
                        }
                        let len = payload[offset] as usize;
                        offset += 1;
                        if offset + len <= payload.len() {
                            let text = String::from_utf8_lossy(&payload[offset..offset + len]).into_owned();
                            strings.push(text);
                            offset += len;
                        }
                    }
                    DnsRecordData::Txt(strings)
                } else {
                    DnsRecordData::Txt(Vec::new())
                }
            }
            DnsRecordType::Mx => {
                if payload.len() >= 2 {
                    let preference = u16::from_le_bytes([payload[0], payload[1]]);
                    let exchange = decode_dns_rpc_name(&payload[2..]).unwrap_or_else(|_| String::new());
                    DnsRecordData::Mx { preference, exchange }
                } else {
                    DnsRecordData::Raw {
                        record_type: record_type_u16,
                        data: payload.to_vec(),
                    }
                }
            }
            DnsRecordType::Srv => {
                if payload.len() >= 6 {
                    let priority = u16::from_le_bytes([payload[0], payload[1]]);
                    let weight = u16::from_le_bytes([payload[2], payload[3]]);
                    let port = u16::from_le_bytes([payload[4], payload[5]]);
                    let target = decode_dns_rpc_name(&payload[6..]).unwrap_or_else(|_| String::new());
                    DnsRecordData::Srv {
                        priority,
                        weight,
                        port,
                        target,
                    }
                } else {
                    DnsRecordData::Raw {
                        record_type: record_type_u16,
                        data: payload.to_vec(),
                    }
                }
            }
            _ => DnsRecordData::Raw {
                record_type: record_type_u16,
                data: payload.to_vec(),
            },
        };

        Ok(Self {
            record_type,
            version,
            rank,
            flags,
            serial,
            ttl_seconds,
            reserved,
            timestamp,
            data,
        })
    }
}

/// Encodes a DNS domain name into `DNS_RPC_NAME` format per `[MS-DNSP]` Section 2.2.2.1.1:
/// `bNameLength` (u8) + sequence of labels (each `len` + bytes) + `\0` terminator.
pub fn encode_dns_rpc_name(name: &str) -> Vec<u8> {
    let clean = name.trim().trim_matches('.');
    if clean.is_empty() {
        return vec![1, 0]; // 1-byte wire name with null terminator
    }

    let mut wire = Vec::new();
    for label in clean.split('.') {
        let bytes = label.as_bytes();
        let len = bytes.len().min(63) as u8;
        wire.push(len);
        wire.extend_from_slice(&bytes[..len as usize]);
    }
    wire.push(0x00); // Terminal null label

    let name_len = wire.len().min(255) as u8;
    let mut out = Vec::with_capacity(1 + wire.len());
    out.push(name_len);
    out.extend_from_slice(&wire);
    out
}

/// Decodes a `DNS_RPC_NAME` from slice into a standard dot-separated domain string.
pub fn decode_dns_rpc_name(slice: &[u8]) -> Result<String, CoreError> {
    if slice.is_empty() {
        return Ok(String::new());
    }

    let total_len = slice[0] as usize;
    if slice.len() < 1 + total_len {
        return Ok(String::new());
    }

    let wire = &slice[1..1 + total_len];
    let mut labels = Vec::new();
    let mut offset = 0;

    while offset < wire.len() {
        let label_len = wire[offset] as usize;
        offset += 1;
        if label_len == 0 {
            break;
        }
        if offset + label_len > wire.len() {
            break;
        }
        let label = String::from_utf8_lossy(&wire[offset..offset + label_len]);
        labels.push(label.into_owned());
        offset += label_len;
    }

    Ok(labels.join("."))
}

/// Helper to format a `DnsRpcRecord` data for display.
pub fn format_dns_record_data(data: &DnsRecordData) -> String {
    match data {
        DnsRecordData::Tombstone => "(Tombstoned)".to_string(),
        DnsRecordData::A(ip) => ip.to_string(),
        DnsRecordData::Aaaa(ip) => ip.to_string(),
        DnsRecordData::Cname(c) => c.clone(),
        DnsRecordData::Ptr(p) => p.clone(),
        DnsRecordData::Ns(n) => n.clone(),
        DnsRecordData::Txt(strings) => format!("\"{}\"", strings.join("\" \"")),
        DnsRecordData::Mx { preference, exchange } => format!("{} {}", preference, exchange),
        DnsRecordData::Srv { priority, weight, port, target } => {
            format!("{} {} {} {}", priority, weight, port, target)
        }
        DnsRecordData::Raw { record_type, data } => {
            format!("TYPE_{} (len: {})", record_type, data.len())
        }
    }
}

/// Result of an Active Directory Integrated DNS node lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsNodeResult {
    pub node_name: String,
    pub object_dn: String,
    pub is_tombstoned: bool,
    pub records: Vec<DnsRpcRecord>,
}

/// Standard Active Directory DNS directory partitions under domain root.
pub fn resolve_dns_partitions(domain_dn: &str) -> Vec<String> {
    vec![
        format!("CN=MicrosoftDNS,DC=DomainDnsZones,{}", domain_dn),
        format!("CN=MicrosoftDNS,DC=ForestDnsZones,{}", domain_dn),
        format!("CN=MicrosoftDNS,CN=System,{}", domain_dn),
    ]
}

/// Lists all Active Directory Integrated DNS zones discovered in the domain.
pub fn list_dns_zones<S: Read + Write>(
    client: &mut LdapClient<S>,
    domain_dn: &str,
) -> Result<Vec<(String, String)>, CoreError> {
    let mut zones = Vec::new();
    let filter = filter_equality("objectClass", "dnsZone");
    let attrs = ["name", "distinguishedName"];

    for partition in resolve_dns_partitions(domain_dn) {
        if let Ok(entries) = client.search_unpaged(&partition, SearchScope::SingleLevel, &filter, &attrs) {
            for entry in entries {
                let name = entry.get_string("name").unwrap_or_else(|| {
                    entry
                        .dn
                        .split(',')
                        .next()
                        .and_then(|p| p.strip_prefix("DC="))
                        .unwrap_or("")
                        .to_string()
                });
                if !name.is_empty() && !name.eq_ignore_ascii_case("RootDNSServers") {
                    zones.push((name, entry.dn));
                }
            }
        }
    }
    Ok(zones)
}

/// Queries an Active Directory DNS node or zone root over LDAP.
pub fn query_dns_node<S: Read + Write>(
    client: &mut LdapClient<S>,
    zone_dn: &str,
    record_name: &str,
) -> Result<Vec<DnsNodeResult>, CoreError> {
    let filter = if record_name.is_empty() || record_name == "*" {
        filter_equality("objectClass", "dnsNode")
    } else {
        filter_and(&[
            filter_equality("objectClass", "dnsNode"),
            filter_equality("dc", record_name),
        ])
    };

    let attrs = ["dc", "dnsRecord", "dNSTombstoned"];

    let entries = client.search_unpaged(zone_dn, SearchScope::SingleLevel, &filter, &attrs)?;
    let mut results = Vec::new();

    for entry in entries {
        let node_name = entry.get_string("dc").unwrap_or_else(|| "@".to_string());
        let is_tombstoned = entry
            .get_string("dNSTombstoned")
            .map(|s| s.eq_ignore_ascii_case("TRUE"))
            .unwrap_or(false);

        let mut records = Vec::new();
        if let Some(raw_records) = entry.get_raw("dnsRecord") {
            for raw in raw_records {
                if let Ok(rec) = DnsRpcRecord::parse(raw) {
                    records.push(rec);
                }
            }
        }

        results.push(DnsNodeResult {
            node_name,
            object_dn: entry.dn,
            is_tombstoned,
            records,
        });
    }

    Ok(results)
}

/// Adds a new DNS record to the specified zone. Creates the `dnsNode` if it does not exist.
pub fn add_dns_node<S: Read + Write>(
    client: &mut LdapClient<S>,
    zone_dn: &str,
    record_name: &str,
    record: &DnsRpcRecord,
) -> Result<(), CoreError> {
    let node_dn = format!("DC={},{}", record_name, zone_dn);
    let rec_bytes = record.to_bytes();

    let existing = query_dns_node(client, zone_dn, record_name)?;
    if existing.is_empty() {
        let attrs = vec![
            LdapAttribute {
                type_name: "objectClass".to_string(),
                values: vec![b"top".to_vec(), b"dnsNode".to_vec()],
            },
            LdapAttribute {
                type_name: "dc".to_string(),
                values: vec![record_name.as_bytes().to_vec()],
            },
            LdapAttribute {
                type_name: "dnsRecord".to_string(),
                values: vec![rec_bytes],
            },
            LdapAttribute {
                type_name: "dNSTombstoned".to_string(),
                values: vec![b"FALSE".to_vec()],
            },
        ];
        client.add(&node_dn, attrs)
    } else {
        let mods = vec![
            AttributeModification {
                operation: ModifyOperation::Add,
                attribute: LdapAttribute {
                    type_name: "dnsRecord".to_string(),
                    values: vec![rec_bytes],
                },
            },
            AttributeModification {
                operation: ModifyOperation::Replace,
                attribute: LdapAttribute {
                    type_name: "dNSTombstoned".to_string(),
                    values: vec![b"FALSE".to_vec()],
                },
            },
        ];
        client.modify(&node_dn, mods)
    }
}

/// Modifies an existing DNS node by replacing its `dnsRecord` values.
pub fn modify_dns_node<S: Read + Write>(
    client: &mut LdapClient<S>,
    zone_dn: &str,
    record_name: &str,
    record: &DnsRpcRecord,
) -> Result<(), CoreError> {
    let node_dn = format!("DC={},{}", record_name, zone_dn);
    let rec_bytes = record.to_bytes();

    let mods = vec![
        AttributeModification {
            operation: ModifyOperation::Replace,
            attribute: LdapAttribute {
                type_name: "dnsRecord".to_string(),
                values: vec![rec_bytes],
            },
        },
        AttributeModification {
            operation: ModifyOperation::Replace,
            attribute: LdapAttribute {
                type_name: "dNSTombstoned".to_string(),
                values: vec![b"FALSE".to_vec()],
            },
        },
    ];
    client.modify(&node_dn, mods)
}

/// Tombstones a DNS record per `[MS-DNSP]` (marks deleted without removing object).
pub fn tombstone_dns_node<S: Read + Write>(
    client: &mut LdapClient<S>,
    zone_dn: &str,
    record_name: &str,
    serial: u32,
) -> Result<(), CoreError> {
    let node_dn = format!("DC={},{}", record_name, zone_dn);
    let tombstone = DnsRpcRecord::new_tombstone(serial, 0);
    let rec_bytes = tombstone.to_bytes();

    let mods = vec![
        AttributeModification {
            operation: ModifyOperation::Replace,
            attribute: LdapAttribute {
                type_name: "dnsRecord".to_string(),
                values: vec![rec_bytes],
            },
        },
        AttributeModification {
            operation: ModifyOperation::Replace,
            attribute: LdapAttribute {
                type_name: "dNSTombstoned".to_string(),
                values: vec![b"TRUE".to_vec()],
            },
        },
    ];
    client.modify(&node_dn, mods)
}

/// Permanently deletes a `dnsNode` object from the directory.
pub fn delete_dns_node<S: Read + Write>(
    client: &mut LdapClient<S>,
    zone_dn: &str,
    record_name: &str,
) -> Result<(), CoreError> {
    let node_dn = format!("DC={},{}", record_name, zone_dn);
    client.delete(&node_dn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_and_decode_dns_rpc_name() {
        let name = "dc01.corp.contoso.com";
        let encoded = encode_dns_rpc_name(name);
        assert_eq!(encoded[0] as usize, encoded.len() - 1);
        let decoded = decode_dns_rpc_name(&encoded).unwrap();
        assert_eq!(decoded, name);
    }

    #[test]
    fn test_dns_record_type_a_roundtrip() {
        let ip = Ipv4Addr::new(192, 168, 100, 25);
        let record = DnsRpcRecord::new_a(ip, 300, 1052);
        let bytes = record.to_bytes();

        assert_eq!(bytes.len(), 28); // 24 header + 4 IP
        let parsed = DnsRpcRecord::parse(&bytes).unwrap();
        assert_eq!(parsed.record_type, DnsRecordType::A);
        assert_eq!(parsed.ttl_seconds, 300);
        assert_eq!(parsed.serial, 1052);
        assert_eq!(parsed.data, DnsRecordData::A(ip));
    }

    #[test]
    fn test_dns_record_type_aaaa_roundtrip() {
        let ip: Ipv6Addr = "fe80::1ff:fe23:4567:890a".parse().unwrap();
        let record = DnsRpcRecord::new_aaaa(ip, 600, 42);
        let bytes = record.to_bytes();

        assert_eq!(bytes.len(), 40); // 24 header + 16 IPv6
        let parsed = DnsRpcRecord::parse(&bytes).unwrap();
        assert_eq!(parsed.record_type, DnsRecordType::Aaaa);
        assert_eq!(parsed.ttl_seconds, 600);
        assert_eq!(parsed.serial, 42);
        assert_eq!(parsed.data, DnsRecordData::Aaaa(ip));
    }

    #[test]
    fn test_dns_record_type_cname_roundtrip() {
        let target = "webserver.corp.local";
        let record = DnsRpcRecord::new_cname(target, 3600, 100);
        let bytes = record.to_bytes();

        let parsed = DnsRpcRecord::parse(&bytes).unwrap();
        assert_eq!(parsed.record_type, DnsRecordType::Cname);
        assert_eq!(parsed.ttl_seconds, 3600);
        assert_eq!(parsed.data, DnsRecordData::Cname(target.to_string()));
    }

    #[test]
    fn test_dns_record_type_srv_roundtrip() {
        let record = DnsRpcRecord::new_srv(0, 100, 389, "dc01.corp.local", 1200, 50);
        let bytes = record.to_bytes();

        let parsed = DnsRpcRecord::parse(&bytes).unwrap();
        assert_eq!(parsed.record_type, DnsRecordType::Srv);
        assert_eq!(
            parsed.data,
            DnsRecordData::Srv {
                priority: 0,
                weight: 100,
                port: 389,
                target: "dc01.corp.local".to_string()
            }
        );
    }

    #[test]
    fn test_dns_record_type_txt_roundtrip() {
        let record = DnsRpcRecord::new_txt(&["v=spf1 include:_spf.google.com ~all"], 300, 10);
        let bytes = record.to_bytes();

        let parsed = DnsRpcRecord::parse(&bytes).unwrap();
        assert_eq!(parsed.record_type, DnsRecordType::Txt);
        assert_eq!(
            parsed.data,
            DnsRecordData::Txt(vec!["v=spf1 include:_spf.google.com ~all".to_string()])
        );
    }

    #[test]
    fn test_dns_record_tombstone_roundtrip() {
        let record = DnsRpcRecord::new_tombstone(999, 12345);
        let bytes = record.to_bytes();

        assert_eq!(bytes.len(), 24);
        let parsed = DnsRpcRecord::parse(&bytes).unwrap();
        assert_eq!(parsed.record_type, DnsRecordType::Tombstone);
        assert_eq!(parsed.data, DnsRecordData::Tombstone);
        assert_eq!(parsed.timestamp, 12345);
    }
}
