//! Connectionless LDAP (CLDAP over UDP port 389) Netlogon Prober.
//!
//! Sends an unauthenticated Netlogon ping to a Domain Controller and parses
//! the `LOGON_SAM_LOGON_RESPONSE_EX` structure (`[MS-NRPC]` §2.2.1.4.2) to extract:
//! - Forest Root Domain
//! - DNS Domain Name
//! - Domain NetBIOS Name
//! - Domain Controller NetBIOS & FQDN Hostname
//! - DC Site Name & Client Site Name
//! - Server Capabilities (PDC, KDC, GC, Writable)

use std::fmt;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::der;
use crate::CoreError;

pub const CLDAP_DEFAULT_PORT: u16 = 389;

/// Server flags in `LOGON_SAM_LOGON_RESPONSE_EX` (`[MS-NRPC]` §2.2.1.4.2).
pub mod dc_flags {
    pub const DS_PDC_FLAG: u32 = 0x00000001;
    pub const DS_GC_FLAG: u32 = 0x00000004;
    pub const DS_LDAP_FLAG: u32 = 0x00000008;
    pub const DS_DS_FLAG: u32 = 0x00000010;
    pub const DS_KDC_FLAG: u32 = 0x00000020;
    pub const DS_TIMESERV_FLAG: u32 = 0x00000040;
    pub const DS_CLOSEST_FLAG: u32 = 0x00000080;
    pub const DS_WRITABLE_FLAG: u32 = 0x00000100;
    pub const DS_GOOD_TIMESERV_FLAG: u32 = 0x00000200;
    pub const DS_NDNC_FLAG: u32 = 0x00000400;
    pub const DS_SELECT_SECRET_DOMAIN_6_FLAG: u32 = 0x00000800;
    pub const DS_FULL_SECRET_DOMAIN_6_FLAG: u32 = 0x00001000;
    pub const DS_WS_FLAG: u32 = 0x00002000;
    pub const DS_DS_8_FLAG: u32 = 0x00004000;
    pub const DS_DS_9_FLAG: u32 = 0x00008000;
    pub const DS_KEY_LIST_FLAG: u32 = 0x00020000;
}

/// Discovered Domain Controller telemetry extracted via unauthenticated CLDAP ping.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CldapDcInfo {
    pub forest_name: String,
    pub dns_domain_name: String,
    pub netbios_domain_name: String,
    pub dc_dns_name: String,
    pub dc_netbios_name: String,
    pub user_name: String,
    pub dc_site_name: String,
    pub client_site_name: String,
    pub server_flags: u32,
    pub domain_guid: [u8; 16],
}

impl CldapDcInfo {
    /// True if the DC is the Primary Domain Controller (PDC) emulator.
    pub fn is_pdc(&self) -> bool {
        self.server_flags & dc_flags::DS_PDC_FLAG != 0
    }

    /// True if the DC is a Global Catalog (GC) server.
    pub fn is_gc(&self) -> bool {
        self.server_flags & dc_flags::DS_GC_FLAG != 0
    }

    /// True if the DC is running the Kerberos Key Distribution Center (KDC).
    pub fn is_kdc(&self) -> bool {
        self.server_flags & dc_flags::DS_KDC_FLAG != 0
    }

    /// True if the DC is writable (not a Read-Only DC / RODC).
    pub fn is_writable(&self) -> bool {
        self.server_flags & dc_flags::DS_WRITABLE_FLAG != 0
    }
}

impl fmt::Display for CldapDcInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Domain: {} ({}) | DC: {} ({}) | Forest: {} | Site: {}",
            self.dns_domain_name,
            self.netbios_domain_name,
            self.dc_dns_name,
            self.dc_netbios_name,
            self.forest_name,
            self.dc_site_name
        )
    }
}

/// Builds a minimal unauthenticated CLDAP Netlogon search request packet.
///
/// Query filter: `(&(DnsDomain=*)(NtVer=\x06\x00\x00\x20))` requesting attribute `Netlogon`.
pub fn build_cldap_ping_packet(message_id: i32) -> Vec<u8> {
    let mut search_body = Vec::new();

    // baseObject: "" (octet string)
    search_body.extend_from_slice(&der::encode_tlv(0x04, &[]));
    // scope: baseObject (0)
    search_body.extend_from_slice(&der::encode_tlv(0x0a, &[0x00]));
    // derefAliases: neverDerefAliases (0)
    search_body.extend_from_slice(&der::encode_tlv(0x0a, &[0x00]));
    // sizeLimit: 0
    search_body.extend_from_slice(&der::encode_tlv(0x02, &[0x00]));
    // timeLimit: 0
    search_body.extend_from_slice(&der::encode_tlv(0x02, &[0x00]));
    // typesOnly: false
    search_body.extend_from_slice(&der::encode_tlv(0x01, &[0x00]));

    // Filter: Present filter (tag 0x87) for DnsDomain
    let filter = der::encode_tlv(0x87, b"DnsDomain");
    search_body.extend_from_slice(&filter);

    // Attributes: SEQUENCE of AttributeDescription { "Netlogon" }
    let attr_netlogon = der::encode_tlv(0x04, b"Netlogon");
    let attributes_seq = der::encode_tlv(0x30, &attr_netlogon);
    search_body.extend_from_slice(&attributes_seq);

    // ProtocolOp: SearchRequest [APPLICATION 3] (0x63)
    let search_req = der::encode_tlv(0x63, &search_body);

    // Top-level LDAPMessage: SEQUENCE { messageID INTEGER, protocolOp }
    let msg_id_bytes = message_id.to_be_bytes();
    let msg_id_der = der::encode_tlv(0x02, &msg_id_bytes[3..]); // minimal integer
    let mut message = Vec::new();
    message.extend_from_slice(&msg_id_der);
    message.extend_from_slice(&search_req);

    der::encode_tlv(0x30, &message)
}

/// Reads a null-terminated or length-prefixed string from a slice at `*offset`.
fn read_netlogon_string(data: &[u8], offset: &mut usize) -> String {
    if *offset >= data.len() {
        return String::new();
    }
    // Check RFC 1035 compressed format or null-terminated string
    let start = *offset;
    while *offset < data.len() && data[*offset] != 0 {
        *offset += 1;
    }
    let s = String::from_utf8_lossy(&data[start..*offset]).to_string();
    if *offset < data.len() && data[*offset] == 0 {
        *offset += 1;
    }
    s
}

/// Parses the raw `LOGON_SAM_LOGON_RESPONSE_EX` binary payload (`[MS-NRPC]` §2.2.1.4.2).
pub fn parse_logon_sam_logon_response_ex(blob: &[u8]) -> Result<CldapDcInfo, CoreError> {
    if blob.len() < 24 {
        return Err(CoreError::BufferUnderflow {
            needed: 24,
            available: blob.len(),
        });
    }

    let mut cursor = 0;
    let opcode = u16::from_le_bytes([blob[cursor], blob[cursor + 1]]);
    cursor += 2;
    let _sbz = u16::from_le_bytes([blob[cursor], blob[cursor + 1]]);
    cursor += 2;
    let server_flags = u32::from_le_bytes([
        blob[cursor],
        blob[cursor + 1],
        blob[cursor + 2],
        blob[cursor + 3],
    ]);
    cursor += 4;

    let mut domain_guid = [0u8; 16];
    domain_guid.copy_from_slice(&blob[cursor..cursor + 16]);
    cursor += 16;

    // Check opcode: 0x17 = LOGON_SAM_LOGON_RESPONSE_EX
    if opcode != 0x17 && opcode != 0x13 {
        return Err(CoreError::ProtocolError(format!(
            "Unexpected Netlogon opcode 0x{:04x}",
            opcode
        )));
    }

    let forest_name = read_netlogon_string(blob, &mut cursor);
    let dns_domain_name = read_netlogon_string(blob, &mut cursor);
    let dc_dns_name = read_netlogon_string(blob, &mut cursor);
    let netbios_domain_name = read_netlogon_string(blob, &mut cursor);
    let dc_netbios_name = read_netlogon_string(blob, &mut cursor);
    let user_name = read_netlogon_string(blob, &mut cursor);
    let dc_site_name = read_netlogon_string(blob, &mut cursor);
    let client_site_name = read_netlogon_string(blob, &mut cursor);

    Ok(CldapDcInfo {
        forest_name,
        dns_domain_name,
        netbios_domain_name,
        dc_dns_name,
        dc_netbios_name,
        user_name,
        dc_site_name,
        client_site_name,
        server_flags,
        domain_guid,
    })
}

/// Executes a live unauthenticated CLDAP ping against target IP.
pub fn cldap_ping(target_ip: IpAddr, timeout: Duration) -> Result<CldapDcInfo, CoreError> {
    let bind_addr: SocketAddr = match target_ip {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };

    let socket = UdpSocket::bind(bind_addr)
        .map_err(|e| CoreError::IoError(format!("Failed to bind UDP socket: {}", e)))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| CoreError::IoError(format!("Failed to set read timeout: {}", e)))?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(|e| CoreError::IoError(format!("Failed to set write timeout: {}", e)))?;

    let target_addr = SocketAddr::new(target_ip, CLDAP_DEFAULT_PORT);
    let packet = build_cldap_ping_packet(1);

    socket
        .send_to(&packet, target_addr)
        .map_err(|e| CoreError::IoError(format!("Failed to send CLDAP ping: {}", e)))?;

    let mut buf = [0u8; 4096];
    let (amt, _src) = socket
        .recv_from(&mut buf)
        .map_err(|e| CoreError::IoError(format!("CLDAP response timed out: {}", e)))?;

    let resp = &buf[..amt];

    // Find "Netlogon" octet string in the LDAP response
    if let Some(pos) = resp.windows(8).position(|w| w == b"Netlogon") {
        let value_start = pos + 8;
        if value_start < resp.len() {
            // Find start of binary payload
            return parse_logon_sam_logon_response_ex(&resp[value_start..]);
        }
    }

    Err(CoreError::ProtocolError(
        "CLDAP response did not contain Netlogon payload".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_cldap_ping_der() {
        let pkt = build_cldap_ping_packet(42);
        assert!(!pkt.is_empty());
        assert_eq!(pkt[0], 0x30); // Top-level SEQUENCE
        assert!(pkt.windows(9).any(|w| w == b"DnsDomain"));
        assert!(pkt.windows(8).any(|w| w == b"Netlogon"));
    }

    #[test]
    fn test_parse_logon_sam_logon_response_ex_mock() {
        let mut blob = Vec::new();
        // Opcode: 0x17 (2 bytes)
        blob.extend_from_slice(&0x0017u16.to_le_bytes());
        // Sbz: 0 (2 bytes)
        blob.extend_from_slice(&0x0000u16.to_le_bytes());
        // ServerFlags: DS_PDC_FLAG | DS_KDC_FLAG | DS_GC_FLAG (0x25)
        let flags = dc_flags::DS_PDC_FLAG | dc_flags::DS_KDC_FLAG | dc_flags::DS_GC_FLAG;
        blob.extend_from_slice(&flags.to_le_bytes());
        // DomainGuid: 16 bytes
        blob.extend_from_slice(&[0xaa; 16]);
        // Strings (null terminated)
        blob.extend_from_slice(b"corp.local\x00"); // Forest
        blob.extend_from_slice(b"corp.local\x00"); // DnsDomain
        blob.extend_from_slice(b"dc01.corp.local\x00"); // DnsHost
        blob.extend_from_slice(b"CORP\x00"); // NetbiosDomain
        blob.extend_from_slice(b"DC01\x00"); // NetbiosHost
        blob.extend_from_slice(b"\x00"); // User
        blob.extend_from_slice(b"Default-First-Site-Name\x00"); // DcSite
        blob.extend_from_slice(b"Default-First-Site-Name\x00"); // ClientSite

        let info = parse_logon_sam_logon_response_ex(&blob).unwrap();
        assert_eq!(info.dns_domain_name, "corp.local");
        assert_eq!(info.netbios_domain_name, "CORP");
        assert_eq!(info.dc_dns_name, "dc01.corp.local");
        assert_eq!(info.dc_netbios_name, "DC01");
        assert_eq!(info.forest_name, "corp.local");
        assert_eq!(info.dc_site_name, "Default-First-Site-Name");
        assert!(info.is_pdc());
        assert!(info.is_kdc());
        assert!(info.is_gc());
    }
}
