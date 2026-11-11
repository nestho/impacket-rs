//! `bindings`: `DUALSTRINGARRAY`, `STRINGBINDING`, and `SECURITYBINDING` parser and serializer (`[MS-DCOM]` Section 2.2.19).

use impacket_core::CoreError;
use impacket_ndr::{NdrReader, NdrWriter};

pub mod tower_id {
    pub const NCACN_NB_NB: u16 = 0x0004;
    pub const NCACN_IP_TCP: u16 = 0x0007;
    pub const NCACN_NP: u16 = 0x0009;
    pub const NCACN_HTTP: u16 = 0x001F;
}

pub mod authn_svc {
    pub const NONE: u16 = 0x0000;
    pub const DCE_PRIVATE: u16 = 0x0001;
    pub const DCE_PUBLIC: u16 = 0x0002;
    pub const DEC_PUBLIC: u16 = 0x0004;
    pub const SPNEGO: u16 = 0x0009;
    pub const NTLMSSP: u16 = 0x000A;
    pub const SCHANNEL: u16 = 0x000E;
    pub const KERBEROS: u16 = 0x0010;
    pub const DEFAULT: u16 = 0xFFFF;
}

/// A network protocol binding entry (`STRINGBINDING`, `[MS-DCOM]` Section 2.2.19.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringBinding {
    pub tower_id: u16,
    pub network_addr: String,
}

impl StringBinding {
    pub fn new(tower_id: u16, network_addr: impl Into<String>) -> Self {
        Self {
            tower_id,
            network_addr: network_addr.into(),
        }
    }

    pub fn tower_name(&self) -> &'static str {
        match self.tower_id {
            tower_id::NCACN_IP_TCP => "ncacn_ip_tcp",
            tower_id::NCACN_NP => "ncacn_np",
            tower_id::NCACN_NB_NB => "ncacn_nb_nb",
            tower_id::NCACN_HTTP => "ncacn_http",
            _ => "unknown",
        }
    }
}

/// A security provider binding entry (`SECURITYBINDING`, `[MS-DCOM]` Section 2.2.19.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityBinding {
    pub authn_svc: u16,
    pub authz_svc: u16,
    pub princ_name: String,
}

impl SecurityBinding {
    pub fn new(authn_svc: u16, authz_svc: u16, princ_name: impl Into<String>) -> Self {
        Self {
            authn_svc,
            authz_svc,
            princ_name: princ_name.into(),
        }
    }

    pub fn authn_name(&self) -> &'static str {
        match self.authn_svc {
            authn_svc::NONE => "None",
            authn_svc::SPNEGO => "SPNEGO",
            authn_svc::NTLMSSP => "NTLMSSP",
            authn_svc::KERBEROS => "Kerberos",
            authn_svc::SCHANNEL => "Schannel",
            _ => "Unknown",
        }
    }
}

/// `DUALSTRINGARRAY`: Container for string and security bindings (`[MS-DCOM]` Section 2.2.19.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DualStringArray {
    pub string_bindings: Vec<StringBinding>,
    pub security_bindings: Vec<SecurityBinding>,
}

impl DualStringArray {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serializes into NDR conformant array layout.
    pub fn serialize(&self, writer: &mut NdrWriter) {
        let mut words: Vec<u16> = Vec::new();

        // 1. String bindings
        for sb in &self.string_bindings {
            words.push(sb.tower_id);
            for c in sb.network_addr.encode_utf16() {
                words.push(c);
            }
            words.push(0x0000); // null terminator for string
        }
        words.push(0x0000); // extra null terminator for string bindings list

        let security_offset = words.len() as u16;

        // 2. Security bindings
        for sec in &self.security_bindings {
            words.push(sec.authn_svc);
            words.push(sec.authz_svc);
            for c in sec.princ_name.encode_utf16() {
                words.push(c);
            }
            words.push(0x0000); // null terminator for princ name
        }
        words.push(0x0000); // extra null terminator for security bindings list

        let num_entries = words.len() as u16;

        // NDR Conformant Array header
        writer.write_u32(num_entries as u32);
        writer.write_u16(num_entries);
        writer.write_u16(security_offset);
        for w in words {
            writer.write_u16(w);
        }
    }

    /// Parses from an NDR reader stream.
    pub fn deserialize(reader: &mut NdrReader) -> Result<Self, CoreError> {
        let max_count = reader.read_u32()? as usize;
        let num_entries = reader.read_u16()? as usize;
        let security_offset = reader.read_u16()? as usize;

        if num_entries > max_count {
            return Err(CoreError::ProtocolError(format!(
                "DUALSTRINGARRAY num_entries ({}) exceeds max_count ({})",
                num_entries, max_count
            )));
        }

        let mut words = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            words.push(reader.read_u16()?);
        }

        let mut string_bindings = Vec::new();
        let mut security_bindings = Vec::new();

        // Walk string bindings [0..security_offset]
        let mut idx = 0;
        while idx < security_offset.min(words.len()) {
            let tower_id = words[idx];
            if tower_id == 0 {
                break;
            }
            idx += 1;

            let mut str_chars = Vec::new();
            while idx < security_offset.min(words.len()) && words[idx] != 0 {
                str_chars.push(words[idx]);
                idx += 1;
            }
            if idx < words.len() && words[idx] == 0 {
                idx += 1; // skip null terminator
            }

            let network_addr = String::from_utf16_lossy(&str_chars);
            string_bindings.push(StringBinding::new(tower_id, network_addr));
        }

        // Walk security bindings [security_offset..num_entries]
        idx = security_offset;
        while idx + 2 <= words.len() {
            let authn_svc = words[idx];
            if authn_svc == 0 {
                break;
            }
            let authz_svc = words[idx + 1];
            idx += 2;

            let mut princ_chars = Vec::new();
            while idx < words.len() && words[idx] != 0 {
                princ_chars.push(words[idx]);
                idx += 1;
            }
            if idx < words.len() && words[idx] == 0 {
                idx += 1; // skip null terminator
            }

            let princ_name = String::from_utf16_lossy(&princ_chars);
            security_bindings.push(SecurityBinding::new(authn_svc, authz_svc, princ_name));
        }

        Ok(Self {
            string_bindings,
            security_bindings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dual_string_array_roundtrip() {
        let mut dsa = DualStringArray::new();
        dsa.string_bindings.push(StringBinding::new(
            tower_id::NCACN_IP_TCP,
            "192.168.1.10",
        ));
        dsa.string_bindings.push(StringBinding::new(
            tower_id::NCACN_IP_TCP,
            "fe80::1",
        ));
        dsa.string_bindings.push(StringBinding::new(
            tower_id::NCACN_NP,
            "DC01",
        ));

        dsa.security_bindings.push(SecurityBinding::new(
            authn_svc::KERBEROS,
            0xFFFF,
            "RPCSS/DC01.corp.contoso.com",
        ));
        dsa.security_bindings.push(SecurityBinding::new(
            authn_svc::NTLMSSP,
            0xFFFF,
            "",
        ));

        let mut writer = NdrWriter::new();
        dsa.serialize(&mut writer);

        let mut reader = NdrReader::new(writer.as_slice());
        let decoded = DualStringArray::deserialize(&mut reader).unwrap();

        assert_eq!(decoded.string_bindings.len(), 3);
        assert_eq!(decoded.string_bindings[0].network_addr, "192.168.1.10");
        assert_eq!(decoded.string_bindings[0].tower_name(), "ncacn_ip_tcp");
        assert_eq!(decoded.string_bindings[1].network_addr, "fe80::1");
        assert_eq!(decoded.string_bindings[2].network_addr, "DC01");

        assert_eq!(decoded.security_bindings.len(), 2);
        assert_eq!(decoded.security_bindings[0].princ_name, "RPCSS/DC01.corp.contoso.com");
        assert_eq!(decoded.security_bindings[0].authn_name(), "Kerberos");
        assert_eq!(decoded.security_bindings[1].authn_name(), "NTLMSSP");
    }
}
