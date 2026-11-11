//! `wkst`: `[MS-WKST]` Workstation Service Remote Protocol client (`impacket/dcerpc/v5/wkst.py`).
//!
//! Implements:
//! - `NetrWkstaGetInfo` (opnum 0) at information level 100 (`WKSTA_INFO_100`): platform ID,
//!   computer name, LAN group / domain name, and OS version major/minor.
//! - `NetrWkstaUserEnum` (opnum 2) at information level 1 (`WKSTA_USER_INFO_1`): logged-on
//!   usernames, logon domains, other domains, and logon server names.
//! - `NetrGetJoinInformation` (opnum 20): workstation domain/workgroup join status.
//!
//! Powers `netview -users` / `netview -info` over `\PIPE\wkssvc` (ncacn_np) or TCP RPC.

use crate::dtypes::{read_string_wchar_pointee, write_string_wchar_pointee, REFERENT_BASE};
use impacket_core::CoreError;
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport, RpcUuid};
use impacket_ndr::{NdrReader, NdrWriter};

/// Workstation Service Interface UUID (`6BFFD098-A112-3610-9833-46C3F87E345A` v1.0).
pub const WKST_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0x6bffd098,
    0xa112,
    0x3610,
    [0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a],
);
pub const WKST_VERSION_MAJOR: u16 = 1;
pub const WKST_VERSION_MINOR: u16 = 0;

pub mod opnum {
    pub const NETR_WKSTA_GET_INFO: u16 = 0;
    pub const NETR_WKSTA_USER_ENUM: u16 = 2;
    pub const NETR_GET_JOIN_INFORMATION: u16 = 20;
}

/// Workstation join status returned by `NetrGetJoinInformation` (`NETSETUP_JOIN_STATUS` in `[MS-WKST] 2.2.3.1`).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NetJoinStatus {
    Unknown = 0,
    Unjoined = 1,
    Workgroup = 2,
    Domain = 3,
}

impl NetJoinStatus {
    pub fn from_u32(raw: u32) -> Self {
        match raw {
            1 => Self::Unjoined,
            2 => Self::Workgroup,
            3 => Self::Domain,
            _ => Self::Unknown,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Unjoined => "Unjoined",
            Self::Workgroup => "Workgroup",
            Self::Domain => "Domain",
        }
    }
}

/// Workstation information level 100 (`WKSTA_INFO_100` in `[MS-WKST] 2.2.5.1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WkstaInfo100 {
    pub platform_id: u32,
    pub computer_name: String,
    pub langroup: String,
    pub ver_major: u32,
    pub ver_minor: u32,
}

/// Workstation logged-on user record level 1 (`WKSTA_USER_INFO_1` in `[MS-WKST] 2.2.5.10`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WkstaUserInfo1 {
    pub username: String,
    pub logon_domain: String,
    pub oth_domains: String,
    pub logon_server: String,
}

/// Builds the request stub for `NetrWkstaGetInfo` level 100 (`[MS-WKST] 3.2.4.1`).
pub fn build_netr_wksta_get_info_stub(server_name: &str, level: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    if server_name.is_empty() {
        w.write_u32(0); // NULL ServerName
    } else {
        w.write_u32(REFERENT_BASE); // ServerName pointer referent
        write_string_wchar_pointee(&mut w, server_name);
        w.align(4);
    }
    w.write_u32(level); // Level
    w.into_bytes()
}

/// Parses a `NetrWkstaGetInfo` level-100 response stub.
pub fn parse_netr_wksta_get_info_response(stub: &[u8]) -> Result<WkstaInfo100, CoreError> {
    let mut r = NdrReader::new(stub);
    let level = r.read_u32()?;
    if level != 100 {
        return Err(CoreError::ProtocolError(format!(
            "Unsupported WKSTA_INFO level {} (expected 100)",
            level
        )));
    }
    let ptr = r.read_u32()?;
    if ptr == 0 {
        return Err(CoreError::ProtocolError("Null WkstaInfo100 pointer returned".into()));
    }
    let platform_id = r.read_u32()?;
    let comp_ref = r.read_u32()?;
    let langroup_ref = r.read_u32()?;
    let ver_major = r.read_u32()?;
    let ver_minor = r.read_u32()?;

    let computer_name = if comp_ref != 0 {
        read_string_wchar_pointee(&mut r)?
    } else {
        String::new()
    };

    let langroup = if langroup_ref != 0 {
        read_string_wchar_pointee(&mut r)?
    } else {
        String::new()
    };

    let error_code = r.read_u32()?;
    if error_code != 0 {
        return Err(CoreError::ProtocolError(format!(
            "NetrWkstaGetInfo failed with error 0x{:08X}",
            error_code
        )));
    }

    Ok(WkstaInfo100 {
        platform_id,
        computer_name,
        langroup,
        ver_major,
        ver_minor,
    })
}

/// Builds a wire-accurate `NetrWkstaGetInfo` level-100 response stub (test fixture).
pub fn build_netr_wksta_get_info_response(info: &WkstaInfo100, error_code: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);
    w.write_u32(100); // Level
    w.write_u32(REFERENT_BASE); // WkstaInfo100 pointer
    w.write_u32(info.platform_id);
    w.write_u32(REFERENT_BASE + 4); // computer_name referent
    w.write_u32(REFERENT_BASE + 8); // langroup referent
    w.write_u32(info.ver_major);
    w.write_u32(info.ver_minor);

    write_string_wchar_pointee(&mut w, &info.computer_name);
    write_string_wchar_pointee(&mut w, &info.langroup);

    w.write_u32(error_code);
    w.into_bytes()
}

/// Builds the request stub for `NetrWkstaUserEnum` level 1 (`[MS-WKST] 3.2.4.3`).
pub fn build_netr_wksta_user_enum_stub(server_name: &str, level: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    if server_name.is_empty() {
        w.write_u32(0);
    } else {
        w.write_u32(REFERENT_BASE);
        write_string_wchar_pointee(&mut w, server_name);
        w.align(4);
    }
    // WKSTA_USER_ENUM_STRUCT
    w.write_u32(level); // Level = 1
    w.write_u32(level); // Union tag = 1
    w.write_u32(REFERENT_BASE + 4); // Container referent
    w.write_u32(0); // EntriesRead = 0
    w.write_u32(0); // Buffer = NULL
    w.write_u32(0xFFFF_FFFF); // PreferredMaximumLength = MAX_PREFERRED_LENGTH
    w.write_u32(0); // ResumeHandle = NULL
    w.into_bytes()
}

/// Parses a `NetrWkstaUserEnum` level-1 response stub into `WkstaUserInfo1` records.
pub fn parse_netr_wksta_user_enum_response(stub: &[u8]) -> Result<Vec<WkstaUserInfo1>, CoreError> {
    let mut r = NdrReader::new(stub);
    let level = r.read_u32()?;
    if level != 1 {
        return Err(CoreError::ProtocolError(format!(
            "Unsupported WKSTA_USER_INFO level {} (expected 1)",
            level
        )));
    }
    let _tag = r.read_u32()?;
    let container_ref = r.read_u32()?;
    if container_ref == 0 {
        return Ok(Vec::new());
    }

    let entries_read = r.read_u32()? as usize;
    let buf_ref = r.read_u32()?;
    if buf_ref == 0 || entries_read == 0 {
        return Ok(Vec::new());
    }

    let max_count = r.read_u32()? as usize;
    let count = entries_read.min(max_count);

    let mut ptrs = Vec::with_capacity(count);
    for _ in 0..count {
        let u_ref = r.read_u32()?;
        let d_ref = r.read_u32()?;
        let o_ref = r.read_u32()?;
        let s_ref = r.read_u32()?;
        ptrs.push((u_ref, d_ref, o_ref, s_ref));
    }

    let mut users = Vec::with_capacity(count);
    for (u_ref, d_ref, o_ref, s_ref) in ptrs {
        let username = if u_ref != 0 {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        let logon_domain = if d_ref != 0 {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        let oth_domains = if o_ref != 0 {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        let logon_server = if s_ref != 0 {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        users.push(WkstaUserInfo1 {
            username,
            logon_domain,
            oth_domains,
            logon_server,
        });
    }

    let _total_entries = r.read_u32()?;
    let remaining = r.remaining();
    let error_code = if remaining >= 8 {
        let _resume_ptr = r.read_u32()?;
        r.read_u32()?
    } else if remaining >= 4 {
        r.read_u32()?
    } else {
        0
    };

    if error_code != 0 && error_code != 0x0000_00EA {
        return Err(CoreError::ProtocolError(format!(
            "NetrWkstaUserEnum failed with error 0x{:08X}",
            error_code
        )));
    }

    Ok(users)
}

/// Builds a wire-accurate `NetrWkstaUserEnum` level-1 response stub (test fixture).
pub fn build_netr_wksta_user_enum_response(users: &[WkstaUserInfo1], error_code: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(256);
    w.write_u32(1); // Level
    w.write_u32(1); // Union tag
    w.write_u32(REFERENT_BASE); // Container referent

    let count = users.len() as u32;
    w.write_u32(count); // EntriesRead
    w.write_u32(REFERENT_BASE + 4); // Buffer referent
    w.write_u32(count); // MaxCount

    for (i, _) in users.iter().enumerate() {
        let base = REFERENT_BASE + 8 + (i as u32) * 4;
        w.write_u32(base);
        w.write_u32(base + 1);
        w.write_u32(base + 2);
        w.write_u32(base + 3);
    }

    for u in users {
        write_string_wchar_pointee(&mut w, &u.username);
        write_string_wchar_pointee(&mut w, &u.logon_domain);
        write_string_wchar_pointee(&mut w, &u.oth_domains);
        write_string_wchar_pointee(&mut w, &u.logon_server);
    }

    w.write_u32(count); // TotalEntries
    w.write_u32(0); // ResumeHandle = NULL
    w.write_u32(error_code);
    w.into_bytes()
}

/// Builds the request stub for `NetrGetJoinInformation` (`[MS-WKST] 3.2.4.13`).
pub fn build_netr_get_join_information_stub(server_name: &str) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    if server_name.is_empty() {
        w.write_u32(0);
    } else {
        w.write_u32(REFERENT_BASE);
        write_string_wchar_pointee(&mut w, server_name);
        w.align(4);
    }
    w.into_bytes()
}

/// Parses a `NetrGetJoinInformation` response stub into `(join_name, join_status)`.
pub fn parse_netr_get_join_information_response(stub: &[u8]) -> Result<(String, NetJoinStatus), CoreError> {
    let mut r = NdrReader::new(stub);
    let name_ref = r.read_u32()?;
    let name = if name_ref != 0 {
        read_string_wchar_pointee(&mut r)?
    } else {
        String::new()
    };
    let buffer_type = r.read_u32()?;
    let error_code = r.read_u32()?;
    if error_code != 0 {
        return Err(CoreError::ProtocolError(format!(
            "NetrGetJoinInformation failed with error 0x{:08X}",
            error_code
        )));
    }
    Ok((name, NetJoinStatus::from_u32(buffer_type)))
}

/// Builds a wire-accurate `NetrGetJoinInformation` response stub (test fixture).
pub fn build_netr_get_join_information_response(
    name: &str,
    status: NetJoinStatus,
    error_code: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_u32(REFERENT_BASE);
    write_string_wchar_pointee(&mut w, name);
    w.write_u32(status as u32);
    w.write_u32(error_code);
    w.into_bytes()
}

/// High-level client for `[MS-WKST]` Workstation Service Remote Protocol.
pub struct WkstClient<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> WkstClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            call_id: 1,
        }
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    fn rpc_call(&mut self, opnum: u16, stub: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let call_id = self.call_id;
        self.call_id = self.call_id.wrapping_add(1);
        let pdu = RpcRequestPdu {
            call_id,
            context_id: 0,
            opnum,
            stub_data: stub,
        }
        .to_bytes();
        let resp_bytes = self.transport.transceive(&pdu)?;
        extract_response_stub(&resp_bytes)
    }

    /// Queries workstation information level 100 (`NetrWkstaGetInfo`).
    pub fn get_info(&mut self, server_name: &str) -> Result<WkstaInfo100, CoreError> {
        let stub = build_netr_wksta_get_info_stub(server_name, 100);
        let resp = self.rpc_call(opnum::NETR_WKSTA_GET_INFO, stub)?;
        parse_netr_wksta_get_info_response(&resp)
    }

    /// Enumerates logged on users level 1 (`NetrWkstaUserEnum`).
    pub fn enumerate_users(&mut self, server_name: &str) -> Result<Vec<WkstaUserInfo1>, CoreError> {
        let stub = build_netr_wksta_user_enum_stub(server_name, 1);
        let resp = self.rpc_call(opnum::NETR_WKSTA_USER_ENUM, stub)?;
        parse_netr_wksta_user_enum_response(&resp)
    }

    /// Queries workstation domain/workgroup join information (`NetrGetJoinInformation`).
    pub fn get_join_information(
        &mut self,
        server_name: &str,
    ) -> Result<(String, NetJoinStatus), CoreError> {
        let stub = build_netr_get_join_information_stub(server_name);
        let resp = self.rpc_call(opnum::NETR_GET_JOIN_INFORMATION, stub)?;
        parse_netr_get_join_information_response(&resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netr_wksta_get_info_roundtrip() {
        let info = WkstaInfo100 {
            platform_id: 500,
            computer_name: "WORKSTATION01".into(),
            langroup: "CORP".into(),
            ver_major: 10,
            ver_minor: 0,
        };

        let resp_stub = build_netr_wksta_get_info_response(&info, 0);
        let parsed = parse_netr_wksta_get_info_response(&resp_stub).unwrap();
        assert_eq!(parsed, info);
    }

    #[test]
    fn test_netr_wksta_user_enum_roundtrip() {
        let users = vec![
            WkstaUserInfo1 {
                username: "Administrator".into(),
                logon_domain: "CORP".into(),
                oth_domains: "".into(),
                logon_server: r"\\DC01".into(),
            },
            WkstaUserInfo1 {
                username: "Alice".into(),
                logon_domain: "CORP".into(),
                oth_domains: "".into(),
                logon_server: r"\\DC02".into(),
            },
        ];

        let resp_stub = build_netr_wksta_user_enum_response(&users, 0);
        let parsed = parse_netr_wksta_user_enum_response(&resp_stub).unwrap();
        assert_eq!(parsed, users);
    }

    #[test]
    fn test_netr_get_join_information_roundtrip() {
        let resp_stub = build_netr_get_join_information_response("CORP.LOCAL", NetJoinStatus::Domain, 0);
        let (name, status) = parse_netr_get_join_information_response(&resp_stub).unwrap();
        assert_eq!(name, "CORP.LOCAL");
        assert_eq!(status, NetJoinStatus::Domain);
    }

    struct MockTransport {
        response_stub: Vec<u8>,
    }

    impl RpcTransport for MockTransport {
        fn transceive(&mut self, _req: &[u8]) -> Result<Vec<u8>, CoreError> {
            use impacket_dcerpc::{pdu_type, RpcCommonHeader};
            use impacket_ndr::NdrSerialize;

            let frag_len = (24 + self.response_stub.len()) as u16;
            let hdr = RpcCommonHeader::new(pdu_type::RPC_RESPONSE, frag_len, 0, 1);
            let mut w = NdrWriter::with_capacity(frag_len as usize);
            hdr.ndr_serialize(&mut w);
            w.write_u32(self.response_stub.len() as u32);
            w.write_u16(0);
            w.write_u16(0);
            w.write_bytes(&self.response_stub);
            Ok(w.into_bytes())
        }
    }

    #[test]
    fn test_wkst_client_mock_methods() {
        let info = WkstaInfo100 {
            platform_id: 500,
            computer_name: "PC01".into(),
            langroup: "TEST".into(),
            ver_major: 10,
            ver_minor: 0,
        };
        let mut client = WkstClient::new(MockTransport {
            response_stub: build_netr_wksta_get_info_response(&info, 0),
        });
        let res = client.get_info("PC01").unwrap();
        assert_eq!(res.computer_name, "PC01");

        let users = vec![WkstaUserInfo1 {
            username: "Bob".into(),
            logon_domain: "TEST".into(),
            oth_domains: "".into(),
            logon_server: r"\\DC".into(),
        }];
        let mut client_u = WkstClient::new(MockTransport {
            response_stub: build_netr_wksta_user_enum_response(&users, 0),
        });
        let res_u = client_u.enumerate_users("PC01").unwrap();
        assert_eq!(res_u.len(), 1);
        assert_eq!(res_u[0].username, "Bob");

        let mut client_j = WkstClient::new(MockTransport {
            response_stub: build_netr_get_join_information_response("TEST.LOCAL", NetJoinStatus::Domain, 0),
        });
        let (j_name, j_stat) = client_j.get_join_information("PC01").unwrap();
        assert_eq!(j_name, "TEST.LOCAL");
        assert_eq!(j_stat, NetJoinStatus::Domain);
    }
}
