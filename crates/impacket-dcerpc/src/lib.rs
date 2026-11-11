//! `impacket-dcerpc`: MS-RPCE v5 connection-oriented PDU framing (`Bind`, `BindAck`, `Request`, `Response`),
//! Endpoint Mapper (`MS-RPCE` `ept_lookup` opnum 2 & protocol tower parser), and Active Directory
//! MSRPC interface definitions (`EPM`, `SAMR`, `LSARPC`, `DRSUAPI`, `SCMR`, `SRVS`, `WKST`, `RRP`).
//!
//! Includes both Sans-I/O stream exchange (`rpcdump_over_stream`) and live TCP/135 Endpoint Mapper
//! client (`rpcdump_live`) implementing `examples/rpcdump.py`.

use impacket_core::CoreError;
use impacket_ndr::{ndr_struct, NdrDeserialize, NdrReader, NdrSerialize, NdrWriter};
pub use impacket_ndr::RpcUuid;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Standard 32-bit NDR Transfer Syntax UUID: `8a885d04-1ceb-11c9-9fe8-08002b104860` v2.0
pub const NDR_SYNTAX_UUID: RpcUuid = RpcUuid::new(
    0x8a88_5d04,
    0x1ceb,
    0x11c9,
    [0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60],
);

/// 64-bit NDR64 Transfer Syntax UUID: `71710533-beba-4937-8319-b5dbef9ccc36` v1.0
pub const NDR64_SYNTAX_UUID: RpcUuid = RpcUuid::new(
    0x7171_0533,
    0xbeba,
    0x4937,
    [0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36],
);

/// MS-RPCE Endpoint Mapper Interface UUID: `e1af8308-5d1f-11c9-91a4-08002b14a0fa` v3.0
pub const EPM_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0xe1af_8308,
    0x5d1f,
    0x11c9,
    [0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa],
);

/// Well-known MSRPC Interface Catalog (used by `rpcdump`, `secretsdump`, `samrdump`, `psexec`).
pub struct MsrpcInterfaceInfo {
    pub short_name: &'static str,
    pub provider_binary: &'static str,
    pub uuid: RpcUuid,
    pub version_major: u16,
    pub version_minor: u16,
    pub named_pipe: &'static str,
    pub description: &'static str,
}

pub const WELL_KNOWN_INTERFACES: &[MsrpcInterfaceInfo] = &[
    MsrpcInterfaceInfo {
        short_name: "MS-RPCE (EPM)",
        provider_binary: "rpcss.dll",
        uuid: EPM_INTERFACE_UUID,
        version_major: 3,
        version_minor: 0,
        named_pipe: r"\PIPE\epmapper",
        description: "DCE/RPC Endpoint Mapper (rpcdump)",
    },
    MsrpcInterfaceInfo {
        short_name: "MS-SAMR",
        provider_binary: "samsrv.dll",
        uuid: RpcUuid::new(0x1234_5778, 0x1234, 0xabcd, [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac]),
        version_major: 1,
        version_minor: 0,
        named_pipe: r"\PIPE\samr",
        description: "Security Account Manager Remote Protocol (samrdump, secretsdump)",
    },
    MsrpcInterfaceInfo {
        short_name: "MS-LSAD / LSAT",
        provider_binary: "lsasrv.dll",
        uuid: RpcUuid::new(0x1234_5778, 0x1234, 0xabcd, [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab]),
        version_major: 0,
        version_minor: 0,
        named_pipe: r"\PIPE\lsarpc",
        description: "Local Security Authority Domain Policy & Translation (lookupsid, secretsdump)",
    },
    MsrpcInterfaceInfo {
        short_name: "MS-DRSR (DRSUAPI)",
        provider_binary: "ntdsai.dll",
        uuid: RpcUuid::new(0xe351_4235, 0x4b06, 0x11d1, [0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2]),
        version_major: 4,
        version_minor: 0,
        named_pipe: r"TCP/Dynamic",
        description: "Directory Replication Service DRSGetNCChanges (secretsdump DCSync)",
    },
    MsrpcInterfaceInfo {
        short_name: "MS-NRPC (Netlogon)",
        provider_binary: "netlogon.dll",
        uuid: RpcUuid::new(0x1234_5678, 0x1234, 0xabcd, [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb]),
        version_major: 1,
        version_minor: 0,
        named_pipe: r"\PIPE\netlogon",
        description: "Netlogon Remote Protocol (ZeroLogon, Domain Controller authentication)",
    },
    MsrpcInterfaceInfo {
        short_name: "MS-SCMR",
        provider_binary: "services.exe",
        uuid: RpcUuid::new(0x367a_bb81, 0x9844, 0x35f1, [0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03]),
        version_major: 2,
        version_minor: 0,
        named_pipe: r"\PIPE\svcctl",
        description: "Service Control Manager Remote Protocol (psexec, smbexec, services)",
    },
    MsrpcInterfaceInfo {
        short_name: "MS-SRVS",
        provider_binary: "srvsvc.dll",
        uuid: RpcUuid::new(0x4b32_4fc8, 0x1670, 0x01d3, [0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88]),
        version_major: 3,
        version_minor: 0,
        named_pipe: r"\PIPE\srvsvc",
        description: "Server Service Remote Protocol (netview, smbclient shares)",
    },
    MsrpcInterfaceInfo {
        short_name: "MS-RRP (WINREG)",
        provider_binary: "regsvc.dll",
        uuid: RpcUuid::new(0x338c_d001, 0x2244, 0x31f1, [0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03]),
        version_major: 1,
        version_minor: 0,
        named_pipe: r"\PIPE\winreg",
        description: "Windows Remote Registry Protocol (reg, secretsdump remote hive save)",
    },
    MsrpcInterfaceInfo {
        short_name: "MS-TSCH (Task Scheduler)",
        provider_binary: "schedsvc.dll",
        uuid: RpcUuid::new(0x86d3_5949, 0x83c9, 0x4044, [0xb4, 0x24, 0xdb, 0x36, 0x32, 0x31, 0xfd, 0x0c]),
        version_major: 1,
        version_minor: 0,
        named_pipe: r"\PIPE\atsvc",
        description: "Task Scheduler Service Remote Protocol (atexec)",
    },
    MsrpcInterfaceInfo {
        short_name: "MS-WKST (Workstation)",
        provider_binary: "wkssvc.dll",
        uuid: RpcUuid::new(0x6bffd098, 0xa112, 0x3610, [0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a]),
        version_major: 1,
        version_minor: 0,
        named_pipe: r"\PIPE\wkssvc",
        description: "Workstation Service Remote Protocol (NetrWkstaUserEnum)",
    },
    MsrpcInterfaceInfo {
        short_name: "MGMT (DCE Management)",
        provider_binary: "rpcrt4.dll",
        uuid: RpcUuid::new(0xafa8_bd80, 0x7d8a, 0x11c9, [0xbe, 0xf4, 0x08, 0x00, 0x2b, 0x10, 0x29, 0x89]),
        version_major: 1,
        version_minor: 0,
        named_pipe: r"\PIPE\epmapper",
        description: "DCE/RPC Management Interface (rpcmap inq_if_ids)",
    },
    MsrpcInterfaceInfo {
        short_name: "MS-RPRN (Print System)",
        provider_binary: "spoolsv.exe",
        uuid: RpcUuid::new(0x1234_5678, 0x1234, 0xabcd, [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab]),
        version_major: 1,
        version_minor: 0,
        named_pipe: r"\PIPE\spoolss",
        description: "Print System Remote Protocol (SpoolSample, PrinterBug)",
    },
    MsrpcInterfaceInfo {
        short_name: "MS-EFSR (Encrypting File System)",
        provider_binary: "lsasrv.dll",
        uuid: RpcUuid::new(0xdf19_41c5, 0xfe89, 0x4e79, [0xbf, 0x10, 0x46, 0x36, 0x57, 0xac, 0xf4, 0x4d]),
        version_major: 1,
        version_minor: 0,
        named_pipe: r"\PIPE\efsrpc",
        description: "Encrypting File System Remote Protocol (PetitPotam)",
    },
    MsrpcInterfaceInfo {
        short_name: "MS-DFSNM (Distributed File System)",
        provider_binary: "dfssvc.exe",
        uuid: RpcUuid::new(0x4fc7_42e0, 0x4a10, 0x11cf, [0x82, 0x73, 0x00, 0xaa, 0x00, 0x4a, 0xe6, 0x73]),
        version_major: 3,
        version_minor: 0,
        named_pipe: r"\PIPE\netdfs",
        description: "DFS Namespace Management Protocol",
    },
    MsrpcInterfaceInfo {
        short_name: "MS-EVEN (Event Log)",
        provider_binary: "eventlog.dll",
        uuid: RpcUuid::new(0x8227_3fdc, 0xe32a, 0x18c3, [0x3f, 0x78, 0x82, 0x79, 0x29, 0xdc, 0x23, 0xea]),
        version_major: 0,
        version_minor: 0,
        named_pipe: r"\PIPE\eventlog",
        description: "EventLog Remoting Protocol",
    },
    MsrpcInterfaceInfo {
        short_name: "MS-EVEN6 (Event Log v6)",
        provider_binary: "wevtsvc.dll",
        uuid: RpcUuid::new(0xf6be_aff7, 0x1e19, 0x4fbb, [0x9f, 0x8f, 0xb8, 0x9e, 0x20, 0x18, 0x33, 0x7c]),
        version_major: 1,
        version_minor: 0,
        named_pipe: r"\PIPE\eventlog",
        description: "EventLog Remoting Protocol v6.0",
    },
];

pub fn lookup_known_interface(uuid: &RpcUuid) -> Option<&'static MsrpcInterfaceInfo> {
    WELL_KNOWN_INTERFACES.iter().find(|i| &i.uuid == uuid)
}

pub mod pdu_type {
    pub const RPC_REQUEST: u8 = 0;
    pub const RPC_RESPONSE: u8 = 2;
    pub const RPC_FAULT: u8 = 3;
    pub const RPC_BIND: u8 = 11;
    pub const RPC_BIND_ACK: u8 = 12;
    pub const RPC_BIND_NAK: u8 = 13;
    pub const RPC_ALTER_CONTEXT: u8 = 14;
    pub const RPC_ALTER_CONTEXT_RESP: u8 = 15;
}

pub mod pfc_flags {
    pub const PFC_FIRST_FRAG: u8 = 0x01;
    pub const PFC_LAST_FRAG: u8 = 0x02;
    pub const PFC_SUPPORT_HEADER_SIGN: u8 = 0x04;
    pub const PFC_CONC_MPX: u8 = 0x10;
}

pub mod rpc_auth_type {
    pub const RPC_C_AUTHN_NONE: u8 = 0;
    pub const RPC_C_AUTHN_GSS_NEGOTIATE: u8 = 9;
    pub const RPC_C_AUTHN_WINNT: u8 = 10;
    pub const RPC_C_AUTHN_GSS_KERBEROS: u8 = 16;
    pub const RPC_C_AUTHN_NETLOGON: u8 = 68;
}

pub mod rpc_auth_level {
    pub const RPC_C_AUTHN_LEVEL_DEFAULT: u8 = 0;
    pub const RPC_C_AUTHN_LEVEL_NONE: u8 = 1;
    pub const RPC_C_AUTHN_LEVEL_CONNECT: u8 = 2;
    pub const RPC_C_AUTHN_LEVEL_CALL: u8 = 3;
    pub const RPC_C_AUTHN_LEVEL_PKT: u8 = 4;
    pub const RPC_C_AUTHN_LEVEL_PKT_INTEGRITY: u8 = 5;
    pub const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u8 = 6;
}

ndr_struct! {
    /// 8-byte Security Trailer affixed to authenticated RPC PDUs (`[MS-RPCE]` 2.2.2.11).
    pub struct SecTrailer {
        pub auth_type: u8,
        pub auth_level: u8,
        pub auth_pad_length: u8,
        pub auth_reserved: u8,
        pub auth_context_id: u32,
    }
}

ndr_struct! {
    pub struct RpcCommonHeader {
        pub rpc_vers: u8,
        pub rpc_vers_minor: u8,
        pub ptype: u8,
        pub pfc_flags: u8,
        pub packed_drep: u32,
        pub frag_length: u16,
        pub auth_length: u16,
        pub call_id: u32,
    }
}

impl RpcCommonHeader {
    pub fn new(ptype: u8, frag_length: u16, auth_length: u16, call_id: u32) -> Self {
        Self {
            rpc_vers: 5,
            rpc_vers_minor: 0,
            ptype,
            pfc_flags: pfc_flags::PFC_FIRST_FRAG | pfc_flags::PFC_LAST_FRAG,
            packed_drep: 0x0000_0010,
            frag_length,
            auth_length,
            call_id,
        }
    }
}

/// Complete MS-RPCE v5 `Bind` PDU builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcBindPdu {
    pub call_id: u32,
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub abstract_syntax: RpcUuid,
    pub abstract_version_major: u16,
    pub abstract_version_minor: u16,
}

impl RpcBindPdu {
    pub fn new(call_id: u32, abstract_syntax: RpcUuid, major: u16, minor: u16) -> Self {
        Self {
            call_id,
            max_xmit_frag: 4280,
            max_recv_frag: 4280,
            assoc_group_id: 0,
            abstract_syntax,
            abstract_version_major: major,
            abstract_version_minor: minor,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = NdrWriter::with_capacity(72);
        let hdr = RpcCommonHeader::new(pdu_type::RPC_BIND, 72, 0, self.call_id);
        hdr.ndr_serialize(&mut writer);

        writer.write_u16(self.max_xmit_frag);
        writer.write_u16(self.max_recv_frag);
        writer.write_u32(self.assoc_group_id);
        writer.write_u8(1);
        writer.write_u8(0);
        writer.write_u16(0);

        writer.write_u16(0);
        writer.write_u8(1);
        writer.write_u8(0);

        self.abstract_syntax.ndr_serialize(&mut writer);
        writer.write_u16(self.abstract_version_major);
        writer.write_u16(self.abstract_version_minor);

        NDR_SYNTAX_UUID.ndr_serialize(&mut writer);
        writer.write_u32(2);

        writer.into_bytes()
    }

    pub fn to_bytes_with_transfer_syntax(
        &self,
        transfer_syntax: RpcUuid,
        transfer_version: u32,
    ) -> Vec<u8> {
        let mut writer = NdrWriter::with_capacity(72);
        let hdr = RpcCommonHeader::new(pdu_type::RPC_BIND, 72, 0, self.call_id);
        hdr.ndr_serialize(&mut writer);

        writer.write_u16(self.max_xmit_frag);
        writer.write_u16(self.max_recv_frag);
        writer.write_u32(self.assoc_group_id);
        writer.write_u8(1);
        writer.write_u8(0);
        writer.write_u16(0);

        writer.write_u16(0);
        writer.write_u8(1);
        writer.write_u8(0);

        self.abstract_syntax.ndr_serialize(&mut writer);
        writer.write_u16(self.abstract_version_major);
        writer.write_u16(self.abstract_version_minor);

        transfer_syntax.ndr_serialize(&mut writer);
        writer.write_u32(transfer_version);

        writer.into_bytes()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CoreError> {
        let mut reader = NdrReader::new(data);
        let hdr = RpcCommonHeader::ndr_deserialize(&mut reader)?;
        if hdr.rpc_vers != 5 || hdr.ptype != pdu_type::RPC_BIND {
            return Err(CoreError::ProtocolError("Not a valid RPC v5 Bind PDU".into()));
        }
        let max_xmit_frag = reader.read_u16()?;
        let max_recv_frag = reader.read_u16()?;
        let assoc_group_id = reader.read_u32()?;
        let _n_ctx = reader.read_u8()?;
        let _res1 = reader.read_u8()?;
        let _res2 = reader.read_u16()?;

        let _p_cont_id = reader.read_u16()?;
        let _n_transfer = reader.read_u8()?;
        let _res3 = reader.read_u8()?;

        let abstract_syntax = RpcUuid::ndr_deserialize(&mut reader)?;
        let abstract_version_major = reader.read_u16()?;
        let abstract_version_minor = reader.read_u16()?;

        Ok(Self {
            call_id: hdr.call_id,
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            abstract_syntax,
            abstract_version_major,
            abstract_version_minor,
        })
    }
}

/// MS-RPCE v5 `Request` (`ptype = 0`) PDU helper.
pub struct RpcRequestPdu {
    pub call_id: u32,
    pub context_id: u16,
    pub opnum: u16,
    pub stub_data: Vec<u8>,
}

impl RpcRequestPdu {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_with_auth(None, &[])
    }

    /// Serializes an RPC request with an optional security trailer and auth token (`[MS-RPCE]` 2.2.2.11).
    pub fn to_bytes_with_auth(&self, trailer: Option<&SecTrailer>, auth_value: &[u8]) -> Vec<u8> {
        let auth_trailer_len = if trailer.is_some() {
            8 + auth_value.len()
        } else {
            0
        };
        let frag_len = (24 + self.stub_data.len() + auth_trailer_len) as u16;
        let auth_len = auth_value.len() as u16;
        let mut writer = NdrWriter::with_capacity(frag_len as usize);
        let hdr = RpcCommonHeader::new(pdu_type::RPC_REQUEST, frag_len, auth_len, self.call_id);
        hdr.ndr_serialize(&mut writer);
        writer.write_u32(self.stub_data.len() as u32);
        writer.write_u16(self.context_id);
        writer.write_u16(self.opnum);
        writer.write_bytes(&self.stub_data);
        if let Some(t) = trailer {
            t.ndr_serialize(&mut writer);
            writer.write_bytes(auth_value);
        }
        writer.into_bytes()
    }
}

/// MS-RPCE v5 `Response` (`ptype = 2`) PDU representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcResponsePdu {
    pub header: RpcCommonHeader,
    pub alloc_hint: u32,
    pub context_id: u16,
    pub cancel_count: u8,
    pub reserved: u8,
    pub stub_data: Vec<u8>,
    pub trailer: Option<SecTrailer>,
    pub auth_value: Vec<u8>,
}

impl RpcResponsePdu {
    pub fn parse(pdu: &[u8]) -> Result<Self, CoreError> {
        if pdu.len() < 24 {
            return Err(CoreError::BufferUnderflow {
                needed: 24,
                available: pdu.len(),
            });
        }
        let mut reader = NdrReader::new(&pdu[..16]);
        let header = RpcCommonHeader::ndr_deserialize(&mut reader)?;
        if header.ptype == pdu_type::RPC_FAULT {
            let status = if pdu.len() >= 28 {
                u32::from_le_bytes([pdu[24], pdu[25], pdu[26], pdu[27]])
            } else {
                0
            };
            return Err(CoreError::RpcFault(status));
        }
        if header.ptype != pdu_type::RPC_RESPONSE {
            return Err(CoreError::ProtocolError(format!(
                "Expected RPC Response (ptype 2), got ptype {}",
                header.ptype
            )));
        }
        let alloc_hint = u32::from_le_bytes([pdu[16], pdu[17], pdu[18], pdu[19]]);
        let context_id = u16::from_le_bytes([pdu[20], pdu[21]]);
        let cancel_count = pdu[22];
        let reserved = pdu[23];

        let auth_length = header.auth_length as usize;
        let (stub_data, trailer, auth_value) = if auth_length > 0 {
            if pdu.len() < 24 + 8 + auth_length {
                return Err(CoreError::BufferUnderflow {
                    needed: 24 + 8 + auth_length,
                    available: pdu.len(),
                });
            }
            let trailer_offset = pdu.len() - (8 + auth_length);
            let mut trailer_reader = NdrReader::new(&pdu[trailer_offset..trailer_offset + 8]);
            let trailer = SecTrailer::ndr_deserialize(&mut trailer_reader)?;
            let auth_value = pdu[trailer_offset + 8..].to_vec();
            let stub = pdu[24..trailer_offset].to_vec();
            (stub, Some(trailer), auth_value)
        } else {
            let stub_end = pdu.len();
            if stub_end < 24 {
                return Err(CoreError::ProtocolError("Invalid RPC Response".into()));
            }
            (pdu[24..stub_end].to_vec(), None, Vec::new())
        };

        Ok(Self {
            header,
            alloc_hint,
            context_id,
            cancel_count,
            reserved,
            stub_data,
            trailer,
            auth_value,
        })
    }

    /// Builds a response PDU byte buffer (useful for mock servers and test harnesses).
    pub fn to_bytes(&self) -> Vec<u8> {
        let auth_trailer_len = if self.trailer.is_some() {
            8 + self.auth_value.len()
        } else {
            0
        };
        let frag_len = (24 + self.stub_data.len() + auth_trailer_len) as u16;
        let mut writer = NdrWriter::with_capacity(frag_len as usize);
        let mut hdr = self.header.clone();
        hdr.frag_length = frag_len;
        hdr.auth_length = self.auth_value.len() as u16;
        hdr.ndr_serialize(&mut writer);
        writer.write_u32(self.alloc_hint);
        writer.write_u16(self.context_id);
        writer.write_u8(self.cancel_count);
        writer.write_u8(self.reserved);
        writer.write_bytes(&self.stub_data);
        if let Some(t) = &self.trailer {
            t.ndr_serialize(&mut writer);
            writer.write_bytes(&self.auth_value);
        }
        writer.into_bytes()
    }
}

/// Helper function to extract the stub data from an RPC Response PDU.
/// Validates the 24-byte header, checks for `RPC_FAULT` status, and strips auth padding.
/// Result of parsing an `RPC_BIND_ACK` (ptype 12) PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcBindResult {
    pub accepted: bool,
    pub secondary_address: String,
    pub reject_reason: u16,
}

/// Parses an `RPC_BIND_ACK` PDU to check whether the requested interface presentation context was accepted.
pub fn parse_bind_ack(pdu: &[u8]) -> Result<RpcBindResult, CoreError> {
    if pdu.len() < 16 {
        return Err(CoreError::BufferUnderflow { needed: 16, available: pdu.len() });
    }
    if pdu[2] == pdu_type::RPC_BIND_NAK {
        let reason = if pdu.len() >= 18 {
            u16::from_le_bytes([pdu[16], pdu[17]])
        } else {
            0
        };
        return Ok(RpcBindResult {
            accepted: false,
            secondary_address: String::new(),
            reject_reason: reason,
        });
    }
    if pdu[2] != pdu_type::RPC_BIND_ACK {
        return Ok(RpcBindResult {
            accepted: false,
            secondary_address: String::new(),
            reject_reason: pdu[2] as u16,
        });
    }
    if pdu.len() < 24 {
        return Err(CoreError::BufferUnderflow { needed: 24, available: pdu.len() });
    }
    // RPC header is 16 bytes: pdu[16..] is the BIND_ACK body
    let body = &pdu[16..];
    if body.len() < 10 {
        return Err(CoreError::BufferUnderflow { needed: 10, available: body.len() });
    }
    let sec_addr_len = u16::from_le_bytes([body[8], body[9]]) as usize;
    let sec_addr_end = 10 + sec_addr_len;
    if body.len() < sec_addr_end {
        return Err(CoreError::BufferUnderflow { needed: sec_addr_end, available: body.len() });
    }
    let sec_addr = String::from_utf8_lossy(&body[10..sec_addr_end])
        .trim_matches('\0')
        .to_string();
    let aligned_offset = (sec_addr_end + 3) & !3;
    if body.len() < aligned_offset + 4 {
        return Ok(RpcBindResult { accepted: true, secondary_address: sec_addr, reject_reason: 0 });
    }
    let n_results = body[aligned_offset];
    if n_results == 0 || body.len() < aligned_offset + 8 {
        return Ok(RpcBindResult { accepted: true, secondary_address: sec_addr, reject_reason: 0 });
    }
    let result = u16::from_le_bytes([body[aligned_offset + 4], body[aligned_offset + 5]]);
    let reason = u16::from_le_bytes([body[aligned_offset + 6], body[aligned_offset + 7]]);
    Ok(RpcBindResult {
        accepted: result == 0,
        secondary_address: sec_addr,
        reject_reason: reason,
    })
}

pub fn extract_response_stub(pdu: &[u8]) -> Result<Vec<u8>, CoreError> {
    let parsed = RpcResponsePdu::parse(pdu)?;
    Ok(parsed.stub_data)
}

/// Remote operating system architecture identified via DCE/RPC transfer syntax negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteArch {
    X64,
    X86,
}

impl std::fmt::Display for RemoteArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X64 => write!(f, "64-bit (x64)"),
            Self::X86 => write!(f, "32-bit (x86)"),
        }
    }
}

/// Discovers remote OS architecture by probing NDR64 transfer syntax support over DCE/RPC (`getArch.py`).
pub fn get_arch_live(target: &str, port: u16, timeout: Duration) -> Result<RemoteArch, CoreError> {
    use std::io::Write;
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

    let addr_str = format!("{}:{}", target, port);
    let sock_addr: SocketAddr = addr_str
        .to_socket_addrs()
        .map_err(|e| CoreError::ProtocolError(format!("Failed resolving {}: {}", addr_str, e)))?
        .next()
        .ok_or_else(|| CoreError::ProtocolError(format!("No address found for {}", addr_str)))?;
    let mut stream = TcpStream::connect_timeout(&sock_addr, timeout).map_err(|e| {
        CoreError::ProtocolError(format!("TCP connect to {} failed: {}", addr_str, e))
    })?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let bind = RpcBindPdu::new(0, EPM_INTERFACE_UUID, 3, 0);
    let bind_bytes = bind.to_bytes_with_transfer_syntax(NDR64_SYNTAX_UUID, 1);
    stream
        .write_all(&bind_bytes)
        .map_err(|e| CoreError::ProtocolError(format!("Send failed: {}", e)))?;

    let (_, pdu) = read_rpc_pdu(&mut stream)?;
    let res = parse_bind_ack(&pdu)?;
    if res.accepted {
        Ok(RemoteArch::X64)
    } else {
        Ok(RemoteArch::X86)
    }
}

/// Reads an entire RPC response stream, reassembling multiple fragments if `PFC_LAST_FRAG` is unset.
/// Returns the complete concatenated stub data.
pub fn read_full_rpc_response<R: Read>(stream: &mut R) -> Result<Vec<u8>, CoreError> {
    let (hdr, pdu) = read_rpc_pdu(stream)?;
    if hdr.ptype == pdu_type::RPC_FAULT {
        let status = if pdu.len() >= 28 {
            u32::from_le_bytes([pdu[24], pdu[25], pdu[26], pdu[27]])
        } else {
            0
        };
        return Err(CoreError::RpcFault(status));
    }
    if hdr.ptype != pdu_type::RPC_RESPONSE {
        return Err(CoreError::ProtocolError(format!(
            "Expected RPC Response (ptype 2), got ptype {}",
            hdr.ptype
        )));
    }
    let mut stub = extract_response_stub(&pdu)?;
    let mut is_last = (hdr.pfc_flags & pfc_flags::PFC_LAST_FRAG) != 0;
    while !is_last {
        let (next_hdr, next_pdu) = read_rpc_pdu(stream)?;
        if next_hdr.ptype == pdu_type::RPC_FAULT {
            let status = if next_pdu.len() >= 28 {
                u32::from_le_bytes([next_pdu[24], next_pdu[25], next_pdu[26], next_pdu[27]])
            } else {
                0
            };
            return Err(CoreError::RpcFault(status));
        }
        if next_hdr.ptype != pdu_type::RPC_RESPONSE {
            return Err(CoreError::ProtocolError(format!(
                "Expected RPC Response fragment, got ptype {}",
                next_hdr.ptype
            )));
        }
        let frag_stub = extract_response_stub(&next_pdu)?;
        stub.extend_from_slice(&frag_stub);
        is_last = (next_hdr.pfc_flags & pfc_flags::PFC_LAST_FRAG) != 0;
    }
    Ok(stub)
}

/// Represents a decoded DCE/RPC Endpoint Mapper Protocol Tower entry (`twr_t` in `impacket/dcerpc/v5/epm.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpmEndpointEntry {
    pub interface_uuid: RpcUuid,
    pub version_major: u16,
    pub version_minor: u16,
    pub string_binding: String,
    pub annotation: String,
}

impl EpmEndpointEntry {
    pub fn to_tower_bytes(&self, tcp_port: u16, ipv4: Ipv4Addr) -> Vec<u8> {
        let mut floors = Vec::with_capacity(75);
        floors.extend_from_slice(&5u16.to_le_bytes());

        // Floor 1: Interface UUID
        floors.extend_from_slice(&19u16.to_le_bytes());
        floors.push(0x0D);
        let mut w = NdrWriter::with_capacity(16);
        self.interface_uuid.ndr_serialize(&mut w);
        floors.extend_from_slice(w.as_slice());
        floors.extend_from_slice(&self.version_major.to_le_bytes());
        floors.extend_from_slice(&2u16.to_le_bytes());
        floors.extend_from_slice(&self.version_minor.to_le_bytes());

        // Floor 2: NDR Transfer Syntax
        floors.extend_from_slice(&19u16.to_le_bytes());
        floors.push(0x0D);
        let mut w2 = NdrWriter::with_capacity(16);
        NDR_SYNTAX_UUID.ndr_serialize(&mut w2);
        floors.extend_from_slice(w2.as_slice());
        floors.extend_from_slice(&2u16.to_le_bytes());
        floors.extend_from_slice(&2u16.to_le_bytes());
        floors.extend_from_slice(&0u16.to_le_bytes());

        // Floor 3: RPC Connection-oriented protocol (0x0B)
        floors.extend_from_slice(&1u16.to_le_bytes());
        floors.push(0x0B);
        floors.extend_from_slice(&2u16.to_le_bytes());
        floors.extend_from_slice(&0u16.to_le_bytes());

        // Floor 4: Dod TCP Port (0x07, big-endian u16 port)
        floors.extend_from_slice(&1u16.to_le_bytes());
        floors.push(0x07);
        floors.extend_from_slice(&2u16.to_le_bytes());
        floors.extend_from_slice(&tcp_port.to_be_bytes());

        // Floor 5: Dod IPv4 Address (0x09, 4-byte IP)
        floors.extend_from_slice(&1u16.to_le_bytes());
        floors.push(0x09);
        floors.extend_from_slice(&4u16.to_le_bytes());
        floors.extend_from_slice(&ipv4.octets());

        floors
    }

    pub fn from_tower_bytes(tower: &[u8], annotation: String) -> Result<Self, CoreError> {
        if tower.len() < 27 {
            return Err(CoreError::BufferUnderflow {
                needed: 27,
                available: tower.len(),
            });
        }
        let num_floors = u16::from_le_bytes([tower[0], tower[1]]) as usize;
        let mut pos = 2;

        let mut interface_uuid = RpcUuid::default();
        let mut version_major = 0u16;
        let mut version_minor = 0u16;
        let mut proto = "ncacn_ip_tcp";
        let mut endpoint = String::new();
        let mut address = String::from("0.0.0.0");

        for floor_idx in 0..num_floors {
            if pos + 2 > tower.len() {
                break;
            }
            let lhs_len = u16::from_le_bytes([tower[pos], tower[pos + 1]]) as usize;
            pos += 2;
            if pos + lhs_len + 2 > tower.len() {
                break;
            }
            let lhs = &tower[pos..pos + lhs_len];
            pos += lhs_len;
            let rhs_len = u16::from_le_bytes([tower[pos], tower[pos + 1]]) as usize;
            pos += 2;
            if pos + rhs_len > tower.len() {
                break;
            }
            let rhs = &tower[pos..pos + rhs_len];
            pos += rhs_len;

            if floor_idx == 0 && lhs.len() == 19 && lhs[0] == 0x0D && rhs.len() == 2 {
                let mut r = NdrReader::new(&lhs[1..17]);
                interface_uuid = RpcUuid::ndr_deserialize(&mut r)?;
                version_major = u16::from_le_bytes([lhs[17], lhs[18]]);
                version_minor = u16::from_le_bytes([rhs[0], rhs[1]]);
            } else if floor_idx >= 3 && !lhs.is_empty() {
                match lhs[0] {
                    0x07 if rhs.len() == 2 => {
                        proto = "ncacn_ip_tcp";
                        endpoint = u16::from_be_bytes([rhs[0], rhs[1]]).to_string();
                    }
                    0x08 if rhs.len() == 2 => {
                        proto = "ncadg_ip_udp";
                        endpoint = u16::from_be_bytes([rhs[0], rhs[1]]).to_string();
                    }
                    0x09 if rhs.len() == 4 => {
                        address = Ipv4Addr::new(rhs[0], rhs[1], rhs[2], rhs[3]).to_string();
                    }
                    0x0F => {
                        proto = "ncacn_np";
                        endpoint = String::from_utf8_lossy(rhs)
                            .trim_end_matches('\0')
                            .to_string();
                    }
                    0x10 => {
                        proto = "ncalrpc";
                        endpoint = String::from_utf8_lossy(rhs)
                            .trim_end_matches('\0')
                            .to_string();
                    }
                    0x1F if rhs.len() == 2 => {
                        proto = "ncacn_http";
                        endpoint = u16::from_be_bytes([rhs[0], rhs[1]]).to_string();
                    }
                    _ => {}
                }
            }
        }

        let string_binding = format!("{}:{}[{}]", proto, address, endpoint);
        Ok(Self {
            interface_uuid,
            version_major,
            version_minor,
            string_binding,
            annotation,
        })
    }

    pub fn is_ncacn_ip_tcp(&self) -> bool {
        self.string_binding.starts_with("ncacn_ip_tcp:")
    }

    pub fn tcp_port(&self) -> Option<u16> {
        if !self.is_ncacn_ip_tcp() {
            return None;
        }
        let start = self.string_binding.find('[')? + 1;
        let end = self.string_binding.find(']')?;
        self.string_binding[start..end].parse::<u16>().ok()
    }

    pub fn is_ncacn_np(&self) -> bool {
        self.string_binding.starts_with("ncacn_np:")
    }

    pub fn named_pipe(&self) -> Option<&str> {
        if !self.is_ncacn_np() {
            return None;
        }
        let start = self.string_binding.find('[')? + 1;
        let end = self.string_binding.find(']')?;
        Some(&self.string_binding[start..end])
    }
}

pub fn build_ept_lookup_request(call_id: u32, inquiry_handle: [u8; 20], max_ents: u32) -> Vec<u8> {
    let mut stub = NdrWriter::with_capacity(76);
    stub.write_u32(0);
    stub.write_u32(1);
    stub.write_fixed_array(&[0u8; 16]);
    stub.write_u32(2);
    stub.write_fixed_array(&[0u8; 20]);
    stub.write_u32(0);
    stub.write_fixed_array(&inquiry_handle);
    stub.write_u32(max_ents);

    let req = RpcRequestPdu {
        call_id,
        context_id: 0,
        opnum: 2,
        stub_data: stub.into_bytes(),
    };
    req.to_bytes()
}

pub fn read_rpc_pdu<R: Read>(stream: &mut R) -> Result<(RpcCommonHeader, Vec<u8>), CoreError> {
    let mut hdr_bytes = [0u8; 16];
    stream
        .read_exact(&mut hdr_bytes)
        .map_err(|e| CoreError::ProtocolError(format!("Failed reading RPC PDU header: {}", e)))?;
    let mut reader = NdrReader::new(&hdr_bytes);
    let hdr = RpcCommonHeader::ndr_deserialize(&mut reader)?;
    if hdr.frag_length < 16 {
        return Err(CoreError::ProtocolError("Invalid RPC frag_length < 16".into()));
    }
    let body_len = (hdr.frag_length as usize) - 16;
    let mut full = Vec::with_capacity(hdr.frag_length as usize);
    full.extend_from_slice(&hdr_bytes);
    let mut rest = vec![0u8; body_len];
    stream
        .read_exact(&mut rest)
        .map_err(|e| CoreError::ProtocolError(format!("Failed reading RPC PDU body: {}", e)))?;
    full.extend_from_slice(&rest);
    Ok((hdr, full))
}

/// A bound DCE/RPC call transport: binds an interface once, then transceives MS-RPCE `Request` PDUs,
/// returning each full response PDU (common header + response fields + stub). Implemented by the
/// `ncacn_ip_tcp` ([`TcpRpcTransport`]) and `ncacn_np` SMB-named-pipe transports; mocked in tests.
///
/// This is the seam that lets the high-level `[MS-SAMR]` / `[MS-LSAT]` / `[MS-SRVS]` clients stay
/// transport-agnostic, exactly like Impacket's `DCERPCTransport` / `rpctransport` abstraction.
pub trait RpcTransport {
    /// Sends one MS-RPCE `Request` PDU and returns the full response PDU bytes.
    fn transceive(&mut self, request_pdu: &[u8]) -> Result<Vec<u8>, CoreError>;
}

/// RPC Authentication Level (`[MS-RPCE]` Section 2.2.1.1.8).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum RpcAuthLevel {
    None = 1,
    Connect = 2,
    Call = 3,
    Pkt = 4,
    PktIntegrity = 5,
    PktPrivacy = 6,
}

/// Dynamic RPC Security Context supporting NTLMSSP Sign & Seal (`PKT_INTEGRITY` & `PKT_PRIVACY`).
pub enum RpcSecurityContext {
    None,
    Ntlm {
        security: impacket_auth::NtlmSessionSecurity,
        level: RpcAuthLevel,
    },
}

impl RpcSecurityContext {
    pub fn new_ntlm(session_key: &[u8; 16], level: RpcAuthLevel) -> Self {
        Self::Ntlm {
            security: impacket_auth::NtlmSessionSecurity::new(session_key),
            level,
        }
    }

    pub fn wrap_request(
        &mut self,
        call_id: u32,
        context_id: u16,
        opnum: u16,
        stub_data: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        match self {
            Self::None => {
                let req = RpcRequestPdu {
                    call_id,
                    context_id,
                    opnum,
                    stub_data: stub_data.to_vec(),
                };
                Ok(req.to_bytes())
            }
            Self::Ntlm { security, level } => match level {
                RpcAuthLevel::PktPrivacy => {
                    let pad_len = (16 - (stub_data.len() % 16)) % 16;
                    let mut padded = stub_data.to_vec();
                    padded.resize(stub_data.len() + pad_len, 0);

                    let (ciphertext, sig) = security.seal_message(&padded);
                    let trailer = SecTrailer {
                        auth_type: rpc_auth_type::RPC_C_AUTHN_WINNT,
                        auth_level: rpc_auth_level::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                        auth_pad_length: pad_len as u8,
                        auth_reserved: 0,
                        auth_context_id: context_id as u32,
                    };
                    let req = RpcRequestPdu {
                        call_id,
                        context_id,
                        opnum,
                        stub_data: ciphertext,
                    };
                    Ok(req.to_bytes_with_auth(Some(&trailer), &sig))
                }
                RpcAuthLevel::PktIntegrity => {
                    let sig = security.sign_message(stub_data);
                    let trailer = SecTrailer {
                        auth_type: rpc_auth_type::RPC_C_AUTHN_WINNT,
                        auth_level: rpc_auth_level::RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
                        auth_pad_length: 0,
                        auth_reserved: 0,
                        auth_context_id: context_id as u32,
                    };
                    let req = RpcRequestPdu {
                        call_id,
                        context_id,
                        opnum,
                        stub_data: stub_data.to_vec(),
                    };
                    Ok(req.to_bytes_with_auth(Some(&trailer), &sig))
                }
                _ => {
                    let req = RpcRequestPdu {
                        call_id,
                        context_id,
                        opnum,
                        stub_data: stub_data.to_vec(),
                    };
                    Ok(req.to_bytes())
                }
            },
        }
    }

    pub fn unwrap_response(&mut self, pdu: &[u8]) -> Result<Vec<u8>, CoreError> {
        let resp = RpcResponsePdu::parse(pdu)?;
        match self {
            Self::None => Ok(resp.stub_data),
            Self::Ntlm { security, level } => match level {
                RpcAuthLevel::PktPrivacy => {
                    let sig: [u8; 16] = resp.auth_value.as_slice().try_into().map_err(|_| {
                        CoreError::ProtocolError(
                            "Invalid NTLM RPC response auth signature length".into(),
                        )
                    })?;
                    let mut plaintext = security.unseal_message(&resp.stub_data, &sig)?;
                    if let Some(t) = &resp.trailer {
                        let pad = t.auth_pad_length as usize;
                        if pad > plaintext.len() {
                            return Err(CoreError::ProtocolError(
                                "Invalid auth pad length in response".into(),
                            ));
                        }
                        plaintext.truncate(plaintext.len() - pad);
                    }
                    Ok(plaintext)
                }
                RpcAuthLevel::PktIntegrity => {
                    let sig: [u8; 16] = resp.auth_value.as_slice().try_into().map_err(|_| {
                        CoreError::ProtocolError(
                            "Invalid NTLM RPC response auth signature length".into(),
                        )
                    })?;
                    security.verify_signature(&resp.stub_data, &sig)?;
                    Ok(resp.stub_data)
                }
                _ => Ok(resp.stub_data),
            },
        }
    }
}

/// Live `ncacn_ip_tcp` DCE/RPC transport over a raw TCP stream (no SMB). Used for endpoint-mapper and
/// dynamic-endpoint interfaces bound directly over TCP.
pub struct TcpRpcTransport {
    stream: TcpStream,
}

impl TcpRpcTransport {
    /// Connects to `host:port`, performs the MS-RPCE `Bind` to `interface` v`major`.`minor`, and
    /// verifies the `BindAck`.
    pub fn connect_and_bind(
        host: &str,
        port: u16,
        interface: RpcUuid,
        version_major: u16,
        version_minor: u16,
        timeout: Duration,
    ) -> Result<Self, CoreError> {
        let addr_str = format!("{}:{}", host, port);
        let sock_addr: SocketAddr = addr_str
            .to_socket_addrs()
            .map_err(|e| CoreError::ProtocolError(format!("Failed resolving {}: {}", addr_str, e)))?
            .next()
            .ok_or_else(|| CoreError::ProtocolError(format!("No address found for {}", addr_str)))?;
        let stream = TcpStream::connect_timeout(&sock_addr, timeout).map_err(|e| {
            CoreError::ProtocolError(format!("TCP connect to {} failed: {}", addr_str, e))
        })?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));

        let mut t = Self { stream };
        let bind = RpcBindPdu::new(0, interface, version_major, version_minor);
        t.write_all_pdu(&bind.to_bytes())?;
        let (ack_hdr, pdu) = read_rpc_pdu(&mut t.stream)?;
        if ack_hdr.ptype != pdu_type::RPC_BIND_ACK {
            return Err(CoreError::ProtocolError(format!(
                "RPC Bind rejected (ptype {})",
                ack_hdr.ptype
            )));
        }
        let bind_res = parse_bind_ack(&pdu)?;
        if !bind_res.accepted {
            return Err(CoreError::ProtocolError(format!(
                "RPC Bind context rejected (reason {})",
                bind_res.reject_reason
            )));
        }
        Ok(t)
    }

    /// Automatically queries EPM on `host:135` to discover the dynamic TCP port for `interface`
    /// and establishes a bound RPC transport to that port.
    pub fn connect_dynamic(
        host: &str,
        interface: RpcUuid,
        version_major: u16,
        version_minor: u16,
        timeout: Duration,
    ) -> Result<Self, CoreError> {
        let port = resolve_dynamic_tcp_port(host, &interface, version_major, timeout)?;
        Self::connect_and_bind(host, port, interface, version_major, version_minor, timeout)
    }

    fn write_all_pdu(&mut self, pdu: &[u8]) -> Result<(), CoreError> {
        self.stream
            .write_all(pdu)
            .map_err(|e| CoreError::ProtocolError(format!("Failed sending RPC PDU: {}", e)))
    }
}

impl RpcTransport for TcpRpcTransport {
    fn transceive(&mut self, request_pdu: &[u8]) -> Result<Vec<u8>, CoreError> {
        self.write_all_pdu(request_pdu)?;
        let (_, pdu) = read_rpc_pdu(&mut self.stream)?;
        Ok(pdu)
    }
}

/// Sans-I/O / Generic Stream executor for `rpcdump`: writes `RpcBindPdu` and `ept_lookup` (opnum 2)
/// to `tx` and parses the `RpcBindAck` and endpoint tower array from `rx`.
pub fn rpcdump_over_stream<R: Read, W: Write>(
    rx: &mut R,
    tx: &mut W,
) -> Result<Vec<EpmEndpointEntry>, CoreError> {
    let bind = RpcBindPdu::new(1, EPM_INTERFACE_UUID, 3, 0);
    tx.write_all(&bind.to_bytes())
        .map_err(|e| CoreError::ProtocolError(format!("Failed sending RPC Bind: {}", e)))?;

    let (ack_hdr, _ack_pdu) = read_rpc_pdu(rx)?;
    if ack_hdr.ptype != pdu_type::RPC_BIND_ACK {
        return Err(CoreError::ProtocolError(format!(
            "Expected RPC_BIND_ACK (12), got ptype {}",
            ack_hdr.ptype
        )));
    }

    let lookup_req = build_ept_lookup_request(2, [0u8; 20], 500);
    tx.write_all(&lookup_req)
        .map_err(|e| CoreError::ProtocolError(format!("Failed sending ept_lookup: {}", e)))?;

    let (resp_hdr, resp_pdu) = read_rpc_pdu(rx)?;
    if resp_hdr.ptype != pdu_type::RPC_RESPONSE || resp_pdu.len() < 24 {
        return Err(CoreError::ProtocolError(format!(
            "Unexpected RPC response ptype {}",
            resp_hdr.ptype
        )));
    }

    let stub = &resp_pdu[24..];
    parse_ept_lookup_response_stub(stub)
}

/// Connects to a live DCE/RPC Endpoint Mapper over TCP/135 (`rpcdump_live`), binds to
/// `E1AF8308-5D1F-11C9-91A4-08002B14A0FA v3.0`, executes `ept_lookup` (opnum 2), and parses
/// all returned endpoint towers (`examples/rpcdump.py`).
pub fn rpcdump_live(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<EpmEndpointEntry>, CoreError> {
    let addr_str = format!("{}:{}", host, port);
    let sock_addr: SocketAddr = addr_str
        .to_socket_addrs()
        .map_err(|e| CoreError::ProtocolError(format!("Failed resolving {}: {}", addr_str, e)))?
        .next()
        .ok_or_else(|| CoreError::ProtocolError(format!("No address found for {}", addr_str)))?;

    let stream = TcpStream::connect_timeout(&sock_addr, timeout)
        .map_err(|e| CoreError::ProtocolError(format!("TCP connect to EPM {} failed: {}", addr_str, e)))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let mut rx = stream
        .try_clone()
        .map_err(|e| CoreError::ProtocolError(format!("Socket clone failed: {}", e)))?;
    let mut tx = stream;
    rpcdump_over_stream(&mut rx, &mut tx)
}

/// Resolves the dynamic TCP port for a given MSRPC interface via EPM (TCP/135) on the remote host.
pub fn resolve_dynamic_tcp_port(
    host: &str,
    interface_uuid: &RpcUuid,
    version_major: u16,
    timeout: Duration,
) -> Result<u16, CoreError> {
    let entries = rpcdump_live(host, 135, timeout)?;
    for entry in &entries {
        if &entry.interface_uuid == interface_uuid && entry.version_major == version_major {
            if let Some(port) = entry.tcp_port() {
                return Ok(port);
            }
        }
    }
    Err(CoreError::ProtocolError(format!(
        "Interface {} v{}.x TCP endpoint not found in EPM on {}",
        interface_uuid, version_major, host
    )))
}

/// Resolves the named pipe for a given MSRPC interface via EPM (TCP/135) on the remote host.
pub fn resolve_named_pipe(
    host: &str,
    interface_uuid: &RpcUuid,
    version_major: u16,
    timeout: Duration,
) -> Result<String, CoreError> {
    let entries = rpcdump_live(host, 135, timeout)?;
    for entry in &entries {
        if &entry.interface_uuid == interface_uuid && entry.version_major == version_major {
            if let Some(pipe) = entry.named_pipe() {
                return Ok(pipe.to_string());
            }
        }
    }
    Err(CoreError::ProtocolError(format!(
        "Interface {} v{}.x named pipe not found in EPM on {}",
        interface_uuid, version_major, host
    )))
}

pub fn parse_ept_lookup_response_stub(stub: &[u8]) -> Result<Vec<EpmEndpointEntry>, CoreError> {
    let mut reader = NdrReader::new(stub);
    let _entry_handle = reader.read_fixed_array::<20>()?;
    let num_ents = reader.read_u32()? as usize;
    let _max_count = reader.read_u32()?;
    let _offset = reader.read_u32()?;
    let actual_count = reader.read_u32()? as usize;

    let count = num_ents.min(actual_count).min(1024);
    let mut annotations = Vec::with_capacity(count);
    for _ in 0..count {
        let _obj_uuid = RpcUuid::ndr_deserialize(&mut reader)?;
        let _tower_ptr = reader.read_u32()?;
        let _ann_offset = reader.read_u32()?;
        let ann_len = reader.read_u32()? as usize;
        if ann_len > 256 {
            return Err(CoreError::ProtocolError("Invalid EPM annotation length".into()));
        }
        let ann_bytes = reader.read_bytes(ann_len)?;
        let ann = String::from_utf8_lossy(ann_bytes)
            .trim_end_matches('\0')
            .to_string();
        annotations.push(ann);
        reader.align(4)?;
    }

    let mut entries = Vec::with_capacity(count);
    for ann in annotations {
        let _tower_max = reader.read_u32()?;
        let tower_len = reader.read_u32()? as usize;
        let tower_bytes = reader.read_bytes(tower_len)?;
        reader.align(4)?;
        if let Ok(entry) = EpmEndpointEntry::from_tower_bytes(tower_bytes, ann) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Test fixture: generates a valid EPM `ept_lookup` response PDU to exercise the real
    /// `rpcdump_over_stream` / `parse_ept_lookup_response_stub` client parser.
    fn build_ept_lookup_response_pdu(
        call_id: u32,
        endpoints: &[(EpmEndpointEntry, u16, Ipv4Addr)],
    ) -> Vec<u8> {
        let mut stub = NdrWriter::with_capacity(512);
        stub.write_fixed_array(&[0u8; 20]);
        let count = endpoints.len() as u32;
        stub.write_u32(count);
        stub.write_u32(count);
        stub.write_u32(0);
        stub.write_u32(count);

        for (idx, (entry, _, _)) in endpoints.iter().enumerate() {
            RpcUuid::default().ndr_serialize(&mut stub);
            stub.write_u32((idx as u32) + 1);
            stub.write_u32(0);
            let mut ann_bytes = entry.annotation.as_bytes().to_vec();
            ann_bytes.push(0);
            stub.write_u32(ann_bytes.len() as u32);
            stub.write_bytes(&ann_bytes);
            stub.align(4);
        }

        for (entry, port, ip) in endpoints {
            let tower = entry.to_tower_bytes(*port, *ip);
            stub.write_u32(tower.len() as u32);
            stub.write_u32(tower.len() as u32);
            stub.write_bytes(&tower);
            stub.align(4);
        }

        stub.write_u32(0);

        let stub_bytes = stub.into_bytes();
        let frag_len = (24 + stub_bytes.len()) as u16;
        let mut pdu = NdrWriter::with_capacity(frag_len as usize);
        let hdr = RpcCommonHeader::new(pdu_type::RPC_RESPONSE, frag_len, 0, call_id);
        hdr.ndr_serialize(&mut pdu);
        pdu.write_u32(stub_bytes.len() as u32);
        pdu.write_u16(0);
        pdu.write_u8(0);
        pdu.write_u8(0);
        pdu.write_bytes(&stub_bytes);
        pdu.into_bytes()
    }

    /// Test fixture: drives `rpcdump_over_stream` against a prebuilt EPM response to verify the
    /// real Bind + `ept_lookup` + tower-decode path end to end.
    fn run_rpcdump_against_fixture() -> Result<Vec<EpmEndpointEntry>, CoreError> {
        let ack_hdr = RpcCommonHeader::new(pdu_type::RPC_BIND_ACK, 24, 0, 1);
        let mut ack_w = NdrWriter::with_capacity(24);
        ack_hdr.ndr_serialize(&mut ack_w);
        ack_w.write_u64(0);

        let drsuapi = &WELL_KNOWN_INTERFACES[3];
        let nrpc = &WELL_KNOWN_INTERFACES[4];
        let samr = &WELL_KNOWN_INTERFACES[1];
        let sample = vec![
            (
                EpmEndpointEntry {
                    interface_uuid: drsuapi.uuid,
                    version_major: drsuapi.version_major,
                    version_minor: drsuapi.version_minor,
                    string_binding: String::new(),
                    annotation: "NTDS Replication RPC".into(),
                },
                49664,
                Ipv4Addr::new(10, 10, 11, 200),
            ),
            (
                EpmEndpointEntry {
                    interface_uuid: nrpc.uuid,
                    version_major: nrpc.version_major,
                    version_minor: nrpc.version_minor,
                    string_binding: String::new(),
                    annotation: "Netlogon".into(),
                },
                49665,
                Ipv4Addr::new(10, 10, 11, 200),
            ),
            (
                EpmEndpointEntry {
                    interface_uuid: samr.uuid,
                    version_major: samr.version_major,
                    version_minor: samr.version_minor,
                    string_binding: String::new(),
                    annotation: "SAMR".into(),
                },
                49668,
                Ipv4Addr::new(10, 10, 11, 200),
            ),
        ];
        let resp_pdu = build_ept_lookup_response_pdu(2, &sample);

        let mut server_stream = Vec::new();
        server_stream.extend_from_slice(ack_w.as_slice());
        server_stream.extend_from_slice(&resp_pdu);

        let mut rx = Cursor::new(server_stream);
        let mut tx = Vec::new();
        rpcdump_over_stream(&mut rx, &mut tx)
    }

    #[test]
    fn test_rpc_bind_pdu_samr_roundtrip() {
        let samr = &WELL_KNOWN_INTERFACES[1];
        let bind = RpcBindPdu::new(1, samr.uuid, samr.version_major, samr.version_minor);
        let bytes = bind.to_bytes();
        assert_eq!(bytes.len(), 72);

        let decoded = RpcBindPdu::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, bind);
        assert_eq!(
            decoded.abstract_syntax.to_string(),
            "12345778-1234-abcd-ef00-0123456789ac"
        );
    }

    #[test]
    fn test_rpcdump_full_protocol_exchange() {
        let endpoints = run_rpcdump_against_fixture().expect("rpcdump exchange should succeed");
        assert_eq!(endpoints.len(), 3);
        assert_eq!(
            endpoints[0].string_binding,
            "ncacn_ip_tcp:10.10.11.200[49664]"
        );
        let known = lookup_known_interface(&endpoints[0].interface_uuid).unwrap();
        assert_eq!(known.short_name, "MS-DRSR (DRSUAPI)");
        assert_eq!(known.provider_binary, "ntdsai.dll");
    }

    #[test]
    fn test_rpc_response_pdu_parse_and_extract_stub() {
        let resp = RpcResponsePdu {
            header: RpcCommonHeader::new(pdu_type::RPC_RESPONSE, 28, 0, 42),
            alloc_hint: 4,
            context_id: 0,
            cancel_count: 0,
            reserved: 0,
            stub_data: vec![0x11, 0x22, 0x33, 0x44],
            trailer: None,
            auth_value: Vec::new(),
        };
        let bytes = resp.to_bytes();
        let parsed = RpcResponsePdu::parse(&bytes).unwrap();
        assert_eq!(parsed.stub_data, vec![0x11, 0x22, 0x33, 0x44]);
        assert_eq!(parsed.header.call_id, 42);

        let stub = extract_response_stub(&bytes).unwrap();
        assert_eq!(stub, vec![0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn test_rpc_fault_pdu_returns_rpc_fault_error() {
        let mut writer = NdrWriter::with_capacity(32);
        let hdr = RpcCommonHeader::new(pdu_type::RPC_FAULT, 32, 0, 1);
        hdr.ndr_serialize(&mut writer);
        writer.write_u32(0); // alloc_hint
        writer.write_u16(0); // context_id
        writer.write_u8(0);  // cancel_count
        writer.write_u8(0);  // reserved
        writer.write_u32(0x0000_0005); // nca_s_fault_access_denied
        writer.write_u32(0); // reserved2
        let fault_pdu = writer.into_bytes();

        let err = extract_response_stub(&fault_pdu).unwrap_err();
        match err {
            CoreError::RpcFault(status) => assert_eq!(status, 0x0000_0005),
            other => panic!("Expected RpcFault, got {:?}", other),
        }
    }

    #[test]
    fn test_rpc_multi_fragment_reassembly() {
        // Fragment 1: FIRST_FRAG (0x01)
        let mut f1 = RpcResponsePdu {
            header: RpcCommonHeader::new(pdu_type::RPC_RESPONSE, 28, 0, 1),
            alloc_hint: 8,
            context_id: 0,
            cancel_count: 0,
            reserved: 0,
            stub_data: vec![1, 2, 3, 4],
            trailer: None,
            auth_value: Vec::new(),
        };
        f1.header.pfc_flags = pfc_flags::PFC_FIRST_FRAG;

        // Fragment 2: LAST_FRAG (0x02)
        let mut f2 = RpcResponsePdu {
            header: RpcCommonHeader::new(pdu_type::RPC_RESPONSE, 28, 0, 1),
            alloc_hint: 4,
            context_id: 0,
            cancel_count: 0,
            reserved: 0,
            stub_data: vec![5, 6, 7, 8],
            trailer: None,
            auth_value: Vec::new(),
        };
        f2.header.pfc_flags = pfc_flags::PFC_LAST_FRAG;

        let mut stream = Vec::new();
        stream.extend_from_slice(&f1.to_bytes());
        stream.extend_from_slice(&f2.to_bytes());

        let mut cursor = Cursor::new(stream);
        let reassembled = read_full_rpc_response(&mut cursor).unwrap();
        assert_eq!(reassembled, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_rpc_pkt_privacy_and_integrity_roundtrip() {
        let session_key = [0x55u8; 16];
        let mut client_ctx = RpcSecurityContext::new_ntlm(&session_key, RpcAuthLevel::PktPrivacy);

        let stub = b"SAMR_CONNECT5_SECRET_STUB_DATA_123456789";
        let req_pdu = client_ctx.wrap_request(1, 0, 64, stub).unwrap();

        // Server receives and parses
        assert!(req_pdu.len() > 24 + stub.len());
        let header = RpcCommonHeader::ndr_deserialize(&mut NdrReader::new(&req_pdu[..16])).unwrap();
        assert_eq!(header.auth_length, 16);

        // Verify with integrity context
        let mut integ_client = RpcSecurityContext::new_ntlm(&session_key, RpcAuthLevel::PktIntegrity);
        let integ_pdu = integ_client.wrap_request(1, 0, 64, stub).unwrap();
        assert!(integ_pdu.len() >= 24 + stub.len() + 8 + 16);
    }

    #[test]
    fn test_epm_entry_helpers() {
        let tcp_entry = EpmEndpointEntry {
            interface_uuid: EPM_INTERFACE_UUID,
            version_major: 3,
            version_minor: 0,
            string_binding: "ncacn_ip_tcp:192.168.1.10[49667]".into(),
            annotation: "EPM TCP".into(),
        };
        assert!(tcp_entry.is_ncacn_ip_tcp());
        assert_eq!(tcp_entry.tcp_port(), Some(49667));
        assert!(!tcp_entry.is_ncacn_np());
        assert_eq!(tcp_entry.named_pipe(), None);

        let np_entry = EpmEndpointEntry {
            interface_uuid: EPM_INTERFACE_UUID,
            version_major: 3,
            version_minor: 0,
            string_binding: r"ncacn_np:192.168.1.10[\PIPE\samr]".into(),
            annotation: "SAMR NP".into(),
        };
        assert!(!np_entry.is_ncacn_ip_tcp());
        assert_eq!(np_entry.tcp_port(), None);
        assert!(np_entry.is_ncacn_np());
        assert_eq!(np_entry.named_pipe(), Some(r"\PIPE\samr"));
    }
}
