//! `impacket-smb`: Multi-Dialect SMB Protocol Engine (`impacket/smb.py`, `smb3.py`, `smb3structs.py`).
//!
//! Designed for maximum compatibility from **Windows 2000 / 2003 (`NT LM 0.12` SMBv1)**
//! through **Windows Server 2025 (`SMB 3.1.1` with SHA-512 Preauth Integrity & AES-128/256-GCM)**.
//!
//! Includes:
//! - `SMB2_NEGOTIATE` & legacy SMBv1 Multi-Protocol Negotiate (`\xFFSMB`)
//! - `SMB2_SESSION_SETUP` (NTLMSSP / SPNEGO authentication)
//! - `SMB2_TREE_CONNECT` (`\\<server>\IPC$` & file shares)
//! - `SMB2_CREATE`, `SMB2_IOCTL` (`FSCTL_PIPE_TRANSCEIVE`), `SMB2_WRITE`, `SMB2_READ`, `SMB2_CLOSE`
//!   powering `ncacn_np` (DCE/RPC over SMB Named Pipes for `lookupsid`, `samrdump`, `psexec`, `secretsdump`).

pub mod server;
pub mod smb1;
pub mod smbd;
pub mod transform;

pub use server::{
    build_smb2_close_response, build_smb2_create_response, build_smb2_error_response,
    build_smb2_negotiate_response, build_smb2_query_directory_response, build_smb2_read_response,
    build_smb2_tree_connect_response, build_smb2_write_response, encode_file_id_both_dir_info,
    ConnectionState, DirEntryInfo, OpenFileHandle, SmbServer, SmbServerConfig, SmbShare,
};
pub use smb1::Smb1Connection;
pub use smbd::{
    SmbdBufferDescriptorV1, SmbdDataTransfer, SmbdMessageReassembler, SmbdNegotiateReq,
    SmbdNegotiateResp, SmbdTransport, SMBD_DEFAULT_CREDITS, SMBD_DEFAULT_MAX_FRAGMENTED_SIZE,
    SMBD_DEFAULT_PORT, SMBD_DEFAULT_RECEIVE_SIZE, SMBD_DEFAULT_SEND_SIZE,
    SMBD_FLAG_RESPONSE_REQUESTED, SMBD_VERSION_1_0,
};
pub use transform::{is_transform_header, Smb3EncryptionState, SmbCipherAlgorithm};

use impacket_auth::{NtlmChallengeMessage, NtlmNegotiateMessage};
use impacket_core::{encode_utf16le, AdCompatProfile, CoreError, FileTime, NtStatus};
use impacket_ndr::{ndr_struct, NdrDeserialize, NdrReader, NdrSerialize, NdrWriter};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// SMB2/3 Dialect Revisions (`impacket/smb3structs.py`).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum SmbDialect {
    Smb202 = 0x0202, // Windows Server 2008 / Vista SP1
    Smb210 = 0x0210, // Windows Server 2008 R2 / Windows 7
    Smb300 = 0x0300, // Windows Server 2012 / Windows 8
    Smb302 = 0x0302, // Windows Server 2012 R2 / Windows 8.1
    Smb311 = 0x0311, // Windows Server 2016 / 2019 / 2022 / 2025 / Windows 10 & 11
}

impl SmbDialect {
    pub const fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x0202 => Some(Self::Smb202),
            0x0210 => Some(Self::Smb210),
            0x0300 => Some(Self::Smb300),
            0x0302 => Some(Self::Smb302),
            0x0311 => Some(Self::Smb311),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Smb202 => "SMB 2.0.2 (Win2008/Vista)",
            Self::Smb210 => "SMB 2.1 (Win2008R2/Win7)",
            Self::Smb300 => "SMB 3.0 (Win2012/Win8)",
            Self::Smb302 => "SMB 3.0.2 (Win2012R2/Win8.1)",
            Self::Smb311 => "SMB 3.1.1 (Win2016/2019/2022/2025)",
        }
    }

    pub fn dialects_for_profile(profile: AdCompatProfile) -> Vec<Self> {
        match profile {
            AdCompatProfile::LegacyWin2000 => vec![Self::Smb202, Self::Smb210],
            AdCompatProfile::UniversalAuto => vec![
                Self::Smb202,
                Self::Smb210,
                Self::Smb300,
                Self::Smb302,
                Self::Smb311,
            ],
            AdCompatProfile::ModernHardened2025 => vec![Self::Smb311],
        }
    }
}

/// SMB2/3 Command Codes (`SMB2_NEGOTIATE`, `SMB2_SESSION_SETUP`, `SMB2_TREE_CONNECT`, etc.).
pub mod smb2_cmd {
    pub const NEGOTIATE: u16 = 0x0000;
    pub const SESSION_SETUP: u16 = 0x0001;
    pub const LOGOFF: u16 = 0x0002;
    pub const TREE_CONNECT: u16 = 0x0003;
    pub const TREE_DISCONNECT: u16 = 0x0004;
    pub const CREATE: u16 = 0x0005;
    pub const CLOSE: u16 = 0x0006;
    pub const FLUSH: u16 = 0x0007;
    pub const READ: u16 = 0x0008;
    pub const WRITE: u16 = 0x0009;
    pub const IOCTL: u16 = 0x000B;
    pub const ECHO: u16 = 0x000D;
    pub const QUERY_DIRECTORY: u16 = 0x000E;
    pub const QUERY_INFO: u16 = 0x0010;
    pub const SET_INFO: u16 = 0x0011;
}

/// `FSCTL_PIPE_TRANSCEIVE` (`0x0011C017`) IOCTL code used by `ncacn_np` to send an MSRPC
/// request PDU and receive the MSRPC response PDU in a single atomic SMB2 roundtrip.
pub const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;

ndr_struct! {
    pub struct Smb2Header {
        pub protocol_id: [u8; 4],
        pub structure_size: u16,
        pub credit_charge: u16,
        pub status: u32,
        pub command: u16,
        pub credit_request_response: u16,
        pub flags: u32,
        pub next_command: u32,
        pub message_id: u64,
        pub reserved: u32,
        pub tree_id: u32,
        pub session_id: u64,
        pub signature: [u8; 16],
    }
}

impl Smb2Header {
    pub const MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];

    pub fn new(command: u16, message_id: u64, session_id: u64, tree_id: u32) -> Self {
        Self {
            protocol_id: Self::MAGIC,
            structure_size: 64,
            credit_charge: 1,
            status: NtStatus::STATUS_SUCCESS.0,
            command,
            credit_request_response: 127,
            flags: 0,
            next_command: 0,
            message_id,
            reserved: 0,
            tree_id,
            session_id,
            signature: [0u8; 16],
        }
    }
}

/// Wraps an SMB1 or SMB2/3 PDU in a 4-byte NetBIOS Session Service header (`0x00` + 24-bit big-endian length).
pub fn wrap_netbios_session(pdu: &[u8]) -> Vec<u8> {
    let len = pdu.len() as u32;
    let mut out = Vec::with_capacity(4 + pdu.len());
    out.extend_from_slice(&(len & 0x00FF_FFFF).to_be_bytes());
    out.extend_from_slice(pdu);
    out
}

/// Reads a single NetBIOS-framed SMB1/SMB2/SMB3 packet from any `Read` stream.
/// Returns an empty `Vec` on clean EOF.
pub fn read_netbios_packet<R: Read>(stream: &mut R) -> Result<Vec<u8>, CoreError> {
    let mut hdr = [0u8; 4];
    match stream.read(&mut hdr[0..1]) {
        Ok(0) => return Ok(Vec::new()), // Clean EOF (peer disconnected)
        Ok(1) => {}
        Ok(_) => unreachable!(),
        Err(e) => {
            return Err(CoreError::ProtocolError(format!(
                "Failed reading NetBIOS header: {}",
                e
            )))
        }
    }
    stream
        .read_exact(&mut hdr[1..4])
        .map_err(|e| CoreError::ProtocolError(format!("Failed reading NetBIOS header: {}", e)))?;
    let len = u32::from_be_bytes([0, hdr[1], hdr[2], hdr[3]]) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(CoreError::ProtocolError(format!(
            "Oversized NetBIOS frame: {} bytes",
            len
        )));
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|e| CoreError::ProtocolError(format!("Failed reading SMB body: {}", e)))?;
    Ok(body)
}

/// Builds a Legacy SMBv1 Multi-Protocol Negotiate Request (`\xFFSMB\x72...`).
pub fn build_smbv1_multiprotocol_negotiate(include_smb2_upgrade: bool) -> Vec<u8> {
    let mut dialects = Vec::new();
    dialects.push(0x02u8);
    dialects.extend_from_slice(b"NT LM 0.12\x00");
    if include_smb2_upgrade {
        dialects.push(0x02u8);
        dialects.extend_from_slice(b"SMB 2.002\x00");
        dialects.push(0x02u8);
        dialects.extend_from_slice(b"SMB 2.???\x00");
    }

    let mut pdu = Vec::with_capacity(35 + dialects.len());
    pdu.extend_from_slice(b"\xFFSMB");
    pdu.push(0x72);
    pdu.extend_from_slice(&0u32.to_le_bytes());
    pdu.push(0x18);
    pdu.extend_from_slice(&0xC853u16.to_le_bytes());
    pdu.extend_from_slice(&[0u8; 12]);
    pdu.extend_from_slice(&0xFFFFu16.to_le_bytes());
    pdu.extend_from_slice(&0xFEFFu16.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());
    pdu.extend_from_slice(&0u16.to_le_bytes());
    pdu.push(0x00);
    pdu.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
    pdu.extend_from_slice(&dialects);
    pdu
}

/// Builds a native SMB2/3 `SMB2_NEGOTIATE` request supporting dialects `0x0202` through `0x0311`.
pub fn build_smb2_negotiate_request(profile: AdCompatProfile, client_guid: [u8; 16]) -> Vec<u8> {
    let dialects = SmbDialect::dialects_for_profile(profile);
    build_smb2_negotiate_request_with_dialects(&dialects, profile, client_guid)
}

/// Builds an `SMB2_NEGOTIATE` request for an explicit dialect list (used by the signed RPC pipe path,
/// which currently caps at SMB 3.0.2 because 3.1.1 signing requires preauth-integrity hashing).
pub fn build_smb2_negotiate_request_with_dialects(
    dialects: &[SmbDialect],
    profile: AdCompatProfile,
    client_guid: [u8; 16],
) -> Vec<u8> {
    let has_311 = dialects.contains(&SmbDialect::Smb311);

    let mut writer = NdrWriter::with_capacity(192);
    let hdr = Smb2Header::new(smb2_cmd::NEGOTIATE, 0, 0, 0);
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(36);
    writer.write_u16(dialects.len() as u16);
    let sec_mode = match profile {
        AdCompatProfile::ModernHardened2025 => 0x0003u16,
        _ => 0x0001u16,
    };
    writer.write_u16(sec_mode);
    writer.write_u16(0);
    writer.write_u32(0x0000_007F);
    writer.write_fixed_array(&client_guid);

    if has_311 {
        let after_dialects = 64 + 36 + dialects.len() * 2;
        let ctx_offset = (after_dialects + 7) & !7;
        writer.write_u32(ctx_offset as u32);
        writer.write_u16(2);
        writer.write_u16(0);
    } else {
        writer.write_u64(0);
    }

    for d in dialects {
        writer.write_u16(*d as u16);
    }

    if has_311 {
        writer.align(8);
        writer.write_u16(0x0001);
        writer.write_u16(38);
        writer.write_u32(0);
        writer.write_u16(1);
        writer.write_u16(32);
        writer.write_u16(0x0001);
        writer.write_fixed_array(&[0xA5u8; 32]);

        writer.align(8);
        writer.write_u16(0x0002);
        writer.write_u16(8);
        writer.write_u32(0);
        writer.write_u16(3);
        writer.write_u16(0x0004);
        writer.write_u16(0x0002);
        writer.write_u16(0x0001);
    }

    writer.into_bytes()
}

/// Builds an `SMB2_SESSION_SETUP` Request carrying an NTLMSSP Type 1 Negotiate or Type 3 Authenticate blob.
pub fn build_smb2_session_setup_request(
    message_id: u64,
    session_id: u64,
    security_blob: &[u8],
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 24 + security_blob.len());
    let hdr = Smb2Header::new(smb2_cmd::SESSION_SETUP, message_id, session_id, 0);
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(25);
    writer.write_u8(0);
    writer.write_u8(0x01);
    writer.write_u32(0x0000_0001);
    writer.write_u32(0);
    writer.write_u16(88);
    writer.write_u16(security_blob.len() as u16);
    writer.write_u64(0);
    writer.write_bytes(security_blob);

    writer.into_bytes()
}

/// Builds an `SMB2_SESSION_SETUP` Response.
pub fn build_smb2_session_setup_response(
    message_id: u64,
    session_id: u64,
    status: NtStatus,
    security_blob: &[u8],
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 8 + security_blob.len());
    let mut hdr = Smb2Header::new(smb2_cmd::SESSION_SETUP, message_id, session_id, 0);
    hdr.flags = 0x0000_0001;
    hdr.status = status.0;
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(9);
    writer.write_u16(0);
    writer.write_u16(72);
    writer.write_u16(security_blob.len() as u16);
    writer.write_bytes(security_blob);

    writer.into_bytes()
}

/// Builds an `SMB2_TREE_CONNECT` Request (`0x0003`) to connect to `\\<server>\IPC$` or any share.
pub fn build_smb2_tree_connect_request(
    message_id: u64,
    session_id: u64,
    unc_path: &str,
) -> Vec<u8> {
    let path_utf16 = encode_utf16le(unc_path);
    let mut writer = NdrWriter::with_capacity(64 + 8 + path_utf16.len());
    let hdr = Smb2Header::new(smb2_cmd::TREE_CONNECT, message_id, session_id, 0);
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(9); // StructureSize = 9
    writer.write_u16(0); // Flags = 0
    writer.write_u16(72); // PathOffset = 64 + 8 = 72
    writer.write_u16(path_utf16.len() as u16);
    writer.write_bytes(&path_utf16);

    writer.into_bytes()
}

/// SMB2 `CreateDisposition` values (`[MS-SMB2] 2.2.13`).
pub mod create_disposition {
    pub const SUPERSEDE: u32 = 0;
    pub const OPEN: u32 = 1;
    pub const CREATE: u32 = 2;
    pub const OPEN_IF: u32 = 3;
    pub const OVERWRITE: u32 = 4;
    pub const OVERWRITE_IF: u32 = 5;
}

/// SMB2 `CreateOptions` / `DesiredAccess` flags commonly used for file transfer.
pub mod file_access {
    pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    pub const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
    pub const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
    pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    pub const SYNCHRONIZE: u32 = 0x0010_0000;
    /// `FILE_GENERIC_READ` (read + attributes + synchronize).
    pub const GENERIC_READ: u32 = 0x0012_0089;
    /// Read + write + delete + attributes + synchronize (used to create/overwrite then optionally delete).
    pub const GENERIC_WRITE: u32 = 0x0013_01BF;
}

pub mod file_attributes {
    pub const READONLY: u32 = 0x0000_0001;
    pub const HIDDEN: u32 = 0x0000_0002;
    pub const SYSTEM: u32 = 0x0000_0004;
    pub const DIRECTORY: u32 = 0x0000_0010;
    pub const ARCHIVE: u32 = 0x0000_0020;
    pub const NORMAL: u32 = 0x0000_0080;
}

pub mod query_dir_flags {
    pub const RESTART_SCANS: u8 = 0x01;
    pub const RETURN_SINGLE_ENTRY: u8 = 0x02;
    pub const INDEX_SPECIFIED: u8 = 0x04;
    pub const REOPEN: u8 = 0x10;
}

pub mod file_info_class {
    pub const FILE_DIRECTORY_INFORMATION: u8 = 1;
    pub const FILE_FULL_DIRECTORY_INFORMATION: u8 = 2;
    pub const FILE_BOTH_DIRECTORY_INFORMATION: u8 = 3;
    pub const FILE_BASIC_INFORMATION: u8 = 4;
    pub const FILE_NAMES_INFORMATION: u8 = 12;
    pub const FILE_ID_BOTH_DIR_INFORMATION: u8 = 37;
}

/// FileBasicInformation record (`[MS-FSCC] 2.4.7`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileBasicInfo {
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub file_attributes: u32,
}

/// Directory entry parsed from `FileBothDirectoryInformation` (`[MS-SMB2] 2.2.33`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbDirectoryEntry {
    pub name: String,
    pub is_directory: bool,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub creation_time: FileTime,
    pub last_access_time: FileTime,
    pub last_write_time: FileTime,
    pub change_time: FileTime,
    pub file_attributes: u32,
}

/// Builds a generic `SMB2_CREATE` Request (`0x0005`) for a path within a connected tree.
#[allow(clippy::too_many_arguments)]
pub fn build_smb2_create_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    path: &str,
    desired_access: u32,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
) -> Vec<u8> {
    let name_utf16 = encode_utf16le(path);

    let mut writer = NdrWriter::with_capacity(64 + 56 + name_utf16.len());
    let hdr = Smb2Header::new(smb2_cmd::CREATE, message_id, session_id, tree_id);
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(57); // StructureSize = 57
    writer.write_u8(0); // SecurityFlags
    writer.write_u8(0); // RequestedOplockLevel = NONE
    writer.write_u32(2); // ImpersonationLevel = SecurityImpersonation
    writer.write_u64(0); // SmbCreateFlags
    writer.write_u64(0); // Reserved
    writer.write_u32(desired_access);
    writer.write_u32(file_attributes);
    writer.write_u32(share_access);
    writer.write_u32(create_disposition);
    writer.write_u32(create_options);
    writer.write_u16(120); // NameOffset = 64 + 56
    writer.write_u16(name_utf16.len() as u16);
    writer.write_u32(0); // CreateContextsOffset
    writer.write_u32(0); // CreateContextsLength
    if name_utf16.is_empty() {
        writer.write_u8(0);
    } else {
        writer.write_bytes(&name_utf16);
    }

    writer.into_bytes()
}

/// Builds an `SMB2_CREATE` Request to open a named pipe inside the `IPC$` tree (`ncacn_np`).
pub fn build_smb2_create_pipe_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    pipe_name: &str,
) -> Vec<u8> {
    let clean_name = pipe_name
        .trim_start_matches(r"\PIPE\")
        .trim_start_matches(r"\pipe\")
        .trim_start_matches('\\');
    build_smb2_create_request(
        message_id,
        session_id,
        tree_id,
        clean_name,
        0x0012_019F, // FILE_READ_DATA|FILE_WRITE_DATA|SYNCHRONIZE|READ_CONTROL
        0,
        0x0000_0003, // FILE_SHARE_READ|FILE_SHARE_WRITE
        create_disposition::OPEN,
        file_access::FILE_NON_DIRECTORY_FILE,
    )
}

/// Builds an `SMB2_WRITE` Request (`0x0009`) writing `data` at `offset` to an open `file_id`.
pub fn build_smb2_write_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: [u8; 16],
    offset: u64,
    data: &[u8],
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 48 + data.len());
    let hdr = Smb2Header::new(smb2_cmd::WRITE, message_id, session_id, tree_id);
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(49); // StructureSize = 49
    writer.write_u16(112); // DataOffset = 64 + 48
    writer.write_u32(data.len() as u32); // Length
    writer.write_u64(offset); // Offset
    writer.write_fixed_array(&file_id);
    writer.write_u32(0); // Channel
    writer.write_u32(0); // RemainingBytes
    writer.write_u16(0); // WriteChannelInfoOffset
    writer.write_u16(0); // WriteChannelInfoLength
    writer.write_u32(0); // Flags
    writer.write_bytes(data);

    writer.into_bytes()
}

/// Builds an `SMB2_READ` Request (`0x0008`) reading `length` bytes at `offset` from an open `file_id`.
pub fn build_smb2_read_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: [u8; 16],
    offset: u64,
    length: u32,
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 49);
    let hdr = Smb2Header::new(smb2_cmd::READ, message_id, session_id, tree_id);
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(49); // StructureSize = 49
    writer.write_u8(0); // Padding
    writer.write_u8(0); // Flags
    writer.write_u32(length); // Length
    writer.write_u64(offset); // Offset
    writer.write_fixed_array(&file_id);
    writer.write_u32(0); // MinimumCount
    writer.write_u32(0); // Channel
    writer.write_u32(0); // RemainingBytes
    writer.write_u16(0); // ReadChannelInfoOffset
    writer.write_u16(0); // ReadChannelInfoLength
    writer.write_u8(0); // Buffer (1-byte pad; StructureSize counts it)

    writer.into_bytes()
}

/// Builds an `SMB2_CLOSE` Request (`0x0006`) for an open `file_id`.
pub fn build_smb2_close_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: [u8; 16],
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 24);
    let hdr = Smb2Header::new(smb2_cmd::CLOSE, message_id, session_id, tree_id);
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(24); // StructureSize = 24
    writer.write_u16(0); // Flags
    writer.write_u32(0); // Reserved
    writer.write_fixed_array(&file_id);

    writer.into_bytes()
}

/// Builds an `SMB2_TREE_DISCONNECT` Request (`0x0004`).
pub fn build_smb2_tree_disconnect_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 4);
    let hdr = Smb2Header::new(smb2_cmd::TREE_DISCONNECT, message_id, session_id, tree_id);
    hdr.ndr_serialize(&mut writer);
    writer.write_u16(4); // StructureSize = 4
    writer.write_u16(0); // Reserved
    writer.into_bytes()
}

/// Builds an `SMB2_LOGOFF` Request (`0x0002`).
pub fn build_smb2_logoff_request(
    message_id: u64,
    session_id: u64,
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 4);
    let hdr = Smb2Header::new(smb2_cmd::LOGOFF, message_id, session_id, 0);
    hdr.ndr_serialize(&mut writer);
    writer.write_u16(4); // StructureSize = 4
    writer.write_u16(0); // Reserved
    writer.into_bytes()
}

/// Builds an `SMB2_IOCTL` Request (`0x000B`) with `FSCTL_PIPE_TRANSCEIVE` (`0x0011C017`)
/// to transact an MS-RPCE PDU over an open SMB2 named pipe handle (`file_id`).
pub fn build_smb2_pipe_transceive_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: [u8; 16],
    rpc_pdu: &[u8],
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 56 + rpc_pdu.len());
    let hdr = Smb2Header::new(smb2_cmd::IOCTL, message_id, session_id, tree_id);
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(57); // StructureSize = 57
    writer.write_u16(0); // Reserved
    writer.write_u32(FSCTL_PIPE_TRANSCEIVE); // CtlCode = 0x0011C017
    writer.write_fixed_array(&file_id); // FileId (16 bytes)
    writer.write_u32(120); // InputOffset = 64 + 56 = 120
    writer.write_u32(rpc_pdu.len() as u32); // InputCount
    writer.write_u32(0); // MaxInputResponse = 0
    writer.write_u32(0); // OutputOffset = 0
    writer.write_u32(0); // OutputCount = 0
    writer.write_u32(65536); // MaxOutputResponse = 65536
    writer.write_u32(0x0000_0001); // Flags = SMB2_0_IOCTL_IS_FSCTL (1)
    writer.write_u32(0); // Reserved2
    writer.write_bytes(rpc_pdu);

    writer.into_bytes()
}

/// Builds an `SMB2_QUERY_DIRECTORY` Request (`0x000E`) (`[MS-SMB2] 2.2.33`).
pub fn build_smb2_query_directory_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: [u8; 16],
    pattern: &str,
    restart_scans: bool,
) -> Vec<u8> {
    let pattern_utf16 = encode_utf16le(pattern);
    let mut writer = NdrWriter::with_capacity(64 + 32 + pattern_utf16.len());
    let hdr = Smb2Header::new(smb2_cmd::QUERY_DIRECTORY, message_id, session_id, tree_id);
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(33); // StructureSize = 33
    writer.write_u8(file_info_class::FILE_BOTH_DIRECTORY_INFORMATION);
    writer.write_u8(if restart_scans { query_dir_flags::RESTART_SCANS } else { 0 });
    writer.write_u32(0); // FileIndex
    writer.write_fixed_array(&file_id);
    writer.write_u16(96); // FileNameOffset = 64 + 32
    writer.write_u16(pattern_utf16.len() as u16);
    writer.write_u32(65536); // OutputBufferLength
    writer.write_bytes(&pattern_utf16);

    writer.into_bytes()
}

/// Extracts the raw directory enumeration buffer from an `SMB2_QUERY_DIRECTORY` response (`[MS-SMB2] 2.2.34`).
pub fn parse_query_directory_response(resp: &[u8]) -> Result<&[u8], CoreError> {
    if resp.len() < 72 {
        return Err(CoreError::BufferUnderflow { needed: 72, available: resp.len() });
    }
    let offset = u16::from_le_bytes([resp[66], resp[67]]) as usize;
    let length = u32::from_le_bytes([resp[68], resp[69], resp[70], resp[71]]) as usize;
    if offset + length > resp.len() {
        return Err(CoreError::BufferUnderflow { needed: offset + length, available: resp.len() });
    }
    Ok(&resp[offset..offset + length])
}

/// Builds an `SMB2_QUERY_INFO` Request for `FileBasicInformation` (`[MS-SMB2] 2.2.37`).
pub fn build_smb2_query_info_basic_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: [u8; 16],
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 40);
    let hdr = Smb2Header::new(smb2_cmd::QUERY_INFO, message_id, session_id, tree_id);
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(41); // StructureSize = 41
    writer.write_u8(1); // InfoType = SMB2_0_INFO_FILE (0x01)
    writer.write_u8(file_info_class::FILE_BASIC_INFORMATION); // FileInfoClass = 4
    writer.write_u32(1024); // OutputBufferLength
    writer.write_u16(0); // InputBufferOffset
    writer.write_u16(0); // Reserved
    writer.write_u32(0); // InputBufferLength
    writer.write_u32(0); // AdditionalInformation
    writer.write_u32(0); // Flags
    writer.write_fixed_array(&file_id);

    writer.into_bytes()
}

/// Parses a `FileBasicInfo` from `SMB2_QUERY_INFO` response (`[MS-SMB2] 2.2.38`).
pub fn parse_smb2_query_info_basic_response(resp: &[u8]) -> Result<FileBasicInfo, CoreError> {
    if resp.len() < 72 {
        return Err(CoreError::BufferUnderflow { needed: 72, available: resp.len() });
    }
    let offset = u16::from_le_bytes([resp[66], resp[67]]) as usize;
    let length = u32::from_le_bytes([resp[68], resp[69], resp[70], resp[71]]) as usize;
    if offset + length > resp.len() || length < 40 {
        return Err(CoreError::BufferUnderflow { needed: offset + 40, available: resp.len() });
    }
    let buf = &resp[offset..offset + length];
    let creation_time = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let last_access_time = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let last_write_time = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let change_time = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let file_attributes = u32::from_le_bytes(buf[32..36].try_into().unwrap());

    Ok(FileBasicInfo {
        creation_time,
        last_access_time,
        last_write_time,
        change_time,
        file_attributes,
    })
}

/// Builds an `SMB2_SET_INFO` Request for `FileBasicInformation` (`[MS-SMB2] 2.2.39`).
pub fn build_smb2_set_info_basic_request(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: [u8; 16],
    info: &FileBasicInfo,
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 32 + 40);
    let hdr = Smb2Header::new(smb2_cmd::SET_INFO, message_id, session_id, tree_id);
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(33); // StructureSize = 33
    writer.write_u8(1); // InfoType = SMB2_0_INFO_FILE (0x01)
    writer.write_u8(file_info_class::FILE_BASIC_INFORMATION); // FileInfoClass = 4
    writer.write_u32(40); // BufferLength = 40
    writer.write_u16(96); // BufferOffset = 64 + 32
    writer.write_u16(0); // Reserved
    writer.write_u32(0); // AdditionalInformation
    writer.write_fixed_array(&file_id);

    // FileBasicInformation buffer
    writer.write_u64(info.creation_time);
    writer.write_u64(info.last_access_time);
    writer.write_u64(info.last_write_time);
    writer.write_u64(info.change_time);
    writer.write_u32(info.file_attributes);
    writer.write_u32(0); // Reserved

    writer.into_bytes()
}

/// Parses entries from `FileBothDirectoryInformation` (`[MS-SMB2] 2.2.33`).
pub fn parse_both_directory_entries(mut buffer: &[u8]) -> Result<Vec<SmbDirectoryEntry>, CoreError> {
    let mut entries = Vec::new();
    while !buffer.is_empty() {
        if buffer.len() < 94 {
            break;
        }
        let next_offset = u32::from_le_bytes(buffer[0..4].try_into().unwrap()) as usize;
        let creation_time = FileTime::from_raw(u64::from_le_bytes(buffer[8..16].try_into().unwrap()));
        let last_access_time = FileTime::from_raw(u64::from_le_bytes(buffer[16..24].try_into().unwrap()));
        let last_write_time = FileTime::from_raw(u64::from_le_bytes(buffer[24..32].try_into().unwrap()));
        let change_time = FileTime::from_raw(u64::from_le_bytes(buffer[32..40].try_into().unwrap()));
        let end_of_file = u64::from_le_bytes(buffer[40..48].try_into().unwrap());
        let allocation_size = u64::from_le_bytes(buffer[48..56].try_into().unwrap());
        let file_attributes = u32::from_le_bytes(buffer[56..60].try_into().unwrap());
        let file_name_length = u32::from_le_bytes(buffer[60..64].try_into().unwrap()) as usize;

        if 94 + file_name_length > buffer.len() {
            return Err(CoreError::BufferUnderflow {
                needed: 94 + file_name_length,
                available: buffer.len(),
            });
        }

        let name_bytes = &buffer[94..94 + file_name_length];
        let name_u16: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name = String::from_utf16_lossy(&name_u16);
        let is_directory = (file_attributes & file_attributes::DIRECTORY) != 0;

        entries.push(SmbDirectoryEntry {
            name,
            is_directory,
            end_of_file,
            allocation_size,
            creation_time,
            last_access_time,
            last_write_time,
            change_time,
            file_attributes,
        });

        if next_offset == 0 || next_offset >= buffer.len() {
            break;
        }
        buffer = &buffer[next_offset..];
    }
    Ok(entries)
}

/// Parses the fixed fields of an `SMB2_NEGOTIATE` Response (`impacket/smb3structs.py:SMB2Negotiate_Response`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2NegotiateResponseSummary {
    pub status: NtStatus,
    pub dialect_revision: u16,
    pub security_mode: u16,
    pub server_guid: [u8; 16],
    pub capabilities: u32,
    pub max_transact_size: u32,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub system_time: FileTime,
    pub server_start_time: FileTime,
}

impl Smb2NegotiateResponseSummary {
    pub fn parse(pdu: &[u8]) -> Result<Self, CoreError> {
        let mut reader = NdrReader::new(pdu);
        let hdr = Smb2Header::ndr_deserialize(&mut reader)?;
        if hdr.protocol_id != Smb2Header::MAGIC {
            return Err(CoreError::ProtocolError("Invalid SMB2/3 magic header".into()));
        }
        let _struct_size = reader.read_u16()?;
        let security_mode = reader.read_u16()?;
        let dialect_revision = reader.read_u16()?;
        let _neg_ctx_count = reader.read_u16()?;
        let server_guid = reader.read_fixed_array::<16>()?;
        let capabilities = reader.read_u32()?;
        let max_transact_size = reader.read_u32()?;
        let max_read_size = reader.read_u32()?;
        let max_write_size = reader.read_u32()?;
        let system_time = FileTime::from_raw(reader.read_u64()?);
        let server_start_time = FileTime::from_raw(reader.read_u64()?);

        Ok(Self {
            status: NtStatus(hdr.status),
            dialect_revision,
            security_mode,
            server_guid,
            capabilities,
            max_transact_size,
            max_read_size,
            max_write_size,
            system_time,
            server_start_time,
        })
    }

    pub fn build_response(
        dialect_revision: u16,
        security_mode: u16,
        system_time: FileTime,
        server_start_time: FileTime,
    ) -> Vec<u8> {
        let mut writer = NdrWriter::with_capacity(128);
        let mut hdr = Smb2Header::new(smb2_cmd::NEGOTIATE, 0, 0, 0);
        hdr.flags = 0x0000_0001;
        hdr.ndr_serialize(&mut writer);

        writer.write_u16(65);
        writer.write_u16(security_mode);
        writer.write_u16(dialect_revision);
        writer.write_u16(0);
        writer.write_fixed_array(&[0x55; 16]);
        writer.write_u32(0x0000_007F);
        writer.write_u32(8_388_608);
        writer.write_u32(8_388_608);
        writer.write_u32(8_388_608);
        writer.write_u64(system_time.0);
        writer.write_u64(server_start_time.0);
        writer.write_u16(128);
        writer.write_u16(0);
        writer.write_u32(0);

        writer.into_bytes()
    }
}

/// Locates and extracts an embedded `NTLMSSP\0` token from either a raw security buffer
/// or an ASN.1 SPNEGO (`NegTokenInit` / `NegTokenResp`) wrapper.
pub fn extract_ntlmssp_from_blob(blob: &[u8]) -> Result<&[u8], CoreError> {
    if blob.starts_with(b"NTLMSSP\x00") {
        return Ok(blob);
    }
    if let Ok(extracted) = impacket_auth::spnego::extract_embedded_auth_token(blob) {
        if let Some(idx) = blob.windows(extracted.len()).position(|w| w == extracted.as_slice()) {
            return Ok(&blob[idx..idx + extracted.len()]);
        }
    }
    if let Some(idx) = blob.windows(8).position(|w| w == b"NTLMSSP\x00") {
        Ok(&blob[idx..])
    } else {
        Err(CoreError::ProtocolError(
            "No NTLMSSP signature found in SMB security blob".into(),
        ))
    }
}

/// Complete report returned by `dump_ntlm_info_over_stream` and `dump_ntlm_info_live` (`examples/DumpNTLMInfo.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpNtlmInfoReport {
    pub target_addr: String,
    pub negotiated_dialect: u16,
    pub signing_enabled: bool,
    pub signing_required: bool,
    pub max_read_size: u32,
    pub max_write_size: u32,
    pub server_time: FileTime,
    pub server_boot_time: FileTime,
    pub challenge: NtlmChallengeMessage,
}

/// Sans-I/O / Generic Stream executor for `DumpNTLMInfo`.
pub fn dump_ntlm_info_over_stream<R: Read, W: Write>(
    target_label: &str,
    profile: AdCompatProfile,
    rx: &mut R,
    tx: &mut W,
) -> Result<DumpNtlmInfoReport, CoreError> {
    let neg_req = build_smb2_negotiate_request(profile, [0x99; 16]);
    tx.write_all(&wrap_netbios_session(&neg_req))
        .map_err(|e| CoreError::ProtocolError(format!("Failed sending SMB2_NEGOTIATE: {}", e)))?;

    let neg_resp_pdu = read_netbios_packet(rx)?;
    let neg_summary = Smb2NegotiateResponseSummary::parse(&neg_resp_pdu)?;

    let ntlm_type1 = NtlmNegotiateMessage::for_profile(profile).to_bytes();
    let sess_req = build_smb2_session_setup_request(1, 0, &ntlm_type1);
    tx.write_all(&wrap_netbios_session(&sess_req))
        .map_err(|e| CoreError::ProtocolError(format!("Failed sending SMB2_SESSION_SETUP: {}", e)))?;

    let sess_resp_pdu = read_netbios_packet(rx)?;
    if sess_resp_pdu.len() < 72 {
        return Err(CoreError::BufferUnderflow {
            needed: 72,
            available: sess_resp_pdu.len(),
        });
    }
    let sec_offset = u16::from_le_bytes([sess_resp_pdu[68], sess_resp_pdu[69]]) as usize;
    let sec_len = u16::from_le_bytes([sess_resp_pdu[70], sess_resp_pdu[71]]) as usize;
    if sec_offset + sec_len > sess_resp_pdu.len() {
        return Err(CoreError::BufferUnderflow {
            needed: sec_offset + sec_len,
            available: sess_resp_pdu.len(),
        });
    }
    let sec_blob = &sess_resp_pdu[sec_offset..sec_offset + sec_len];
    let ntlm_bytes = extract_ntlmssp_from_blob(sec_blob)?;
    let challenge = NtlmChallengeMessage::from_bytes(ntlm_bytes)?;

    Ok(DumpNtlmInfoReport {
        target_addr: target_label.to_string(),
        negotiated_dialect: neg_summary.dialect_revision,
        signing_enabled: (neg_summary.security_mode & 0x01) != 0,
        signing_required: (neg_summary.security_mode & 0x02) != 0,
        max_read_size: neg_summary.max_read_size,
        max_write_size: neg_summary.max_write_size,
        server_time: neg_summary.system_time,
        server_boot_time: neg_summary.server_start_time,
        challenge,
    })
}

/// Connects to a live SMB server (TCP/445 or TCP/139) and extracts the `DumpNtlmInfoReport`.
pub fn dump_ntlm_info_live(
    host: &str,
    port: u16,
    profile: AdCompatProfile,
    timeout: Duration,
) -> Result<DumpNtlmInfoReport, CoreError> {
    let addr_str = format!("{}:{}", host, port);
    let sock_addr: SocketAddr = addr_str
        .to_socket_addrs()
        .map_err(|e| CoreError::ProtocolError(format!("Failed resolving {}: {}", addr_str, e)))?
        .next()
        .ok_or_else(|| CoreError::ProtocolError(format!("No address found for {}", addr_str)))?;

    let stream = TcpStream::connect_timeout(&sock_addr, timeout)
        .map_err(|e| CoreError::ProtocolError(format!("TCP connect to {} failed: {}", addr_str, e)))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let mut rx = stream
        .try_clone()
        .map_err(|e| CoreError::ProtocolError(format!("Socket clone failed: {}", e)))?;
    let mut tx = stream;
    dump_ntlm_info_over_stream(&addr_str, profile, &mut rx, &mut tx)
}

// ============================================================================
// Live authenticated SMB2 connection + ncacn_np named-pipe transact (`impacket/smbconnection.py`).
// ============================================================================

/// NTLM credentials for an authenticated SMB logon: either a password or pass-the-hash.
#[derive(Clone)]
pub enum SmbCredential {
    Password(String),
    NtlmHashes(impacket_core::NtlmHashes),
}

/// An authenticated SMB2/3 session over TCP/445 driving `ncacn_np` DCE/RPC named pipes
/// (`\PIPE\samr`, `\PIPE\lsarpc`, `\PIPE\srvsvc`, `\PIPE\svcctl`).
///
/// SMB signing is not yet implemented, so this authenticates and transacts against servers that do
/// not *require* signing. Domain Controllers that enforce signing will reject post-auth requests with
/// `STATUS_ACCESS_DENIED`; message signing (SMB 2.1 HMAC-SHA256 / SMB 3.x AES-CMAC) is the next step.
pub struct SmbConnection {
    stream: TcpStream,
    session_id: u64,
    tree_id: u32,
    message_id: u64,
    negotiated_dialect: u16,
    signing_required: bool,
    /// 16-byte signing key + CMAC flag, set once authenticated and the dialect supports signing.
    signing: Option<([u8; 16], bool)>,
    /// Running SMB 3.1.1 preauth-integrity hash (SHA-512 over the connect/auth message chain).
    preauth: [u8; 64],
    /// Negotiated 16-byte NTLMSSP session key.
    session_key: [u8; 16],
    /// Optional SMB 3.x transport encryption engine (AES-128-CCM or AES-128-GCM).
    encryption: Option<transform::Smb3EncryptionState>,
    /// Whether encryption is actively required for outgoing requests.
    encryption_required: bool,
}

impl SmbConnection {
    fn next_mid(&mut self) -> u64 {
        let m = self.message_id;
        self.message_id += 1;
        m
    }

    /// Computes and embeds the SMB2 signature over `pdu` (signature field zeroed first), per dialect:
    /// SMB 2.x = HMAC-SHA256, SMB 3.0/3.0.2 = AES-128-CMAC (`[MS-SMB2] 3.1.4.1`).
    fn sign(&self, pdu: &mut [u8]) {
        let (key, use_cmac) = match &self.signing {
            Some(s) => *s,
            None => return,
        };
        if pdu.len() < 64 {
            return;
        }
        // Set SMB2_FLAGS_SIGNED (0x08) and zero the 16-byte Signature field [48..64].
        pdu[16] |= 0x08;
        for b in &mut pdu[48..64] {
            *b = 0;
        }
        let sig = if use_cmac {
            impacket_crypto::aes128_cmac(&key, pdu)
        } else {
            let full = impacket_crypto::hmac_sha256(&key, pdu);
            full[..16].try_into().unwrap()
        };
        pdu[48..64].copy_from_slice(&sig);
    }

    /// Folds one SMB2 message into the running preauth-integrity hash (`[MS-SMB2] 3.1.4.2`:
    /// `hash = SHA-512(hash || message)`). Only consequential for an SMB 3.1.1 session.
    fn update_preauth(&mut self, msg: &[u8]) {
        let mut buf = Vec::with_capacity(64 + msg.len());
        buf.extend_from_slice(&self.preauth);
        buf.extend_from_slice(msg);
        self.preauth = impacket_crypto::sha512(&buf);
    }

    fn send(&mut self, pdu: &[u8]) -> Result<Vec<u8>, CoreError> {
        let wire = if let Some(enc) = &mut self.encryption {
            if self.encryption_required {
                enc.encrypt(self.session_id, pdu)?
            } else {
                pdu.to_vec()
            }
        } else {
            pdu.to_vec()
        };
        self.stream
            .write_all(&wrap_netbios_session(&wire))
            .map_err(|e| CoreError::ProtocolError(format!("SMB send failed: {}", e)))?;
        let resp = read_netbios_packet(&mut self.stream)?;
        if transform::is_transform_header(&resp) {
            if let Some(enc) = &self.encryption {
                enc.decrypt(&resp)
            } else {
                Err(CoreError::ProtocolError(
                    "Received encrypted SMB3 message but no encryption key established".into(),
                ))
            }
        } else {
            Ok(resp)
        }
    }

    /// Signs (when a session key is established) and sends an SMB2 request.
    fn send_signed(&mut self, mut pdu: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        self.sign(&mut pdu);
        self.send(&pdu)
    }

    fn header_status(pdu: &[u8]) -> Result<NtStatus, CoreError> {
        if pdu.len() < 64 || pdu[0..4] != Smb2Header::MAGIC {
            return Err(CoreError::ProtocolError("Not an SMB2 response".into()));
        }
        Ok(NtStatus(u32::from_le_bytes([pdu[8], pdu[9], pdu[10], pdu[11]])))
    }

    /// Connects to `host:port` and performs `SMB2_NEGOTIATE`.
    pub fn connect(host: &str, port: u16, profile: AdCompatProfile, timeout: Duration) -> Result<Self, CoreError> {
        let addr_str = format!("{}:{}", host, port);
        let sock_addr: SocketAddr = addr_str
            .to_socket_addrs()
            .map_err(|e| CoreError::ProtocolError(format!("Failed resolving {}: {}", addr_str, e)))?
            .next()
            .ok_or_else(|| CoreError::ProtocolError(format!("No address for {}", addr_str)))?;
        let stream = TcpStream::connect_timeout(&sock_addr, timeout)
            .map_err(|e| CoreError::ProtocolError(format!("TCP connect to {} failed: {}", addr_str, e)))?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));

        let mut conn = Self {
            stream,
            session_id: 0,
            tree_id: 0,
            message_id: 0,
            negotiated_dialect: 0,
            signing_required: false,
            signing: None,
            preauth: [0u8; 64],
            session_key: [0u8; 16],
            encryption: None,
            encryption_required: false,
        };
        // Offer the full SMB2/3 dialect set for this profile, including SMB 3.1.1.
        let dialects = SmbDialect::dialects_for_profile(profile);
        let neg = build_smb2_negotiate_request_with_dialects(&dialects, profile, [0x99; 16]);
        conn.update_preauth(&neg);
        let resp = conn.send(&neg)?;
        conn.update_preauth(&resp);
        let summary = Smb2NegotiateResponseSummary::parse(&resp)?;
        conn.negotiated_dialect = summary.dialect_revision;
        conn.signing_required = (summary.security_mode & 0x02) != 0;
        Ok(conn)
    }

    /// Returns the negotiated NTLMSSP session key.
    pub fn session_key(&self) -> &[u8; 16] {
        &self.session_key
    }

    /// Authenticates with NTLM (`SMB2_SESSION_SETUP` Type 1 -> Type 2 -> Type 3).
    pub fn login(
        &mut self,
        domain: &str,
        username: &str,
        credential: &SmbCredential,
        workstation: &str,
    ) -> Result<(), CoreError> {
        use impacket_auth::{
            compute_ntlm_hashes, compute_ntlmv2_response, ntlm_flags, NtlmAuthenticateMessage,
            NtlmChallengeMessage, NtlmNegotiateMessage,
        };

        // Type 1.
        let type1 = NtlmNegotiateMessage::for_profile(AdCompatProfile::UniversalAuto).to_bytes();
        let mid = self.next_mid();
        let setup1 = build_smb2_session_setup_request(mid, 0, &type1);
        self.update_preauth(&setup1);
        let resp1 = self.send(&setup1)?;
        self.update_preauth(&resp1);
        let status1 = Self::header_status(&resp1)?;
        if status1 != NtStatus::STATUS_MORE_PROCESSING_REQUIRED {
            return Err(CoreError::ProtocolError(format!(
                "SESSION_SETUP#1 unexpected status {}",
                status1.name()
            )));
        }
        self.session_id = u64::from_le_bytes(resp1[40..48].try_into().unwrap());

        // Extract Type 2 (server challenge + raw target info).
        let sec_off = u16::from_le_bytes([resp1[68], resp1[69]]) as usize;
        let sec_len = u16::from_le_bytes([resp1[70], resp1[71]]) as usize;
        if sec_off + sec_len > resp1.len() {
            return Err(CoreError::BufferUnderflow {
                needed: sec_off + sec_len,
                available: resp1.len(),
            });
        }
        let type2_bytes = extract_ntlmssp_from_blob(&resp1[sec_off..sec_off + sec_len])?;
        let challenge = NtlmChallengeMessage::from_bytes(type2_bytes)?;
        // Exact contiguous target-info bytes (required for a valid NTProofStr).
        let ti_off = u32::from_le_bytes([type2_bytes[44], type2_bytes[45], type2_bytes[46], type2_bytes[47]]) as usize;
        let ti_len = u16::from_le_bytes([type2_bytes[40], type2_bytes[41]]) as usize;
        let target_info_raw = type2_bytes
            .get(ti_off..ti_off + ti_len)
            .ok_or(CoreError::ProtocolError("NTLM Type2 target info out of range".into()))?;

        let hashes = match credential {
            SmbCredential::Password(p) => compute_ntlm_hashes(p),
            SmbCredential::NtlmHashes(h) => h.clone(),
        };
        let client_challenge: [u8; 8] = {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0x1337);
            let mut c = [0u8; 8];
            c[..4].copy_from_slice(&nanos.to_le_bytes());
            c[4..].copy_from_slice(&(nanos ^ 0xA5A5_A5A5).to_le_bytes());
            c
        };
        let timestamp = challenge
            .target_info
            .timestamp
            .unwrap_or_else(|| FileTime::from_unix_secs(0));

        let v2 = compute_ntlmv2_response(
            username,
            domain,
            &hashes,
            &challenge.server_challenge,
            &client_challenge,
            timestamp,
            target_info_raw,
        );
        // With NTLMSSP_NEGOTIATE_KEY_EXCH cleared, the exported session key is the session base key.
        let session_key = v2.session_base_key;
        self.session_key = session_key;

        let type3 = NtlmAuthenticateMessage {
            domain: domain.to_string(),
            username: username.to_string(),
            workstation: workstation.to_string(),
            lm_challenge_response: v2.lm_challenge_response,
            nt_challenge_response: v2.nt_challenge_response,
            encrypted_session_key: Vec::new(),
            flags: challenge.flags & !ntlm_flags::NTLMSSP_NEGOTIATE_KEY_EXCH,
            os_major: 10,
            os_minor: 0,
            os_build: 19041,
        }
        .to_bytes();

        let mid = self.next_mid();
        let setup2 = build_smb2_session_setup_request(mid, self.session_id, &type3);
        // Fold the final SESSION_SETUP request into the preauth hash BEFORE deriving the 3.1.1 key.
        self.update_preauth(&setup2);
        let resp2 = self.send(&setup2)?;
        let status2 = Self::header_status(&resp2)?;
        if !status2.is_success() {
            return Err(CoreError::NtStatus(status2));
        }

        // Derive the SMB2 signing key now that the session key is established (`[MS-SMB2] 3.1.4.2`).
        self.signing = match self.negotiated_dialect {
            0x0311 => {
                // SMB 3.1.1: AES-CMAC key = KDF(SessionKey, "SMBSigningKey\0", PreauthHash).
                let sk = impacket_crypto::sp800_108_counter_kdf(
                    &session_key,
                    b"SMBSigningKey\0",
                    &self.preauth,
                    16,
                );
                Some((sk.try_into().unwrap(), true))
            }
            0x0300 | 0x0302 => {
                // SMB 3.0/3.0.2: AES-CMAC key = KDF(SessionKey, "SMB2AESCMAC\0", "SmbSign\0").
                let sk = impacket_crypto::sp800_108_counter_kdf(
                    &session_key,
                    b"SMB2AESCMAC\0",
                    b"SmbSign\0",
                    16,
                );
                Some((sk.try_into().unwrap(), true))
            }
            // SMB 2.0.2 / 2.1: HMAC-SHA256 with the session key directly.
            0x0202 | 0x0210 => Some((session_key, false)),
            _ => None,
        };

        // Derive SMB 3.x transport encryption keys (`[MS-SMB2]` 3.1.4.2).
        self.encryption = match self.negotiated_dialect {
            0x0311 => Some(transform::Smb3EncryptionState::new_smb311(
                &session_key,
                &self.preauth,
                transform::SmbCipherAlgorithm::Aes128Gcm,
            )),
            0x0300 | 0x0302 => Some(transform::Smb3EncryptionState::new_smb30(&session_key)),
            _ => None,
        };

        let session_flags = if resp2.len() >= 66 {
            u16::from_le_bytes([resp2[64], resp2[65]])
        } else {
            0
        };
        // SMB2_SESSION_FLAG_ENCRYPT_DATA = 0x0004
        if (session_flags & 0x0004) != 0 && self.encryption.is_some() {
            self.encryption_required = true;
        }

        Ok(())
    }

    /// Returns whether SMB 3.x transport encryption is actively protecting requests.
    pub fn is_encrypted(&self) -> bool {
        self.encryption_required && self.encryption.is_some()
    }

    /// Explicitly enables or disables SMB 3.x transport encryption.
    pub fn set_encryption(&mut self, enable: bool) -> Result<(), CoreError> {
        if enable && self.encryption.is_none() {
            return Err(CoreError::ProtocolError(
                "Cannot enable encryption: dialect does not support SMB3 encryption".into(),
            ));
        }
        self.encryption_required = enable;
        Ok(())
    }

    /// `SMB2_TREE_CONNECT` to `\\<host>\IPC$` (or any share), storing the returned `TreeId`.
    pub fn tree_connect(&mut self, unc_path: &str) -> Result<u32, CoreError> {
        let mid = self.next_mid();
        let req = build_smb2_tree_connect_request(mid, self.session_id, unc_path);
        let resp = self.send_signed(req)?;
        let status = Self::header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        // TreeId is in the response header at bytes 36..40.
        self.tree_id = u32::from_le_bytes([resp[36], resp[37], resp[38], resp[39]]);

        // If the share indicates SMB2_SHAREFLAG_ENCRYPT_DATA (0x00000001), enforce encryption.
        if resp.len() >= 72 {
            let share_flags = u32::from_le_bytes([resp[68], resp[69], resp[70], resp[71]]);
            if (share_flags & 0x0000_0001) != 0 && self.encryption.is_some() {
                self.encryption_required = true;
            }
        }

        Ok(self.tree_id)
    }

    /// `SMB2_CREATE` to open a named pipe in the connected `IPC$` tree; returns its 16-byte `FileId`.
    pub fn open_pipe(&mut self, pipe_name: &str) -> Result<[u8; 16], CoreError> {
        let mid = self.next_mid();
        let req = build_smb2_create_pipe_request(mid, self.session_id, self.tree_id, pipe_name);
        let resp = self.send_signed(req)?;
        let status = Self::header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        // SMB2 CREATE Response FileId is at offset 128..144.
        if resp.len() < 144 {
            return Err(CoreError::BufferUnderflow {
                needed: 144,
                available: resp.len(),
            });
        }
        Ok(resp[128..144].try_into().unwrap())
    }

    /// `FSCTL_PIPE_TRANSCEIVE` — write one DCE/RPC PDU to the pipe and read the response PDU bytes.
    pub fn transact_pipe(&mut self, file_id: [u8; 16], rpc_pdu: &[u8]) -> Result<Vec<u8>, CoreError> {
        let mid = self.next_mid();
        let req = build_smb2_pipe_transceive_request(mid, self.session_id, self.tree_id, file_id, rpc_pdu);
        let resp = self.send_signed(req)?;
        let status = Self::header_status(&resp)?;
        // STATUS_BUFFER_OVERFLOW (0x80000005) means more pipe data remains; we treat the returned
        // output as the (possibly first) fragment. Success is the common case for small PDUs.
        if !status.is_success() && status.0 != 0x8000_0005 {
            return Err(CoreError::NtStatus(status));
        }
        // SMB2 IOCTL Response layout: header(64) + StructureSize(2) + Reserved(2) + CtlCode(4) +
        // FileId(16) + InputOffset(4) + InputCount(4) => OutputOffset@96, OutputCount@100, Buffer@112.
        if resp.len() < 104 {
            return Err(CoreError::BufferUnderflow {
                needed: 104,
                available: resp.len(),
            });
        }
        let output_offset = u32::from_le_bytes([resp[96], resp[97], resp[98], resp[99]]) as usize;
        let output_count = u32::from_le_bytes([resp[100], resp[101], resp[102], resp[103]]) as usize;
        if output_offset + output_count > resp.len() {
            return Err(CoreError::BufferUnderflow {
                needed: output_offset + output_count,
                available: resp.len(),
            });
        }
        Ok(resp[output_offset..output_offset + output_count].to_vec())
    }

    /// `SMB2_CREATE` of a regular file in the connected tree; returns its 16-byte `FileId`.
    pub fn create_file(
        &mut self,
        path: &str,
        desired_access: u32,
        create_disposition: u32,
        create_options: u32,
    ) -> Result<[u8; 16], CoreError> {
        let mid = self.next_mid();
        let req = build_smb2_create_request(
            mid,
            self.session_id,
            self.tree_id,
            path,
            desired_access,
            0x0000_0080, // FILE_ATTRIBUTE_NORMAL
            0x0000_0007, // FILE_SHARE_READ|WRITE|DELETE
            create_disposition,
            create_options | file_access::FILE_NON_DIRECTORY_FILE,
        );
        let resp = self.send_signed(req)?;
        let status = Self::header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        if resp.len() < 144 {
            return Err(CoreError::BufferUnderflow { needed: 144, available: resp.len() });
        }
        Ok(resp[128..144].try_into().unwrap())
    }

    /// `SMB2_WRITE` `data` at `offset`; returns the byte count written.
    pub fn write_file(&mut self, file_id: [u8; 16], offset: u64, data: &[u8]) -> Result<u32, CoreError> {
        let mid = self.next_mid();
        let req = build_smb2_write_request(mid, self.session_id, self.tree_id, file_id, offset, data);
        let resp = self.send_signed(req)?;
        let status = Self::header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        if resp.len() < 72 {
            return Err(CoreError::BufferUnderflow { needed: 72, available: resp.len() });
        }
        Ok(u32::from_le_bytes([resp[68], resp[69], resp[70], resp[71]]))
    }

    /// `SMB2_READ` up to `length` bytes at `offset`. Returns the bytes read (empty at EOF).
    pub fn read_file(&mut self, file_id: [u8; 16], offset: u64, length: u32) -> Result<Vec<u8>, CoreError> {
        let mid = self.next_mid();
        let req = build_smb2_read_request(mid, self.session_id, self.tree_id, file_id, offset, length);
        let resp = self.send_signed(req)?;
        let status = Self::header_status(&resp)?;
        // STATUS_END_OF_FILE (0xC0000011) => no more data.
        if status.0 == 0xC000_0011 {
            return Ok(Vec::new());
        }
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        if resp.len() < 72 {
            return Err(CoreError::BufferUnderflow { needed: 72, available: resp.len() });
        }
        let data_offset = resp[66] as usize;
        let data_len = u32::from_le_bytes([resp[68], resp[69], resp[70], resp[71]]) as usize;
        if data_offset + data_len > resp.len() {
            return Err(CoreError::BufferUnderflow { needed: data_offset + data_len, available: resp.len() });
        }
        Ok(resp[data_offset..data_offset + data_len].to_vec())
    }

    /// `SMB2_CLOSE` an open handle.
    pub fn close_file(&mut self, file_id: [u8; 16]) -> Result<(), CoreError> {
        let mid = self.next_mid();
        let req = build_smb2_close_request(mid, self.session_id, self.tree_id, file_id);
        let resp = self.send_signed(req)?;
        let status = Self::header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        Ok(())
    }

    /// Reads an entire file by path (open → read in 64 KiB chunks → close).
    pub fn read_full_file(&mut self, path: &str) -> Result<Vec<u8>, CoreError> {
        let fid = self.create_file(path, file_access::GENERIC_READ, create_disposition::OPEN, 0)?;
        let mut out = Vec::new();
        let mut offset = 0u64;
        loop {
            let chunk = self.read_file(fid, offset, 65536)?;
            if chunk.is_empty() {
                break;
            }
            offset += chunk.len() as u64;
            out.extend_from_slice(&chunk);
            if chunk.len() < 65536 {
                break;
            }
        }
        let _ = self.close_file(fid);
        Ok(out)
    }

    /// Writes an entire file by path (create/overwrite → write in 60 KiB chunks → close).
    pub fn write_full_file(&mut self, path: &str, data: &[u8]) -> Result<(), CoreError> {
        let fid = self.create_file(
            path,
            file_access::GENERIC_WRITE,
            create_disposition::OVERWRITE_IF,
            0,
        )?;
        let mut offset = 0u64;
        for chunk in data.chunks(61440) {
            self.write_file(fid, offset, chunk)?;
            offset += chunk.len() as u64;
        }
        let _ = self.close_file(fid);
        Ok(())
    }

    /// Deletes a file by opening it with `DELETE` access + `FILE_DELETE_ON_CLOSE`, then closing.
    pub fn delete_file(&mut self, path: &str) -> Result<(), CoreError> {
        let fid = self.create_file(
            path,
            0x0001_0000 | 0x0000_0080, // DELETE | FILE_READ_ATTRIBUTES
            create_disposition::OPEN,
            file_access::FILE_DELETE_ON_CLOSE,
        )?;
        self.close_file(fid)
    }

    /// Creates a new directory on the connected tree (`FILE_DIRECTORY_FILE`).
    pub fn create_directory(&mut self, path: &str) -> Result<(), CoreError> {
        let mid = self.next_mid();
        let req = build_smb2_create_request(
            mid,
            self.session_id,
            self.tree_id,
            path,
            file_access::FILE_LIST_DIRECTORY | file_access::FILE_READ_ATTRIBUTES | file_access::SYNCHRONIZE,
            file_attributes::DIRECTORY,
            0x0000_0007,
            create_disposition::CREATE,
            file_access::FILE_DIRECTORY_FILE,
        );
        let resp = self.send_signed(req)?;
        let status = Self::header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        if resp.len() >= 144 {
            let fid: [u8; 16] = resp[128..144].try_into().unwrap();
            let _ = self.close_file(fid);
        }
        Ok(())
    }

    /// Deletes an empty directory on the connected tree.
    pub fn delete_directory(&mut self, path: &str) -> Result<(), CoreError> {
        let mid = self.next_mid();
        let req = build_smb2_create_request(
            mid,
            self.session_id,
            self.tree_id,
            path,
            0x0001_0000 | file_access::SYNCHRONIZE, // DELETE | SYNCHRONIZE
            file_attributes::DIRECTORY,
            0x0000_0007,
            create_disposition::OPEN,
            file_access::FILE_DIRECTORY_FILE | file_access::FILE_DELETE_ON_CLOSE,
        );
        let resp = self.send_signed(req)?;
        let status = Self::header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        if resp.len() >= 144 {
            let fid: [u8; 16] = resp[128..144].try_into().unwrap();
            let _ = self.close_file(fid);
        }
        Ok(())
    }

    /// Opens a directory handle for querying.
    pub fn open_directory(&mut self, path: &str) -> Result<[u8; 16], CoreError> {
        let mid = self.next_mid();
        let req = build_smb2_create_request(
            mid,
            self.session_id,
            self.tree_id,
            path,
            file_access::FILE_LIST_DIRECTORY | file_access::FILE_READ_ATTRIBUTES | file_access::SYNCHRONIZE,
            file_attributes::DIRECTORY,
            0x0000_0007,
            create_disposition::OPEN,
            file_access::FILE_DIRECTORY_FILE | 0x0000_0020,
        );
        let resp = self.send_signed(req)?;
        let status = Self::header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        if resp.len() < 144 {
            return Err(CoreError::BufferUnderflow { needed: 144, available: resp.len() });
        }
        Ok(resp[128..144].try_into().unwrap())
    }

    /// Enumerates directory contents using `SMB2_QUERY_DIRECTORY` (`[MS-SMB2] 2.2.33`).
    pub fn list_directory(&mut self, path: &str) -> Result<Vec<SmbDirectoryEntry>, CoreError> {
        let dir_fid = self.open_directory(path)?;
        let mut entries = Vec::new();
        let mut restart = true;
        loop {
            let mid = self.next_mid();
            let req = build_smb2_query_directory_request(
                mid,
                self.session_id,
                self.tree_id,
                dir_fid,
                "*",
                restart,
            );
            restart = false;
            let resp = self.send_signed(req)?;
            let status = Self::header_status(&resp)?;
            if status == NtStatus::STATUS_NO_MORE_FILES {
                break;
            }
            if !status.is_success() {
                let _ = self.close_file(dir_fid);
                return Err(CoreError::NtStatus(status));
            }
            let buf = parse_query_directory_response(&resp)?;
            if buf.is_empty() {
                break;
            }
            let batch = parse_both_directory_entries(buf)?;
            if batch.is_empty() {
                break;
            }
            entries.extend(batch);
        }
        let _ = self.close_file(dir_fid);
        Ok(entries)
    }

    /// `SMB2_QUERY_INFO` for `FileBasicInformation` using an open `file_id`.
    pub fn query_file_basic_info(&mut self, file_id: [u8; 16]) -> Result<FileBasicInfo, CoreError> {
        let mid = self.next_mid();
        let req = build_smb2_query_info_basic_request(mid, self.session_id, self.tree_id, file_id);
        let resp = self.send_signed(req)?;
        let status = Self::header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        parse_smb2_query_info_basic_response(&resp)
    }

    /// `SMB2_SET_INFO` for `FileBasicInformation` using an open `file_id`.
    pub fn set_file_basic_info(&mut self, file_id: [u8; 16], info: &FileBasicInfo) -> Result<(), CoreError> {
        let mid = self.next_mid();
        let req = build_smb2_set_info_basic_request(mid, self.session_id, self.tree_id, file_id, info);
        let resp = self.send_signed(req)?;
        let status = Self::header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        Ok(())
    }

    /// Queries `FileBasicInfo` by file path.
    pub fn get_file_basic_info_by_path(&mut self, path: &str) -> Result<FileBasicInfo, CoreError> {
        let fid = self.create_file(path, file_access::GENERIC_READ, create_disposition::OPEN, 0)?;
        let info = self.query_file_basic_info(fid);
        let _ = self.close_file(fid);
        info
    }

    /// Sets `FileBasicInfo` by file path.
    pub fn set_file_basic_info_by_path(&mut self, path: &str, info: &FileBasicInfo) -> Result<(), CoreError> {
        let fid = self.create_file(
            path,
            file_access::FILE_READ_ATTRIBUTES | file_access::FILE_WRITE_ATTRIBUTES | file_access::SYNCHRONIZE,
            create_disposition::OPEN,
            0,
        )?;
        let res = self.set_file_basic_info(fid, info);
        let _ = self.close_file(fid);
        res
    }

    /// Connects to a share (`\\<host>\<share>`), replacing any current tree. Returns the `TreeId`.
    pub fn tree_connect_share(&mut self, host: &str, share: &str) -> Result<u32, CoreError> {
        self.tree_connect(&format!(r"\\{}\{}", host, share))
    }

    /// Disconnects from the currently connected tree (`SMB2_TREE_DISCONNECT` 0x0004).
    pub fn tree_disconnect(&mut self) -> Result<(), CoreError> {
        if self.tree_id == 0 {
            return Ok(());
        }
        let mid = self.next_mid();
        let req = build_smb2_tree_disconnect_request(mid, self.session_id, self.tree_id);
        let resp = self.send_signed(req)?;
        let status = Self::header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        self.tree_id = 0;
        Ok(())
    }

    /// Logs off the current authenticated session (`SMB2_LOGOFF` 0x0002).
    pub fn logoff(&mut self) -> Result<(), CoreError> {
        if self.session_id == 0 {
            return Ok(());
        }
        let mid = self.next_mid();
        let req = build_smb2_logoff_request(mid, self.session_id);
        let resp = self.send_signed(req)?;
        let status = Self::header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        self.session_id = 0;
        Ok(())
    }

    pub fn negotiated_dialect(&self) -> u16 {
        self.negotiated_dialect
    }

    pub fn signing_required(&self) -> bool {
        self.signing_required
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Test fixture: drives the real `dump_ntlm_info_over_stream` client against a prebuilt
    /// Windows Server 2025 `SMB2_NEGOTIATE` + `SMB2_SESSION_SETUP` (NTLMSSP Type 2) response pair.
    fn run_dump_ntlm_info_against_fixture() -> Result<DumpNtlmInfoReport, CoreError> {
    use impacket_auth::{ntlm_flags, NtlmTargetInfo};

    let neg_out = Smb2NegotiateResponseSummary::build_response(
        SmbDialect::Smb311 as u16,
        0x0003,
        FileTime::from_unix_secs(1_762_266_000),
        FileTime::from_unix_secs(1_762_000_000),
    );
    let mut ti = NtlmTargetInfo::default();
    ti.nb_domain_name = Some("CORP".into());
    ti.nb_computer_name = Some("DC01".into());
    ti.dns_domain_name = Some("corp.contoso.com".into());
    ti.dns_computer_name = Some("dc01.corp.contoso.com".into());
    ti.dns_tree_name = Some("corp.contoso.com".into());
    ti.timestamp = Some(FileTime::from_unix_secs(1_762_266_000));

    let chall = NtlmChallengeMessage {
        target_name: "CORP".into(),
        flags: ntlm_flags::DEFAULT_CLIENT_FLAGS | ntlm_flags::NTLMSSP_NEGOTIATE_TARGET_INFO,
        server_challenge: [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48],
        os_major: 10,
        os_minor: 0,
        os_build: 26100,
        ntlm_revision: 15,
        target_info: ti,
    };
    let sess_out = build_smb2_session_setup_response(
        1,
        0x0000_0400_0000_0001,
        NtStatus::STATUS_MORE_PROCESSING_REQUIRED,
        &chall.to_bytes(),
    );

    let mut server_stream_bytes = Vec::new();
    server_stream_bytes.extend_from_slice(&wrap_netbios_session(&neg_out));
    server_stream_bytes.extend_from_slice(&wrap_netbios_session(&sess_out));

    let mut rx = Cursor::new(server_stream_bytes);
    let mut tx = Vec::new();

    let report = dump_ntlm_info_over_stream(
        "dc01.corp.contoso.com:445",
        AdCompatProfile::UniversalAuto,
        &mut rx,
        &mut tx,
    )?;

    let mut client_rx = Cursor::new(tx);
    let sent_neg = read_netbios_packet(&mut client_rx)?;
    let sent_sess = read_netbios_packet(&mut client_rx)?;
    assert_eq!(&sent_neg[0..4], b"\xFESMB");
    assert_eq!(&sent_sess[0..4], b"\xFESMB");

    Ok(report)
    }

    #[test]
    fn test_dump_ntlm_info_full_protocol_exchange() {
        let report =
            run_dump_ntlm_info_against_fixture().expect("DumpNTLMInfo exchange should succeed");
        assert_eq!(report.negotiated_dialect, SmbDialect::Smb311 as u16);
        assert!(report.signing_required);
        assert_eq!(
            report.challenge.target_info.dns_computer_name.as_deref(),
            Some("dc01.corp.contoso.com")
        );
        assert_eq!(
            report.challenge.guessed_os_version(),
            "Windows Server 2025 (Build 26100)"
        );
    }

    #[test]
    fn test_smb2_named_pipe_tree_create_and_ioctl_builders() {
        let tree = build_smb2_tree_connect_request(2, 0x1001, r"\\dc01.corp.local\IPC$");
        assert_eq!(&tree[0..4], b"\xFESMB");
        assert_eq!(u16::from_le_bytes([tree[12], tree[13]]), smb2_cmd::TREE_CONNECT);

        let create = build_smb2_create_pipe_request(3, 0x1001, 1, r"\PIPE\lsarpc");
        assert_eq!(u16::from_le_bytes([create[12], create[13]]), smb2_cmd::CREATE);

        let ioctl = build_smb2_pipe_transceive_request(4, 0x1001, 1, [0x77; 16], &[1, 2, 3, 4]);
        assert_eq!(u16::from_le_bytes([ioctl[12], ioctl[13]]), smb2_cmd::IOCTL);
    }

    #[test]
    fn test_smb2_file_io_builders() {
        let create = build_smb2_create_request(
            1, 0x10, 2, r"temp\out.txt",
            file_access::GENERIC_WRITE, 0x80, 0x07,
            create_disposition::OVERWRITE_IF, 0,
        );
        assert_eq!(u16::from_le_bytes([create[12], create[13]]), smb2_cmd::CREATE);

        let write = build_smb2_write_request(2, 0x10, 2, [0x55; 16], 0, b"hello");
        assert_eq!(u16::from_le_bytes([write[12], write[13]]), smb2_cmd::WRITE);
        // DataOffset = 112, Length = 5.
        assert_eq!(u16::from_le_bytes([write[66], write[67]]), 112);
        assert_eq!(u32::from_le_bytes([write[68], write[69], write[70], write[71]]), 5);
        assert_eq!(&write[112..117], b"hello");

        let read = build_smb2_read_request(3, 0x10, 2, [0x55; 16], 1024, 65536);
        assert_eq!(u16::from_le_bytes([read[12], read[13]]), smb2_cmd::READ);
        assert_eq!(u32::from_le_bytes([read[68], read[69], read[70], read[71]]), 65536); // Length @68
        assert_eq!(u32::from_le_bytes([read[72], read[73], read[74], read[75]]), 1024); // Offset low @72

        let close = build_smb2_close_request(4, 0x10, 2, [0x55; 16]);
        assert_eq!(u16::from_le_bytes([close[12], close[13]]), smb2_cmd::CLOSE);
    }

    #[test]
    fn test_smb2_query_directory_roundtrip() {
        let req = build_smb2_query_directory_request(5, 0x10, 2, [0x99; 16], "*", true);
        assert_eq!(u16::from_le_bytes([req[12], req[13]]), smb2_cmd::QUERY_DIRECTORY);
        assert_eq!(u16::from_le_bytes([req[64], req[65]]), 33); // StructureSize = 33
        assert_eq!(req[66], file_info_class::FILE_BOTH_DIRECTORY_INFORMATION);
        assert_eq!(req[67], query_dir_flags::RESTART_SCANS);

        // Build a synthetic SMB2_QUERY_DIRECTORY response containing two entries:
        // Entry 1: "." (directory)
        // Entry 2: "secrets.txt" (file, size 1234)
        let mut entry1 = vec![0u8; 94];
        let name1 = encode_utf16le(".");
        entry1[60..64].copy_from_slice(&(name1.len() as u32).to_le_bytes()); // FileNameLength
        entry1[56..60].copy_from_slice(&file_attributes::DIRECTORY.to_le_bytes());
        entry1.extend_from_slice(&name1);
        // Pad entry1 to 8-byte boundary.
        let pad1 = (8 - (entry1.len() % 8)) % 8;
        entry1.extend(std::iter::repeat(0).take(pad1));
        let next_offset = entry1.len() as u32;
        entry1[0..4].copy_from_slice(&next_offset.to_le_bytes());

        let mut entry2 = vec![0u8; 94];
        let name2 = encode_utf16le("secrets.txt");
        entry2[60..64].copy_from_slice(&(name2.len() as u32).to_le_bytes());
        entry2[40..48].copy_from_slice(&1234u64.to_le_bytes()); // EndOfFile
        entry2[56..60].copy_from_slice(&file_attributes::ARCHIVE.to_le_bytes());
        entry2.extend_from_slice(&name2);
        // NextEntryOffset = 0 for the last entry.
        entry2[0..4].copy_from_slice(&0u32.to_le_bytes());

        let mut entries_buf = entry1;
        entries_buf.extend_from_slice(&entry2);

        // Wrap entries_buf in an SMB2_QUERY_DIRECTORY response PDU.
        let mut resp = vec![0u8; 64]; // Smb2Header
        resp[0..4].copy_from_slice(b"\xFESMB");
        resp[12..14].copy_from_slice(&smb2_cmd::QUERY_DIRECTORY.to_le_bytes());
        let mut body = vec![0u8; 8];
        body[0..2].copy_from_slice(&9u16.to_le_bytes()); // StructureSize = 9
        body[2..4].copy_from_slice(&72u16.to_le_bytes()); // OutputBufferOffset = 64 + 8 = 72
        body[4..8].copy_from_slice(&(entries_buf.len() as u32).to_le_bytes());
        resp.extend_from_slice(&body);
        resp.extend_from_slice(&entries_buf);

        let buf = parse_query_directory_response(&resp).unwrap();
        assert_eq!(buf.len(), entries_buf.len());

        let parsed = parse_both_directory_entries(buf).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].name, ".");
        assert!(parsed[0].is_directory);
        assert_eq!(parsed[1].name, "secrets.txt");
        assert!(!parsed[1].is_directory);
        assert_eq!(parsed[1].end_of_file, 1234);
    }

    #[test]
    fn test_smb2_tree_disconnect_and_logoff_builders() {
        let t_disc = build_smb2_tree_disconnect_request(10, 0x1000, 0x20);
        assert_eq!(&t_disc[0..4], b"\xFESMB");
        assert_eq!(u16::from_le_bytes([t_disc[12], t_disc[13]]), smb2_cmd::TREE_DISCONNECT);
        assert_eq!(u16::from_le_bytes([t_disc[64], t_disc[65]]), 4); // StructureSize = 4

        let logoff = build_smb2_logoff_request(11, 0x1000);
        assert_eq!(&logoff[0..4], b"\xFESMB");
        assert_eq!(u16::from_le_bytes([logoff[12], logoff[13]]), smb2_cmd::LOGOFF);
        assert_eq!(u16::from_le_bytes([logoff[64], logoff[65]]), 4); // StructureSize = 4
    }
}
