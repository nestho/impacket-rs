//! `srvs`: `[MS-SRVS]` Server Service Remote Protocol client (`impacket/dcerpc/v5/srvs.py`).
//!
//! Implements `NetrShareEnum` (opnum 15) at information level 1 (`SHARE_INFO_1`): the real
//! `SHARE_ENUM_STRUCT` / `SHARE_INFO_1_CONTAINER` NDR layout with `unique` container/array pointers,
//! deferred `[string] wchar_t*` `shi1_netname` / `shi1_remark` buffers, and `STYPE_*` classification.
//! Drives `netview` and `smbclient` share browsing over any [`RpcTransport`].

use crate::dtypes::{read_string_wchar_pointee, write_string_wchar_pointee, REFERENT_BASE};
use impacket_core::{CoreError, NtStatus};
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport};
use impacket_ndr::{NdrReader, NdrWriter};

pub mod opnum {
    pub const NETR_FILE_ENUM: u16 = 9;
    pub const NETR_SESSION_ENUM: u16 = 12;
    pub const NETR_SHARE_ENUM: u16 = 15;
}

pub const PERM_FILE_READ: u32 = 0x01;
pub const PERM_FILE_WRITE: u32 = 0x02;
pub const PERM_FILE_CREATE: u32 = 0x04;

/// A `FILE_INFO_3` record (`[MS-SRVS] 2.2.4.30`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo3 {
    pub id: u32,
    pub permissions: u32,
    pub num_locks: u32,
    pub path_name: String,
    pub user_name: String,
}

impl FileInfo3 {
    pub fn permissions_string(&self) -> String {
        let mut perms = Vec::new();
        if self.permissions & PERM_FILE_READ != 0 {
            perms.push("READ");
        }
        if self.permissions & PERM_FILE_WRITE != 0 {
            perms.push("WRITE");
        }
        if self.permissions & PERM_FILE_CREATE != 0 {
            perms.push("CREATE");
        }
        if perms.is_empty() {
            format!("{:#x}", self.permissions)
        } else {
            perms.join("|")
        }
    }
}

/// A `SESSION_INFO_10` record (`[MS-SRVS] 2.2.4.14`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo10 {
    pub client_name: String,
    pub username: String,
    pub active_time_secs: u32,
    pub idle_time_secs: u32,
}

/// `SHARE_TYPE` values (`STYPE_*` in `[MS-SRVS] 2.2.2.4`).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ShareType {
    DiskTree,
    PrintQueue,
    Device,
    Ipc,
    Unknown(u32),
}

impl ShareType {
    /// Masks off `STYPE_SPECIAL` (`0x80000000`) and `STYPE_TEMPORARY` (`0x40000000`) before classifying.
    pub const fn from_u32(raw: u32) -> Self {
        match raw & 0x0FFF_FFFF {
            0 => Self::DiskTree,
            1 => Self::PrintQueue,
            2 => Self::Device,
            3 => Self::Ipc,
            other => Self::Unknown(other),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::DiskTree => "STYPE_DISKTREE",
            Self::PrintQueue => "STYPE_PRINTQ",
            Self::Device => "STYPE_DEVICE",
            Self::Ipc => "STYPE_IPC",
            Self::Unknown(_) => "STYPE_UNKNOWN",
        }
    }
}

/// A `SHARE_INFO_1` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareInfo1 {
    pub netname: String,
    pub share_type: ShareType,
    pub remark: String,
}

/// Builds the request stub for `NetrShareEnum` level 1 (`[MS-SRVS] 3.1.4.8`).
///
/// Layout: `ServerName` (`unique [string] wchar_t*`), `InfoStruct: SHARE_ENUM_STRUCT { Level=1,
/// ShareInfo union tag=1, PSHARE_INFO_1_CONTAINER { EntriesRead=0, Buffer=NULL } }`,
/// `PreferedMaximumLength = MAX_PREFERRED_LENGTH`, `ResumeHandle = NULL`.
pub fn build_netr_share_enum_stub(server_name: &str) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_u32(REFERENT_BASE); // ServerName referent
    write_string_wchar_pointee(&mut w, server_name);
    w.align(4);

    w.write_u32(1); // Level = 1
    w.write_u32(1); // ShareInfo union tag = 1
    w.write_u32(REFERENT_BASE + 4); // SHARE_INFO_1_CONTAINER referent
    w.write_u32(0); // EntriesRead = 0
    w.write_u32(0); // Buffer = NULL

    w.write_u32(0xFFFF_FFFF); // PreferedMaximumLength = MAX_PREFERRED_LENGTH
    w.write_u32(0); // ResumeHandle = NULL
    w.into_bytes()
}

/// Builds a wire-accurate `NetrShareEnum` level-1 response stub (test fixture / mock SRVS server).
pub fn build_netr_share_enum_response(shares: &[ShareInfo1], status: NtStatus) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(512);
    w.write_u32(1); // Level
    w.write_u32(1); // union tag
    w.write_u32(REFERENT_BASE); // container referent

    let count = shares.len() as u32;
    w.write_u32(count); // EntriesRead
    w.write_u32(REFERENT_BASE + 4); // array referent
    w.write_u32(count); // conformant MaxCount

    // Inline SHARE_INFO_1 records.
    for (i, s) in shares.iter().enumerate() {
        w.write_u32(REFERENT_BASE + 8 + (i as u32) * 2); // shi1_netname referent
        w.write_u32(share_type_to_raw(s.share_type));
        w.write_u32(REFERENT_BASE + 9 + (i as u32) * 2); // shi1_remark referent
    }
    // Deferred string buffers, per entry in order: netname then remark.
    for s in shares {
        write_string_wchar_pointee(&mut w, &s.netname);
        write_string_wchar_pointee(&mut w, &s.remark);
    }

    w.write_u32(count); // TotalEntries
    w.write_u32(0); // ResumeHandle pointer = NULL
    w.write_u32(status.0); // return NTSTATUS
    w.into_bytes()
}

fn share_type_to_raw(t: ShareType) -> u32 {
    match t {
        ShareType::DiskTree => 0,
        ShareType::PrintQueue => 1,
        ShareType::Device => 2,
        ShareType::Ipc => 0x8000_0003, // IPC shares carry STYPE_SPECIAL
        ShareType::Unknown(v) => v,
    }
}

/// Parses a `NetrShareEnum` level-1 response stub into `SHARE_INFO_1` records.
pub fn parse_netr_share_enum_response(stub: &[u8]) -> Result<Vec<ShareInfo1>, CoreError> {
    let mut r = NdrReader::new(stub);
    let level = r.read_u32()?;
    let _union_tag = r.read_u32()?;
    if level != 1 {
        return Err(CoreError::ProtocolError(format!(
            "NetrShareEnum: unsupported info level {}",
            level
        )));
    }
    let container_ref = r.read_u32()?;
    if container_ref == 0 {
        let _total = r.read_u32()?;
        let _resume = r.read_u32()?;
        let status = NtStatus(r.read_u32()?);
        accept_enum_status(status)?;
        return Ok(Vec::new());
    }

    let entries_read = r.read_u32()? as usize;
    let array_ref = r.read_u32()?;
    if array_ref == 0 || entries_read > 65_536 {
        return Err(CoreError::ProtocolError(
            "NetrShareEnum: container Buffer pointer invalid".into(),
        ));
    }
    let max_count = r.read_u32()? as usize;
    if max_count < entries_read {
        return Err(CoreError::ProtocolError(
            "NetrShareEnum: MaxCount < EntriesRead".into(),
        ));
    }

    // Inline records.
    let mut raw = Vec::with_capacity(entries_read);
    for _ in 0..entries_read {
        let netname_ref = r.read_u32()?;
        let stype = r.read_u32()?;
        let remark_ref = r.read_u32()?;
        raw.push((netname_ref != 0, stype, remark_ref != 0));
    }
    // Deferred buffers in element order: netname then remark.
    let mut shares = Vec::with_capacity(entries_read);
    for (has_netname, stype, has_remark) in raw {
        let netname = if has_netname {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        let remark = if has_remark {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        shares.push(ShareInfo1 {
            netname,
            share_type: ShareType::from_u32(stype),
            remark,
        });
    }

    let _total_entries = r.read_u32()?;
    let resume_ref = r.read_u32()?;
    if resume_ref != 0 {
        let _resume = r.read_u32()?;
    }
    let status = NtStatus(r.read_u32()?);
    accept_enum_status(status)?;
    Ok(shares)
}

/// Builds the request stub for `NetrSessionEnum` level 10 (`[MS-SRVS] 3.1.4.5`).
pub fn build_netr_session_enum_stub(
    server_name: &str,
    client_name: Option<&str>,
    username: Option<&str>,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);
    let mut ref_id = REFERENT_BASE;

    // 1. ServerName
    if server_name.is_empty() {
        w.write_u32(0);
    } else {
        w.write_u32(ref_id);
        ref_id += 4;
        write_string_wchar_pointee(&mut w, server_name);
        w.align(4);
    }

    // 2. ClientName
    if let Some(c) = client_name {
        w.write_u32(ref_id);
        ref_id += 4;
        write_string_wchar_pointee(&mut w, c);
        w.align(4);
    } else {
        w.write_u32(0);
    }

    // 3. UserName
    if let Some(u) = username {
        w.write_u32(ref_id);
        ref_id += 4;
        write_string_wchar_pointee(&mut w, u);
        w.align(4);
    } else {
        w.write_u32(0);
    }

    // 4. InfoStruct: SESSION_ENUM_STRUCT { Level=10, SessionInfo union tag=10, PSESSION_INFO_10_CONTAINER { EntriesRead=0, Buffer=NULL } }
    w.write_u32(10); // Level = 10
    w.write_u32(10); // SessionInfo union tag = 10
    w.write_u32(ref_id); // SESSION_INFO_10_CONTAINER referent
    w.write_u32(0); // EntriesRead = 0
    w.write_u32(0); // Buffer = NULL

    // 5. PreferedMaximumLength
    w.write_u32(0xFFFF_FFFF);

    // 6. ResumeHandle = NULL
    w.write_u32(0);

    w.into_bytes()
}

/// Parses a `NetrSessionEnum` level-10 response stub into `SessionInfo10` records.
pub fn parse_netr_session_enum_response(stub: &[u8]) -> Result<Vec<SessionInfo10>, CoreError> {
    let mut r = NdrReader::new(stub);
    let level = r.read_u32()?;
    let _union_tag = r.read_u32()?;
    if level != 10 {
        return Err(CoreError::ProtocolError(format!(
            "NetrSessionEnum: unsupported info level {} (expected 10)",
            level
        )));
    }
    let container_ref = r.read_u32()?;
    if container_ref == 0 {
        let _total = r.read_u32()?;
        let _resume = r.read_u32()?;
        let status = NtStatus(r.read_u32()?);
        accept_enum_status(status)?;
        return Ok(Vec::new());
    }

    let entries_read = r.read_u32()? as usize;
    let array_ref = r.read_u32()?;
    if array_ref == 0 || entries_read > 65_536 {
        return Err(CoreError::ProtocolError(
            "NetrSessionEnum: container Buffer pointer invalid".into(),
        ));
    }
    let max_count = r.read_u32()? as usize;
    if max_count < entries_read {
        return Err(CoreError::ProtocolError(
            "NetrSessionEnum: MaxCount < EntriesRead".into(),
        ));
    }

    // Inline records: sesi10_cname (ref), sesi10_username (ref), sesi10_time (u32), sesi10_idle_time (u32)
    let mut raw = Vec::with_capacity(entries_read);
    for _ in 0..entries_read {
        let cname_ref = r.read_u32()?;
        let username_ref = r.read_u32()?;
        let active_time = r.read_u32()?;
        let idle_time = r.read_u32()?;
        raw.push((cname_ref != 0, username_ref != 0, active_time, idle_time));
    }

    // Deferred buffers in element order: cname then username per entry
    let mut sessions = Vec::with_capacity(entries_read);
    for (has_cname, has_username, active_time_secs, idle_time_secs) in raw {
        let client_name = if has_cname {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        let username = if has_username {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        sessions.push(SessionInfo10 {
            client_name,
            username,
            active_time_secs,
            idle_time_secs,
        });
    }

    let _total_entries = r.read_u32()?;
    let resume_ref = r.read_u32()?;
    if resume_ref != 0 {
        let _resume = r.read_u32()?;
    }
    let status = NtStatus(r.read_u32()?);
    accept_enum_status(status)?;
    Ok(sessions)
}

/// Builds a wire-accurate `NetrSessionEnum` level-10 response stub (test fixture).
pub fn build_netr_session_enum_response(sessions: &[SessionInfo10], status: NtStatus) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(512);
    w.write_u32(10); // Level = 10
    w.write_u32(10); // union tag = 10
    w.write_u32(REFERENT_BASE); // container referent

    let count = sessions.len() as u32;
    w.write_u32(count); // EntriesRead
    w.write_u32(REFERENT_BASE + 4); // array referent
    w.write_u32(count); // MaxCount

    for (i, s) in sessions.iter().enumerate() {
        w.write_u32(REFERENT_BASE + 8 + (i as u32) * 2); // cname referent
        w.write_u32(REFERENT_BASE + 9 + (i as u32) * 2); // username referent
        w.write_u32(s.active_time_secs);
        w.write_u32(s.idle_time_secs);
    }

    for s in sessions {
        write_string_wchar_pointee(&mut w, &s.client_name);
        write_string_wchar_pointee(&mut w, &s.username);
    }

    w.write_u32(count); // TotalEntries
    w.write_u32(0); // ResumeHandle = NULL
    w.write_u32(status.0);
    w.into_bytes()
}

/// Builds the request stub for `NetrFileEnum` level 3 (`[MS-SRVS] 3.1.4.3`).
pub fn build_netr_file_enum_stub(
    server_name: &str,
    base_path: Option<&str>,
    user_name: Option<&str>,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);
    let mut ref_id = REFERENT_BASE;

    // 1. ServerName
    if server_name.is_empty() {
        w.write_u32(0);
    } else {
        w.write_u32(ref_id);
        ref_id += 4;
        write_string_wchar_pointee(&mut w, server_name);
        w.align(4);
    }

    // 2. BasePath
    if let Some(bp) = base_path {
        w.write_u32(ref_id);
        ref_id += 4;
        write_string_wchar_pointee(&mut w, bp);
        w.align(4);
    } else {
        w.write_u32(0);
    }

    // 3. UserName
    if let Some(un) = user_name {
        w.write_u32(ref_id);
        ref_id += 4;
        write_string_wchar_pointee(&mut w, un);
        w.align(4);
    } else {
        w.write_u32(0);
    }

    // 4. InfoStruct: FILE_ENUM_STRUCT { Level=3, FileInfo union tag=3, PFILE_INFO_3_CONTAINER { EntriesRead=0, Buffer=NULL } }
    w.write_u32(3); // Level = 3
    w.write_u32(3); // FileInfo union tag = 3
    w.write_u32(ref_id); // FILE_INFO_3_CONTAINER referent
    w.write_u32(0); // EntriesRead = 0
    w.write_u32(0); // Buffer = NULL

    // 5. PreferedMaximumLength
    w.write_u32(0xFFFF_FFFF);

    // 6. ResumeHandle = NULL
    w.write_u32(0);

    w.into_bytes()
}

/// Parses a `NetrFileEnum` level-3 response stub into `FileInfo3` records.
pub fn parse_netr_file_enum_response(stub: &[u8]) -> Result<Vec<FileInfo3>, CoreError> {
    let mut r = NdrReader::new(stub);
    let level = r.read_u32()?;
    let _union_tag = r.read_u32()?;
    if level != 3 {
        return Err(CoreError::ProtocolError(format!(
            "NetrFileEnum: unsupported info level {} (expected 3)",
            level
        )));
    }
    let container_ref = r.read_u32()?;
    if container_ref == 0 {
        let _total = r.read_u32()?;
        let _resume = r.read_u32()?;
        let status = NtStatus(r.read_u32()?);
        accept_enum_status(status)?;
        return Ok(Vec::new());
    }

    let entries_read = r.read_u32()? as usize;
    let array_ref = r.read_u32()?;
    if array_ref == 0 || entries_read > 65_536 {
        return Err(CoreError::ProtocolError(
            "NetrFileEnum: container Buffer pointer invalid".into(),
        ));
    }
    let max_count = r.read_u32()? as usize;
    if max_count < entries_read {
        return Err(CoreError::ProtocolError(
            "NetrFileEnum: MaxCount < EntriesRead".into(),
        ));
    }

    // Inline records: fi3_id (u32), fi3_permissions (u32), fi3_num_locks (u32), fi3_pathname (ref), fi3_username (ref)
    let mut raw = Vec::with_capacity(entries_read);
    for _ in 0..entries_read {
        let id = r.read_u32()?;
        let permissions = r.read_u32()?;
        let num_locks = r.read_u32()?;
        let pathname_ref = r.read_u32()?;
        let username_ref = r.read_u32()?;
        raw.push((id, permissions, num_locks, pathname_ref != 0, username_ref != 0));
    }

    // Deferred buffers in element order: pathname then username per entry
    let mut files = Vec::with_capacity(entries_read);
    for (id, permissions, num_locks, has_path, has_user) in raw {
        let path_name = if has_path {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        let user_name = if has_user {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        files.push(FileInfo3 {
            id,
            permissions,
            num_locks,
            path_name,
            user_name,
        });
    }

    let _total_entries = r.read_u32()?;
    let resume_ref = r.read_u32()?;
    if resume_ref != 0 {
        let _resume = r.read_u32()?;
    }
    let status = NtStatus(r.read_u32()?);
    accept_enum_status(status)?;
    Ok(files)
}

/// Builds a wire-accurate `NetrFileEnum` level-3 response stub (test fixture).
pub fn build_netr_file_enum_response(files: &[FileInfo3], status: NtStatus) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(512);
    w.write_u32(3); // Level = 3
    w.write_u32(3); // union tag = 3
    w.write_u32(REFERENT_BASE); // container referent

    let count = files.len() as u32;
    w.write_u32(count); // EntriesRead
    w.write_u32(REFERENT_BASE + 4); // array referent
    w.write_u32(count); // MaxCount

    for (i, f) in files.iter().enumerate() {
        w.write_u32(f.id);
        w.write_u32(f.permissions);
        w.write_u32(f.num_locks);
        w.write_u32(REFERENT_BASE + 8 + (i as u32) * 2); // pathname referent
        w.write_u32(REFERENT_BASE + 9 + (i as u32) * 2); // username referent
    }

    for f in files {
        write_string_wchar_pointee(&mut w, &f.path_name);
        write_string_wchar_pointee(&mut w, &f.user_name);
    }

    w.write_u32(count); // TotalEntries
    w.write_u32(0); // ResumeHandle = NULL
    w.write_u32(status.0);
    w.into_bytes()
}

fn accept_enum_status(status: NtStatus) -> Result<(), CoreError> {
    if status.is_success() || status == NtStatus::STATUS_MORE_ENTRIES {
        Ok(())
    } else {
        Err(CoreError::NtStatus(status))
    }
}

/// `[MS-SRVS]` high-level client over a bound [`RpcTransport`] (`\PIPE\srvsvc`).
pub struct SrvsClient<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> SrvsClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            call_id: 1,
        }
    }

    /// `NetrShareEnum` level 1 — enumerate all shared resources on the server.
    pub fn net_share_enum(&mut self, server_name: &str) -> Result<Vec<ShareInfo1>, CoreError> {
        let call_id = self.call_id;
        self.call_id += 1;
        let pdu = RpcRequestPdu {
            call_id,
            context_id: 0,
            opnum: opnum::NETR_SHARE_ENUM,
            stub_data: build_netr_share_enum_stub(server_name),
        }
        .to_bytes();
        let resp = self.transport.transceive(&pdu)?;
        let stub = extract_response_stub(&resp)?;
        parse_netr_share_enum_response(&stub)
    }

    /// `NetrSessionEnum` level 10 — enumerate active sessions on the server.
    pub fn net_session_enum(&mut self, server_name: &str) -> Result<Vec<SessionInfo10>, CoreError> {
        self.net_session_enum_filter(server_name, None, None)
    }

    /// `NetrSessionEnum` level 10 with client name or username filters.
    pub fn net_session_enum_filter(
        &mut self,
        server_name: &str,
        client_name: Option<&str>,
        username: Option<&str>,
    ) -> Result<Vec<SessionInfo10>, CoreError> {
        let call_id = self.call_id;
        self.call_id += 1;
        let pdu = RpcRequestPdu {
            call_id,
            context_id: 0,
            opnum: opnum::NETR_SESSION_ENUM,
            stub_data: build_netr_session_enum_stub(server_name, client_name, username),
        }
        .to_bytes();
        let resp = self.transport.transceive(&pdu)?;
        let stub = extract_response_stub(&resp)?;
        parse_netr_session_enum_response(&stub)
    }

    /// `NetrFileEnum` level 3 — enumerate open files and resources on the server.
    pub fn net_file_enum(&mut self, server_name: &str) -> Result<Vec<FileInfo3>, CoreError> {
        self.net_file_enum_filter(server_name, None, None)
    }

    /// `NetrFileEnum` level 3 with base path or username filters.
    pub fn net_file_enum_filter(
        &mut self,
        server_name: &str,
        base_path: Option<&str>,
        user_name: Option<&str>,
    ) -> Result<Vec<FileInfo3>, CoreError> {
        let call_id = self.call_id;
        self.call_id += 1;
        let pdu = RpcRequestPdu {
            call_id,
            context_id: 0,
            opnum: opnum::NETR_FILE_ENUM,
            stub_data: build_netr_file_enum_stub(server_name, base_path, user_name),
        }
        .to_bytes();
        let resp = self.transport.transceive(&pdu)?;
        let stub = extract_response_stub(&resp)?;
        parse_netr_file_enum_response(&stub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use impacket_dcerpc::{pdu_type, RpcCommonHeader};
    use impacket_ndr::NdrSerialize;

    struct MockSrvs {
        response_stub: Vec<u8>,
    }

    impl RpcTransport for MockSrvs {
        fn transceive(&mut self, _req: &[u8]) -> Result<Vec<u8>, CoreError> {
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
    fn test_netr_share_enum_roundtrip() {
        let shares = vec![
            ShareInfo1 {
                netname: "ADMIN$".into(),
                share_type: ShareType::DiskTree,
                remark: "Remote Admin".into(),
            },
            ShareInfo1 {
                netname: "IPC$".into(),
                share_type: ShareType::Ipc,
                remark: "Remote IPC".into(),
            },
            ShareInfo1 {
                netname: "NETLOGON".into(),
                share_type: ShareType::DiskTree,
                remark: "Logon server share".into(),
            },
        ];
        let wire = build_netr_share_enum_response(&shares, NtStatus::STATUS_SUCCESS);
        let parsed = parse_netr_share_enum_response(&wire).unwrap();
        assert_eq!(parsed, shares);
    }

    #[test]
    fn test_srvs_client_over_mock_transport() {
        let shares = vec![ShareInfo1 {
            netname: "Backups".into(),
            share_type: ShareType::DiskTree,
            remark: "Veeam repo".into(),
        }];
        let mock = MockSrvs {
            response_stub: build_netr_share_enum_response(&shares, NtStatus::STATUS_SUCCESS),
        };
        let mut client = SrvsClient::new(mock);
        let got = client.net_share_enum(r"\\DC01").unwrap();
        assert_eq!(got, shares);
    }

    // Prove STYPE_SPECIAL/STYPE_TEMPORARY are masked off during classification.
    #[test]
    fn test_share_type_masks_special_flags() {
        assert_eq!(ShareType::from_u32(0x8000_0003), ShareType::Ipc);
        assert_eq!(ShareType::from_u32(0x4000_0000), ShareType::DiskTree);
    }

    #[test]
    fn test_netr_session_enum_roundtrip() {
        let sessions = vec![
            SessionInfo10 {
                client_name: r"\\192.168.1.101".into(),
                username: "Administrator".into(),
                active_time_secs: 3600,
                idle_time_secs: 120,
            },
            SessionInfo10 {
                client_name: r"\\192.168.1.105".into(),
                username: "alice".into(),
                active_time_secs: 7200,
                idle_time_secs: 45,
            },
        ];
        let wire = build_netr_session_enum_response(&sessions, NtStatus::STATUS_SUCCESS);
        let parsed = parse_netr_session_enum_response(&wire).unwrap();
        assert_eq!(parsed, sessions);
    }

    #[test]
    fn test_srvs_session_client_over_mock_transport() {
        let sessions = vec![SessionInfo10 {
            client_name: r"\\10.0.0.5".into(),
            username: "bob".into(),
            active_time_secs: 1500,
            idle_time_secs: 300,
        }];
        let mock = MockSrvs {
            response_stub: build_netr_session_enum_response(&sessions, NtStatus::STATUS_SUCCESS),
        };
        let mut client = SrvsClient::new(mock);
        let got = client.net_session_enum(r"\\FS01").unwrap();
        assert_eq!(got, sessions);
    }

    #[test]
    fn test_netr_file_enum_roundtrip() {
        let files = vec![
            FileInfo3 {
                id: 101,
                permissions: PERM_FILE_READ | PERM_FILE_WRITE,
                num_locks: 0,
                path_name: r"C:\Share\document.docx".into(),
                user_name: "corp\\alice".into(),
            },
            FileInfo3 {
                id: 102,
                permissions: PERM_FILE_READ,
                num_locks: 1,
                path_name: r"C:\Share\database.db".into(),
                user_name: "corp\\bob".into(),
            },
        ];
        let wire = build_netr_file_enum_response(&files, NtStatus::STATUS_SUCCESS);
        let parsed = parse_netr_file_enum_response(&wire).unwrap();
        assert_eq!(parsed, files);
        assert_eq!(files[0].permissions_string(), "READ|WRITE");
        assert_eq!(files[1].permissions_string(), "READ");
    }

    #[test]
    fn test_srvs_file_client_over_mock_transport() {
        let files = vec![FileInfo3 {
            id: 200,
            permissions: PERM_FILE_CREATE,
            num_locks: 0,
            path_name: r"D:\Logs\access.log".into(),
            user_name: "NT AUTHORITY\\SYSTEM".into(),
        }];
        let mock = MockSrvs {
            response_stub: build_netr_file_enum_response(&files, NtStatus::STATUS_SUCCESS),
        };
        let mut client = SrvsClient::new(mock);
        let got = client.net_file_enum(r"\\FS02").unwrap();
        assert_eq!(got, files);
    }
}
