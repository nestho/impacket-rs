//! `dfsnm`: `[MS-DFSNM]` Distributed File System Namespace Management Protocol client (`impacket/dcerpc/v5/dfsnm.py`).
//!
//! Provides pure-Rust RPC methods for discovering, querying, enumerating, and configuring
//! Active Directory DFS namespaces, roots, and referral targets over `\PIPE\netdfs` or TCP RPC:
//! - `NetrDfsGetManagerVersion` (Opnum 0)
//! - `NetrDfsAdd` (Opnum 1)
//! - `NetrDfsRemove` (Opnum 2)
//! - `NetrDfsGetInfo` (Opnum 4)
//! - `NetrDfsEnum` (Opnum 5)
//! - `NetrDfsEnumEx` (Opnum 19)

use crate::dtypes::{read_string_wchar_pointee, write_string_wchar_pointee, REFERENT_BASE};
use impacket_core::CoreError;
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport, RpcUuid};
use impacket_ndr::{NdrReader, NdrWriter};

/// `[MS-DFSNM]` Interface UUID: `4FC742E0-4A10-11CF-8273-00AA004AE673` v3.0
pub const DFSNM_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0x4fc7_42e0,
    0x4a10,
    0x11cf,
    [0x82, 0x73, 0x00, 0xaa, 0x00, 0x4a, 0xe6, 0x73],
);
pub const DFSNM_VERSION_MAJOR: u16 = 3;
pub const DFSNM_VERSION_MINOR: u16 = 0;
pub const DFSNM_PIPE: &str = r"\PIPE\netdfs";

pub mod opnum {
    pub const NETR_DFS_GET_MANAGER_VERSION: u16 = 0;
    pub const NETR_DFS_ADD: u16 = 1;
    pub const NETR_DFS_REMOVE: u16 = 2;
    pub const NETR_DFS_SET_INFO: u16 = 3;
    pub const NETR_DFS_GET_INFO: u16 = 4;
    pub const NETR_DFS_ENUM: u16 = 5;
    pub const NETR_DFS_MOVE: u16 = 6;
    pub const NETR_DFS_ENUM_EX: u16 = 19;
    pub const NETR_DFS_GET_INFO_EX: u16 = 21;
}

pub mod volume_state {
    pub const DFS_VOLUME_STATE_OK: u32 = 0x0000_0001;
    pub const DFS_VOLUME_STATE_INCONSISTENT: u32 = 0x0000_0002;
    pub const DFS_VOLUME_STATE_OFFLINE: u32 = 0x0000_0003;
    pub const DFS_VOLUME_STATE_ONLINE: u32 = 0x0000_0004;
}

pub mod storage_state {
    pub const DFS_STORAGE_STATE_OFFLINE: u32 = 0x0000_0001;
    pub const DFS_STORAGE_STATE_ONLINE: u32 = 0x0000_0002;
    pub const DFS_STORAGE_STATE_ACTIVE: u32 = 0x0000_0004;
}

pub mod namespace_flavor {
    pub const DFS_NAMESPACE_CAPABILITY_STANDALONE: u32 = 0x0000_0001;
    pub const DFS_NAMESPACE_CAPABILITY_DOMAIN_JOINED: u32 = 0x0000_0002;
}

/// Target storage server information (`DFS_STORAGE_INFO` per `[MS-DFSNM] 2.2.1.2.3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfsStorageInfo {
    pub state: u32,
    pub server_name: String,
    pub share_name: String,
}

impl DfsStorageInfo {
    pub fn is_online(&self) -> bool {
        self.state & storage_state::DFS_STORAGE_STATE_ONLINE != 0
    }

    pub fn is_active(&self) -> bool {
        self.state & storage_state::DFS_STORAGE_STATE_ACTIVE != 0
    }

    pub fn state_string(&self) -> String {
        let mut flags = Vec::new();
        if self.is_online() {
            flags.push("ONLINE");
        }
        if self.is_active() {
            flags.push("ACTIVE");
        }
        if self.state & storage_state::DFS_STORAGE_STATE_OFFLINE != 0 {
            flags.push("OFFLINE");
        }
        if flags.is_empty() {
            format!("{:#x}", self.state)
        } else {
            flags.join("|")
        }
    }
}

/// DFS link or root level 1 (`DFS_INFO_1` per `[MS-DFSNM] 2.2.1.2.1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfsInfo1 {
    pub entry_path: String,
}

/// DFS link or root level 2 (`DFS_INFO_2` per `[MS-DFSNM] 2.2.1.2.2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfsInfo2 {
    pub entry_path: String,
    pub comment: String,
    pub state: u32,
    pub number_of_stores: u32,
}

/// DFS link or root with target storage servers (`DFS_INFO_3` per `[MS-DFSNM] 2.2.1.2.3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfsInfo3 {
    pub entry_path: String,
    pub comment: String,
    pub state: u32,
    pub number_of_stores: u32,
    pub stores: Vec<DfsStorageInfo>,
}

/// DFS namespace descriptor level 300 (`DFS_INFO_300` per `[MS-DFSNM] 2.2.1.2.17`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DfsInfo300 {
    pub flags: u32,
    pub dfs_name: String,
}

impl DfsInfo300 {
    pub fn is_domain_joined(&self) -> bool {
        self.flags & namespace_flavor::DFS_NAMESPACE_CAPABILITY_DOMAIN_JOINED != 0
    }

    pub fn flavor_string(&self) -> &'static str {
        if self.is_domain_joined() {
            "Domain-Joined"
        } else {
            "Standalone"
        }
    }
}

// ---------------------------------------------------------------------------
// Request Builders & Response Parsers
// ---------------------------------------------------------------------------

/// Builds request stub for `NetrDfsGetManagerVersion` (Opnum 0).
pub fn build_netr_dfs_get_manager_version_stub() -> Vec<u8> {
    Vec::new()
}

/// Parses response stub for `NetrDfsGetManagerVersion` (Opnum 0).
pub fn parse_netr_dfs_get_manager_version_response(stub: &[u8]) -> Result<u32, CoreError> {
    let mut r = NdrReader::new(stub);
    let version = r.read_u32()?;
    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::RpcFault(status));
    }
    Ok(version)
}

/// Builds request stub for `NetrDfsEnum` (Opnum 5) or `NetrDfsEnumEx` (Opnum 19).
pub fn build_netr_dfs_enum_stub(level: u32, pref_max_len: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_u32(level);
    w.write_u32(pref_max_len);
    // DFS_INFO_ENUM_STRUCT
    w.write_u32(level); // Level
    w.write_u32(level); // Union switch
    w.write_u32(REFERENT_BASE); // Container referent
    w.write_u32(0); // EntriesRead = 0
    w.write_u32(0); // Buffer = NULL (referent 0)
    w.write_u32(0); // ResumeHandle = NULL
    w.into_bytes()
}

/// Parses response stub for `NetrDfsEnum` level 1.
pub fn parse_netr_dfs_enum_level1_response(stub: &[u8]) -> Result<Vec<DfsInfo1>, CoreError> {
    let mut r = NdrReader::new(stub);
    let _level = r.read_u32()?;
    let _switch = r.read_u32()?;
    let container_ref = r.read_u32()?;
    if container_ref == 0 {
        return Ok(Vec::new());
    }
    let entries_read = r.read_u32()? as usize;
    let buffer_ref = r.read_u32()?;
    if buffer_ref == 0 || entries_read == 0 {
        let _resume_ref = r.read_u32()?;
        let status = r.read_u32()?;
        if status != 0 {
            return Err(CoreError::RpcFault(status));
        }
        return Ok(Vec::new());
    }
    let max_count = r.read_u32()? as usize;
    if max_count != entries_read {
        return Err(CoreError::ProtocolError(format!(
            "DFS enum max_count ({}) != entries_read ({})",
            max_count, entries_read
        )));
    }
    let mut path_refs = Vec::with_capacity(entries_read);
    for _ in 0..entries_read {
        let p_ref = r.read_u32()?;
        path_refs.push(p_ref != 0);
    }
    let mut entries = Vec::with_capacity(entries_read);
    for has_path in path_refs {
        let entry_path = if has_path {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        entries.push(DfsInfo1 { entry_path });
    }
    let _resume_ref = r.read_u32()?;
    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::RpcFault(status));
    }
    Ok(entries)
}

/// Parses response stub for `NetrDfsEnum` level 300 (namespaces).
pub fn parse_netr_dfs_enum_level300_response(stub: &[u8]) -> Result<Vec<DfsInfo300>, CoreError> {
    let mut r = NdrReader::new(stub);
    let _level = r.read_u32()?;
    let _switch = r.read_u32()?;
    let container_ref = r.read_u32()?;
    if container_ref == 0 {
        return Ok(Vec::new());
    }
    let entries_read = r.read_u32()? as usize;
    let buffer_ref = r.read_u32()?;
    if buffer_ref == 0 || entries_read == 0 {
        let _resume_ref = r.read_u32()?;
        let status = r.read_u32()?;
        if status != 0 {
            return Err(CoreError::RpcFault(status));
        }
        return Ok(Vec::new());
    }
    let max_count = r.read_u32()? as usize;
    if max_count != entries_read {
        return Err(CoreError::ProtocolError(format!(
            "DFS enum max_count ({}) != entries_read ({})",
            max_count, entries_read
        )));
    }
    let mut headers = Vec::with_capacity(entries_read);
    for _ in 0..entries_read {
        let flags = r.read_u32()?;
        let name_ref = r.read_u32()?;
        headers.push((flags, name_ref != 0));
    }
    let mut entries = Vec::with_capacity(entries_read);
    for (flags, has_name) in headers {
        let dfs_name = if has_name {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        entries.push(DfsInfo300 { flags, dfs_name });
    }
    let _resume_ref = r.read_u32()?;
    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::RpcFault(status));
    }
    Ok(entries)
}

/// Parses response stub for `NetrDfsEnum` level 3 (referral targets).
pub fn parse_netr_dfs_enum_level3_response(stub: &[u8]) -> Result<Vec<DfsInfo3>, CoreError> {
    let mut r = NdrReader::new(stub);
    let _level = r.read_u32()?;
    let _switch = r.read_u32()?;
    let container_ref = r.read_u32()?;
    if container_ref == 0 {
        return Ok(Vec::new());
    }
    let entries_read = r.read_u32()? as usize;
    let buffer_ref = r.read_u32()?;
    if buffer_ref == 0 || entries_read == 0 {
        let _resume_ref = r.read_u32()?;
        let status = r.read_u32()?;
        if status != 0 {
            return Err(CoreError::RpcFault(status));
        }
        return Ok(Vec::new());
    }
    let max_count = r.read_u32()? as usize;
    if max_count != entries_read {
        return Err(CoreError::ProtocolError(format!(
            "DFS enum max_count ({}) != entries_read ({})",
            max_count, entries_read
        )));
    }
    let mut headers = Vec::with_capacity(entries_read);
    for _ in 0..entries_read {
        let path_ref = r.read_u32()?;
        let comment_ref = r.read_u32()?;
        let state = r.read_u32()?;
        let num_stores = r.read_u32()?;
        let stores_ref = r.read_u32()?;
        headers.push((
            path_ref != 0,
            comment_ref != 0,
            state,
            num_stores as usize,
            stores_ref != 0,
        ));
    }
    let mut entries = Vec::with_capacity(entries_read);
    for (has_path, has_comment, state, num_stores, has_stores) in headers {
        let entry_path = if has_path {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        let comment = if has_comment {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        let mut stores = Vec::with_capacity(num_stores);
        if has_stores && num_stores > 0 {
            let _s_max = r.read_u32()? as usize;
            let mut s_headers = Vec::with_capacity(num_stores);
            for _ in 0..num_stores {
                let s_state = r.read_u32()?;
                let s_server_ref = r.read_u32()?;
                let s_share_ref = r.read_u32()?;
                s_headers.push((s_state, s_server_ref != 0, s_share_ref != 0));
            }
            for (s_state, has_server, has_share) in s_headers {
                let server_name = if has_server {
                    read_string_wchar_pointee(&mut r)?
                } else {
                    String::new()
                };
                let share_name = if has_share {
                    read_string_wchar_pointee(&mut r)?
                } else {
                    String::new()
                };
                stores.push(DfsStorageInfo {
                    state: s_state,
                    server_name,
                    share_name,
                });
            }
        }
        entries.push(DfsInfo3 {
            entry_path,
            comment,
            state,
            number_of_stores: num_stores as u32,
            stores,
        });
    }
    let _resume_ref = r.read_u32()?;
    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::RpcFault(status));
    }
    Ok(entries)
}

/// Builds request stub for `NetrDfsGetInfo` (Opnum 4).
pub fn build_netr_dfs_get_info_stub(
    entry_path: &str,
    server_name: Option<&str>,
    share_name: Option<&str>,
    level: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);
    let mut ref_id = REFERENT_BASE;

    // 1. DfsEntryPath
    w.write_u32(ref_id);
    ref_id += 4;
    write_string_wchar_pointee(&mut w, entry_path);

    // 2. ServerName
    if let Some(s) = server_name {
        w.write_u32(ref_id);
        ref_id += 4;
        write_string_wchar_pointee(&mut w, s);
    } else {
        w.write_u32(0);
    }

    // 3. ShareName
    if let Some(s) = share_name {
        w.write_u32(ref_id);
        write_string_wchar_pointee(&mut w, s);
    } else {
        w.write_u32(0);
    }

    // 4. Level
    w.write_u32(level);

    w.into_bytes()
}

/// Parses response stub for `NetrDfsGetInfo` level 3.
pub fn parse_netr_dfs_get_info_level3_response(stub: &[u8]) -> Result<DfsInfo3, CoreError> {
    let mut r = NdrReader::new(stub);
    let _level = r.read_u32()?;
    let _switch = r.read_u32()?;
    let info_ref = r.read_u32()?;
    if info_ref == 0 {
        let status = r.read_u32()?;
        return Err(CoreError::RpcFault(status));
    }
    let path_ref = r.read_u32()?;
    let comment_ref = r.read_u32()?;
    let state = r.read_u32()?;
    let num_stores = r.read_u32()? as usize;
    let stores_ref = r.read_u32()?;

    let entry_path = if path_ref != 0 {
        read_string_wchar_pointee(&mut r)?
    } else {
        String::new()
    };
    let comment = if comment_ref != 0 {
        read_string_wchar_pointee(&mut r)?
    } else {
        String::new()
    };

    let mut stores = Vec::with_capacity(num_stores);
    if stores_ref != 0 && num_stores > 0 {
        let _max_count = r.read_u32()?;
        let mut s_headers = Vec::with_capacity(num_stores);
        for _ in 0..num_stores {
            let s_state = r.read_u32()?;
            let s_server_ref = r.read_u32()?;
            let s_share_ref = r.read_u32()?;
            s_headers.push((s_state, s_server_ref != 0, s_share_ref != 0));
        }
        for (s_state, has_server, has_share) in s_headers {
            let server_name = if has_server {
                read_string_wchar_pointee(&mut r)?
            } else {
                String::new()
            };
            let share_name = if has_share {
                read_string_wchar_pointee(&mut r)?
            } else {
                String::new()
            };
            stores.push(DfsStorageInfo {
                state: s_state,
                server_name,
                share_name,
            });
        }
    }

    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::RpcFault(status));
    }

    Ok(DfsInfo3 {
        entry_path,
        comment,
        state,
        number_of_stores: num_stores as u32,
        stores,
    })
}

/// Builds request stub for `NetrDfsAdd` (Opnum 1).
pub fn build_netr_dfs_add_stub(
    entry_path: &str,
    server_name: &str,
    share_name: &str,
    comment: Option<&str>,
    flags: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(256);
    let mut ref_id = REFERENT_BASE;

    w.write_u32(ref_id);
    ref_id += 4;
    write_string_wchar_pointee(&mut w, entry_path);

    w.write_u32(ref_id);
    ref_id += 4;
    write_string_wchar_pointee(&mut w, server_name);

    w.write_u32(ref_id);
    ref_id += 4;
    write_string_wchar_pointee(&mut w, share_name);

    if let Some(c) = comment {
        w.write_u32(ref_id);
        write_string_wchar_pointee(&mut w, c);
    } else {
        w.write_u32(0);
    }

    w.write_u32(flags);
    w.into_bytes()
}

/// Builds request stub for `NetrDfsRemove` (Opnum 2).
pub fn build_netr_dfs_remove_stub(
    entry_path: &str,
    server_name: Option<&str>,
    share_name: Option<&str>,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);
    let mut ref_id = REFERENT_BASE;

    w.write_u32(ref_id);
    ref_id += 4;
    write_string_wchar_pointee(&mut w, entry_path);

    if let Some(s) = server_name {
        w.write_u32(ref_id);
        ref_id += 4;
        write_string_wchar_pointee(&mut w, s);
    } else {
        w.write_u32(0);
    }

    if let Some(s) = share_name {
        w.write_u32(ref_id);
        write_string_wchar_pointee(&mut w, s);
    } else {
        w.write_u32(0);
    }

    w.into_bytes()
}

// ---------------------------------------------------------------------------
// High-Level DfsClient
// ---------------------------------------------------------------------------

/// High-level client for `[MS-DFSNM]` Distributed File System Namespace Management.
pub struct DfsClient<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> DfsClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            call_id: 1,
        }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Queries the DFS server manager version.
    pub fn get_manager_version(&mut self) -> Result<u32, CoreError> {
        let req = RpcRequestPdu {
            call_id: self.call_id,
            context_id: 0,
            opnum: opnum::NETR_DFS_GET_MANAGER_VERSION,
            stub_data: Vec::new(),
        };
        self.call_id += 1;
        let resp = self.transport.transceive(&req.to_bytes())?;
        let stub = extract_response_stub(&resp)?;
        parse_netr_dfs_get_manager_version_response(&stub)
    }

    /// Enumerates Active Directory DFS namespaces (Level 300).
    pub fn enum_namespaces(&mut self) -> Result<Vec<DfsInfo300>, CoreError> {
        let stub = build_netr_dfs_enum_stub(300, 0xFFFF_FFFF);
        let req = RpcRequestPdu {
            call_id: self.call_id,
            context_id: 0,
            opnum: opnum::NETR_DFS_ENUM,
            stub_data: stub,
        };
        self.call_id += 1;
        let resp = self.transport.transceive(&req.to_bytes())?;
        let r_stub = extract_response_stub(&resp)?;
        parse_netr_dfs_enum_level300_response(&r_stub)
    }

    /// Enumerates DFS links and entry paths (Level 1).
    pub fn enum_links(&mut self) -> Result<Vec<DfsInfo1>, CoreError> {
        let stub = build_netr_dfs_enum_stub(1, 0xFFFF_FFFF);
        let req = RpcRequestPdu {
            call_id: self.call_id,
            context_id: 0,
            opnum: opnum::NETR_DFS_ENUM,
            stub_data: stub,
        };
        self.call_id += 1;
        let resp = self.transport.transceive(&req.to_bytes())?;
        let r_stub = extract_response_stub(&resp)?;
        parse_netr_dfs_enum_level1_response(&r_stub)
    }

    /// Enumerates DFS links with target storage servers (Level 3).
    pub fn enum_targets(&mut self) -> Result<Vec<DfsInfo3>, CoreError> {
        let stub = build_netr_dfs_enum_stub(3, 0xFFFF_FFFF);
        let req = RpcRequestPdu {
            call_id: self.call_id,
            context_id: 0,
            opnum: opnum::NETR_DFS_ENUM,
            stub_data: stub,
        };
        self.call_id += 1;
        let resp = self.transport.transceive(&req.to_bytes())?;
        let r_stub = extract_response_stub(&resp)?;
        parse_netr_dfs_enum_level3_response(&r_stub)
    }

    /// Retrieves detailed configuration for a specific DFS entry path (Level 3).
    pub fn get_info(&mut self, entry_path: &str) -> Result<DfsInfo3, CoreError> {
        let stub = build_netr_dfs_get_info_stub(entry_path, None, None, 3);
        let req = RpcRequestPdu {
            call_id: self.call_id,
            context_id: 0,
            opnum: opnum::NETR_DFS_GET_INFO,
            stub_data: stub,
        };
        self.call_id += 1;
        let resp = self.transport.transceive(&req.to_bytes())?;
        let r_stub = extract_response_stub(&resp)?;
        parse_netr_dfs_get_info_level3_response(&r_stub)
    }

    /// Adds a new DFS link or storage target to an existing link.
    pub fn add(
        &mut self,
        entry_path: &str,
        server_name: &str,
        share_name: &str,
        comment: Option<&str>,
        flags: u32,
    ) -> Result<(), CoreError> {
        let stub = build_netr_dfs_add_stub(entry_path, server_name, share_name, comment, flags);
        let req = RpcRequestPdu {
            call_id: self.call_id,
            context_id: 0,
            opnum: opnum::NETR_DFS_ADD,
            stub_data: stub,
        };
        self.call_id += 1;
        let resp = self.transport.transceive(&req.to_bytes())?;
        let r_stub = extract_response_stub(&resp)?;
        let mut r = NdrReader::new(&r_stub);
        let status = r.read_u32()?;
        if status != 0 {
            return Err(CoreError::RpcFault(status));
        }
        Ok(())
    }

    /// Removes a DFS link or a specific storage target.
    pub fn remove(
        &mut self,
        entry_path: &str,
        server_name: Option<&str>,
        share_name: Option<&str>,
    ) -> Result<(), CoreError> {
        let stub = build_netr_dfs_remove_stub(entry_path, server_name, share_name);
        let req = RpcRequestPdu {
            call_id: self.call_id,
            context_id: 0,
            opnum: opnum::NETR_DFS_REMOVE,
            stub_data: stub,
        };
        self.call_id += 1;
        let resp = self.transport.transceive(&req.to_bytes())?;
        let r_stub = extract_response_stub(&resp)?;
        let mut r = NdrReader::new(&r_stub);
        let status = r.read_u32()?;
        if status != 0 {
            return Err(CoreError::RpcFault(status));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dfsnm_get_manager_version_response() {
        let mut w = NdrWriter::new();
        w.write_u32(5); // Version = 5 (Windows Server 2008+)
        w.write_u32(0); // ErrorCode = ERROR_SUCCESS
        let ver = parse_netr_dfs_get_manager_version_response(&w.into_bytes()).unwrap();
        assert_eq!(ver, 5);
    }

    #[test]
    fn test_dfsnm_enum_level1_roundtrip() {
        let mut w = NdrWriter::new();
        w.write_u32(1); // Level = 1
        w.write_u32(1); // Switch = 1
        w.write_u32(REFERENT_BASE); // Container referent
        w.write_u32(2); // EntriesRead = 2
        w.write_u32(REFERENT_BASE + 4); // Buffer referent
        w.write_u32(2); // MaxCount = 2
        w.write_u32(REFERENT_BASE + 8); // Entry 1 path ref
        w.write_u32(REFERENT_BASE + 12); // Entry 2 path ref
        write_string_wchar_pointee(&mut w, r"\\corp.local\dfs\Public");
        write_string_wchar_pointee(&mut w, r"\\corp.local\dfs\Finance");
        w.write_u32(0); // ResumeHandle = NULL
        w.write_u32(0); // ErrorCode = ERROR_SUCCESS

        let entries = parse_netr_dfs_enum_level1_response(&w.into_bytes()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].entry_path, r"\\corp.local\dfs\Public");
        assert_eq!(entries[1].entry_path, r"\\corp.local\dfs\Finance");
    }

    #[test]
    fn test_dfsnm_enum_level300_roundtrip() {
        let mut w = NdrWriter::new();
        w.write_u32(300); // Level = 300
        w.write_u32(300); // Switch = 300
        w.write_u32(REFERENT_BASE); // Container referent
        w.write_u32(2); // EntriesRead = 2
        w.write_u32(REFERENT_BASE + 4); // Buffer referent
        w.write_u32(2); // MaxCount = 2

        // Header 1
        w.write_u32(namespace_flavor::DFS_NAMESPACE_CAPABILITY_DOMAIN_JOINED);
        w.write_u32(REFERENT_BASE + 8);
        // Header 2
        w.write_u32(namespace_flavor::DFS_NAMESPACE_CAPABILITY_STANDALONE);
        w.write_u32(REFERENT_BASE + 12);

        write_string_wchar_pointee(&mut w, "CorpDfs");
        write_string_wchar_pointee(&mut w, "LocalDfs");
        w.write_u32(0); // ResumeHandle = NULL
        w.write_u32(0); // ErrorCode = ERROR_SUCCESS

        let namespaces = parse_netr_dfs_enum_level300_response(&w.into_bytes()).unwrap();
        assert_eq!(namespaces.len(), 2);
        assert_eq!(namespaces[0].dfs_name, "CorpDfs");
        assert!(namespaces[0].is_domain_joined());
        assert_eq!(namespaces[0].flavor_string(), "Domain-Joined");
        assert_eq!(namespaces[1].dfs_name, "LocalDfs");
        assert!(!namespaces[1].is_domain_joined());
        assert_eq!(namespaces[1].flavor_string(), "Standalone");
    }

    #[test]
    fn test_dfsnm_enum_level3_roundtrip() {
        let mut w = NdrWriter::new();
        w.write_u32(3); // Level = 3
        w.write_u32(3); // Switch = 3
        w.write_u32(REFERENT_BASE); // Container referent
        w.write_u32(1); // EntriesRead = 1
        w.write_u32(REFERENT_BASE + 4); // Buffer referent
        w.write_u32(1); // MaxCount = 1

        // DFS_INFO_3 header
        w.write_u32(REFERENT_BASE + 8); // Path referent
        w.write_u32(REFERENT_BASE + 12); // Comment referent
        w.write_u32(volume_state::DFS_VOLUME_STATE_OK); // State
        w.write_u32(2); // NumberOfStores = 2
        w.write_u32(REFERENT_BASE + 16); // Stores referent

        write_string_wchar_pointee(&mut w, r"\\corp.local\dfs\Public");
        write_string_wchar_pointee(&mut w, "Public Documents Link");

        // Stores conformant array
        w.write_u32(2); // MaxCount = 2
        // Store 1 header
        w.write_u32(storage_state::DFS_STORAGE_STATE_ONLINE | storage_state::DFS_STORAGE_STATE_ACTIVE);
        w.write_u32(REFERENT_BASE + 20); // Server referent
        w.write_u32(REFERENT_BASE + 24); // Share referent
        // Store 2 header
        w.write_u32(storage_state::DFS_STORAGE_STATE_ONLINE);
        w.write_u32(REFERENT_BASE + 28);
        w.write_u32(REFERENT_BASE + 32);

        write_string_wchar_pointee(&mut w, "FS01.corp.local");
        write_string_wchar_pointee(&mut w, "PublicShare");
        write_string_wchar_pointee(&mut w, "FS02.corp.local");
        write_string_wchar_pointee(&mut w, "PublicShareReplica");

        w.write_u32(0); // ResumeHandle = NULL
        w.write_u32(0); // ErrorCode = ERROR_SUCCESS

        let entries = parse_netr_dfs_enum_level3_response(&w.into_bytes()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_path, r"\\corp.local\dfs\Public");
        assert_eq!(entries[0].comment, "Public Documents Link");
        assert_eq!(entries[0].stores.len(), 2);
        assert_eq!(entries[0].stores[0].server_name, "FS01.corp.local");
        assert_eq!(entries[0].stores[0].share_name, "PublicShare");
        assert!(entries[0].stores[0].is_active());
        assert!(entries[0].stores[0].is_online());
        assert_eq!(entries[0].stores[1].server_name, "FS02.corp.local");
        assert_eq!(entries[0].stores[1].share_name, "PublicShareReplica");
        assert!(!entries[0].stores[1].is_active());
        assert!(entries[0].stores[1].is_online());
    }

    #[test]
    fn test_dfsnm_get_info_level3_roundtrip() {
        let mut w = NdrWriter::new();
        w.write_u32(3); // Level = 3
        w.write_u32(3); // Switch = 3
        w.write_u32(REFERENT_BASE); // Info referent

        w.write_u32(REFERENT_BASE + 4); // Path referent
        w.write_u32(REFERENT_BASE + 8); // Comment referent
        w.write_u32(volume_state::DFS_VOLUME_STATE_OK); // State
        w.write_u32(1); // NumberOfStores = 1
        w.write_u32(REFERENT_BASE + 12); // Stores referent

        write_string_wchar_pointee(&mut w, r"\\corp.local\dfs\Archive");
        write_string_wchar_pointee(&mut w, "Archive Data");

        w.write_u32(1); // Stores MaxCount = 1
        w.write_u32(storage_state::DFS_STORAGE_STATE_ONLINE);
        w.write_u32(REFERENT_BASE + 16);
        w.write_u32(REFERENT_BASE + 20);

        write_string_wchar_pointee(&mut w, "ARCHIVE01");
        write_string_wchar_pointee(&mut w, "ArchiveShare");

        w.write_u32(0); // ErrorCode = ERROR_SUCCESS

        let info = parse_netr_dfs_get_info_level3_response(&w.into_bytes()).unwrap();
        assert_eq!(info.entry_path, r"\\corp.local\dfs\Archive");
        assert_eq!(info.comment, "Archive Data");
        assert_eq!(info.stores.len(), 1);
        assert_eq!(info.stores[0].server_name, "ARCHIVE01");
        assert_eq!(info.stores[0].share_name, "ArchiveShare");
    }

    #[test]
    fn test_dfsnm_add_and_remove_stubs() {
        let add_stub = build_netr_dfs_add_stub(
            r"\\corp.local\dfs\Test",
            "SRV01",
            "ShareTest",
            Some("Test Link"),
            1,
        );
        assert!(!add_stub.is_empty());

        let remove_stub = build_netr_dfs_remove_stub(
            r"\\corp.local\dfs\Test",
            Some("SRV01"),
            Some("ShareTest"),
        );
        assert!(!remove_stub.is_empty());
    }
}
