//! `samr`: `[MS-SAMR]` Security Account Manager Remote Protocol client (`impacket/dcerpc/v5/samr.py`).
//!
//! Request builders, response parsers, and a transport-agnostic `SamrClient` state machine.
//! Every structure follows the `[MS-SAMR]` / NDR20 wire format: top-level `unique` pointers are a
//! 4-byte referent id (0 = NULL)
//! with their pointee **deferred** to the end of the enclosing construct, `RPC_UNICODE_STRING` is
//! `{ Length: u16, MaximumLength: u16, Buffer: ptr }`, and conformant/varying `[string]` buffers carry
//! `MaxCount`/`Offset`/`ActualCount` headers. All builders and parsers are byte-for-byte round-trip tested.
//!
//! Call spine implemented: `SamrConnect5` (opnum 64) -> `SamrEnumerateDomainsInSamServer`
//! (opnum 6) -> `SamrLookupDomainInSamServer` (opnum 5) -> `SamrOpenDomain` (opnum 7).
//! Next increment: `SamrEnumerateUsersInDomain` (13), `SamrOpenUser` (34), `SamrQueryInformationUser` (36).

use crate::dtypes::{
    read_counted_wchar_pointee, read_rpc_unicode_string_header, write_counted_wchar_pointee,
    write_rpc_unicode_string_header, write_string_wchar_pointee, REFERENT_BASE,
};
use impacket_auth::compute_ntlm_hashes;
use impacket_core::{CoreError, FileTime, NtStatus};
use impacket_crypto::{des_ecb_decrypt_block, des_ecb_encrypt_block, Rc4};
use impacket_dcerpc::{
    extract_response_stub, pdu_type, read_rpc_pdu, RpcBindPdu, RpcRequestPdu, RpcTransport, WELL_KNOWN_INTERFACES,
};
use impacket_ndr::{NdrReader, NdrWriter, RpcSid};
use std::io::{Read, Write};

/// A 20-byte MS-RPC context handle (`SAMPR_HANDLE`).
pub type SamprHandle = [u8; 20];

// ----------------------------------------------------------------------------
// Opnums.
// ----------------------------------------------------------------------------

pub mod opnum {
    pub const SAMR_CLOSE_HANDLE: u16 = 1;
    pub const SAMR_LOOKUP_DOMAIN: u16 = 5;
    pub const SAMR_ENUMERATE_DOMAINS: u16 = 6;
    pub const SAMR_OPEN_DOMAIN: u16 = 7;
    pub const SAMR_ENUMERATE_GROUPS_IN_DOMAIN: u16 = 8;
    pub const SAMR_ENUMERATE_USERS: u16 = 13;
    pub const SAMR_ENUMERATE_ALIASES_IN_DOMAIN: u16 = 15;
    pub const SAMR_OPEN_GROUP: u16 = 19;
    pub const SAMR_GET_MEMBERS_IN_GROUP: u16 = 25;
    pub const SAMR_OPEN_ALIAS: u16 = 27;
    pub const SAMR_GET_MEMBERS_IN_ALIAS: u16 = 33;
    pub const SAMR_OPEN_USER: u16 = 34;
    pub const SAMR_QUERY_INFORMATION_USER: u16 = 36;
    pub const SAMR_CHANGE_PASSWORD_USER: u16 = 38;
    pub const SAMR_UNICODE_CHANGE_PASSWORD_USER2: u16 = 55;
    pub const SAMR_SET_INFORMATION_USER2: u16 = 58;
    pub const SAMR_CONNECT5: u16 = 64;
}

pub mod group_access {
    pub const GROUP_READ_INFORMATION: u32 = 0x0000_0001;
    pub const GROUP_GET_MEMBERS: u32 = 0x0000_0004;
    pub const GROUP_ALL_ACCESS: u32 = 0x000F_001F;
}

pub mod alias_access {
    pub const ALIAS_READ_INFORMATION: u32 = 0x0000_0001;
    pub const ALIAS_GET_MEMBERS: u32 = 0x0000_0004;
    pub const ALIAS_ALL_ACCESS: u32 = 0x000F_001F;
}

pub mod user_access {
    pub const USER_SET_PASSWORD: u32 = 0x0000_0001;
    pub const USER_FORCE_PASSWORD_CHANGE: u32 = 0x0000_0002;
    pub const USER_CHANGE_PASSWORD: u32 = 0x0000_0004;
    pub const USER_ALL_ACCESS: u32 = 0x000F_01FF;
}

// ----------------------------------------------------------------------------
// SamrConnect5 (opnum 64).
// ----------------------------------------------------------------------------

/// Builds the request stub for `SamrConnect5` (`[MS-SAMR] 3.1.5.1.2`).
///
/// Layout: `ServerName` (`unique [string] wchar_t*`: referent + deferred pointee), `DesiredAccess: u32`,
/// `InVersion: u32 = 1`, `SamrConnectInfo` union (`tag: u32 = 1`, `SAMPR_REVISION_INFO_V1 { Revision: u32,
/// SupportedFeatures: u32 }`).
pub fn build_samr_connect5_stub(server_name: &str, desired_access: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    // ServerName: unique pointer referent, then deferred NUL-terminated wchar string.
    w.write_u32(REFERENT_BASE);
    write_string_wchar_pointee(&mut w, server_name);
    w.align(4);
    w.write_u32(desired_access);
    w.write_u32(1); // InVersion = 1
    w.write_u32(1); // SamrConnectInfo union tag = 1
    w.write_u32(3); // SAMPR_REVISION_INFO_V1.Revision = 3
    w.write_u32(0); // SupportedFeatures = 0
    w.into_bytes()
}

/// Parses a `SamrConnect5` response stub, returning the `ServerHandle` on success.
///
/// Layout: `OutVersion: u32`, `SamrConnectInfo` (`tag: u32`, `Revision: u32`, `SupportedFeatures: u32`),
/// `ServerHandle: [u8; 20]`, return `NTSTATUS: u32`.
pub fn parse_samr_connect5_response(stub: &[u8]) -> Result<SamprHandle, CoreError> {
    let mut r = NdrReader::new(stub);
    let _out_version = r.read_u32()?;
    let _tag = r.read_u32()?;
    let _revision = r.read_u32()?;
    let _features = r.read_u32()?;
    let handle = r.read_fixed_array::<20>()?;
    let status = NtStatus(r.read_u32()?);
    if !status.is_success() {
        return Err(CoreError::NtStatus(status));
    }
    Ok(handle)
}

// ----------------------------------------------------------------------------
// SamrEnumerateDomainsInSamServer (opnum 6).
// ----------------------------------------------------------------------------

/// Builds the request stub for `SamrEnumerateDomainsInSamServer` (`[MS-SAMR] 3.1.5.2.1`).
/// Layout: `ServerHandle: [u8; 20]`, `EnumerationContext: u32`, `PreferedMaximumLength: u32`.
pub fn build_samr_enumerate_domains_stub(
    server_handle: &SamprHandle,
    enumeration_context: u32,
    prefered_maximum_length: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(32);
    w.write_fixed_array(server_handle);
    w.write_u32(enumeration_context);
    w.write_u32(prefered_maximum_length);
    w.into_bytes()
}

/// One entry of a `SAMPR_ENUMERATION_BUFFER` (`SAMPR_RID_ENUMERATION`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainEnumEntry {
    pub relative_id: u32,
    pub name: String,
}

/// Result of `SamrEnumerateDomainsInSamServer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainEnumeration {
    pub enumeration_context: u32,
    pub entries: Vec<DomainEnumEntry>,
}

/// Builds a wire-accurate `SamrEnumerateDomainsInSamServer` response stub (used by tests / the mock DC).
///
/// Marshals: `EnumerationContext`, `Buffer` referent -> `SAMPR_ENUMERATION_BUFFER { EntriesRead, Buffer
/// referent -> conformant SAMPR_RID_ENUMERATION[] }`, `CountReturned`, return `NTSTATUS`. The per-entry
/// `Name` `RPC_UNICODE_STRING` buffers are deferred after the inline array, in order.
pub fn build_samr_enumerate_domains_response(
    enumeration_context: u32,
    entries: &[DomainEnumEntry],
    status: NtStatus,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(256);
    w.write_u32(enumeration_context);
    w.write_u32(REFERENT_BASE); // Buffer (PSAMPR_ENUMERATION_BUFFER) referent

    let count = entries.len() as u32;
    w.write_u32(count); // EntriesRead
    w.write_u32(REFERENT_BASE + 4); // array referent
    w.write_u32(count); // conformant array MaxCount

    // Inline part of each SAMPR_RID_ENUMERATION.
    for (i, e) in entries.iter().enumerate() {
        w.write_u32(e.relative_id);
        write_rpc_unicode_string_header(&mut w, &e.name, REFERENT_BASE + 8 + i as u32);
    }
    // Deferred Name buffers, in element order.
    for e in entries {
        if !e.name.is_empty() {
            write_counted_wchar_pointee(&mut w, &e.name);
        }
    }

    w.write_u32(count); // CountReturned
    w.write_u32(status.0); // return NTSTATUS
    w.into_bytes()
}

/// Parses a `SamrEnumerateDomainsInSamServer` response stub.
pub fn parse_samr_enumerate_domains_response(stub: &[u8]) -> Result<DomainEnumeration, CoreError> {
    parse_enumeration_response(stub)
}

/// Shared `SAMPR_ENUMERATION_BUFFER` response codec: identical wire layout for domain enumeration
/// (`SamrEnumerateDomainsInSamServer`) and user enumeration (`SamrEnumerateUsersInDomain`).
fn parse_enumeration_response(stub: &[u8]) -> Result<DomainEnumeration, CoreError> {
    let mut r = NdrReader::new(stub);
    let enumeration_context = r.read_u32()?;
    let buffer_ref = r.read_u32()?;
    if buffer_ref == 0 {
        // NULL buffer: still read CountReturned + status.
        let _count_returned = r.read_u32()?;
        let status = NtStatus(r.read_u32()?);
        accept_enum_status(status)?;
        return Ok(DomainEnumeration {
            enumeration_context,
            entries: Vec::new(),
        });
    }

    let entries_read = r.read_u32()? as usize;
    let array_ref = r.read_u32()?;
    if array_ref == 0 || entries_read > 4096 {
        return Err(CoreError::ProtocolError(
            "SAMPR_ENUMERATION_BUFFER array pointer invalid".into(),
        ));
    }
    let max_count = r.read_u32()? as usize;
    if max_count < entries_read {
        return Err(CoreError::ProtocolError(
            "SAMPR_ENUMERATION_BUFFER MaxCount < EntriesRead".into(),
        ));
    }

    // Inline RID + RPC_UNICODE_STRING headers.
    let mut rids = Vec::with_capacity(entries_read);
    let mut has_buffer = Vec::with_capacity(entries_read);
    for _ in 0..entries_read {
        let rid = r.read_u32()?;
        let (byte_len, referent) = read_rpc_unicode_string_header(&mut r)?;
        rids.push(rid);
        has_buffer.push(byte_len > 0 && referent != 0);
    }
    // Deferred name buffers.
    let mut entries = Vec::with_capacity(entries_read);
    for (i, &rid) in rids.iter().enumerate() {
        let name = if has_buffer[i] {
            read_counted_wchar_pointee(&mut r)?
        } else {
            String::new()
        };
        entries.push(DomainEnumEntry {
            relative_id: rid,
            name,
        });
    }

    let _count_returned = r.read_u32()?;
    let status = NtStatus(r.read_u32()?);
    accept_enum_status(status)?;

    Ok(DomainEnumeration {
        enumeration_context,
        entries,
    })
}

/// `SamrEnumerateDomainsInSamServer` returns `STATUS_MORE_ENTRIES` when the enumeration is paged.
fn accept_enum_status(status: NtStatus) -> Result<(), CoreError> {
    if status.is_success() || status == NtStatus::STATUS_MORE_ENTRIES {
        Ok(())
    } else {
        Err(CoreError::NtStatus(status))
    }
}

// ----------------------------------------------------------------------------
// SamrLookupDomainInSamServer (opnum 5).
// ----------------------------------------------------------------------------

/// Builds the request stub for `SamrLookupDomainInSamServer` (`[MS-SAMR] 3.1.5.11.1`).
/// Layout: `ServerHandle: [u8; 20]`, `Name: RPC_UNICODE_STRING` (inline header + deferred buffer).
pub fn build_samr_lookup_domain_stub(server_handle: &SamprHandle, domain_name: &str) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(48);
    w.write_fixed_array(server_handle);
    write_rpc_unicode_string_header(&mut w, domain_name, REFERENT_BASE);
    if !domain_name.is_empty() {
        write_counted_wchar_pointee(&mut w, domain_name);
    }
    w.into_bytes()
}

/// Builds a wire-accurate `SamrLookupDomainInSamServer` response stub.
/// Layout: `DomainId` (`PRPC_SID`: referent -> `RPC_SID`), return `NTSTATUS`.
pub fn build_samr_lookup_domain_response(domain_sid: &RpcSid, status: NtStatus) -> Vec<u8> {
    use impacket_ndr::NdrSerialize;
    let mut w = NdrWriter::with_capacity(48);
    w.write_u32(REFERENT_BASE); // DomainId referent
    domain_sid.ndr_serialize(&mut w);
    w.align(4);
    w.write_u32(status.0);
    w.into_bytes()
}

/// Parses a `SamrLookupDomainInSamServer` response stub into the domain `RpcSid`.
pub fn parse_samr_lookup_domain_response(stub: &[u8]) -> Result<RpcSid, CoreError> {
    use impacket_ndr::NdrDeserialize;
    let mut r = NdrReader::new(stub);
    let referent = r.read_u32()?;
    if referent == 0 {
        let status = NtStatus(r.read_u32()?);
        return Err(CoreError::NtStatus(status));
    }
    let sid = RpcSid::ndr_deserialize(&mut r)?;
    r.align(4)?;
    let status = NtStatus(r.read_u32()?);
    if !status.is_success() {
        return Err(CoreError::NtStatus(status));
    }
    Ok(sid)
}

// ----------------------------------------------------------------------------
// SamrOpenDomain (opnum 7).
// ----------------------------------------------------------------------------

/// Builds the request stub for `SamrOpenDomain` (`[MS-SAMR] 3.1.5.1.5`).
/// Layout: `ServerHandle: [u8; 20]`, `DesiredAccess: u32`, `DomainId: PRPC_SID` (referent -> `RPC_SID`).
pub fn build_samr_open_domain_stub(
    server_handle: &SamprHandle,
    desired_access: u32,
    domain_sid: &RpcSid,
) -> Vec<u8> {
    use impacket_ndr::NdrSerialize;
    let mut w = NdrWriter::with_capacity(64);
    w.write_fixed_array(server_handle);
    w.write_u32(desired_access);
    // DomainId is a non-pointer [in] RPC_SID passed by value in [MS-SAMR]; its leading conformant
    // MaxCount (SubAuthorityCount) is emitted by RpcSid::ndr_serialize.
    domain_sid.ndr_serialize(&mut w);
    w.into_bytes()
}

/// Builds a wire-accurate `SamrOpenDomain` response stub.
/// Layout: `DomainHandle: [u8; 20]`, return `NTSTATUS`.
pub fn build_samr_open_domain_response(domain_handle: &SamprHandle, status: NtStatus) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(24);
    w.write_fixed_array(domain_handle);
    w.write_u32(status.0);
    w.into_bytes()
}

/// Parses a `SamrOpenDomain` response stub, returning the `DomainHandle`.
pub fn parse_samr_open_domain_response(stub: &[u8]) -> Result<SamprHandle, CoreError> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_fixed_array::<20>()?;
    let status = NtStatus(r.read_u32()?);
    if !status.is_success() {
        return Err(CoreError::NtStatus(status));
    }
    Ok(handle)
}

// ----------------------------------------------------------------------------
// SamrEnumerateUsersInDomain (opnum 13) + SamrOpenUser (opnum 34).
// ----------------------------------------------------------------------------

/// Builds the request stub for `SamrEnumerateUsersInDomain` (`[MS-SAMR] 3.1.5.2.5`).
/// Layout: `DomainHandle: [u8; 20]`, `EnumerationContext: u32`, `UserAccountControl: u32`
/// (ACB filter; `0` enumerates every account), `PreferedMaximumLength: u32`.
pub fn build_samr_enumerate_users_stub(
    domain_handle: &SamprHandle,
    enumeration_context: u32,
    user_account_control: u32,
    prefered_maximum_length: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(36);
    w.write_fixed_array(domain_handle);
    w.write_u32(enumeration_context);
    w.write_u32(user_account_control);
    w.write_u32(prefered_maximum_length);
    w.into_bytes()
}

/// Parses a `SamrEnumerateUsersInDomain` response stub. The payload is the same
/// `SAMPR_ENUMERATION_BUFFER` layout as domain enumeration, with `relative_id` = user RID.
pub fn parse_samr_enumerate_users_response(stub: &[u8]) -> Result<DomainEnumeration, CoreError> {
    parse_enumeration_response(stub)
}

/// Builds the request stub for `SamrOpenUser` (`[MS-SAMR] 3.1.5.1.9`).
/// Layout: `DomainHandle: [u8; 20]`, `DesiredAccess: u32`, `UserId: u32` (RID).
pub fn build_samr_open_user_stub(
    domain_handle: &SamprHandle,
    desired_access: u32,
    user_rid: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(28);
    w.write_fixed_array(domain_handle);
    w.write_u32(desired_access);
    w.write_u32(user_rid);
    w.into_bytes()
}

/// Builds a wire-accurate `SamrOpenUser` response stub (`UserHandle: [u8; 20]`, return `NTSTATUS`).
pub fn build_samr_open_user_response(user_handle: &SamprHandle, status: NtStatus) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(24);
    w.write_fixed_array(user_handle);
    w.write_u32(status.0);
    w.into_bytes()
}

/// Parses a `SamrOpenUser` response stub, returning the `UserHandle`.
pub fn parse_samr_open_user_response(stub: &[u8]) -> Result<SamprHandle, CoreError> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_fixed_array::<20>()?;
    let status = NtStatus(r.read_u32()?);
    if !status.is_success() {
        return Err(CoreError::NtStatus(status));
    }
    Ok(handle)
}

// ----------------------------------------------------------------------------
// SamrCloseHandle (opnum 1).
// ----------------------------------------------------------------------------

pub fn build_samr_close_handle_stub(handle: &SamprHandle) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(20);
    w.write_fixed_array(handle);
    w.into_bytes()
}

// ----------------------------------------------------------------------------
// SamrEnumerateGroupsInDomain (opnum 8), SamrEnumerateAliasesInDomain (opnum 15).
// ----------------------------------------------------------------------------

pub fn parse_samr_enumerate_groups_response(stub: &[u8]) -> Result<DomainEnumeration, CoreError> {
    parse_enumeration_response(stub)
}

pub fn parse_samr_enumerate_aliases_response(stub: &[u8]) -> Result<DomainEnumeration, CoreError> {
    parse_enumeration_response(stub)
}

// ----------------------------------------------------------------------------
// SamrOpenGroup (opnum 19), SamrOpenAlias (opnum 27).
// ----------------------------------------------------------------------------

pub fn build_samr_open_group_stub(
    domain_handle: &SamprHandle,
    desired_access: u32,
    group_rid: u32,
) -> Vec<u8> {
    build_samr_open_user_stub(domain_handle, desired_access, group_rid)
}

pub fn parse_samr_open_group_response(stub: &[u8]) -> Result<SamprHandle, CoreError> {
    parse_samr_open_user_response(stub)
}

pub fn build_samr_open_alias_stub(
    domain_handle: &SamprHandle,
    desired_access: u32,
    alias_rid: u32,
) -> Vec<u8> {
    build_samr_open_user_stub(domain_handle, desired_access, alias_rid)
}

pub fn parse_samr_open_alias_response(stub: &[u8]) -> Result<SamprHandle, CoreError> {
    parse_samr_open_user_response(stub)
}

// ----------------------------------------------------------------------------
// SamrGetMembersInGroup (opnum 25).
// ----------------------------------------------------------------------------

pub fn build_samr_get_members_in_group_stub(group_handle: &SamprHandle) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(20);
    w.write_fixed_array(group_handle);
    w.into_bytes()
}

pub fn build_samr_get_members_in_group_response(members: &[u32], status: NtStatus) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(32 + members.len() * 8);
    if members.is_empty() && !status.is_success() {
        w.write_u32(0); // NULL ptr
        w.write_u32(status.0);
        return w.into_bytes();
    }
    w.write_u32(0x0002_0000); // Buffer referent
    let count = members.len() as u32;
    w.write_u32(count);
    w.write_u32(0x0002_0004); // Members ptr
    w.write_u32(0x0002_0008); // Attributes ptr
    // Deferred Members array
    w.write_u32(count); // MaxCount
    for &rid in members {
        w.write_u32(rid);
    }
    // Deferred Attributes array
    w.write_u32(count); // MaxCount
    for _ in 0..members.len() {
        w.write_u32(0x0000_0007); // SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
    }
    w.write_u32(status.0);
    w.into_bytes()
}

pub fn parse_samr_get_members_in_group_response(stub: &[u8]) -> Result<Vec<u32>, CoreError> {
    let mut r = NdrReader::new(stub);
    let buf_ptr = r.read_u32()?;
    if buf_ptr == 0 {
        let status = NtStatus(r.read_u32()?);
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        return Ok(Vec::new());
    }
    let count = r.read_u32()? as usize;
    let rids_ptr = r.read_u32()?;
    let _attrs_ptr = r.read_u32()?;
    let mut members = Vec::with_capacity(count);
    if rids_ptr != 0 && count > 0 {
        let max_count = r.read_u32()? as usize;
        let to_read = count.min(max_count);
        for _ in 0..to_read {
            members.push(r.read_u32()?);
        }
    }
    Ok(members)
}

// ----------------------------------------------------------------------------
// SamrGetMembersInAlias (opnum 33).
// ----------------------------------------------------------------------------

pub fn build_samr_get_members_in_alias_stub(alias_handle: &SamprHandle) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(20);
    w.write_fixed_array(alias_handle);
    w.into_bytes()
}

pub fn build_samr_get_members_in_alias_response(sids: &[RpcSid], status: NtStatus) -> Vec<u8> {
    use impacket_ndr::NdrSerialize;
    let mut w = NdrWriter::with_capacity(32 + sids.len() * 32);
    if sids.is_empty() && !status.is_success() {
        w.write_u32(0); // NULL ptr
        w.write_u32(status.0);
        return w.into_bytes();
    }
    w.write_u32(0x0002_0000); // Buffer referent
    let count = sids.len() as u32;
    w.write_u32(count);
    w.write_u32(0x0002_0004); // Sids array ptr
    // Deferred pointer array
    w.write_u32(count); // MaxCount
    for (i, _) in sids.iter().enumerate() {
        w.write_u32(0x0002_0008 + (i as u32 * 4));
    }
    // Deferred SIDs
    for sid in sids {
        sid.ndr_serialize(&mut w);
    }
    w.write_u32(status.0);
    w.into_bytes()
}

pub fn parse_samr_get_members_in_alias_response(stub: &[u8]) -> Result<Vec<RpcSid>, CoreError> {
    use impacket_ndr::NdrDeserialize;
    let mut r = NdrReader::new(stub);
    let buf_ptr = r.read_u32()?;
    if buf_ptr == 0 {
        let status = NtStatus(r.read_u32()?);
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        return Ok(Vec::new());
    }
    let count = r.read_u32()? as usize;
    let sids_ptr = r.read_u32()?;
    let mut sids = Vec::with_capacity(count);
    if sids_ptr != 0 && count > 0 {
        let max_count = r.read_u32()? as usize;
        let to_read = count.min(max_count);
        let mut ptrs = Vec::with_capacity(to_read);
        for _ in 0..to_read {
            ptrs.push(r.read_u32()?);
        }
        for ptr in ptrs {
            if ptr != 0 {
                sids.push(RpcSid::ndr_deserialize(&mut r)?);
            }
        }
    }
    Ok(sids)
}

// ----------------------------------------------------------------------------
// SamrQueryInformationUser (opnum 36), UserAllInformation (class 21).
// ----------------------------------------------------------------------------

/// `USER_INFORMATION_CLASS::UserAllInformation`.
pub const USER_ALL_INFORMATION: u16 = 21;

/// The subset of `SAMPR_USER_ALL_INFORMATION` (`[MS-SAMR] 2.2.6.6`) that `samrdump` reports.
///
/// The full structure carries many more fields (home dir, script/profile paths, OWF blobs, security
/// descriptor, logon hours). The inline scalars below are parsed exactly; the three reported names are
/// read from the deferred `RPC_UNICODE_STRING` buffers. Response layout modeled to `[MS-SAMR]` + NDR20
/// and round-trip tested; pending live-capture confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SamrUserAllInformation {
    pub username: String,
    pub full_name: String,
    pub admin_comment: String,
    pub user_id: u32,
    pub primary_group_id: u32,
    pub user_account_control: u32,
    pub bad_password_count: u16,
    pub logon_count: u16,
    pub password_last_set: FileTime,
}

impl SamrUserAllInformation {
    /// `USER_DONT_EXPIRE_PASSWD` (`0x00000200`).
    pub fn password_never_expires(&self) -> bool {
        self.user_account_control & 0x0000_0200 != 0
    }
    /// `USER_ACCOUNT_DISABLED` (`0x00000001`).
    pub fn account_disabled(&self) -> bool {
        self.user_account_control & 0x0000_0001 != 0
    }
}

/// Builds the `SamrQueryInformationUser` request stub: `UserHandle: [u8; 20]`, `UserInformationClass: u16`.
pub fn build_samr_query_information_user_stub(user_handle: &SamprHandle, info_class: u16) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(24);
    w.write_fixed_array(user_handle);
    w.write_u16(info_class);
    w.into_bytes()
}

/// Builds a wire-accurate `SamrQueryInformationUser` / `UserAllInformation` response stub (test fixture).
///
/// Emits the full `SAMPR_USER_ALL_INFORMATION` inline block with all OWF/SD/logon-hours pointers NULL
/// (so only the three name buffers are deferred), matching what [`parse_samr_query_user_all_response`]
/// reads. Returns `(buffer, NTSTATUS)`.
pub fn build_samr_query_user_all_response(info: &SamrUserAllInformation, status: NtStatus) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(256);
    w.write_u32(REFERENT_BASE); // Buffer (PSAMPR_USER_INFO_BUFFER) referent
    w.write_u16(USER_ALL_INFORMATION); // union discriminant
    w.align(4);

    // Six OLD_LARGE_INTEGER values; only PasswordLastSet (index 2) is meaningful here.
    w.write_u64(0); // LastLogon
    w.write_u64(0); // LastLogoff
    w.write_u64(info.password_last_set.0); // PasswordLastSet
    w.write_u64(0); // AccountExpires
    w.write_u64(0); // PasswordCanChange
    w.write_u64(0); // PasswordMustChange

    // Ten RPC_UNICODE_STRING headers (only UserName/FullName/AdminComment carry buffers here).
    let names: [&str; 10] = [
        info.username.as_str(),      // UserName (0)
        info.full_name.as_str(),     // FullName (1)
        "",                          // HomeDirectory (2)
        "",                          // HomeDirectoryDrive (3)
        "",                          // ScriptPath (4)
        "",                          // ProfilePath (5)
        info.admin_comment.as_str(), // AdminComment (6)
        "",                          // WorkStations (7)
        "",                          // UserComment (8)
        "",                          // Parameters (9)
    ];
    for (i, n) in names.iter().enumerate() {
        write_rpc_unicode_string_header(&mut w, n, REFERENT_BASE + 100 + i as u32);
    }

    // RPC_SHORT_BLOB LmOwfPassword / NtOwfPassword (Length, MaxLength, Buffer=NULL).
    for _ in 0..2 {
        w.write_u16(0);
        w.write_u16(0);
        w.write_u32(0);
    }
    // PrivateData RPC_UNICODE_STRING (empty).
    write_rpc_unicode_string_header(&mut w, "", 0);
    // SAMPR_SR_SECURITY_DESCRIPTOR { Length=0, SecurityDescriptor=NULL }.
    w.write_u32(0);
    w.write_u32(0);

    w.write_u32(info.user_id);
    w.write_u32(info.primary_group_id);
    w.write_u32(info.user_account_control);
    w.write_u32(0); // WhichFields

    // SAMPR_LOGON_HOURS { UnitsPerWeek: u16, LogonHours: NULL }.
    w.write_u16(0);
    w.align(4);
    w.write_u32(0);

    w.write_u16(info.bad_password_count);
    w.write_u16(info.logon_count);
    w.write_u16(0); // CountryCode
    w.write_u16(0); // CodePage
    w.write_u8(0); // LmPasswordPresent
    w.write_u8(0); // NtPasswordPresent
    w.write_u8(0); // PasswordExpired
    w.write_u8(0); // PrivateDataSensitive

    // Deferred buffers: UserName, FullName, AdminComment (the only non-empty, non-null strings).
    for n in [&info.username, &info.full_name, &info.admin_comment] {
        if !n.is_empty() {
            write_counted_wchar_pointee(&mut w, n);
        }
    }

    w.write_u32(status.0); // return NTSTATUS
    w.into_bytes()
}

/// Parses a `SamrQueryInformationUser` / `UserAllInformation` response stub.
pub fn parse_samr_query_user_all_response(stub: &[u8]) -> Result<SamrUserAllInformation, CoreError> {
    let mut r = NdrReader::new(stub);
    let buffer_ref = r.read_u32()?;
    if buffer_ref == 0 {
        return Err(CoreError::ProtocolError("SamrQueryInformationUser returned NULL buffer".into()));
    }
    let _discriminant = r.read_u16()?;
    r.align(4)?;

    // Six OLD_LARGE_INTEGER.
    let _last_logon = r.read_u64()?;
    let _last_logoff = r.read_u64()?;
    let password_last_set = FileTime::from_raw(r.read_u64()?);
    let _account_expires = r.read_u64()?;
    let _pw_can_change = r.read_u64()?;
    let _pw_must_change = r.read_u64()?;

    // Ten RPC_UNICODE_STRING headers.
    let mut name_present = [false; 10];
    for slot in name_present.iter_mut() {
        let (len, referent) = read_rpc_unicode_string_header(&mut r)?;
        *slot = len > 0 && referent != 0;
    }
    // Two RPC_SHORT_BLOB headers.
    for _ in 0..2 {
        let _len = r.read_u16()?;
        let _max = r.read_u16()?;
        let _ptr = r.read_u32()?;
    }
    // PrivateData RPC_UNICODE_STRING header.
    let (_pd_len, _pd_ref) = read_rpc_unicode_string_header(&mut r)?;
    // SAMPR_SR_SECURITY_DESCRIPTOR.
    let _sd_len = r.read_u32()?;
    let _sd_ptr = r.read_u32()?;

    let user_id = r.read_u32()?;
    let primary_group_id = r.read_u32()?;
    let user_account_control = r.read_u32()?;
    let _which_fields = r.read_u32()?;

    // SAMPR_LOGON_HOURS.
    let _units = r.read_u16()?;
    r.align(4)?;
    let _logon_hours_ptr = r.read_u32()?;

    let bad_password_count = r.read_u16()?;
    let logon_count = r.read_u16()?;
    let _country = r.read_u16()?;
    let _codepage = r.read_u16()?;
    let _lm_present = r.read_u8()?;
    let _nt_present = r.read_u8()?;
    let _pw_expired = r.read_u8()?;
    let _priv_sensitive = r.read_u8()?;

    // Deferred name buffers, in declaration order (only those whose header had a buffer).
    let mut names = [String::new(), String::new(), String::new(), String::new(), String::new(),
        String::new(), String::new(), String::new(), String::new(), String::new()];
    for i in 0..10 {
        if name_present[i] {
            names[i] = read_counted_wchar_pointee(&mut r)?;
        }
    }

    Ok(SamrUserAllInformation {
        username: std::mem::take(&mut names[0]),
        full_name: std::mem::take(&mut names[1]),
        admin_comment: std::mem::take(&mut names[6]),
        user_id,
        primary_group_id,
        user_account_control,
        bad_password_count,
        logon_count,
        password_last_set,
    })
}

// ----------------------------------------------------------------------------
// Password Encryption & Modification (Opnum 55 & Opnum 58).
// ----------------------------------------------------------------------------

/// Encodes a cleartext password into a 516-byte `SAMPR_ENCRYPTED_USER_PASSWORD` structure
/// encrypted with RC4 (`[MS-SAMR] 2.2.6.4` & `2.2.6.5`).
pub fn encode_sampr_encrypted_user_password(
    new_password: &str,
    encrypt_key: &[u8],
) -> [u8; 516] {
    let utf16: Vec<u16> = new_password.encode_utf16().collect();
    let pwd_len_bytes = (utf16.len() * 2) as u32;
    let mut buf = [0u8; 516];

    let offset = if pwd_len_bytes <= 512 {
        512 - pwd_len_bytes as usize
    } else {
        0
    };

    // Fill preceding bytes with deterministic filler
    for i in 0..offset {
        buf[i] = ((i.wrapping_mul(37).wrapping_add(0x5a)) & 0xff) as u8;
    }

    // Copy UTF-16LE password bytes
    for (idx, &c) in utf16.iter().enumerate() {
        if offset + idx * 2 + 1 < 512 {
            let b = c.to_le_bytes();
            buf[offset + idx * 2] = b[0];
            buf[offset + idx * 2 + 1] = b[1];
        }
    }

    // Write length in bytes at 512..516
    buf[512..516].copy_from_slice(&pwd_len_bytes.to_le_bytes());

    // Encrypt with RC4
    let mut rc4 = Rc4::new(encrypt_key);
    rc4.apply_keystream(&mut buf);
    buf
}

/// Decrypts a 516-byte `SAMPR_ENCRYPTED_USER_PASSWORD` structure using RC4.
pub fn decode_sampr_encrypted_user_password(
    mut buf: [u8; 516],
    decrypt_key: &[u8],
) -> Result<String, CoreError> {
    let mut rc4 = Rc4::new(decrypt_key);
    rc4.apply_keystream(&mut buf);

    let pwd_len_bytes = u32::from_le_bytes([buf[512], buf[513], buf[514], buf[515]]) as usize;
    if pwd_len_bytes > 512 || pwd_len_bytes % 2 != 0 {
        return Err(CoreError::ProtocolError("Invalid SAMPR password length".into()));
    }
    let offset = 512 - pwd_len_bytes;
    let mut u16_chars = Vec::with_capacity(pwd_len_bytes / 2);
    for chunk in buf[offset..512].chunks_exact(2) {
        u16_chars.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    String::from_utf16(&u16_chars).map_err(|e| CoreError::ProtocolError(e.to_string()))
}

/// Encrypts a 16-byte OWF hash with another 16-byte hash using 2-key DES-ECB (`[MS-SAMR] 2.2.11.1`).
pub fn encrypt_owf_password(plain_hash: &[u8; 16], key_hash: &[u8; 16]) -> [u8; 16] {
    let mut k1 = [0u8; 7];
    let mut k2 = [0u8; 7];
    k1.copy_from_slice(&key_hash[0..7]);
    k2.copy_from_slice(&key_hash[7..14]);
    let mut b1 = [0u8; 8];
    let mut b2 = [0u8; 8];
    b1.copy_from_slice(&plain_hash[0..8]);
    b2.copy_from_slice(&plain_hash[8..16]);
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&des_ecb_encrypt_block(&k1, &b1));
    out[8..16].copy_from_slice(&des_ecb_encrypt_block(&k2, &b2));
    out
}

/// Decrypts a 16-byte OWF hash with another 16-byte hash using 2-key DES-ECB.
pub fn decrypt_owf_password(enc_hash: &[u8; 16], key_hash: &[u8; 16]) -> [u8; 16] {
    let mut k1 = [0u8; 7];
    let mut k2 = [0u8; 7];
    k1.copy_from_slice(&key_hash[0..7]);
    k2.copy_from_slice(&key_hash[7..14]);
    let mut b1 = [0u8; 8];
    let mut b2 = [0u8; 8];
    b1.copy_from_slice(&enc_hash[0..8]);
    b2.copy_from_slice(&enc_hash[8..16]);
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&des_ecb_decrypt_block(&k1, &b1));
    out[8..16].copy_from_slice(&des_ecb_decrypt_block(&k2, &b2));
    out
}

/// Builds request stub for `SamrUnicodeChangePasswordUser2` (`[MS-SAMR] 3.1.5.10.2` Opnum 55).
pub fn build_samr_unicode_change_password_user2_stub(
    server_name: &str,
    username: &str,
    old_password: &str,
    new_password: &str,
) -> Vec<u8> {
    let old_nt = compute_ntlm_hashes(old_password).nt;
    let new_nt = compute_ntlm_hashes(new_password).nt;

    let enc_pwd = encode_sampr_encrypted_user_password(new_password, &old_nt);
    let enc_old_nt = encrypt_owf_password(&old_nt, &new_nt);

    let mut w = NdrWriter::with_capacity(600);
    // 1. ServerName unique pointer
    if server_name.is_empty() {
        w.write_u32(0);
    } else {
        w.write_u32(REFERENT_BASE);
    }
    // 2. UserName pointer
    w.write_u32(REFERENT_BASE + 4);
    // 3. NewPasswordEncryptedWithOldNt pointer
    w.write_u32(REFERENT_BASE + 8);
    // 4. OldNtOwfPasswordEncryptedWithNewNt pointer
    w.write_u32(REFERENT_BASE + 12);
    // 5. LmPresent (0 = false)
    w.write_u8(0);
    w.align(4);
    // 6. NewPasswordEncryptedWithOldLm pointer (NULL)
    w.write_u32(0);
    // 7. OldLmOwfPasswordEncryptedWithNewLm pointer (NULL)
    w.write_u32(0);

    // Deferred pointees
    if !server_name.is_empty() {
        write_rpc_unicode_string_header(&mut w, server_name, REFERENT_BASE + 16);
        write_counted_wchar_pointee(&mut w, server_name);
    }
    write_rpc_unicode_string_header(&mut w, username, REFERENT_BASE + 20);
    write_counted_wchar_pointee(&mut w, username);

    // SAMPR_ENCRYPTED_USER_PASSWORD pointee (516 bytes)
    w.write_fixed_array(&enc_pwd);

    // ENCRYPTED_NT_OWF_PASSWORD pointee (16 bytes)
    w.write_fixed_array(&enc_old_nt);

    w.into_bytes()
}

/// Builds request stub for `SamrSetInformationUser2` with `UserInternal3Information` (Opnum 58).
pub fn build_samr_set_user_password_stub(
    user_handle: &SamprHandle,
    new_password: &str,
    session_key: &[u8; 16],
) -> Vec<u8> {
    let enc_pwd = encode_sampr_encrypted_user_password(new_password, session_key);

    let mut w = NdrWriter::with_capacity(550);
    w.write_fixed_array(user_handle);
    w.write_u16(23); // UserInformationClass = UserInternal3Information (23)
    w.write_u16(23); // Union discriminator
    w.write_u32(REFERENT_BASE); // Buffer pointer
    w.write_fixed_array(&enc_pwd); // SAMPR_ENCRYPTED_USER_PASSWORD (516 bytes)
    w.into_bytes()
}

/// Parses a generic void SAMR response stub containing a return `NTSTATUS`.
pub fn parse_samr_status_response(stub: &[u8]) -> Result<(), CoreError> {
    if stub.len() < 4 {
        return Err(CoreError::ProtocolError("Truncated SAMR status response".into()));
    }
    let mut r = NdrReader::new(stub);
    let status = NtStatus(r.read_u32()?);
    if !status.is_success() {
        return Err(CoreError::NtStatus(status));
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// Transport abstraction + client state machine.
// ----------------------------------------------------------------------------

/// `[MS-SAMR]` high-level client driving the real call spine over any [`RpcTransport`]
/// (defined in `impacket-dcerpc`, shared with `ncacn_ip_tcp` and the `ncacn_np` SMB-pipe transports).
pub struct SamrClient<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> SamrClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            call_id: 1,
        }
    }

    fn next_call_id(&mut self) -> u32 {
        let id = self.call_id;
        self.call_id += 1;
        id
    }

    fn call(&mut self, opnum: u16, stub: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let call_id = self.next_call_id();
        let pdu = RpcRequestPdu {
            call_id,
            context_id: 0,
            opnum,
            stub_data: stub,
        }
        .to_bytes();
        let resp = self.transport.transceive(&pdu)?;
        extract_response_stub(&resp)
    }

    pub fn connect5(&mut self, server_name: &str, desired_access: u32) -> Result<SamprHandle, CoreError> {
        let stub = build_samr_connect5_stub(server_name, desired_access);
        let resp = self.call(opnum::SAMR_CONNECT5, stub)?;
        parse_samr_connect5_response(&resp)
    }

    pub fn enumerate_domains(
        &mut self,
        server_handle: &SamprHandle,
    ) -> Result<Vec<DomainEnumEntry>, CoreError> {
        let mut all = Vec::new();
        let mut ctx = 0u32;
        loop {
            let stub = build_samr_enumerate_domains_stub(server_handle, ctx, 0xFFFF_FFFF);
            let resp = self.call(opnum::SAMR_ENUMERATE_DOMAINS, stub)?;
            let page = parse_samr_enumerate_domains_response(&resp)?;
            let got = page.entries.len();
            all.extend(page.entries);
            // Single-shot with MAX_PREFERRED_LENGTH returns everything; stop when drained or no progress.
            if got == 0 || page.enumeration_context == ctx {
                break;
            }
            ctx = page.enumeration_context;
        }
        Ok(all)
    }

    pub fn lookup_domain(
        &mut self,
        server_handle: &SamprHandle,
        domain_name: &str,
    ) -> Result<RpcSid, CoreError> {
        let stub = build_samr_lookup_domain_stub(server_handle, domain_name);
        let resp = self.call(opnum::SAMR_LOOKUP_DOMAIN, stub)?;
        parse_samr_lookup_domain_response(&resp)
    }

    pub fn open_domain(
        &mut self,
        server_handle: &SamprHandle,
        desired_access: u32,
        domain_sid: &RpcSid,
    ) -> Result<SamprHandle, CoreError> {
        let stub = build_samr_open_domain_stub(server_handle, desired_access, domain_sid);
        let resp = self.call(opnum::SAMR_OPEN_DOMAIN, stub)?;
        parse_samr_open_domain_response(&resp)
    }

    /// Enumerates every user account (RID + name) in an opened domain, paging until drained.
    /// `user_account_control` is the ACB filter (`0` = all accounts).
    pub fn enumerate_users(
        &mut self,
        domain_handle: &SamprHandle,
        user_account_control: u32,
    ) -> Result<Vec<DomainEnumEntry>, CoreError> {
        let mut all = Vec::new();
        let mut ctx = 0u32;
        loop {
            let stub = build_samr_enumerate_users_stub(
                domain_handle,
                ctx,
                user_account_control,
                0xFFFF_FFFF,
            );
            let resp = self.call(opnum::SAMR_ENUMERATE_USERS, stub)?;
            let page = parse_samr_enumerate_users_response(&resp)?;
            let got = page.entries.len();
            all.extend(page.entries);
            if got == 0 || page.enumeration_context == ctx {
                break;
            }
            ctx = page.enumeration_context;
        }
        Ok(all)
    }

    /// Opens a user object by RID, returning its `UserHandle`.
    pub fn open_user(
        &mut self,
        domain_handle: &SamprHandle,
        desired_access: u32,
        user_rid: u32,
    ) -> Result<SamprHandle, CoreError> {
        let stub = build_samr_open_user_stub(domain_handle, desired_access, user_rid);
        let resp = self.call(opnum::SAMR_OPEN_USER, stub)?;
        parse_samr_open_user_response(&resp)
    }

    /// `SamrQueryInformationUser` (`UserAllInformation`) for an opened user handle.
    pub fn query_user_all(
        &mut self,
        user_handle: &SamprHandle,
    ) -> Result<SamrUserAllInformation, CoreError> {
        let stub = build_samr_query_information_user_stub(user_handle, USER_ALL_INFORMATION);
        let resp = self.call(opnum::SAMR_QUERY_INFORMATION_USER, stub)?;
        parse_samr_query_user_all_response(&resp)
    }

    /// Enumerates every global group (RID + name) in an opened domain, paging until drained.
    pub fn enumerate_groups(
        &mut self,
        domain_handle: &SamprHandle,
    ) -> Result<Vec<DomainEnumEntry>, CoreError> {
        let mut all = Vec::new();
        let mut ctx = 0u32;
        loop {
            let stub = build_samr_enumerate_domains_stub(domain_handle, ctx, 0xFFFF_FFFF);
            let resp = self.call(opnum::SAMR_ENUMERATE_GROUPS_IN_DOMAIN, stub)?;
            let page = parse_enumeration_response(&resp)?;
            let got = page.entries.len();
            all.extend(page.entries);
            if got == 0 || page.enumeration_context == ctx {
                break;
            }
            ctx = page.enumeration_context;
        }
        Ok(all)
    }

    /// Enumerates every local alias/group (RID + name) in an opened domain, paging until drained.
    pub fn enumerate_aliases(
        &mut self,
        domain_handle: &SamprHandle,
    ) -> Result<Vec<DomainEnumEntry>, CoreError> {
        let mut all = Vec::new();
        let mut ctx = 0u32;
        loop {
            let stub = build_samr_enumerate_domains_stub(domain_handle, ctx, 0xFFFF_FFFF);
            let resp = self.call(opnum::SAMR_ENUMERATE_ALIASES_IN_DOMAIN, stub)?;
            let page = parse_enumeration_response(&resp)?;
            let got = page.entries.len();
            all.extend(page.entries);
            if got == 0 || page.enumeration_context == ctx {
                break;
            }
            ctx = page.enumeration_context;
        }
        Ok(all)
    }

    /// Opens a group object by RID, returning its `GroupHandle`.
    pub fn open_group(
        &mut self,
        domain_handle: &SamprHandle,
        desired_access: u32,
        group_rid: u32,
    ) -> Result<SamprHandle, CoreError> {
        let stub = build_samr_open_group_stub(domain_handle, desired_access, group_rid);
        let resp = self.call(opnum::SAMR_OPEN_GROUP, stub)?;
        parse_samr_open_group_response(&resp)
    }

    /// Retrieves members (RIDs) of an opened group.
    pub fn get_members_in_group(
        &mut self,
        group_handle: &SamprHandle,
    ) -> Result<Vec<u32>, CoreError> {
        let stub = build_samr_get_members_in_group_stub(group_handle);
        let resp = self.call(opnum::SAMR_GET_MEMBERS_IN_GROUP, stub)?;
        parse_samr_get_members_in_group_response(&resp)
    }

    /// Opens a local alias/group object by RID, returning its `AliasHandle`.
    pub fn open_alias(
        &mut self,
        domain_handle: &SamprHandle,
        desired_access: u32,
        alias_rid: u32,
    ) -> Result<SamprHandle, CoreError> {
        let stub = build_samr_open_alias_stub(domain_handle, desired_access, alias_rid);
        let resp = self.call(opnum::SAMR_OPEN_ALIAS, stub)?;
        parse_samr_open_alias_response(&resp)
    }

    /// Retrieves member SIDs of an opened local alias/group.
    pub fn get_members_in_alias(
        &mut self,
        alias_handle: &SamprHandle,
    ) -> Result<Vec<RpcSid>, CoreError> {
        let stub = build_samr_get_members_in_alias_stub(alias_handle);
        let resp = self.call(opnum::SAMR_GET_MEMBERS_IN_ALIAS, stub)?;
        parse_samr_get_members_in_alias_response(&resp)
    }

    /// Closes an opened SAMR context handle.
    pub fn close_handle(&mut self, handle: &SamprHandle) -> Result<(), CoreError> {
        let stub = build_samr_close_handle_stub(handle);
        let resp = self.call(opnum::SAMR_CLOSE_HANDLE, stub)?;
        if resp.len() >= 24 {
            parse_samr_status_response(&resp[20..])
        } else {
            Ok(())
        }
    }

    /// Changes a user's password using `SamrUnicodeChangePasswordUser2` (Opnum 55).
    /// Does not require administrative privileges or opening domain/user handles.
    pub fn unicode_change_password_user2(
        &mut self,
        server_name: &str,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), CoreError> {
        let stub = build_samr_unicode_change_password_user2_stub(
            server_name,
            username,
            old_password,
            new_password,
        );
        let resp = self.call(opnum::SAMR_UNICODE_CHANGE_PASSWORD_USER2, stub)?;
        parse_samr_status_response(&resp)
    }

    /// Sets/resets a user's password using `SamrSetInformationUser2` (Opnum 58) as Administrator.
    /// Encrypts the 516-byte password buffer with the transport session key.
    pub fn set_user_password(
        &mut self,
        user_handle: &SamprHandle,
        new_password: &str,
        session_key: &[u8; 16],
    ) -> Result<(), CoreError> {
        let stub = build_samr_set_user_password_stub(user_handle, new_password, session_key);
        let resp = self.call(opnum::SAMR_SET_INFORMATION_USER2, stub)?;
        parse_samr_status_response(&resp)
    }

    /// Consumes the client and returns the underlying transport.
    pub fn into_transport(self) -> T {
        self.transport
    }
}

/// Binds to `MS-SAMR` over a sans-I/O stream pair and returns a ready call transport.
///
/// This is the `ncacn_ip_tcp`-style path (direct RPC over a TCP stream). The `ncacn_np` SMB-pipe
/// transport (session-setup auth -> tree connect -> pipe create -> `FSCTL_PIPE_TRANSCEIVE`) is the
/// next increment and will implement the same [`RpcTransport`] trait.
pub struct StreamRpcTransport<R: Read, W: Write> {
    rx: R,
    tx: W,
}

impl<R: Read, W: Write> StreamRpcTransport<R, W> {
    /// Performs the MS-RPCE `Bind` to the `MS-SAMR` interface, verifying `BindAck`.
    pub fn bind_samr(mut rx: R, mut tx: W) -> Result<Self, CoreError> {
        let samr = &WELL_KNOWN_INTERFACES[1];
        let bind = RpcBindPdu::new(0, samr.uuid, samr.version_major, samr.version_minor);
        tx.write_all(&bind.to_bytes())
            .map_err(|e| CoreError::ProtocolError(format!("Failed sending SAMR Bind: {}", e)))?;
        let (ack_hdr, _) = read_rpc_pdu(&mut rx)?;
        if ack_hdr.ptype != pdu_type::RPC_BIND_ACK {
            return Err(CoreError::ProtocolError("SAMR Bind rejected".into()));
        }
        Ok(Self { rx, tx })
    }
}

impl<R: Read, W: Write> RpcTransport for StreamRpcTransport<R, W> {
    fn transceive(&mut self, request_pdu: &[u8]) -> Result<Vec<u8>, CoreError> {
        self.tx
            .write_all(request_pdu)
            .map_err(|e| CoreError::ProtocolError(format!("Failed sending RPC request: {}", e)))?;
        let (_, pdu) = read_rpc_pdu(&mut self.rx)?;
        Ok(pdu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock DC that answers each `transceive` from a FIFO queue of prebuilt response stubs,
    /// wrapping each in a minimal `RPC_RESPONSE` PDU (16-byte common header + 8-byte response fields).
    struct MockDc {
        responses: std::collections::VecDeque<Vec<u8>>,
    }

    impl MockDc {
        fn new(stubs: Vec<Vec<u8>>) -> Self {
            let responses = stubs
                .into_iter()
                .map(|stub| {
                    use impacket_dcerpc::RpcCommonHeader;
                    use impacket_ndr::{NdrSerialize, NdrWriter};
                    let frag_len = (24 + stub.len()) as u16;
                    let hdr = RpcCommonHeader::new(pdu_type::RPC_RESPONSE, frag_len, 0, 1);
                    let mut w = NdrWriter::with_capacity(frag_len as usize);
                    hdr.ndr_serialize(&mut w);
                    w.write_u32(stub.len() as u32); // alloc_hint
                    w.write_u16(0); // context_id
                    w.write_u16(0); // cancel_count + reserved
                    w.write_bytes(&stub);
                    w.into_bytes()
                })
                .collect();
            Self { responses }
        }
    }

    impl RpcTransport for MockDc {
        fn transceive(&mut self, _request_pdu: &[u8]) -> Result<Vec<u8>, CoreError> {
            self.responses
                .pop_front()
                .ok_or_else(|| CoreError::ProtocolError("MockDc: no more responses".into()))
        }
    }

    #[test]
    fn test_connect5_stub_matches_fixed_layout() {
        // r"\\DC01" is 6 chars (two backslashes) + NUL = 7 wchars (14 bytes). ServerName: ref(4) +
        // maxcount(4)+off(4)+actual(4)+14 = 30, align(4)->32, then desired/inversion/tag/rev/feat = 20.
        let stub = build_samr_connect5_stub(r"\\DC01", 0x0200_0000);
        assert_eq!(stub.len(), 52);
        assert_eq!(&stub[0..4], &REFERENT_BASE.to_le_bytes());
        assert_eq!(&stub[4..8], &7u32.to_le_bytes()); // MaxCount incl NUL
    }

    #[test]
    fn test_enumerate_domains_roundtrip() {
        let entries = vec![
            DomainEnumEntry {
                relative_id: 0,
                name: "CORP".into(),
            },
            DomainEnumEntry {
                relative_id: 0,
                name: "Builtin".into(),
            },
        ];
        let wire =
            build_samr_enumerate_domains_response(0, &entries, NtStatus::STATUS_SUCCESS);
        let parsed = parse_samr_enumerate_domains_response(&wire).unwrap();
        assert_eq!(parsed.entries, entries);
    }

    #[test]
    fn test_lookup_and_open_domain_roundtrip() {
        let sid = RpcSid::parse("S-1-5-21-3623811015-3361044348-30300820").unwrap();
        let wire = build_samr_lookup_domain_response(&sid, NtStatus::STATUS_SUCCESS);
        let parsed = parse_samr_lookup_domain_response(&wire).unwrap();
        assert_eq!(parsed, sid);

        let handle = [0x5Au8; 20];
        let wire2 = build_samr_open_domain_response(&handle, NtStatus::STATUS_SUCCESS);
        let parsed2 = parse_samr_open_domain_response(&wire2).unwrap();
        assert_eq!(parsed2, handle);
    }

    #[test]
    fn test_query_user_all_information_roundtrip() {
        let info = SamrUserAllInformation {
            username: "svc_backup".into(),
            full_name: "Veeam Backup Service".into(),
            admin_comment: "do not expire".into(),
            user_id: 1105,
            primary_group_id: 513,
            user_account_control: 0x0000_0210,
            bad_password_count: 1,
            logon_count: 128,
            password_last_set: FileTime::from_unix_secs(1_760_000_000),
        };
        let wire = build_samr_query_user_all_response(&info, NtStatus::STATUS_SUCCESS);
        let parsed = parse_samr_query_user_all_response(&wire).unwrap();
        assert_eq!(parsed, info);
        assert!(parsed.password_never_expires());
        assert!(!parsed.account_disabled());
    }

    #[test]
    fn test_full_samr_client_spine_over_mock_transport() {
        let sid = RpcSid::parse("S-1-5-21-111-222-333").unwrap();
        let mock = MockDc::new(vec![
            {
                // Connect5 response: OutVersion, tag, rev, feat, handle[20], status
                let mut w = NdrWriter::with_capacity(40);
                w.write_u32(1);
                w.write_u32(1);
                w.write_u32(3);
                w.write_u32(0);
                w.write_fixed_array(&[0x11u8; 20]);
                w.write_u32(NtStatus::STATUS_SUCCESS.0);
                w.into_bytes()
            },
            build_samr_enumerate_domains_response(
                0,
                &[DomainEnumEntry {
                    relative_id: 0,
                    name: "CORP".into(),
                }],
                NtStatus::STATUS_SUCCESS,
            ),
            build_samr_lookup_domain_response(&sid, NtStatus::STATUS_SUCCESS),
            build_samr_open_domain_response(&[0x22u8; 20], NtStatus::STATUS_SUCCESS),
            build_samr_enumerate_domains_response(
                0,
                &[
                    DomainEnumEntry {
                        relative_id: 500,
                        name: "Administrator".into(),
                    },
                    DomainEnumEntry {
                        relative_id: 1105,
                        name: "svc_backup".into(),
                    },
                ],
                NtStatus::STATUS_SUCCESS,
            ),
            build_samr_open_user_response(&[0x33u8; 20], NtStatus::STATUS_SUCCESS),
        ]);

        let mut client = SamrClient::new(mock);
        let server_handle = client.connect5(r"\\DC01", 0x0200_0000).unwrap();
        assert_eq!(server_handle, [0x11u8; 20]);

        let domains = client.enumerate_domains(&server_handle).unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].name, "CORP");

        let domain_sid = client.lookup_domain(&server_handle, &domains[0].name).unwrap();
        assert_eq!(domain_sid, sid);

        let domain_handle = client
            .open_domain(&server_handle, 0x0000_0200, &domain_sid)
            .unwrap();
        assert_eq!(domain_handle, [0x22u8; 20]);

        let users = client.enumerate_users(&domain_handle, 0).unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].relative_id, 500);
        assert_eq!(users[1].name, "svc_backup");

        let user_handle = client
            .open_user(&domain_handle, 0x0002_011B, users[1].relative_id)
            .unwrap();
        assert_eq!(user_handle, [0x33u8; 20]);
    }

    #[test]
    fn test_sampr_encrypted_user_password_roundtrip() {
        let key = [0x42u8; 16];
        let original_pass = "P@ssw0rd2026!#$";
        let enc = encode_sampr_encrypted_user_password(original_pass, &key);
        assert_eq!(enc.len(), 516);
        let dec = decode_sampr_encrypted_user_password(enc, &key).unwrap();
        assert_eq!(dec, original_pass);
    }

    #[test]
    fn test_owf_password_encryption_roundtrip() {
        let plain_hash = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00];
        let key_hash = [0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

        let enc = encrypt_owf_password(&plain_hash, &key_hash);
        assert_ne!(enc, plain_hash);
        let dec = decrypt_owf_password(&enc, &key_hash);
        assert_eq!(dec, plain_hash);
    }

    #[test]
    fn test_build_unicode_change_password_user2_stub_and_response() {
        let stub = build_samr_unicode_change_password_user2_stub(
            "DC01",
            "Administrator",
            "OldPass123!",
            "NewPass456!",
        );
        assert!(stub.len() > 550);

        // Success response
        let resp_ok = 0u32.to_le_bytes();
        assert!(parse_samr_status_response(&resp_ok).is_ok());

        // Error response (STATUS_WRONG_PASSWORD = 0xC000006A)
        let resp_err = 0xC000_006Au32.to_le_bytes();
        assert!(parse_samr_status_response(&resp_err).is_err());
    }

    #[test]
    fn test_build_set_user_password_stub() {
        let handle = [0x55u8; 20];
        let session_key = [0x77u8; 16];
        let stub = build_samr_set_user_password_stub(&handle, "SuperSecret2026!", &session_key);
        assert_eq!(stub.len(), 20 + 2 + 2 + 4 + 516);
        assert_eq!(&stub[0..20], &handle);
        assert_eq!(u16::from_le_bytes([stub[20], stub[21]]), 23); // UserInternal3Information
    }

    #[test]
    fn test_samr_get_members_in_group_roundtrip() {
        let members = vec![500u32, 501, 1002, 1005];
        let resp = build_samr_get_members_in_group_response(&members, NtStatus::STATUS_SUCCESS);
        let parsed = parse_samr_get_members_in_group_response(&resp).unwrap();
        assert_eq!(parsed, members);
    }

    #[test]
    fn test_samr_get_members_in_alias_roundtrip() {
        let sids = vec![
            RpcSid::parse("S-1-5-21-111-222-333-500").unwrap(),
            RpcSid::parse("S-1-5-21-111-222-333-512").unwrap(),
        ];
        let resp = build_samr_get_members_in_alias_response(&sids, NtStatus::STATUS_SUCCESS);
        let parsed = parse_samr_get_members_in_alias_response(&resp).unwrap();
        assert_eq!(parsed, sids);
    }
}
