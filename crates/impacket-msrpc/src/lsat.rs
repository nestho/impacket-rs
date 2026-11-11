//! `lsat`: `[MS-LSAT]` / `[MS-LSAD]` Local Security Authority (Translation) client
//! (`impacket/dcerpc/v5/lsat.py` & `lsad.py`).
//!
//! Implements the `lookupsid` call spine over `\PIPE\lsarpc`: `LsarOpenPolicy2` (opnum 44, with the
//! legacy `LsarOpenPolicy` opnum 6 fallback for Windows 2000) -> `LsarLookupSids` (opnum 15) ->
//! `LsarClose` (opnum 0). Structures follow `[MS-LSAT] 2.2` and NDR20 pointer/deferral rules:
//! `LSAPR_SID_ENUM_BUFFER`, `LSAPR_REFERENCED_DOMAIN_LIST`, `LSAPR_TRANSLATED_NAMES`.
//!
//! NOTE: the `LsarLookupSids` response layout is modeled to `[MS-LSAT]` + the standard NDR20 top-level
//! pointer/deferral discipline and is byte-for-byte round-trip tested here; it has not yet been diffed
//! against a live-DC packet capture. The request side is fully deterministic.

use crate::dtypes::{
    read_counted_wchar_pointee, read_rpc_unicode_string_header, write_counted_wchar_pointee,
    write_rpc_unicode_string_header, write_string_wchar_pointee, REFERENT_BASE,
};
use impacket_core::{AdCompatProfile, CoreError, NtStatus};
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport};
use impacket_ndr::{NdrReader, NdrWriter, RpcSid};

pub mod opnum {
    pub const LSAR_CLOSE: u16 = 0;
    /// `LsarOpenPolicy` (Windows NT4 / 2000).
    pub const LSAR_OPEN_POLICY_LEGACY: u16 = 6;
    /// `LsarLookupSids` (SID -> name translation).
    pub const LSAR_LOOKUP_SIDS: u16 = 15;
    /// `LsarEnumerateAccountRights` (query user rights / privileges).
    pub const LSAR_ENUMERATE_ACCOUNT_RIGHTS: u16 = 36;
    /// `LsarOpenPolicy2` (Windows XP / 2003 -> 2025).
    pub const LSAR_OPEN_POLICY2: u16 = 44;
}

/// A 20-byte LSA policy handle (`LSAPR_HANDLE`).
pub type LsaHandle = [u8; 20];

/// `SID_NAME_USE` (`[MS-SAMR] 2.2.6.1`), returned by `LsarLookupSids`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum SidNameUse {
    User = 1,
    Group = 2,
    Domain = 3,
    Alias = 4,
    WellKnownGroup = 5,
    DeletedAccount = 6,
    Invalid = 7,
    Unknown = 8,
    Computer = 9,
    Label = 10,
}

impl SidNameUse {
    pub const fn from_u16(v: u16) -> Self {
        match v {
            1 => Self::User,
            2 => Self::Group,
            3 => Self::Domain,
            4 => Self::Alias,
            5 => Self::WellKnownGroup,
            6 => Self::DeletedAccount,
            7 => Self::Invalid,
            9 => Self::Computer,
            10 => Self::Label,
            _ => Self::Unknown,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::User => "SidTypeUser",
            Self::Group => "SidTypeGroup",
            Self::Domain => "SidTypeDomain",
            Self::Alias => "SidTypeAlias",
            Self::WellKnownGroup => "SidTypeWellKnownGroup",
            Self::DeletedAccount => "SidTypeDeletedAccount",
            Self::Invalid => "SidTypeInvalid",
            Self::Unknown => "SidTypeUnknown",
            Self::Computer => "SidTypeComputer",
            Self::Label => "SidTypeLabel",
        }
    }
}

/// One resolved SID: `DOMAIN\name` plus its `SID_NAME_USE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranslatedName {
    pub sid_type: SidNameUse,
    pub domain: String,
    pub name: String,
}

// ----------------------------------------------------------------------------
// LsarOpenPolicy2 (opnum 44) / LsarOpenPolicy (opnum 6).
// ----------------------------------------------------------------------------

/// Builds the request stub for `LsarOpenPolicy2` / `LsarOpenPolicy` (`[MS-LSAD] 3.1.4.4.1/3.1.4.4.2`).
///
/// Layout: `SystemName` (`unique [string] wchar_t*`), `ObjectAttributes` (`LSAPR_OBJECT_ATTRIBUTES`:
/// `Length=24`, five NULL/zero fields), `DesiredAccess: u32`.
pub fn build_lsar_open_policy_stub(system_name: &str, desired_access: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    // SystemName: unique pointer + deferred NUL-terminated wchar string.
    w.write_u32(REFERENT_BASE);
    write_string_wchar_pointee(&mut w, system_name);
    w.align(4);

    // LSAPR_OBJECT_ATTRIBUTES (all pointers NULL, Attributes 0).
    w.write_u32(24); // Length
    w.write_u32(0); // RootDirectory
    w.write_u32(0); // ObjectName
    w.write_u32(0); // Attributes
    w.write_u32(0); // SecurityDescriptor
    w.write_u32(0); // SecurityQualityOfService

    w.write_u32(desired_access);
    w.into_bytes()
}

/// Selects `LsarOpenPolicy2` (opnum 44) on modern Windows, `LsarOpenPolicy` (opnum 6) on legacy.
pub fn open_policy_opnum(profile: AdCompatProfile) -> u16 {
    if profile == AdCompatProfile::LegacyWin2000 {
        opnum::LSAR_OPEN_POLICY_LEGACY
    } else {
        opnum::LSAR_OPEN_POLICY2
    }
}

/// Builds a wire-accurate `LsarOpenPolicy2` response stub (test fixture): `PolicyHandle` + `NTSTATUS`.
pub fn build_lsar_open_policy_response(handle: &LsaHandle, status: NtStatus) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(24);
    w.write_fixed_array(handle);
    w.write_u32(status.0);
    w.into_bytes()
}

/// Parses an `LsarOpenPolicy2` response stub, returning the `PolicyHandle`.
pub fn parse_lsar_open_policy_response(stub: &[u8]) -> Result<LsaHandle, CoreError> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_fixed_array::<20>()?;
    let status = NtStatus(r.read_u32()?);
    if !status.is_success() {
        return Err(CoreError::NtStatus(status));
    }
    Ok(handle)
}

// ----------------------------------------------------------------------------
// LsarLookupSids (opnum 15).
// ----------------------------------------------------------------------------

/// Builds the request stub for `LsarLookupSids` (`[MS-LSAT] 3.1.4.11`).
///
/// Layout: `PolicyHandle: [u8; 20]`, `SidEnumBuffer: LSAPR_SID_ENUM_BUFFER { Entries,
/// SidInfo -> LSAPR_SID_INFORMATION[] { Sid -> RPC_SID } }`, `TranslatedNames` (empty, Entries=0,
/// Names=NULL), `LookupLevel: u16 = LsapLookupWksta(1)`, `MappedCount: u32 = 0`.
pub fn build_lsar_lookup_sids_stub(policy_handle: &LsaHandle, sids: &[RpcSid]) -> Vec<u8> {
    use impacket_ndr::NdrSerialize;
    let mut w = NdrWriter::with_capacity(64 + sids.len() * 40);
    w.write_fixed_array(policy_handle);

    let count = sids.len() as u32;
    // LSAPR_SID_ENUM_BUFFER
    w.write_u32(count); // Entries
    w.write_u32(REFERENT_BASE); // SidInfo array referent
    w.write_u32(count); // conformant MaxCount
    // Inline LSAPR_SID_INFORMATION[]: each is a single Sid pointer.
    for i in 0..sids.len() {
        w.write_u32(REFERENT_BASE + 4 + i as u32); // Sid referent
    }
    // Deferred RPC_SID pointees, in element order.
    for sid in sids {
        sid.ndr_serialize(&mut w);
        w.align(4);
    }

    // TranslatedNames (empty on input): Entries=0, Names=NULL.
    w.write_u32(0);
    w.write_u32(0);
    // LookupLevel = LsapLookupWksta (1), then MappedCount = 0.
    w.write_u16(1);
    w.align(4);
    w.write_u32(0);
    w.into_bytes()
}

/// Builds a wire-accurate `LsarLookupSids` response stub (test fixture / mock LSA server).
///
/// `translations[i] = (sid_name_use, domain_index, name)`; `domains[domain_index]` supplies the
/// NetBIOS domain. Models `LSAPR_REFERENCED_DOMAIN_LIST` + `LSAPR_TRANSLATED_NAMES` with standard
/// NDR20 deferral (array pointees deferred after inline elements, in element/field order).
pub fn build_lsar_lookup_sids_response(
    domains: &[(String, RpcSid)],
    translations: &[(SidNameUse, i32, String)],
    status: NtStatus,
) -> Vec<u8> {
    use impacket_ndr::NdrSerialize;
    let mut w = NdrWriter::with_capacity(256);

    // ReferencedDomains: unique pointer to LSAPR_REFERENCED_DOMAIN_LIST.
    w.write_u32(REFERENT_BASE);
    w.write_u32(domains.len() as u32); // Entries
    w.write_u32(REFERENT_BASE + 4); // Domains array referent
    w.write_u32(domains.len() as u32); // MaxEntries
    w.write_u32(domains.len() as u32); // conformant MaxCount for the array
    // Inline LSAPR_TRUST_INFORMATION[]: Name header + Sid pointer.
    for (i, (name, _sid)) in domains.iter().enumerate() {
        write_rpc_unicode_string_header(&mut w, name, REFERENT_BASE + 8 + (i as u32) * 2);
        w.write_u32(REFERENT_BASE + 9 + (i as u32) * 2); // Sid referent
    }
    // Deferred per trust-info: Name buffer, then Sid RPC_SID.
    for (name, sid) in domains {
        write_counted_wchar_pointee(&mut w, name);
        sid.ndr_serialize(&mut w);
        w.align(4);
    }

    // TranslatedNames (ref struct, inline): Entries + Names pointer.
    w.write_u32(translations.len() as u32);
    w.write_u32(REFERENT_BASE + 1000); // Names array referent
    w.write_u32(translations.len() as u32); // conformant MaxCount
    // Inline LSAPR_TRANSLATED_NAME[]: Use(u16), Name header, DomainIndex(i32).
    for (i, (use_, dom_idx, name)) in translations.iter().enumerate() {
        w.write_u16(*use_ as u16);
        write_rpc_unicode_string_header(&mut w, name, REFERENT_BASE + 2000 + i as u32);
        w.write_u32(*dom_idx as u32); // DomainIndex (long)
    }
    // Deferred per translated name: Name buffer.
    for (_use_, _dom_idx, name) in translations {
        write_counted_wchar_pointee(&mut w, name);
    }

    // MappedCount, return NTSTATUS.
    w.write_u32(translations.len() as u32);
    w.write_u32(status.0);
    w.into_bytes()
}

/// Parses an `LsarLookupSids` response stub into resolved `DOMAIN\name` entries.
pub fn parse_lsar_lookup_sids_response(stub: &[u8]) -> Result<Vec<TranslatedName>, CoreError> {
    use impacket_ndr::NdrDeserialize;
    let mut r = NdrReader::new(stub);

    // ReferencedDomains (unique pointer).
    let mut domain_names: Vec<String> = Vec::new();
    let ref_domains = r.read_u32()?;
    if ref_domains != 0 {
        let entries = r.read_u32()? as usize;
        let domains_ref = r.read_u32()?;
        let _max_entries = r.read_u32()?;
        if domains_ref != 0 {
            let max_count = r.read_u32()? as usize;
            if max_count < entries || entries > 4096 {
                return Err(CoreError::ProtocolError(
                    "LSAPR_REFERENCED_DOMAIN_LIST count invalid".into(),
                ));
            }
            // Inline trust-info headers.
            let mut has_sid = Vec::with_capacity(entries);
            let mut name_present = Vec::with_capacity(entries);
            for _ in 0..entries {
                let (len, buf_ref) = read_rpc_unicode_string_header(&mut r)?;
                let sid_ref = r.read_u32()?;
                name_present.push(len > 0 && buf_ref != 0);
                has_sid.push(sid_ref != 0);
            }
            // Deferred: Name buffer then Sid, per element.
            for i in 0..entries {
                let name = if name_present[i] {
                    read_counted_wchar_pointee(&mut r)?
                } else {
                    String::new()
                };
                if has_sid[i] {
                    let _sid = RpcSid::ndr_deserialize(&mut r)?;
                    r.align(4)?;
                }
                domain_names.push(name);
            }
        }
    }

    // TranslatedNames (ref struct, inline).
    let entries = r.read_u32()? as usize;
    let names_ref = r.read_u32()?;
    let mut out = Vec::new();
    if names_ref != 0 {
        let max_count = r.read_u32()? as usize;
        if max_count < entries || entries > 65_536 {
            return Err(CoreError::ProtocolError(
                "LSAPR_TRANSLATED_NAMES count invalid".into(),
            ));
        }
        let mut inline = Vec::with_capacity(entries);
        for _ in 0..entries {
            let use_ = r.read_u16()?;
            let (len, buf_ref) = read_rpc_unicode_string_header(&mut r)?;
            let dom_idx = r.read_u32()? as i32;
            inline.push((use_, len > 0 && buf_ref != 0, dom_idx));
        }
        for (use_, name_present, dom_idx) in inline {
            let name = if name_present {
                read_counted_wchar_pointee(&mut r)?
            } else {
                String::new()
            };
            let domain = domain_names
                .get(dom_idx as usize)
                .cloned()
                .unwrap_or_default();
            out.push(TranslatedName {
                sid_type: SidNameUse::from_u16(use_),
                domain,
                name,
            });
        }
    }

    let _mapped_count = r.read_u32()?;
    let status = NtStatus(r.read_u32()?);
    if !status.is_success()
        && status != NtStatus::STATUS_SOME_NOT_MAPPED
        && status != NtStatus::STATUS_NONE_MAPPED
    {
        return Err(CoreError::NtStatus(status));
    }
    Ok(out)
}

// ----------------------------------------------------------------------------
// LsarEnumerateAccountRights (opnum 36).
// ----------------------------------------------------------------------------

/// Builds `LsarEnumerateAccountRights` (36) request stub (`[MS-LSAD] 3.1.4.5.12`).
pub fn build_lsar_enumerate_account_rights_stub(
    policy_handle: &LsaHandle,
    sid: &RpcSid,
) -> Vec<u8> {
    use impacket_ndr::NdrSerialize;
    let mut w = NdrWriter::with_capacity(64);
    w.write_bytes(policy_handle);
    w.write_u32(REFERENT_BASE); // AccountSid pointer referent
    sid.ndr_serialize(&mut w);
    w.into_bytes()
}

/// Parses `LsarEnumerateAccountRights` response into privilege / right names (`Se*Privilege`, etc.).
pub fn parse_lsar_enumerate_account_rights_response(stub: &[u8]) -> Result<Vec<String>, CoreError> {
    let mut r = NdrReader::new(stub);
    let container_ref = r.read_u32()?;
    let mut rights = Vec::new();

    if container_ref != 0 {
        let entries_read = r.read_u32()? as usize;
        let array_ref = r.read_u32()?;
        if array_ref != 0 && entries_read > 0 {
            if entries_read > 65_536 {
                return Err(CoreError::ProtocolError(
                    "LsarEnumerateAccountRights: invalid count".into(),
                ));
            }
            let max_count = r.read_u32()? as usize;
            if max_count < entries_read {
                return Err(CoreError::ProtocolError(
                    "LsarEnumerateAccountRights: MaxCount < entries".into(),
                ));
            }

            // Headers for each RPC_UNICODE_STRING
            let mut headers = Vec::with_capacity(entries_read);
            for _ in 0..entries_read {
                let (len, buf_ref) = read_rpc_unicode_string_header(&mut r)?;
                headers.push((len, buf_ref));
            }

            // Deferred counted wchar strings
            for (_len, buf_ref) in headers {
                if buf_ref != 0 {
                    rights.push(read_counted_wchar_pointee(&mut r)?);
                } else {
                    rights.push(String::new());
                }
            }
        }
    }

    let status = NtStatus(r.read_u32()?);
    // STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034) means account has no explicit rights assigned
    if status.0 == 0xC000_0034 {
        return Ok(Vec::new());
    }
    if !status.is_success() {
        return Err(CoreError::NtStatus(status));
    }
    Ok(rights)
}

/// Builds a wire-accurate `LsarEnumerateAccountRights` response stub (test fixture).
pub fn build_lsar_enumerate_account_rights_response(
    rights: &[String],
    status: NtStatus,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(256);
    if rights.is_empty() {
        w.write_u32(REFERENT_BASE); // container_ref
        w.write_u32(0); // EntriesRead = 0
        w.write_u32(0); // array_ref = NULL
    } else {
        w.write_u32(REFERENT_BASE); // container_ref
        let count = rights.len() as u32;
        w.write_u32(count);
        w.write_u32(REFERENT_BASE + 4); // array_ref
        w.write_u32(count); // max_count

        for (i, right) in rights.iter().enumerate() {
            write_rpc_unicode_string_header(&mut w, right, REFERENT_BASE + 8 + (i as u32));
        }

        for right in rights {
            write_counted_wchar_pointee(&mut w, right);
        }
    }
    w.write_u32(status.0);
    w.into_bytes()
}

// ----------------------------------------------------------------------------
// Client.
// ----------------------------------------------------------------------------

/// `[MS-LSAT]` high-level client over a bound [`RpcTransport`] (`\PIPE\lsarpc`).
pub struct LsatClient<T: RpcTransport> {
    transport: T,
    profile: AdCompatProfile,
    call_id: u32,
}

impl<T: RpcTransport> LsatClient<T> {
    pub fn new(transport: T, profile: AdCompatProfile) -> Self {
        Self {
            transport,
            profile,
            call_id: 1,
        }
    }

    fn call(&mut self, opnum: u16, stub: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let call_id = self.call_id;
        self.call_id += 1;
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

    /// `LsarOpenPolicy2` (or legacy `LsarOpenPolicy`), returning a policy handle.
    pub fn open_policy(&mut self, system_name: &str, desired_access: u32) -> Result<LsaHandle, CoreError> {
        let opnum = open_policy_opnum(self.profile);
        let stub = build_lsar_open_policy_stub(system_name, desired_access);
        let resp = self.call(opnum, stub)?;
        parse_lsar_open_policy_response(&resp)
    }

    /// `LsarLookupSids` — resolve a batch of SIDs to `DOMAIN\name` entries.
    pub fn lookup_sids(
        &mut self,
        policy_handle: &LsaHandle,
        sids: &[RpcSid],
    ) -> Result<Vec<TranslatedName>, CoreError> {
        let stub = build_lsar_lookup_sids_stub(policy_handle, sids);
        let resp = self.call(opnum::LSAR_LOOKUP_SIDS, stub)?;
        parse_lsar_lookup_sids_response(&resp)
    }

    /// `LsarEnumerateAccountRights` — enumerate privilege / right strings assigned to a SID.
    pub fn enumerate_account_rights(
        &mut self,
        policy_handle: &LsaHandle,
        sid: &RpcSid,
    ) -> Result<Vec<String>, CoreError> {
        let stub = build_lsar_enumerate_account_rights_stub(policy_handle, sid);
        let resp = self.call(opnum::LSAR_ENUMERATE_ACCOUNT_RIGHTS, stub)?;
        parse_lsar_enumerate_account_rights_response(&resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use impacket_dcerpc::{pdu_type, RpcCommonHeader};
    use impacket_ndr::NdrSerialize;
    use std::collections::VecDeque;

    struct MockLsa {
        responses: VecDeque<Vec<u8>>,
    }

    impl MockLsa {
        fn new(stubs: Vec<Vec<u8>>) -> Self {
            let responses = stubs
                .into_iter()
                .map(|stub| {
                    let frag_len = (24 + stub.len()) as u16;
                    let hdr = RpcCommonHeader::new(pdu_type::RPC_RESPONSE, frag_len, 0, 1);
                    let mut w = NdrWriter::with_capacity(frag_len as usize);
                    hdr.ndr_serialize(&mut w);
                    w.write_u32(stub.len() as u32);
                    w.write_u16(0);
                    w.write_u16(0);
                    w.write_bytes(&stub);
                    w.into_bytes()
                })
                .collect();
            Self { responses }
        }
    }

    impl RpcTransport for MockLsa {
        fn transceive(&mut self, _req: &[u8]) -> Result<Vec<u8>, CoreError> {
            self.responses
                .pop_front()
                .ok_or_else(|| CoreError::ProtocolError("MockLsa: no more responses".into()))
        }
    }

    #[test]
    fn test_lookup_sids_roundtrip() {
        let dom_sid = RpcSid::parse("S-1-5-21-111-222-333").unwrap();
        let domains = vec![("CORP".to_string(), dom_sid)];
        let translations = vec![
            (SidNameUse::User, 0, "Administrator".to_string()),
            (SidNameUse::Group, 0, "Domain Admins".to_string()),
            (SidNameUse::Computer, 0, "DC01$".to_string()),
        ];
        let wire = build_lsar_lookup_sids_response(
            &domains,
            &translations,
            NtStatus::STATUS_SOME_NOT_MAPPED,
        );
        let parsed = parse_lsar_lookup_sids_response(&wire).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].domain, "CORP");
        assert_eq!(parsed[0].name, "Administrator");
        assert_eq!(parsed[0].sid_type, SidNameUse::User);
        assert_eq!(parsed[2].name, "DC01$");
        assert_eq!(parsed[2].sid_type, SidNameUse::Computer);
    }

    #[test]
    fn test_lsat_client_open_and_lookup() {
        let dom_sid = RpcSid::parse("S-1-5-21-111-222-333").unwrap();
        let mock = MockLsa::new(vec![
            build_lsar_open_policy_response(&[0xA1u8; 20], NtStatus::STATUS_SUCCESS),
            build_lsar_lookup_sids_response(
                &[("CORP".to_string(), dom_sid.clone())],
                &[(SidNameUse::User, 0, "krbtgt".to_string())],
                NtStatus::STATUS_SUCCESS,
            ),
        ]);
        let mut client = LsatClient::new(mock, AdCompatProfile::UniversalAuto);
        let handle = client.open_policy(r"\\DC01", 0x0200_0800).unwrap();
        assert_eq!(handle, [0xA1u8; 20]);

        let mut sid = dom_sid;
        sid.sub_authorities.push(502);
        let names = client.lookup_sids(&handle, &[sid]).unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].name, "krbtgt");
        assert_eq!(names[0].domain, "CORP");
    }

    #[test]
    fn test_lsar_enumerate_account_rights_roundtrip() {
        let rights = vec![
            "SeSecurityPrivilege".to_string(),
            "SeBackupPrivilege".to_string(),
            "SeRestorePrivilege".to_string(),
        ];
        let wire = build_lsar_enumerate_account_rights_response(&rights, NtStatus::STATUS_SUCCESS);
        let parsed = parse_lsar_enumerate_account_rights_response(&wire).unwrap();
        assert_eq!(parsed, rights);
    }

    #[test]
    fn test_lsar_enumerate_account_rights_empty_or_not_found() {
        let not_found_wire = build_lsar_enumerate_account_rights_response(&[], NtStatus(0xC000_0034));
        let parsed = parse_lsar_enumerate_account_rights_response(&not_found_wire).unwrap();
        assert!(parsed.is_empty());

        let empty_success_wire = build_lsar_enumerate_account_rights_response(&[], NtStatus::STATUS_SUCCESS);
        let parsed_empty = parse_lsar_enumerate_account_rights_response(&empty_success_wire).unwrap();
        assert!(parsed_empty.is_empty());
    }
}
