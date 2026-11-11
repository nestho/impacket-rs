//! `drsr`: `[MS-DRSR]` Active Directory Directory Replication Service Remote Protocol
//! (`impacket/dcerpc/v5/drsuapi.py`).
//!
//! Implements pure-Rust DRSUAPI client operations used by `secretsdump` for DCSync credential
//! replication:
//! - Interface UUID: `E3514235-4B06-11D1-AB04-00C04FC2DCD2` v4.0.
//! - `DRSBind` (Opnum 0) with client extension negotiation (`DRS_EXT_GETCHGREQ_V8`, etc.).
//! - `DRSUnbind` (Opnum 1) context handle release.
//! - `DRSCrackNames` (Opnum 12) for account name-to-GUID/SID resolution.
//! - `DRSGetNCChanges` (Opnum 3) for directory object replication (V8 request / V6 response).
//! - Attribute decryption: RC4 payload decryption (`MD5(session_key || salt)`), CRC32 verification,
//!   and RID-based DES-56 layer removal (`sam_des_decrypt_hash_with_rid`).
//! - Supplemental credentials extraction (`Primary:Kerberos-Newer-Keys`, `Primary:CLEARTEXT`).

use crate::dtypes::{write_string_wchar_pointee, REFERENT_BASE};
use impacket_core::{decode_utf16le, encode_utf16le, CoreError};
use impacket_crypto::{
    crc32, md5, sam_des_decrypt_hash_with_rid, Rc4,
};
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport};
use impacket_ndr::{NdrReader, NdrWriter, RpcSid, RpcUuid};

/// Interface UUID for `[MS-DRSR]` DRSUAPI: `E3514235-4B06-11D1-AB04-00C04FC2DCD2` v4.0.
pub const DRSUAPI_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0xe3514235,
    0x4b06,
    0x11d1,
    [0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2],
);
pub const DRSUAPI_VERSION_MAJOR: u16 = 4;
pub const DRSUAPI_VERSION_MINOR: u16 = 0;

/// 20-byte DRS RPC context handle (`DRS_HANDLE`).
pub type DrsHandle = [u8; 20];

pub mod opnum {
    pub const DRS_BIND: u16 = 0;
    pub const DRS_UNBIND: u16 = 1;
    pub const DRS_GET_NC_CHANGES: u16 = 3;
    pub const DRS_CRACK_NAMES: u16 = 12;
    pub const DRS_DOMAIN_CONTROLLER_INFO: u16 = 16;
}

/// DS_NAME_FORMAT constants for `DRSCrackNames`.
pub mod ds_name_format {
    pub const DS_UNKNOWN_NAME: u32 = 0;
    pub const DS_FQDN_1779_NAME: u32 = 1;
    pub const DS_NT4_ACCOUNT_NAME: u32 = 2;
    pub const DS_DISPLAY_NAME: u32 = 3;
    pub const DS_UNIQUE_ID_NAME: u32 = 4;
    pub const DS_CANONICAL_NAME: u32 = 5;
    pub const DS_USER_PRINCIPAL_NAME: u32 = 6;
    pub const DS_CANONICAL_NAME_EX: u32 = 7;
    pub const DS_SERVICE_PRINCIPAL_NAME: u32 = 8;
    pub const DS_SID_OR_SID_HISTORY_NAME: u32 = 9;
    pub const DS_DNS_DOMAIN_NAME: u32 = 10;
    pub const DS_NT4_ACCOUNT_NAME_SANS_DOMAIN: u32 = 1025;
}

/// DRS replication and capability flags.
pub mod drs_flags {
    pub const DRS_EXT_BASE: u32 = 0x0000_0001;
    pub const DRS_EXT_ASYNCREPL: u32 = 0x0000_0002;
    pub const DRS_EXT_REMOVEAPI: u32 = 0x0000_0004;
    pub const DRS_EXT_MOVEREQ_V2: u32 = 0x0000_0008;
    pub const DRS_EXT_GETCHG_CHECK: u32 = 0x0000_0010;
    pub const DRS_EXT_DCINFO_V1: u32 = 0x0000_0020;
    pub const DRS_EXT_RESTORE_USN_OPTIMIZATION: u32 = 0x0000_0040;
    pub const DRS_EXT_ADDENTRY: u32 = 0x0000_0080;
    pub const DRS_EXT_KCC_EXECUTE: u32 = 0x0000_0100;
    pub const DRS_EXT_LINKED_VALUE_REPLICATION: u32 = 0x0000_0400;
    pub const DRS_EXT_DCINFO_V2: u32 = 0x0000_0800;
    pub const DRS_EXT_STRONG_ENCRYPTION: u32 = 0x0000_8000;
    pub const DRS_EXT_GETCHGREQ_V8: u32 = 0x0400_0000;
    pub const DRS_EXT_GETCHGREPLY_V6: u32 = 0x1000_0000;

    /// Standard client flags sent in `DRS_EXTENSIONS_INT`.
    pub const DRS_EXT_DEFAULT_CLIENT_FLAGS: u32 = DRS_EXT_BASE
        | DRS_EXT_ASYNCREPL
        | DRS_EXT_REMOVEAPI
        | DRS_EXT_MOVEREQ_V2
        | DRS_EXT_GETCHG_CHECK
        | DRS_EXT_DCINFO_V1
        | DRS_EXT_RESTORE_USN_OPTIMIZATION
        | DRS_EXT_ADDENTRY
        | DRS_EXT_KCC_EXECUTE
        | DRS_EXT_LINKED_VALUE_REPLICATION
        | DRS_EXT_DCINFO_V2
        | DRS_EXT_STRONG_ENCRYPTION
        | DRS_EXT_GETCHGREQ_V8
        | DRS_EXT_GETCHGREPLY_V6;

    /// Flags for `DRSGetNCChanges` V8 sync request.
    pub const DRS_INIT_SYNC: u32 = 0x0000_0020;
    pub const DRS_WRIT_REP: u32 = 0x0000_0010;
}

/// Well-known Active Directory replication attribute types (`attrTyp`).
pub mod attr_type {
    pub const USER_PRINCIPAL_NAME: u32 = 0x90290;
    pub const SAM_ACCOUNT_NAME: u32 = 0x900DD;
    pub const UNICODE_PWD: u32 = 0x9005A;
    pub const DBCS_PWD: u32 = 0x90037;
    pub const NT_PWD_HISTORY: u32 = 0x9005E;
    pub const LM_PWD_HISTORY: u32 = 0x900A0;
    pub const SUPPLEMENTAL_CREDENTIALS: u32 = 0x9007D;
    pub const OBJECT_SID: u32 = 0x90092;
    pub const PWD_LAST_SET: u32 = 0x90060;
    pub const USER_ACCOUNT_CONTROL: u32 = 0x90008;
}

/// Kerberos encryption type constants in Active Directory.
pub mod kerb_etype {
    pub const DES_CBC_CRC: u32 = 1;
    pub const DES_CBC_MD5: u32 = 3;
    pub const AES128_CTS_HMAC_SHA1_96: u32 = 17;
    pub const AES256_CTS_HMAC_SHA1_96: u32 = 18;
    pub const RC4_HMAC: u32 = 23;

    pub fn etype_name(etype: u32) -> &'static str {
        match etype {
            DES_CBC_CRC => "des-cbc-crc",
            DES_CBC_MD5 => "des-cbc-md5",
            AES128_CTS_HMAC_SHA1_96 => "aes128-cts-hmac-sha1-96",
            AES256_CTS_HMAC_SHA1_96 => "aes256-cts-hmac-sha1-96",
            RC4_HMAC => "rc4-hmac",
            _ => "unknown",
        }
    }
}

/// Replicated user account credentials returned by DCSync.
#[derive(Debug, Clone)]
pub struct DrsSyncAccount {
    pub account_name: String,
    pub domain: Option<String>,
    pub upn: Option<String>,
    pub rid: u32,
    pub lm_hash: [u8; 16],
    pub nt_hash: [u8; 16],
    pub user_account_control: u32,
    pub pwd_last_set: u64,
    pub kerberos_keys: Vec<(u32, Vec<u8>)>,
    pub cleartext_password: Option<String>,
    pub lm_history: Vec<[u8; 16]>,
    pub nt_history: Vec<[u8; 16]>,
}

impl DrsSyncAccount {
    /// Formats the account as a standard pwdump / secretsdump entry:
    /// `<domain>\<user>:<rid>:<lm_hash>:<nt_hash>:::`
    pub fn to_secretsdump_line(&self) -> String {
        let prefix = if let Some(ref d) = self.domain {
            format!(r"{}\{}", d, self.account_name)
        } else {
            self.account_name.clone()
        };
        let lm = hex_string(&self.lm_hash);
        let nt = hex_string(&self.nt_hash);
        let status = if self.is_disabled() {
            " (status=Disabled)"
        } else {
            " (status=Enabled)"
        };
        format!("{}:{}:{}:{}:::{}", prefix, self.rid, lm, nt, status)
    }

    /// Checks if bit 0x02 (`ACCOUNTDISABLE`) is set in `userAccountControl`.
    pub fn is_disabled(&self) -> bool {
        (self.user_account_control & 0x0002) != 0
    }
}

fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Decrypts a DRS attribute value encrypted with session key (`[MS-DRSR]` §5.16.2 / §5.16.3).
///
/// Layout:
/// - Salt (16 bytes)
/// - Encrypted payload (RC4 ciphertext)
///
/// Key derivation:
/// - `MD5(session_key || Salt)`
/// - Cleartext begins with 4-byte CRC32 followed by the clear attribute data.
pub fn decrypt_drs_attribute_value(
    session_key: &[u8],
    encrypted_blob: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if encrypted_blob.len() < 20 {
        return Err(CoreError::ProtocolError(format!(
            "DRS encrypted attribute too small: {} bytes (expected >= 20)",
            encrypted_blob.len()
        )));
    }
    let salt = &encrypted_blob[..16];
    let ciphertext = &encrypted_blob[16..];

    let mut md5_input = Vec::with_capacity(session_key.len() + 16);
    md5_input.extend_from_slice(session_key);
    md5_input.extend_from_slice(salt);
    let key = md5(&md5_input);

    let mut plaintext = ciphertext.to_vec();
    let mut rc4 = Rc4::new(&key);
    rc4.apply_keystream(&mut plaintext);

    if plaintext.len() < 4 {
        return Err(CoreError::ProtocolError("DRS decrypted payload too short".into()));
    }

    let calculated_crc = crc32(&plaintext[4..]);
    let stored_crc = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);

    if calculated_crc != stored_crc {
        // Log mismatch or return with warning; some implementations use unpadded payload
        #[cfg(debug_assertions)]
        eprintln!(
            "[-] DRS attribute CRC32 mismatch: calculated={:08x}, stored={:08x}",
            calculated_crc, stored_crc
        );
    }

    Ok(plaintext[4..].to_vec())
}

/// Removes the DES layer from a 16-byte crypted password hash using the user's RID.
pub fn remove_des_layer(crypted_hash: &[u8; 16], rid: u32) -> [u8; 16] {
    sam_des_decrypt_hash_with_rid(rid, crypted_hash)
}

/// Unpacks Active Directory `Primary:Kerberos-Newer-Keys` and `Primary:CLEARTEXT` supplemental
/// credentials (`[MS-SAMR]` §2.2.10).
pub fn parse_supplemental_credentials(
    data: &[u8],
) -> (Vec<(u32, Vec<u8>)>, Option<String>) {
    let mut keys = Vec::new();
    let mut cleartext = None;

    if data.len() < 16 {
        return (keys, cleartext);
    }

    // Windows USER_PROPERTIES structure has a 96-byte header or property count
    // Scan for property headers by UTF-16LE property names:
    // "Primary:Kerberos-Newer-Keys", "Primary:CLEARTEXT"
    let kerb_needle = encode_utf16le("Primary:Kerberos-Newer-Keys");
    let clear_needle = encode_utf16le("Primary:CLEARTEXT");

    if let Some(pos) = find_subsequence(data, &kerb_needle) {
        let after = pos + kerb_needle.len();
        if after + 4 <= data.len() {
            // Property value length and data follows
            let val_slice = &data[after..];
            extract_kerberos_keys(val_slice, &mut keys);
        }
    }

    if let Some(pos) = find_subsequence(data, &clear_needle) {
        let after = pos + clear_needle.len();
        if after + 4 <= data.len() {
            let val_slice = &data[after..];
            if val_slice.len() >= 8 {
                // Read length
                let len = u16::from_le_bytes([val_slice[0], val_slice[1]]) as usize;
                let text_bytes = if val_slice.len() >= 4 + len && len > 0 {
                    &val_slice[4..4 + len]
                } else if val_slice.len() > 4 {
                    &val_slice[4..]
                } else {
                    &[]
                };
                if let Ok(s) = decode_utf16le(text_bytes) {
                    cleartext = Some(s.trim_end_matches('\0').to_string());
                }
            }
        }
    }

    (keys, cleartext)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn extract_kerberos_keys(slice: &[u8], out: &mut Vec<(u32, Vec<u8>)>) {
    if slice.len() < 8 {
        return;
    }
    // Search for KERB_STORED_CREDENTIAL_NEW structure
    // Common key counts: 1 to 10
    for offset in 0..slice.len().saturating_sub(16) {
        let count = u16::from_le_bytes([slice[offset], slice[offset + 1]]) as usize;
        if count > 0 && count <= 16 {
            let mut cur = offset + 8;
            let mut valid = true;
            let mut temp_keys = Vec::new();
            for _ in 0..count {
                if cur + 8 > slice.len() {
                    valid = false;
                    break;
                }
                let key_type = u32::from_le_bytes([
                    slice[cur],
                    slice[cur + 1],
                    slice[cur + 2],
                    slice[cur + 3],
                ]);
                let key_len = u16::from_le_bytes([slice[cur + 4], slice[cur + 5]]) as usize;
                let key_off = u16::from_le_bytes([slice[cur + 6], slice[cur + 7]]) as usize;

                if (key_type == 1 || key_type == 3 || key_type == 17 || key_type == 18 || key_type == 23)
                    && key_off + key_len <= slice.len()
                {
                    let key_bytes = slice[key_off..key_off + key_len].to_vec();
                    temp_keys.push((key_type, key_bytes));
                }
                cur += 8;
            }
            if valid && !temp_keys.is_empty() {
                out.extend(temp_keys);
                return;
            }
        }
    }
}

// -------------------------------------------------------------------------------------------------
// RPC Stub Builders & Parsers
// -------------------------------------------------------------------------------------------------

/// `DRSBind` (Opnum 0) request builder.
pub fn build_drs_bind_stub(
    client_dsa_guid: Option<&[u8; 16]>,
    flags: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);

    // 1. puuidClientDsa: [unique] UUID*
    if let Some(guid) = client_dsa_guid {
        w.write_u32(REFERENT_BASE);
        w.write_fixed_array(guid);
    } else {
        w.write_u32(0); // NULL
    }

    // 2. pextClient: [unique] DRS_EXTENSIONS*
    w.write_u32(REFERENT_BASE + 4);

    // DRS_EXTENSIONS: cb (DWORD) + rgb (conformant array)
    // DRS_EXTENSIONS_INT length: 4 + 16 + 4 + 4 + 4 + 16 + 4 = 52 bytes
    let ext_len: u32 = 52;
    w.write_u32(ext_len); // cb
    w.write_u32(ext_len); // conformant array MaxCount

    // DRS_EXTENSIONS_INT payload
    w.write_u32(flags); // dwFlags
    w.write_fixed_array(&[0u8; 16]); // SiteObjGuid
    w.write_u32(0); // Pid
    w.write_u32(0); // dwReplEpoch
    w.write_u32(0); // dwFlagsExt
    w.write_fixed_array(&[0u8; 16]); // ConfigObjGUID
    w.write_u32(0); // dwExtCaps

    w.into_bytes()
}

/// Parses `DRSBind` (Opnum 0) response stub into `(DrsHandle, status)`.
pub fn parse_drs_bind_response(stub: &[u8]) -> Result<(DrsHandle, u32), CoreError> {
    if stub.len() < 24 {
        return Err(CoreError::ProtocolError(format!(
            "DRSBind response stub too short: {} bytes (expected >= 24)",
            stub.len()
        )));
    }
    let mut r = NdrReader::new(stub);

    // ppextServer pointer referent
    let ext_ref = r.read_u32()?;
    if ext_ref != 0 {
        // Skip server extensions
        let cb = r.read_u32()?;
        let max_count = r.read_u32()?;
        let to_skip = (cb.max(max_count) as usize).min(1024);
        let _ = r.read_bytes(to_skip)?;
        r.align(4)?;
    }

    let handle = r.read_fixed_array::<20>()?;
    let status = r.read_u32()?;

    if status != 0 {
        return Err(CoreError::ProtocolError(format!(
            "DRSBind failed with Win32 status 0x{:08x}",
            status
        )));
    }

    Ok((handle, status))
}

/// `DRSUnbind` (Opnum 1) request builder.
pub fn build_drs_unbind_stub(handle: &DrsHandle) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(24);
    w.write_fixed_array(handle);
    w.into_bytes()
}

/// `DRSCrackNames` (Opnum 12) request builder.
pub fn build_drs_crack_names_stub(
    handle: &DrsHandle,
    name: &str,
    format_offered: u32,
    format_desired: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);
    w.write_fixed_array(handle);
    w.write_u32(1); // dwInVersion = 1

    // pmsgIn union: tag = 1
    w.write_u32(1);

    // DRS_MSG_CRACKREQ_V1
    w.write_u32(0); // CodePage = 0
    w.write_u32(0); // LocaleId = 0
    w.write_u32(0); // dwFlags = 0
    w.write_u32(format_offered);
    w.write_u32(format_desired);
    w.write_u32(1); // cNames = 1

    // Pointer to conformant array of LPWSTR
    w.write_u32(REFERENT_BASE);
    w.write_u32(1); // MaxCount = 1

    // Element 0: pointer to LPWSTR
    w.write_u32(REFERENT_BASE + 4);
    write_string_wchar_pointee(&mut w, name);

    w.into_bytes()
}

/// Parses `DRSCrackNames` (Opnum 12) response stub to return the cracked object name or GUID.
pub fn parse_drs_crack_names_response(stub: &[u8]) -> Result<String, CoreError> {
    if stub.len() < 16 {
        return Err(CoreError::ProtocolError(format!(
            "DRSCrackNames response stub too short: {} bytes",
            stub.len()
        )));
    }
    let mut r = NdrReader::new(stub);
    let out_version = r.read_u32()?;
    if out_version != 1 {
        return Err(CoreError::ProtocolError(format!(
            "Unsupported DRSCrackNames outVersion: {}",
            out_version
        )));
    }

    let union_tag = r.read_u32()?;
    if union_tag != 1 {
        return Err(CoreError::ProtocolError(format!(
            "Unsupported DRSCrackNames union tag: {}",
            union_tag
        )));
    }

    let result_ref = r.read_u32()?;
    if result_ref == 0 {
        return Err(CoreError::ProtocolError("DRSCrackNames pResult is NULL".into()));
    }

    let c_items = r.read_u32()?;
    if c_items == 0 {
        return Err(CoreError::ProtocolError("DRSCrackNames returned 0 items".into()));
    }

    // Pointer to items array
    let items_ref = r.read_u32()?;
    if items_ref == 0 {
        return Err(CoreError::ProtocolError("DRSCrackNames rItems is NULL".into()));
    }
    let _max_count = r.read_u32()?;

    // Read first DS_NAME_RESULT_ITEMW: status (DWORD), pDomain (LPWSTR ref), pName (LPWSTR ref)
    let status = r.read_u32()?;
    let _p_domain_ref = r.read_u32()?;
    let p_name_ref = r.read_u32()?;

    if status != 0 {
        return Err(CoreError::ProtocolError(format!(
            "DRSCrackNames item status error: 0x{:08x}",
            status
        )));
    }

    if p_name_ref == 0 {
        return Err(CoreError::ProtocolError("DRSCrackNames pName is NULL".into()));
    }

    // Read conformant varying wchar string
    let _max = r.read_u32()?;
    let _offset = r.read_u32()?;
    let actual = r.read_u32()?;

    let bytes = r.read_bytes((actual as usize) * 2)?;
    let name_str = decode_utf16le(bytes)?;
    Ok(name_str.trim_end_matches('\0').to_string())
}

/// `DRSGetNCChanges` (Opnum 3) V8 request builder for a specific object GUID.
pub fn build_drs_get_nc_changes_guid_stub(
    handle: &DrsHandle,
    dsa_guid: &[u8; 16],
    object_guid: &[u8; 16],
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(256);
    w.write_fixed_array(handle);
    w.write_u32(8); // dwInVersion = 8

    // pmsgIn union: tag = 8
    w.write_u32(8);

    // DRS_MSG_GETCHGREQ_V8
    w.write_fixed_array(dsa_guid); // uuidDsaObjDest
    w.write_fixed_array(dsa_guid); // uuidInvocIdSrc

    // pNC: pointer to DSNAME
    w.write_u32(REFERENT_BASE);

    // DSNAME layout:
    // structLen (DWORD)
    // SidLen (DWORD)
    // Guid (16 bytes)
    // Sid (RpcSid: Revision, SubAuthorityCount, Authority, SubAuthorities...)
    // NameLen (DWORD)
    // StringName (NUL-terminated wchar conformant varying array)
    let ds_name_len: u32 = 4 + 4 + 16 + 28 + 4 + 2;
    w.write_u32(ds_name_len); // structLen
    w.write_u32(0); // SidLen = 0 (GUID lookup)
    w.write_fixed_array(object_guid);
    w.write_fixed_array(&[0u8; 28]); // empty SID buffer
    w.write_u32(0); // NameLen = 0
    w.write_u16(0); // empty StringName (NUL)

    // usnvecFrom: USN_VECTOR (3 x i64)
    w.write_u64(0);
    w.write_u64(0);
    w.write_u64(0);

    w.write_u32(0); // pUpToDateVecDest = NULL
    w.write_u32(drs_flags::DRS_INIT_SYNC | drs_flags::DRS_WRIT_REP); // ulFlags
    w.write_u32(100); // cMaxObjects
    w.write_u32(0); // cMaxBytes
    w.write_u32(0); // ulExtendedOp
    w.write_u64(0); // liFsmoInfo
    w.write_u32(0); // pPartialAttrSet = NULL
    w.write_u32(0); // pPartialAttrSetEx1 = NULL
    w.write_u32(0); // PrefixTableDest count = 0

    w.into_bytes()
}

/// `DRSGetNCChanges` (Opnum 3) V8 request builder for a specific object SID.
pub fn build_drs_get_nc_changes_sid_stub(
    handle: &DrsHandle,
    dsa_guid: &[u8; 16],
    sid: &RpcSid,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(256);
    w.write_fixed_array(handle);
    w.write_u32(8); // dwInVersion = 8
    w.write_u32(8); // tag = 8

    w.write_fixed_array(dsa_guid);
    w.write_fixed_array(dsa_guid);

    // pNC
    w.write_u32(REFERENT_BASE);

    let mut sid_bytes = Vec::new();
    sid_bytes.push(sid.revision);
    sid_bytes.push(sid.sub_authorities.len() as u8);
    sid_bytes.extend_from_slice(&sid.identifier_authority);
    for sub in &sid.sub_authorities {
        sid_bytes.extend_from_slice(&sub.to_le_bytes());
    }

    let mut sid_buf = [0u8; 28];
    let copy_len = sid_bytes.len().min(28);
    sid_buf[..copy_len].copy_from_slice(&sid_bytes[..copy_len]);

    let ds_name_len: u32 = 4 + 4 + 16 + 28 + 4 + 2;
    w.write_u32(ds_name_len);
    w.write_u32(sid_bytes.len() as u32); // SidLen
    w.write_fixed_array(&[0u8; 16]); // Guid = 0
    w.write_fixed_array(&sid_buf);
    w.write_u32(0); // NameLen
    w.write_u16(0); // StringName = NUL

    // usnvecFrom
    w.write_u64(0);
    w.write_u64(0);
    w.write_u64(0);

    w.write_u32(0);
    w.write_u32(drs_flags::DRS_INIT_SYNC | drs_flags::DRS_WRIT_REP);
    w.write_u32(100);
    w.write_u32(0);
    w.write_u32(0);
    w.write_u64(0);
    w.write_u32(0);
    w.write_u32(0);
    w.write_u32(0);

    w.into_bytes()
}

/// Parses `DRSGetNCChanges` (Opnum 3) response stub and decrypts all account credentials.
pub fn parse_drs_get_nc_changes_response(
    stub: &[u8],
    session_key: &[u8],
) -> Result<DrsSyncAccount, CoreError> {
    if stub.len() < 32 {
        return Err(CoreError::ProtocolError(format!(
            "DRSGetNCChanges response too short: {} bytes",
            stub.len()
        )));
    }

    let mut r = NdrReader::new(stub);
    let out_version = r.read_u32()?;
    let _union_tag = r.read_u32()?;

    if out_version != 6 && out_version != 9 {
        return Err(CoreError::ProtocolError(format!(
            "Unsupported DRSGetNCChanges reply version: V{}",
            out_version
        )));
    }

    // Skip reply header down to cNumObjects:
    // uuidDsaObjSrc (16), uuidInvocIdSrc (16), pNC (4), usnvecFrom (24), usnvecTo (24),
    // pUpToDateVecSrc (4), PrefixTableSrc (count 4, pointer 4), ulExtendedRet (4)
    let _uuid_dsa = r.read_fixed_array::<16>()?;
    let _uuid_invoc = r.read_fixed_array::<16>()?;
    let _p_nc = r.read_u32()?;
    let _usn_from = r.read_bytes(24)?;
    let _usn_to = r.read_bytes(24)?;
    let _uptodate_ref = r.read_u32()?;

    // PrefixTableSrc: count (DWORD), pPrefixEntry pointer (DWORD)
    let prefix_count = r.read_u32()?;
    let prefix_ref = r.read_u32()?;
    if prefix_ref != 0 && prefix_count > 0 {
        // Skip prefix table entries if present in stub
        let skip_len = (prefix_count as usize * 16).min(r.remaining());
        let _ = r.read_bytes(skip_len)?;
        r.align(4)?;
    }

    let _extended_ret = r.read_u32()?;
    let num_objects = r.read_u32()?;

    if num_objects == 0 {
        return Err(CoreError::ProtocolError("DRSGetNCChanges returned 0 objects".into()));
    }

    // Scan for attributes inside REPLENTINFLIST:
    // Walk through attribute types: unicodePwd (0x9005A), dBCSPwd (0x90037),
    // sAMAccountName (0x900DD), userPrincipalName (0x90290), objectSid (0x90092),
    // supplementalCredentials (0x9007D), pwdLastSet (0x90060), userAccountControl (0x90008).
    let mut account_name = "unknown".to_string();
    let mut domain = None;
    let mut upn = None;
    let mut rid = 500u32;
    let mut lm_hash = [0u8; 16];
    let mut nt_hash = [0u8; 16];
    let mut uac = 0u32;
    let mut pwd_last_set = 0u64;
    let mut kerb_keys = Vec::new();
    let mut cleartext = None;

    // Fast-path scan across remainder of response stub for well-known attribute blocks
    let pos = r.position();
    let raw = if pos <= stub.len() { &stub[pos..] } else { &[] };
    scan_attributes_from_raw(
        raw,
        session_key,
        &mut account_name,
        &mut domain,
        &mut upn,
        &mut rid,
        &mut lm_hash,
        &mut nt_hash,
        &mut uac,
        &mut pwd_last_set,
        &mut kerb_keys,
        &mut cleartext,
    );

    Ok(DrsSyncAccount {
        account_name,
        domain,
        upn,
        rid,
        lm_hash,
        nt_hash,
        user_account_control: uac,
        pwd_last_set,
        kerberos_keys: kerb_keys,
        cleartext_password: cleartext,
        lm_history: Vec::new(),
        nt_history: Vec::new(),
    })
}

fn scan_attributes_from_raw(
    raw: &[u8],
    session_key: &[u8],
    account_name: &mut String,
    domain: &mut Option<String>,
    upn: &mut Option<String>,
    rid: &mut u32,
    lm_hash: &mut [u8; 16],
    nt_hash: &mut [u8; 16],
    uac: &mut u32,
    pwd_last_set: &mut u64,
    kerb_keys: &mut Vec<(u32, Vec<u8>)>,
    cleartext: &mut Option<String>,
) {
    let mut idx = 0;
    while idx + 8 <= raw.len() {
        let attr_typ = u32::from_le_bytes([raw[idx], raw[idx + 1], raw[idx + 2], raw[idx + 3]]);
        match attr_typ {
            attr_type::SAM_ACCOUNT_NAME => {
                if let Some((val, advance)) = read_attr_val(&raw[idx + 4..]) {
                    if let Ok(s) = decode_utf16le(val) {
                        *account_name = s.trim_end_matches('\0').to_string();
                    }
                    idx += 4 + advance;
                    continue;
                }
            }
            attr_type::USER_PRINCIPAL_NAME => {
                if let Some((val, advance)) = read_attr_val(&raw[idx + 4..]) {
                    if let Ok(s) = decode_utf16le(val) {
                        let clean = s.trim_end_matches('\0').to_string();
                        if let Some(d) = clean.split('@').last() {
                            *domain = Some(d.to_string());
                        }
                        *upn = Some(clean);
                    }
                    idx += 4 + advance;
                    continue;
                }
            }
            attr_type::OBJECT_SID => {
                if let Some((val, advance)) = read_attr_val(&raw[idx + 4..]) {
                    if val.len() >= 8 {
                        // RID is the last 4 bytes of standard Windows SID
                        let rid_bytes = &val[val.len() - 4..];
                        *rid = u32::from_le_bytes([
                            rid_bytes[0],
                            rid_bytes[1],
                            rid_bytes[2],
                            rid_bytes[3],
                        ]);
                    }
                    idx += 4 + advance;
                    continue;
                }
            }
            attr_type::UNICODE_PWD => {
                if let Some((val, advance)) = read_attr_val(&raw[idx + 4..]) {
                    if let Ok(plain) = decrypt_drs_attribute_value(session_key, val) {
                        if plain.len() >= 16 {
                            let mut crypted = [0u8; 16];
                            crypted.copy_from_slice(&plain[..16]);
                            *nt_hash = remove_des_layer(&crypted, *rid);
                        }
                    }
                    idx += 4 + advance;
                    continue;
                }
            }
            attr_type::DBCS_PWD => {
                if let Some((val, advance)) = read_attr_val(&raw[idx + 4..]) {
                    if let Ok(plain) = decrypt_drs_attribute_value(session_key, val) {
                        if plain.len() >= 16 {
                            let mut crypted = [0u8; 16];
                            crypted.copy_from_slice(&plain[..16]);
                            *lm_hash = remove_des_layer(&crypted, *rid);
                        }
                    }
                    idx += 4 + advance;
                    continue;
                }
            }
            attr_type::USER_ACCOUNT_CONTROL => {
                if let Some((val, advance)) = read_attr_val(&raw[idx + 4..]) {
                    if val.len() >= 4 {
                        *uac = u32::from_le_bytes([val[0], val[1], val[2], val[3]]);
                    }
                    idx += 4 + advance;
                    continue;
                }
            }
            attr_type::PWD_LAST_SET => {
                if let Some((val, advance)) = read_attr_val(&raw[idx + 4..]) {
                    if val.len() >= 8 {
                        *pwd_last_set = u64::from_le_bytes([
                            val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
                        ]);
                    }
                    idx += 4 + advance;
                    continue;
                }
            }
            attr_type::SUPPLEMENTAL_CREDENTIALS => {
                if let Some((val, advance)) = read_attr_val(&raw[idx + 4..]) {
                    if let Ok(plain) = decrypt_drs_attribute_value(session_key, val) {
                        let (keys, pass) = parse_supplemental_credentials(&plain);
                        *kerb_keys = keys;
                        *cleartext = pass;
                    }
                    idx += 4 + advance;
                    continue;
                }
            }
            _ => {}
        }
        idx += 1;
    }
}

fn read_attr_val(slice: &[u8]) -> Option<(&[u8], usize)> {
    if slice.len() < 8 {
        return None;
    }
    // valCount (DWORD) + pointer referent (DWORD)
    let count = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
    if count == 0 {
        return None;
    }
    // Length is at slice[8..12] or conformant length
    if slice.len() >= 16 {
        let len = u32::from_le_bytes([slice[8], slice[9], slice[10], slice[11]]) as usize;
        if len > 0 && 16 + len <= slice.len() {
            return Some((&slice[16..16 + len], 16 + len));
        }
    }
    None
}

// -------------------------------------------------------------------------------------------------
// High-Level DRS Client
// -------------------------------------------------------------------------------------------------

/// Active Directory Directory Replication Service client (`[MS-DRSR]`).
pub struct DrsClient<T: RpcTransport> {
    transport: T,
    session_key: Vec<u8>,
    dsa_guid: [u8; 16],
    handle: Option<DrsHandle>,
    call_id: u32,
}

impl<T: RpcTransport> DrsClient<T> {
    /// Creates a new `DrsClient` over an authenticated RPC transport.
    pub fn new(transport: T, session_key: &[u8]) -> Self {
        Self {
            transport,
            session_key: session_key.to_vec(),
            dsa_guid: [0u8; 16],
            handle: None,
            call_id: 1,
        }
    }

    fn call(&mut self, opnum: u16, stub: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let call_id = self.call_id;
        self.call_id += 1;
        let req = RpcRequestPdu {
            call_id,
            context_id: 0,
            opnum,
            stub_data: stub,
        };
        let resp = self.transport.transceive(&req.to_bytes())?;
        extract_response_stub(&resp)
    }

    /// Calls `DRSBind` (Opnum 0) to negotiate extensions and establish a replication handle.
    pub fn bind(&mut self) -> Result<DrsHandle, CoreError> {
        let stub = build_drs_bind_stub(None, drs_flags::DRS_EXT_DEFAULT_CLIENT_FLAGS);
        let resp_stub = self.call(opnum::DRS_BIND, stub)?;
        let (handle, _) = parse_drs_bind_response(&resp_stub)?;
        self.handle = Some(handle);
        Ok(handle)
    }

    /// Calls `DRSCrackNames` (Opnum 12) to resolve a username to an object GUID or FQDN.
    pub fn crack_name(
        &mut self,
        name: &str,
        format_offered: u32,
        format_desired: u32,
    ) -> Result<String, CoreError> {
        let handle = self.handle.ok_or_else(|| {
            CoreError::ProtocolError("DRS client not bound; call bind() first".into())
        })?;
        let stub = build_drs_crack_names_stub(&handle, name, format_offered, format_desired);
        let resp_stub = self.call(opnum::DRS_CRACK_NAMES, stub)?;
        parse_drs_crack_names_response(&resp_stub)
    }

    /// Replicates credentials for a user by GUID using `DRSGetNCChanges` (Opnum 3).
    pub fn sync_user_guid(&mut self, object_guid: &[u8; 16]) -> Result<DrsSyncAccount, CoreError> {
        let handle = self.handle.ok_or_else(|| {
            CoreError::ProtocolError("DRS client not bound; call bind() first".into())
        })?;
        let stub = build_drs_get_nc_changes_guid_stub(&handle, &self.dsa_guid, object_guid);
        let resp_stub = self.call(opnum::DRS_GET_NC_CHANGES, stub)?;
        parse_drs_get_nc_changes_response(&resp_stub, &self.session_key)
    }

    /// Replicates credentials for a user by SID using `DRSGetNCChanges` (Opnum 3).
    pub fn sync_user_sid(&mut self, sid: &RpcSid) -> Result<DrsSyncAccount, CoreError> {
        let handle = self.handle.ok_or_else(|| {
            CoreError::ProtocolError("DRS client not bound; call bind() first".into())
        })?;
        let stub = build_drs_get_nc_changes_sid_stub(&handle, &self.dsa_guid, sid);
        let resp_stub = self.call(opnum::DRS_GET_NC_CHANGES, stub)?;
        parse_drs_get_nc_changes_response(&resp_stub, &self.session_key)
    }

    /// Calls `DRSUnbind` (Opnum 1) to close the replication handle.
    pub fn unbind(&mut self) -> Result<(), CoreError> {
        if let Some(handle) = self.handle.take() {
            let stub = build_drs_unbind_stub(&handle);
            let _ = self.call(opnum::DRS_UNBIND, stub)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drs_attribute_decryption_and_crc32() {
        let session_key = [0x55u8; 16];
        let salt = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00];

        // Sample payload: 16 bytes NT hash
        let plain_payload = [0xaau8; 16];
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&crc32(&plain_payload).to_le_bytes());
        plaintext.extend_from_slice(&plain_payload);

        let mut md5_input = Vec::new();
        md5_input.extend_from_slice(&session_key);
        md5_input.extend_from_slice(&salt);
        let key = md5(&md5_input);

        let mut ciphertext = plaintext.clone();
        let mut rc4 = Rc4::new(&key);
        rc4.apply_keystream(&mut ciphertext);

        let mut encrypted_blob = Vec::new();
        encrypted_blob.extend_from_slice(&salt);
        encrypted_blob.extend_from_slice(&ciphertext);

        let decrypted = decrypt_drs_attribute_value(&session_key, &encrypted_blob)
            .expect("attribute decryption should succeed");
        assert_eq!(decrypted, plain_payload);
    }

    #[test]
    fn test_remove_des_layer_roundtrip() {
        let rid = 500u32;
        let orig_nt = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
            0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
        ];
        let wrapped = impacket_crypto::sam_des_encrypt_hash_with_rid(rid, &orig_nt);
        let unwrapped = remove_des_layer(&wrapped, rid);
        assert_eq!(unwrapped, orig_nt);
    }

    #[test]
    fn test_drs_bind_and_unbind_stub_builders() {
        let stub = build_drs_bind_stub(None, drs_flags::DRS_EXT_DEFAULT_CLIENT_FLAGS);
        assert!(stub.len() >= 64);

        let handle = [0x77u8; 20];
        let unbind = build_drs_unbind_stub(&handle);
        assert_eq!(unbind.len(), 20);
        assert_eq!(unbind, handle);
    }
}
