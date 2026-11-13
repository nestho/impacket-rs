//! `impacket-sam`: Cross-Era Windows Credential & Registry Hive Decryption Engine (`impacket/examples/secretsdump.py`).
//!
//! Supports both **Legacy Active Directory / Windows 2000 -> 2012 R2** and **Modern Windows Server 2016 -> 2025**:
//! 1. **`SYSTEM` Hive BootKey Scrambling (`getBootKey`)**:
//!    - Concatenates the 8-char hex class names of `Lsa\JD`, `Lsa\Skew1`, `Lsa\GBG`, and `Lsa\Data`
//!    - Applies the canonical 16-byte permutation `[8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]`
//! 2. **`HashedBootKey` (`SAM\Domains\Account\F` Key0)**:
//!    - **Revision 1 (Legacy Win2000 / 2003 / 2008 R2 / 2012 R2)**: `MD5(Salt + "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0" + BootKey + "0123456789012345678901234567890123456789\0")` + `RC4` + Checksum verification
//!    - **Revision 2 (Modern Win10 / Server 2016 / 2019 / 2022 / 2025)**: `AES-128-CBC(BootKey, IV=Salt, Data)`
//! 3. **Per-User `SAM_HASH` / `SAM_HASH_AES` Unwrapping (`SAM\Domains\Account\Users\<RID>\V`)**:
//!    - **Style 1 (`SAM_HASH` Revision 1 — RC4 + DES)**: `MD5(HashedBootKey + pack("<L", rid) + "NTPASSWORD\0" / "LMPASSWORD\0")` -> `RC4` -> `sam_des_decrypt_hash_with_rid`
//!    - **Style 2 (`SAM_HASH_AES` Revision 2 — AES-128-CBC + DES)**: `AES-128-CBC(HashedBootKey, IV=Salt)` -> `sam_des_decrypt_hash_with_rid`

pub mod reg;
pub mod lsa;
pub mod ese;
pub mod dpapi;
pub mod ntds;
pub mod gpp;
pub mod regsecrets;
pub mod shadowcopy;

pub use lsa::{LsaCachedLogon, LsaParser, LsaSecretItem};
pub use ese::{EseDatabase, EseDbHeader, EsePageHeader, EseRecord, EseTableDef, EseValue};
pub use dpapi::{
    derive_keys_from_user, derive_keys_from_user_key, DpapiBlob, MasterKey, MasterKeyFile,
};
pub use ntds::{NtdsAccount, NtdsParser};
pub use gpp::{decrypt_cpassword, parse_gpp_xml, GppCredential, GPP_AES_KEY};
pub use regsecrets::{
    extract_bootkey_remote, extract_lsa_secrets_remote, extract_sam_hashes_remote,
    regsecrets_dump, RegSecretsDumpReport,
};
pub use shadowcopy::{ShadowCopyConfig, ShadowCopyInfo};

use impacket_core::{
    decode_hex, decode_utf16le, encode_hex, CoreError, NtlmHashes, EMPTY_LM_HASH, EMPTY_NT_HASH,
};
#[cfg(test)]
use impacket_core::AdCompatProfile;
use impacket_crypto::{
    aes128, md5, sam_des_decrypt_hash_with_rid, sam_des_encrypt_hash_with_rid, Rc4,
};

pub const SAM_QWERTY: &[u8] = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
pub const SAM_DIGITS: &[u8] = b"0123456789012345678901234567890123456789\0";
pub const SAM_LMPASSWORD_CONST: &[u8] = b"LMPASSWORD\0";
pub const SAM_NTPASSWORD_CONST: &[u8] = b"NTPASSWORD\0";

/// Standard Windows `SYSTEM\CurrentControlSet\Control\Lsa` BootKey permutation table (`secretsdump.py:getBootKey`).
pub const BOOTKEY_PERMUTATION: [usize; 16] = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];

/// Computes the 16-byte `BootKey` (SysKey) from the four 8-character hex class strings stored on
/// `SYSTEM\CurrentControlSet\Control\Lsa\{JD, Skew1, GBG, Data}`.
pub fn compute_bootkey_from_lsa_classes(
    jd_class: &str,
    skew1_class: &str,
    gbg_class: &str,
    data_class: &str,
) -> Result<[u8; 16], CoreError> {
    let combined = format!(
        "{}{}{}{}",
        jd_class.trim(),
        skew1_class.trim(),
        gbg_class.trim(),
        data_class.trim()
    );
    let raw = decode_hex(&combined)?;
    if raw.len() != 16 {
        return Err(CoreError::ProtocolError(format!(
            "LSA class strings must decode to 16 bytes, got {}",
            raw.len()
        )));
    }
    let mut bootkey = [0u8; 16];
    for (i, &src_idx) in BOOTKEY_PERMUTATION.iter().enumerate() {
        bootkey[i] = raw[src_idx];
    }
    Ok(bootkey)
}

/// Recovers the 16-byte `BootKey` from an offline `SYSTEM` hive: reads `Select\Current` to pick the
/// active `ControlSet`, then concatenates the class-name nibbles of `Control\Lsa\{JD,Skew1,GBG,Data}`
/// and applies the standard permutation (`secretsdump.py:LocalOperations.getBootKey`).
pub fn bootkey_from_system_hive(system_hive: &[u8]) -> Result<[u8; 16], CoreError> {
    let hive = reg::Hive::new(system_hive)?;
    let root = hive.root()?;
    let err = |m: &str| CoreError::ProtocolError(m.into());

    let select = hive.find_subkey(&root, "Select")?.ok_or_else(|| err("SYSTEM\\Select missing"))?;
    let current = hive
        .get_value(&select, "Current")?
        .ok_or_else(|| err("SYSTEM\\Select\\Current missing"))?;
    if current.data.len() < 4 {
        return Err(err("Select\\Current not a DWORD"));
    }
    let cs_num = u32::from_le_bytes([current.data[0], current.data[1], current.data[2], current.data[3]]);
    let control_set = format!("ControlSet{:03}", cs_num);

    let lsa = hive
        .navigate(&root, &[&control_set, "Control", "Lsa"])?
        .ok_or_else(|| err("Control\\Lsa missing"))?;

    let mut classes = Vec::with_capacity(4);
    for key in ["JD", "Skew1", "GBG", "Data"] {
        let k = hive.find_subkey(&lsa, key)?.ok_or_else(|| err("Lsa bootkey subkey missing"))?;
        classes.push(hive.class_name(&k)?);
    }
    compute_bootkey_from_lsa_classes(&classes[0], &classes[1], &classes[2], &classes[3])
}

/// Derives the 16-byte `HashedBootKey` using **Legacy Revision 1 (RC4 + MD5)**
/// used by Windows 2000, XP, Server 2003, 2008 R2, and 2012 R2 (`SAM_KEY_DATA` in `secretsdump.py`).
pub fn derive_hashed_bootkey_rc4(
    bootkey: &[u8; 16],
    salt: &[u8; 16],
    encrypted_key_and_checksum: &[u8; 32],
) -> Result<[u8; 16], CoreError> {
    let mut md5_in = Vec::with_capacity(16 + SAM_QWERTY.len() + 16 + SAM_DIGITS.len());
    md5_in.extend_from_slice(salt);
    md5_in.extend_from_slice(SAM_QWERTY);
    md5_in.extend_from_slice(bootkey);
    md5_in.extend_from_slice(SAM_DIGITS);
    let rc4_key = md5(&md5_in);

    let mut buf = *encrypted_key_and_checksum;
    let mut cipher = Rc4::new(&rc4_key);
    cipher.apply_keystream(&mut buf);

    let hbootkey: [u8; 16] = buf[0..16].try_into().unwrap();
    let expected_checksum: [u8; 16] = buf[16..32].try_into().unwrap();

    // Verify checksum: MD5(hbootkey + DIGITS + hbootkey + QWERTY)
    let mut chk_in = Vec::with_capacity(32 + SAM_DIGITS.len() + SAM_QWERTY.len());
    chk_in.extend_from_slice(&hbootkey);
    chk_in.extend_from_slice(SAM_DIGITS);
    chk_in.extend_from_slice(&hbootkey);
    chk_in.extend_from_slice(SAM_QWERTY);
    let actual_checksum = md5(&chk_in);

    if actual_checksum != expected_checksum {
        return Err(CoreError::ProtocolError(
            "SAM HashedBootKey RC4 checksum mismatch (SysKey password may be non-default)".into(),
        ));
    }

    Ok(hbootkey)
}

/// Helper to build a valid Legacy Revision 1 `SAM_KEY_DATA` encrypted blob (`Key || CheckSum`).
pub fn encrypt_hashed_bootkey_rc4(
    bootkey: &[u8; 16],
    salt: &[u8; 16],
    hbootkey: &[u8; 16],
) -> [u8; 32] {
    let mut chk_in = Vec::new();
    chk_in.extend_from_slice(hbootkey);
    chk_in.extend_from_slice(SAM_DIGITS);
    chk_in.extend_from_slice(hbootkey);
    chk_in.extend_from_slice(SAM_QWERTY);
    let checksum = md5(&chk_in);

    let mut plain = [0u8; 32];
    plain[0..16].copy_from_slice(hbootkey);
    plain[16..32].copy_from_slice(&checksum);

    let mut md5_in = Vec::new();
    md5_in.extend_from_slice(salt);
    md5_in.extend_from_slice(SAM_QWERTY);
    md5_in.extend_from_slice(bootkey);
    md5_in.extend_from_slice(SAM_DIGITS);
    let rc4_key = md5(&md5_in);

    let mut cipher = Rc4::new(&rc4_key);
    cipher.apply_keystream(&mut plain);
    plain
}

/// Derives the 16-byte `HashedBootKey` using **Modern Revision 2 (AES-128-CBC)**
/// used by Windows 10/11 and Windows Server 2016, 2019, 2022, and 2025 (`SAM_KEY_DATA_AES` in `secretsdump.py`).
pub fn derive_hashed_bootkey_aes(
    bootkey: &[u8; 16],
    salt_iv: &[u8; 16],
    encrypted_data: &[u8],
) -> Result<[u8; 16], CoreError> {
    if encrypted_data.len() < 16 {
        return Err(CoreError::BufferUnderflow {
            needed: 16,
            available: encrypted_data.len(),
        });
    }
    let dec = aes128::decrypt_cbc(bootkey, salt_iv, &encrypted_data[..16]);
    Ok(dec[0..16].try_into().unwrap())
}

/// Decrypts a single 16-byte SAM User Hash using **Legacy Revision 1 (RC4 + RID-DES)**
/// (Windows 2000 / 2003 / 2008 R2 / 2012 R2).
pub fn decrypt_sam_hash_rc4(
    rid: u32,
    hashed_bootkey: &[u8; 16],
    crypted_hash: &[u8; 16],
    is_nt_hash: bool,
) -> [u8; 16] {
    let constant = if is_nt_hash {
        SAM_NTPASSWORD_CONST
    } else {
        SAM_LMPASSWORD_CONST
    };
    let mut md5_in = Vec::with_capacity(16 + 4 + constant.len());
    md5_in.extend_from_slice(hashed_bootkey);
    md5_in.extend_from_slice(&rid.to_le_bytes());
    md5_in.extend_from_slice(constant);
    let rc4_key = md5(&md5_in);

    let mut des_wrapped = *crypted_hash;
    let mut rc4 = Rc4::new(&rc4_key);
    rc4.apply_keystream(&mut des_wrapped);

    sam_des_decrypt_hash_with_rid(rid, &des_wrapped)
}

/// Encrypts a single 16-byte SAM User Hash using **Legacy Revision 1 (RC4 + RID-DES)** (`samedit.py`).
pub fn encrypt_sam_hash_rc4(
    rid: u32,
    hashed_bootkey: &[u8; 16],
    plain_hash: &[u8; 16],
    is_nt_hash: bool,
) -> [u8; 16] {
    let mut des_wrapped = sam_des_encrypt_hash_with_rid(rid, plain_hash);
    let constant = if is_nt_hash {
        SAM_NTPASSWORD_CONST
    } else {
        SAM_LMPASSWORD_CONST
    };
    let mut md5_in = Vec::with_capacity(16 + 4 + constant.len());
    md5_in.extend_from_slice(hashed_bootkey);
    md5_in.extend_from_slice(&rid.to_le_bytes());
    md5_in.extend_from_slice(constant);
    let rc4_key = md5(&md5_in);

    let mut rc4 = Rc4::new(&rc4_key);
    rc4.apply_keystream(&mut des_wrapped);
    des_wrapped
}

/// Decrypts a single 16-byte SAM User Hash using **Modern Revision 2 (`SAM_HASH_AES`: AES-128-CBC + RID-DES)**
/// (Windows Server 2016 / 2019 / 2022 / 2025).
pub fn decrypt_sam_hash_aes(
    rid: u32,
    hashed_bootkey: &[u8; 16],
    salt_iv: &[u8; 16],
    crypted_hash_16: &[u8; 16],
) -> [u8; 16] {
    let dec = aes128::decrypt_cbc(hashed_bootkey, salt_iv, crypted_hash_16);
    let des_wrapped: [u8; 16] = dec[0..16].try_into().unwrap();
    sam_des_decrypt_hash_with_rid(rid, &des_wrapped)
}

/// Encrypts a single 16-byte SAM User Hash using **Modern Revision 2 (`SAM_HASH_AES`: AES-128-CBC + RID-DES)**.
pub fn encrypt_sam_hash_aes(
    rid: u32,
    hashed_bootkey: &[u8; 16],
    salt_iv: &[u8; 16],
    plain_hash: &[u8; 16],
) -> [u8; 16] {
    let des_wrapped = sam_des_encrypt_hash_with_rid(rid, plain_hash);
    let enc = aes128::encrypt_cbc(hashed_bootkey, salt_iv, &des_wrapped);
    enc[0..16].try_into().unwrap()
}

// ----------------------------------------------------------------------------
// Offline SAM-hive user extraction (secretsdump LOCAL).
// ----------------------------------------------------------------------------

#[inline]
fn rd_u32_le(b: &[u8], o: usize) -> Result<u32, CoreError> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(CoreError::BufferUnderflow { needed: o + 4, available: b.len() })
}

/// Derives the `HashedBootKey` from the `SAM\Domains\Account` `F` value using the `BootKey`
/// (`secretsdump.py:SAMHashes.getHashedBootKey`). Handles Revision 1 (RC4) and Revision 2/3 (AES).
pub fn hashed_bootkey_from_f(f: &[u8], bootkey: &[u8; 16]) -> Result<[u8; 16], CoreError> {
    if f.len() < 0x74 {
        return Err(CoreError::BufferUnderflow { needed: 0x74, available: f.len() });
    }
    let revision = rd_u32_le(f, 0x70)?;
    match revision {
        1 => {
            let salt: [u8; 16] = f
                .get(0x78..0x88)
                .ok_or(CoreError::BufferUnderflow { needed: 0x88, available: f.len() })?
                .try_into()
                .unwrap();
            let enc: [u8; 32] = f
                .get(0x88..0xA8)
                .ok_or(CoreError::BufferUnderflow { needed: 0xA8, available: f.len() })?
                .try_into()
                .unwrap();
            derive_hashed_bootkey_rc4(bootkey, &salt, &enc)
        }
        2 | 3 => {
            let data_len = rd_u32_le(f, 0x7C)? as usize;
            let salt: [u8; 16] = f
                .get(0x80..0x90)
                .ok_or(CoreError::BufferUnderflow { needed: 0x90, available: f.len() })?
                .try_into()
                .unwrap();
            let data = f
                .get(0x90..0x90 + data_len)
                .ok_or(CoreError::BufferUnderflow { needed: 0x90 + data_len, available: f.len() })?;
            derive_hashed_bootkey_aes(bootkey, &salt, data)
        }
        other => Err(CoreError::ProtocolError(format!("unknown SAM_KEY_DATA revision {}", other))),
    }
}

/// Decrypts one hash block (`SAM_HASH` rev1 RC4 or `SAM_HASH_AES` rev2) from a user `V` record.
/// Empty/absent blocks yield the Windows empty-hash constant.
fn decrypt_sam_hash_block(block: &[u8], rid: u32, hbootkey: &[u8; 16], is_nt: bool) -> [u8; 16] {
    let empty = if is_nt { EMPTY_NT_HASH } else { EMPTY_LM_HASH };
    if block.len() < 4 {
        return empty;
    }
    let revision = u16::from_le_bytes([block[2], block[3]]);
    match revision {
        1 => {
            if block.len() >= 20 {
                let enc: [u8; 16] = block[4..20].try_into().unwrap();
                decrypt_sam_hash_rc4(rid, hbootkey, &enc, is_nt)
            } else {
                empty
            }
        }
        2 => {
            if block.len() >= 40 {
                let salt: [u8; 16] = block[8..24].try_into().unwrap();
                let enc: [u8; 16] = block[24..40].try_into().unwrap();
                decrypt_sam_hash_aes(rid, hbootkey, &salt, &enc)
            } else {
                empty
            }
        }
        _ => empty,
    }
}

/// Parses a user `V` record into a decrypted account (`secretsdump.py` user-hash extraction).
///
/// Header offset/length pairs (relative to the `0xCC` data base): name @0x0C, LM-hash @0x9C, NT-hash
/// @0xA8.
pub fn parse_sam_user_v(v: &[u8], rid: u32, hbootkey: &[u8; 16]) -> Result<DecryptedSamAccount, CoreError> {
    if v.len() < 0xCC {
        return Err(CoreError::BufferUnderflow { needed: 0xCC, available: v.len() });
    }
    let base = 0xCCusize;
    let name_off = base + rd_u32_le(v, 0x0C)? as usize;
    let name_len = rd_u32_le(v, 0x10)? as usize;
    let username = v
        .get(name_off..name_off + name_len)
        .map(decode_utf16le)
        .transpose()?
        .unwrap_or_default();

    let lm_off = base + rd_u32_le(v, 0x9C)? as usize;
    let lm_len = rd_u32_le(v, 0xA0)? as usize;
    let nt_off = base + rd_u32_le(v, 0xA8)? as usize;
    let nt_len = rd_u32_le(v, 0xAC)? as usize;

    let lm = if lm_len > 0 {
        decrypt_sam_hash_block(v.get(lm_off..lm_off + lm_len).unwrap_or(&[]), rid, hbootkey, false)
    } else {
        EMPTY_LM_HASH
    };
    let nt = if nt_len > 0 {
        decrypt_sam_hash_block(v.get(nt_off..nt_off + nt_len).unwrap_or(&[]), rid, hbootkey, true)
    } else {
        EMPTY_NT_HASH
    };

    Ok(DecryptedSamAccount {
        username,
        rid,
        hashes: NtlmHashes { lm, nt, has_lm: lm_len > 0 },
    })
}

/// Dumps local SAM accounts from offline `SAM` + `SYSTEM` hives (`secretsdump` LOCAL mode).
pub fn secretsdump_local(sam_hive: &[u8], system_hive: &[u8]) -> Result<Vec<DecryptedSamAccount>, CoreError> {
    let bootkey = bootkey_from_system_hive(system_hive)?;
    let hive = reg::Hive::new(sam_hive)?;
    let root = hive.root()?;
    let err = |m: &str| CoreError::ProtocolError(m.into());

    let account = hive
        .navigate(&root, &["SAM", "Domains", "Account"])?
        .ok_or_else(|| err("SAM\\Domains\\Account missing"))?;
    let f = hive.get_value(&account, "F")?.ok_or_else(|| err("Account\\F missing"))?;
    let hbootkey = hashed_bootkey_from_f(&f.data, &bootkey)?;

    let users = hive.find_subkey(&account, "Users")?.ok_or_else(|| err("Account\\Users missing"))?;
    let mut out = Vec::new();
    for user in hive.subkeys(&users)? {
        if user.name.eq_ignore_ascii_case("Names") {
            continue;
        }
        let rid = match u32::from_str_radix(&user.name, 16) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if let Some(v) = hive.get_value(&user, "V")? {
            if let Ok(acct) = parse_sam_user_v(&v.data, rid, &hbootkey) {
                out.push(acct);
            }
        }
    }
    Ok(out)
}

/// Computes standard NT hash from UTF-16LE password bytes using MD4.
pub fn compute_nt_hash(password: &str) -> [u8; 16] {
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    impacket_crypto::md4(&utf16)
}

/// Updates a user's NT password hash inside an offline SAM hive byte buffer (`samedit.py`).
/// Returns the user's RID upon successful update.
pub fn update_sam_user_password(
    sam_hive: &mut [u8],
    system_hive: &[u8],
    target_username: &str,
    new_password: &str,
) -> Result<u32, CoreError> {
    let bootkey = bootkey_from_system_hive(system_hive)?;
    let hive = reg::Hive::new(sam_hive)?;
    let root = hive.root()?;
    let err = |m: &str| CoreError::ProtocolError(m.into());

    let account = hive
        .navigate(&root, &["SAM", "Domains", "Account"])?
        .ok_or_else(|| err("SAM\\Domains\\Account missing"))?;
    let f = hive.get_value(&account, "F")?.ok_or_else(|| err("Account\\F missing"))?;
    let hbootkey = hashed_bootkey_from_f(&f.data, &bootkey)?;

    let users = hive.find_subkey(&account, "Users")?.ok_or_else(|| err("Account\\Users missing"))?;

    let mut target_rid = None;
    let mut target_nk = None;
    for user_nk in hive.subkeys(&users)? {
        if user_nk.name.eq_ignore_ascii_case("Names") {
            continue;
        }
        let rid = match u32::from_str_radix(&user_nk.name, 16) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if let Some(v) = hive.get_value(&user_nk, "V")? {
            if let Ok(acct) = parse_sam_user_v(&v.data, rid, &hbootkey) {
                if acct.username.eq_ignore_ascii_case(target_username) {
                    target_rid = Some(rid);
                    target_nk = Some(user_nk);
                    break;
                }
            }
        }
    }

    let rid = target_rid.ok_or_else(|| {
        CoreError::ProtocolError(format!("User '{}' not found in SAM hive", target_username))
    })?;
    let nk = target_nk.unwrap();

    let (v_abs_offset, v_len) = hive
        .get_value_data_location(&nk, "V")?
        .ok_or_else(|| err("User V value not found"))?;

    if v_abs_offset + v_len > sam_hive.len() || v_len < 0xCC {
        return Err(CoreError::BufferUnderflow {
            needed: v_abs_offset + v_len,
            available: sam_hive.len(),
        });
    }

    let new_nt = compute_nt_hash(new_password);

    let v_slice = &mut sam_hive[v_abs_offset..v_abs_offset + v_len];
    let base = 0xCCusize;
    let nt_off = base + rd_u32_le(v_slice, 0xA8)? as usize;
    let nt_len = rd_u32_le(v_slice, 0xAC)? as usize;

    if nt_off + nt_len > v_slice.len() {
        return Err(CoreError::BufferUnderflow {
            needed: nt_off + nt_len,
            available: v_slice.len(),
        });
    }

    let block = &mut v_slice[nt_off..nt_off + nt_len];
    if block.len() < 4 {
        return Err(CoreError::ProtocolError("Invalid NT hash block".into()));
    }
    let rev = u16::from_le_bytes([block[2], block[3]]);
    match rev {
        1 => {
            if block.len() < 20 {
                return Err(CoreError::ProtocolError("RC4 NT hash block < 20 bytes".into()));
            }
            let enc = encrypt_sam_hash_rc4(rid, &hbootkey, &new_nt, true);
            block[4..20].copy_from_slice(&enc);
        }
        2 => {
            if block.len() < 40 {
                return Err(CoreError::ProtocolError("AES NT hash block < 40 bytes".into()));
            }
            let salt: [u8; 16] = block[8..24].try_into().unwrap();
            let enc = encrypt_sam_hash_aes(rid, &hbootkey, &salt, &new_nt);
            block[24..40].copy_from_slice(&enc);
        }
        _ => return Err(CoreError::ProtocolError(format!("Unsupported NT hash revision {}", rev))),
    }

    // Zero out / disable LM hash if present
    let lm_off = base + rd_u32_le(v_slice, 0x9C)? as usize;
    let lm_len = rd_u32_le(v_slice, 0xA0)? as usize;
    if lm_len > 0 && lm_off + lm_len <= v_slice.len() {
        let lm_block = &mut v_slice[lm_off..lm_off + lm_len];
        if lm_block.len() >= 4 {
            let lm_rev = u16::from_le_bytes([lm_block[2], lm_block[3]]);
            match lm_rev {
                1 if lm_block.len() >= 20 => {
                    let enc = encrypt_sam_hash_rc4(rid, &hbootkey, &EMPTY_LM_HASH, false);
                    lm_block[4..20].copy_from_slice(&enc);
                }
                2 if lm_block.len() >= 40 => {
                    let salt: [u8; 16] = lm_block[8..24].try_into().unwrap();
                    let enc = encrypt_sam_hash_aes(rid, &hbootkey, &salt, &EMPTY_LM_HASH);
                    lm_block[24..40].copy_from_slice(&enc);
                }
                _ => {}
            }
        }
    }

    reg::update_hive_checksum(sam_hive);
    Ok(rid)
}

/// Decrypted user credential record formatted in standard `secretsdump.py` `username:RID:LMHASH:NTHASH:::` syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedSamAccount {
    pub username: String,
    pub rid: u32,
    pub hashes: NtlmHashes,
}

impl DecryptedSamAccount {
    pub fn to_secretsdump_line(&self) -> String {
        format!(
            "{}:{}:{}:{}:::",
            self.username,
            self.rid,
            encode_hex(&self.hashes.lm),
            encode_hex(&self.hashes.nt)
        )
    }
}

/// Complete report returned by `secretsdump` (`examples/secretsdump.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretsDumpReport {
    pub target: String,
    pub bootkey: [u8; 16],
    pub hashed_bootkey: [u8; 16],
    pub encryption_style: &'static str,
    pub sam_accounts: Vec<DecryptedSamAccount>,
}

/// Test-only crypto round-trip: encrypts then decrypts SAM hashes across Legacy Revision 1 (RC4+DES)
/// and Modern Revision 2 (AES-128-CBC+DES) to verify the real `secretsdump` decryption primitives.
/// Not a live `secretsdump`; offline hive (`SAM`/`SYSTEM`) parsing is a separate (pending) module.
#[cfg(test)]
fn run_secretsdump_crypto_roundtrip(profile: AdCompatProfile) -> Result<SecretsDumpReport, CoreError> {
    // 1. Recover BootKey from SYSTEM\CurrentControlSet\Control\Lsa\{JD, Skew1, GBG, Data}
    let bootkey = compute_bootkey_from_lsa_classes("4a6f7931", "536b6577", "47424732", "44617461")?;
    let expected_hbootkey: [u8; 16] = [
        0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
        0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce, 0xbf, 0xb0,
    ];
    let f_salt = [0x3Cu8; 16];

    let raw_users: &[(&str, u32, [u8; 16], [u8; 16])] = &[
        (
            "Administrator",
            500,
            EMPTY_LM_HASH,
            [
                0x2b, 0x57, 0x6a, 0xcb, 0xe6, 0xbc, 0xfd, 0xa7,
                0x29, 0x4d, 0x6b, 0xd1, 0x80, 0x41, 0xb8, 0xfe,
            ],
        ),
        ("Guest", 501, EMPTY_LM_HASH, EMPTY_NT_HASH),
        (
            "DefaultAccount",
            503,
            EMPTY_LM_HASH,
            EMPTY_NT_HASH,
        ),
        (
            "svc_backup",
            1105,
            EMPTY_LM_HASH,
            [
                0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17,
                0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c,
            ],
        ),
    ];

    if profile == AdCompatProfile::LegacyWin2000 {
        // Legacy Revision 1: RC4 HashedBootKey + RC4/DES per-RID hash encryption
        let enc_key0 = encrypt_hashed_bootkey_rc4(&bootkey, &f_salt, &expected_hbootkey);
        let hbootkey = derive_hashed_bootkey_rc4(&bootkey, &f_salt, &enc_key0)?;

        let mut sam_accounts = Vec::with_capacity(raw_users.len());
        for (user, rid, lm, nt) in raw_users {
            let enc_lm = encrypt_sam_hash_rc4(*rid, &hbootkey, lm, false);
            let enc_nt = encrypt_sam_hash_rc4(*rid, &hbootkey, nt, true);

            let dec_lm = decrypt_sam_hash_rc4(*rid, &hbootkey, &enc_lm, false);
            let dec_nt = decrypt_sam_hash_rc4(*rid, &hbootkey, &enc_nt, true);

            sam_accounts.push(DecryptedSamAccount {
                username: (*user).to_string(),
                rid: *rid,
                hashes: NtlmHashes {
                    lm: dec_lm,
                    nt: dec_nt,
                    has_lm: false,
                },
            });
        }

        Ok(SecretsDumpReport {
            target: "LOCAL (SAM/SYSTEM Hive - Legacy Revision 1)".into(),
            bootkey,
            hashed_bootkey: hbootkey,
            encryption_style: "SAM_HASH Revision 1 (MD5 + RC4 + RID-DES [Win2000 -> Win2012R2])",
            sam_accounts,
        })
    } else {
        // Modern Revision 2: AES-128-CBC HashedBootKey + AES-128-CBC/DES per-RID hash encryption
        let enc_key0 = aes128::encrypt_cbc(&bootkey, &f_salt, &expected_hbootkey);
        let hbootkey = derive_hashed_bootkey_aes(&bootkey, &f_salt, &enc_key0)?;

        let user_salt = [0x7Eu8; 16];
        let mut sam_accounts = Vec::with_capacity(raw_users.len());
        for (user, rid, lm, nt) in raw_users {
            let enc_lm = encrypt_sam_hash_aes(*rid, &hbootkey, &user_salt, lm);
            let enc_nt = encrypt_sam_hash_aes(*rid, &hbootkey, &user_salt, nt);

            let dec_lm = decrypt_sam_hash_aes(*rid, &hbootkey, &user_salt, &enc_lm);
            let dec_nt = decrypt_sam_hash_aes(*rid, &hbootkey, &user_salt, &enc_nt);

            sam_accounts.push(DecryptedSamAccount {
                username: (*user).to_string(),
                rid: *rid,
                hashes: NtlmHashes {
                    lm: dec_lm,
                    nt: dec_nt,
                    has_lm: false,
                },
            });
        }

        Ok(SecretsDumpReport {
            target: "LOCAL (SAM/SYSTEM Hive - Modern AES Revision 2)".into(),
            bootkey,
            hashed_bootkey: hbootkey,
            encryption_style: "SAM_HASH_AES Revision 2 (AES-128-CBC + RID-DES [Win2016 -> Win2025])",
            sam_accounts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashed_bootkey_from_f_and_user_v_parse() {
        let bootkey = [0x42u8; 16];
        let hbootkey: [u8; 16] = [
            0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
            0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce, 0xbf, 0xb0,
        ];
        // Build a Revision-1 F value: salt @0x78, encrypted Key||CheckSum @0x88.
        let salt = [0x3Cu8; 16];
        let enc = encrypt_hashed_bootkey_rc4(&bootkey, &salt, &hbootkey);
        let mut f = vec![0u8; 0xA8];
        f[0x70] = 1; // Revision
        f[0x78..0x88].copy_from_slice(&salt);
        f[0x88..0xA8].copy_from_slice(&enc);
        assert_eq!(hashed_bootkey_from_f(&f, &bootkey).unwrap(), hbootkey);

        // Build a V record: name "Administrator" at data base, NT SAM_HASH (rev1) after it.
        let rid = 500u32;
        let plain_nt: [u8; 16] = [
            0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17,
            0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c,
        ];
        let nt_enc = encrypt_sam_hash_rc4(rid, &hbootkey, &plain_nt, true);
        let name: Vec<u8> = "Administrator".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();

        let base = 0xCCusize;
        let mut v = vec![0u8; 0x120];
        // name at data rel 0.
        v[base..base + name.len()].copy_from_slice(&name);
        v[0x0C..0x10].copy_from_slice(&0u32.to_le_bytes());
        v[0x10..0x14].copy_from_slice(&(name.len() as u32).to_le_bytes());
        // NT hash block at data rel = name.len().
        let nt_rel = name.len();
        let block_abs = base + nt_rel;
        v[block_abs] = 0; // PekID
        v[block_abs + 1] = 0;
        v[block_abs + 2] = 1; // Revision = 1 (RC4)
        v[block_abs + 3] = 0;
        v[block_abs + 4..block_abs + 20].copy_from_slice(&nt_enc);
        v[0xA8..0xAC].copy_from_slice(&(nt_rel as u32).to_le_bytes());
        v[0xAC..0xB0].copy_from_slice(&20u32.to_le_bytes());

        let acct = parse_sam_user_v(&v, rid, &hbootkey).unwrap();
        assert_eq!(acct.username, "Administrator");
        assert_eq!(acct.rid, 500);
        assert_eq!(acct.hashes.nt, plain_nt);
        assert_eq!(acct.hashes.lm, EMPTY_LM_HASH);
        assert_eq!(
            acct.to_secretsdump_line(),
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"
        );
    }

    #[test]
    fn test_secretsdump_legacy_rc4_and_modern_aes_roundtrip() {
        let legacy = run_secretsdump_crypto_roundtrip(AdCompatProfile::LegacyWin2000).unwrap();
        assert_eq!(
            legacy.sam_accounts[0].to_secretsdump_line(),
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::"
        );
        assert_eq!(
            legacy.sam_accounts[3].to_secretsdump_line(),
            "svc_backup:1105:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"
        );

        let modern = run_secretsdump_crypto_roundtrip(AdCompatProfile::UniversalAuto).unwrap();
        assert_eq!(modern.bootkey, legacy.bootkey);
        assert_eq!(modern.hashed_bootkey, legacy.hashed_bootkey);
        assert_eq!(
            modern.sam_accounts[0].to_secretsdump_line(),
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::"
        );
    }

    #[test]
    fn test_update_sam_user_v_in_place() {
        let rid = 500u32;
        let hbootkey: [u8; 16] = [
            0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
            0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce, 0xbf, 0xb0,
        ];
        let plain_nt: [u8; 16] = [
            0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17,
            0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c,
        ];
        let nt_enc = encrypt_sam_hash_rc4(rid, &hbootkey, &plain_nt, true);
        let name: Vec<u8> = "Administrator".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();

        let base = 0xCCusize;
        let mut v = vec![0u8; 0x120];
        v[base..base + name.len()].copy_from_slice(&name);
        v[0x0C..0x10].copy_from_slice(&0u32.to_le_bytes());
        v[0x10..0x14].copy_from_slice(&(name.len() as u32).to_le_bytes());
        let nt_rel = name.len();
        let block_abs = base + nt_rel;
        v[block_abs] = 0;
        v[block_abs + 1] = 0;
        v[block_abs + 2] = 1; // Revision = 1 (RC4)
        v[block_abs + 3] = 0;
        v[block_abs + 4..block_abs + 20].copy_from_slice(&nt_enc);
        v[0xA8..0xAC].copy_from_slice(&(nt_rel as u32).to_le_bytes());
        v[0xAC..0xB0].copy_from_slice(&20u32.to_le_bytes());

        // Replace password with "NewP@ssw0rd!"
        let new_nt = compute_nt_hash("NewP@ssw0rd!");
        let new_enc = encrypt_sam_hash_rc4(rid, &hbootkey, &new_nt, true);
        v[block_abs + 4..block_abs + 20].copy_from_slice(&new_enc);

        let acct = parse_sam_user_v(&v, rid, &hbootkey).unwrap();
        assert_eq!(acct.hashes.nt, new_nt);
    }
}
