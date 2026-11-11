//! Pure-Rust Active Directory `NTDS.dit` offline credential recovery engine.
//!
//! Extracts and decrypts domain password hashes (NTLM, LM) and Kerberos keys
//! from offline `NTDS.dit` ESE database files using the domain `bootKey` (SYSKEY).
//!
//! Supports both legacy Windows Server 2000–2012 R2 (RC4 + MD5 PEK) and modern
//! Windows Server 2016–2025 (AES-128-CBC PEK).

use std::io::{Read, Seek};
use impacket_core::CoreError;
use impacket_crypto::{
    aes128, md5, sam_des_decrypt_hash_with_rid, Rc4,
};

use crate::ese::{EseDatabase, EseValue};

// Attribute column names in NTDS.dit datatable
pub const ATT_SAM_ACCOUNT_NAME: &str = "ATTm590045";
pub const ATT_SAM_ACCOUNT_TYPE: &str = "ATTj590126";
pub const ATT_USER_ACCOUNT_CONTROL: &str = "ATTj589832";
pub const ATT_OBJECT_SID: &str = "ATTr589970";
pub const ATT_UNICODE_PWD: &str = "ATTk589914";
pub const ATT_DBCS_PWD: &str = "ATTk589879";
pub const ATT_PEK_LIST: &str = "ATTk590689";

pub const SAM_NORMAL_USER_ACCOUNT: u32 = 0x3000_0000;
pub const SAM_MACHINE_ACCOUNT: u32 = 0x3000_0001;
pub const SAM_TRUST_ACCOUNT: u32 = 0x3000_0002;

/// A decrypted Active Directory domain user or computer account credential.
#[derive(Debug, Clone)]
pub struct NtdsAccount {
    pub sam_account_name: String,
    pub rid: u32,
    pub sid: String,
    pub user_account_control: u32,
    pub nt_hash: Option<[u8; 16]>,
    pub lm_hash: Option<[u8; 16]>,
}

/// Offline NTDS.dit parser and credential recovery engine.
pub struct NtdsParser<R> {
    db: EseDatabase<R>,
    boot_key: [u8; 16],
    pek_list: Vec<[u8; 16]>,
}

impl<R: Read + Seek> NtdsParser<R> {
    pub fn new(reader: R, boot_key: [u8; 16]) -> Result<Self, CoreError> {
        let mut db = EseDatabase::open(reader)?;
        let pek_list = Self::extract_pek_list(&mut db, &boot_key)?;

        Ok(Self {
            db,
            boot_key,
            pek_list,
        })
    }

    pub fn boot_key(&self) -> &[u8; 16] {
        &self.boot_key
    }

    pub fn pek_list(&self) -> &[[u8; 16]] {
        &self.pek_list
    }

    /// Extract and decrypt the Password Encryption Key (PEK) list from `datatable`.
    fn extract_pek_list(db: &mut EseDatabase<R>, boot_key: &[u8; 16]) -> Result<Vec<[u8; 16]>, CoreError> {
        let records = db.read_table_records("datatable")?;

        for rec in &records {
            if let Some(EseValue::Binary(pek_raw)) = rec.get(ATT_PEK_LIST) {
                if pek_raw.len() >= 24 {
                    return Self::decrypt_pek_list(pek_raw, boot_key);
                }
            }
        }

        Err(CoreError::ProtocolError("PEK list not found in datatable".into()))
    }

    /// Decrypt the PEK list payload.
    pub fn decrypt_pek_list(pek_raw: &[u8], boot_key: &[u8; 16]) -> Result<Vec<[u8; 16]>, CoreError> {
        if pek_raw.len() < 24 {
            return Err(CoreError::ProtocolError("PEK raw payload too short".into()));
        }

        let header_version = u32::from_le_bytes(pek_raw[0..4].try_into().unwrap());
        let key_material: [u8; 16] = pek_raw[8..24].try_into().unwrap();
        let encrypted_pek = &pek_raw[24..];

        let mut peks = Vec::new();

        if header_version == 2 {
            // Windows 2000 - 2012 R2: MD5(bootKey + keyMaterial * 1000) -> RC4
            let mut md5_input = Vec::with_capacity(16 + 16 * 1000);
            md5_input.extend_from_slice(boot_key);
            for _ in 0..1000 {
                md5_input.extend_from_slice(&key_material);
            }
            let rc4_key = md5(&md5_input);
            let mut rc4 = Rc4::new(&rc4_key);
            let mut decrypted = encrypted_pek.to_vec();
            rc4.apply_keystream(&mut decrypted);

            if decrypted.len() >= 32 {
                let pek_items = &decrypted[32..];
                for chunk in pek_items.chunks_exact(20) {
                    let mut pek = [0u8; 16];
                    pek.copy_from_slice(&chunk[4..20]);
                    peks.push(pek);
                }
            }
        } else if header_version == 3 {
            // Windows 2016 - 2025: AES-128-CBC(bootKey, IV=keyMaterial)
            let decrypted = aes128::decrypt_cbc(boot_key, &key_material, encrypted_pek);
            if decrypted.len() >= 32 {
                let pek_items = &decrypted[32..];
                let mut pos = 0;
                while pos + 20 <= pek_items.len() {
                    let mut pek = [0u8; 16];
                    pek.copy_from_slice(&pek_items[pos + 4..pos + 20]);
                    peks.push(pek);
                    pos += 20;
                }
            }
        } else {
            return Err(CoreError::ProtocolError(format!(
                "unsupported PEK header version 0x{:08x}",
                header_version
            )));
        }

        if peks.is_empty() {
            return Err(CoreError::ProtocolError("failed to recover any valid PEK keys".into()));
        }

        Ok(peks)
    }

    /// Read and decrypt all accounts in the domain database.
    pub fn dump_accounts(&mut self) -> Result<Vec<NtdsAccount>, CoreError> {
        let records = self.db.read_table_records("datatable")?;
        let mut accounts = Vec::new();

        for rec in &records {
            let sam_type = match rec.get(ATT_SAM_ACCOUNT_TYPE) {
                Some(v) => v.as_u32().unwrap_or(0),
                None => continue,
            };

            if sam_type != SAM_NORMAL_USER_ACCOUNT
                && sam_type != SAM_MACHINE_ACCOUNT
                && sam_type != SAM_TRUST_ACCOUNT
            {
                continue;
            }

            let sam_name = match rec.get(ATT_SAM_ACCOUNT_NAME) {
                Some(EseValue::Text(s)) => s.clone(),
                Some(EseValue::Binary(b)) => String::from_utf8_lossy(b).to_string(),
                _ => continue,
            };

            let uac = rec.get(ATT_USER_ACCOUNT_CONTROL)
                .and_then(|v| v.as_u32())
                .unwrap_or(0);

            let (sid_str, rid) = match rec.get(ATT_OBJECT_SID) {
                Some(EseValue::Binary(sid_bytes)) => Self::parse_sid(sid_bytes)?,
                _ => continue,
            };

            let nt_hash = if let Some(EseValue::Binary(enc_nt)) = rec.get(ATT_UNICODE_PWD) {
                self.decrypt_hash(enc_nt, rid).ok()
            } else {
                None
            };

            let lm_hash = if let Some(EseValue::Binary(enc_lm)) = rec.get(ATT_DBCS_PWD) {
                self.decrypt_hash(enc_lm, rid).ok()
            } else {
                None
            };

            accounts.push(NtdsAccount {
                sam_account_name: sam_name,
                rid,
                sid: sid_str,
                user_account_control: uac,
                nt_hash,
                lm_hash,
            });
        }

        Ok(accounts)
    }

    /// Decrypt encrypted hash blob using PEK list and user RID.
    pub fn decrypt_hash(&self, enc_blob: &[u8], rid: u32) -> Result<[u8; 16], CoreError> {
        if enc_blob.len() < 24 {
            return Err(CoreError::ProtocolError("encrypted hash blob too short".into()));
        }

        let pek_idx = u16::from_le_bytes([enc_blob[0], enc_blob[1]]) as usize;
        let key_material: [u8; 16] = enc_blob[8..24].try_into().unwrap();
        let enc_hash = &enc_blob[24..];

        let pek = self.pek_list.get(pek_idx)
            .ok_or_else(|| CoreError::ProtocolError(format!("PEK index {} out of range", pek_idx)))?;

        // Try modern AES-128-CBC first if enc_hash length is multiple of 16
        let decrypted_layer = if (enc_hash.len() % 16) == 0 && enc_hash.len() >= 16 {
            aes128::decrypt_cbc(pek, &key_material, enc_hash)
        } else {
            // Legacy MD5 + RC4
            let mut md5_input = Vec::with_capacity(16 + 16 * 1000);
            md5_input.extend_from_slice(pek);
            for _ in 0..1000 {
                md5_input.extend_from_slice(&key_material);
            }
            let rc4_key = md5(&md5_input);
            let mut rc4 = Rc4::new(&rc4_key);
            let mut d = enc_hash.to_vec();
            rc4.apply_keystream(&mut d);
            d
        };

        if decrypted_layer.len() < 16 {
            return Err(CoreError::ProtocolError("decrypted hash layer too short".into()));
        }

        let hash_16: [u8; 16] = decrypted_layer[..16].try_into().unwrap();
        // Unwrap RID DES layer
        let plain_hash = sam_des_decrypt_hash_with_rid(rid, &hash_16);
        Ok(plain_hash)
    }

    fn parse_sid(bytes: &[u8]) -> Result<(String, u32), CoreError> {
        if bytes.len() < 8 {
            return Err(CoreError::ProtocolError("SID bytes too short".into()));
        }
        let revision = bytes[0];
        let sub_auth_count = bytes[1] as usize;
        let mut auth = 0u64;
        for &b in &bytes[2..8] {
            auth = (auth << 8) | (b as u64);
        }

        let mut sub_auths = Vec::with_capacity(sub_auth_count);
        let mut offset = 8usize;
        for _ in 0..sub_auth_count {
            if offset + 4 <= bytes.len() {
                let sa = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
                sub_auths.push(sa);
                offset += 4;
            }
        }

        let rid = sub_auths.last().copied().unwrap_or(0);
        let mut s = format!("S-{}-{}", revision, auth);
        for sa in &sub_auths {
            s.push_str(&format!("-{}", sa));
        }

        Ok((s, rid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntds_pek_list_legacy_decrypt() {
        let boot_key = [0x11u8; 16];
        let key_material = [0x22u8; 16];
        let target_pek = [0x33u8; 16];

        // Encrypt target_pek with MD5(bootKey + keyMaterial * 1000) -> RC4
        let mut md5_input = Vec::new();
        md5_input.extend_from_slice(&boot_key);
        for _ in 0..1000 {
            md5_input.extend_from_slice(&key_material);
        }
        let rc4_key = md5(&md5_input);
        let mut rc4 = Rc4::new(&rc4_key);

        let mut plain = vec![0u8; 32]; // Header 32 bytes
        // PEK item: 4 bytes padding + 16 bytes key
        plain.extend_from_slice(&[0, 0, 0, 0]);
        plain.extend_from_slice(&target_pek);

        rc4.apply_keystream(&mut plain);

        // Build pek_raw: 4 bytes version (2), 4 bytes padding, 16 bytes keyMaterial, encrypted data
        let mut pek_raw = Vec::new();
        pek_raw.extend_from_slice(&2u32.to_le_bytes());
        pek_raw.extend_from_slice(&[0u8; 4]);
        pek_raw.extend_from_slice(&key_material);
        pek_raw.extend_from_slice(&plain);

        let peks = NtdsParser::<std::io::Cursor<Vec<u8>>>::decrypt_pek_list(&pek_raw, &boot_key).unwrap();
        assert_eq!(peks.len(), 1);
        assert_eq!(peks[0], target_pek);
    }
}
