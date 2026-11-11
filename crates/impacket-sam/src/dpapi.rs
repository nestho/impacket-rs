//! Pure-Rust Data Protection API (DPAPI) MasterKey and Blob parser and decryption engine.
//!
//! Provides offline extraction and decryption of Windows DPAPI MasterKey files,
//! stored Credential Manager entries, and encrypted DPAPI blobs using recovered
//! domain backup keys, user password hashes, or `SECURITY` hive `DPAPI_SYSTEM` keys.
//!
//! Reference:
//! - [MS-BKRP]: Backup Key Remote Protocol
//! - Benjamin Delpy (Gentilkiwi), Mimikatz DPAPI documentation
//! - Alberto Solino, Impacket `impacket/dpapi.py`

use impacket_core::CoreError;
use impacket_crypto::{
    aes256, des3_cbc_decrypt, hmac_sha1, hmac_sha512, md4, pbkdf2_hmac_sha256, sha1,
};

pub const CALG_MD5: u32 = 0x8003;
pub const CALG_SHA1: u32 = 0x8004;
pub const CALG_3DES: u32 = 0x6603;
pub const CALG_AES_128: u32 = 0x660e;
pub const CALG_AES_192: u32 = 0x660f;
pub const CALG_AES_256: u32 = 0x6610;
pub const CALG_HMAC: u32 = 0x8009;
pub const CALG_SHA_512: u32 = 0x800e;

/// Parsed DPAPI MasterKey file (from `%APPDATA%\Microsoft\Protect\<SID>\<GUID>`).
#[derive(Debug, Clone)]
pub struct MasterKeyFile {
    pub version: u32,
    pub guid: String,
    pub flags: u32,
    pub policy: u32,
    pub master_key_bytes: Vec<u8>,
    pub backup_key_bytes: Vec<u8>,
    pub cred_hist_bytes: Vec<u8>,
    pub domain_key_bytes: Vec<u8>,
}

impl MasterKeyFile {
    pub fn parse(buf: &[u8]) -> Result<Self, CoreError> {
        if buf.len() < 120 {
            return Err(CoreError::ProtocolError("master key file header too small".into()));
        }
        let version = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let guid_raw = &buf[12..84];
        let guid_u16s: Vec<u16> = guid_raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        let guid = String::from_utf16_lossy(&guid_u16s);

        let policy = u32::from_le_bytes(buf[88..92].try_into().unwrap());
        let flags = u32::from_le_bytes(buf[92..96].try_into().unwrap());
        let master_key_len = u64::from_le_bytes(buf[96..104].try_into().unwrap()) as usize;
        let backup_key_len = u64::from_le_bytes(buf[104..112].try_into().unwrap()) as usize;
        let cred_hist_len = u64::from_le_bytes(buf[112..120].try_into().unwrap()) as usize;
        let domain_key_len = if buf.len() >= 128 {
            u64::from_le_bytes(buf[120..128].try_into().unwrap()) as usize
        } else {
            0
        };

        let mut offset = if buf.len() >= 128 { 128 } else { 120 };

        let mk_end = (offset + master_key_len).min(buf.len());
        let master_key_bytes = if offset < buf.len() { buf[offset..mk_end].to_vec() } else { Vec::new() };
        offset += master_key_len;

        let bk_end = (offset + backup_key_len).min(buf.len());
        let backup_key_bytes = if offset < buf.len() { buf[offset..bk_end].to_vec() } else { Vec::new() };
        offset += backup_key_len;

        let ch_end = (offset + cred_hist_len).min(buf.len());
        let cred_hist_bytes = if offset < buf.len() { buf[offset..ch_end].to_vec() } else { Vec::new() };
        offset += cred_hist_len;

        let dk_end = (offset + domain_key_len).min(buf.len());
        let domain_key_bytes = if offset < buf.len() { buf[offset..dk_end].to_vec() } else { Vec::new() };

        Ok(Self {
            version,
            guid,
            flags,
            policy,
            master_key_bytes,
            backup_key_bytes,
            cred_hist_bytes,
            domain_key_bytes,
        })
    }
}

/// Parsed DPAPI MasterKey structure.
#[derive(Debug, Clone)]
pub struct MasterKey {
    pub version: u32,
    pub salt: [u8; 16],
    pub rounds: u32,
    pub hash_algo: u32,
    pub crypt_algo: u32,
    pub data: Vec<u8>,
}

impl MasterKey {
    pub fn parse(buf: &[u8]) -> Result<Self, CoreError> {
        if buf.len() < 32 {
            return Err(CoreError::ProtocolError("master key payload too small".into()));
        }
        let version = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&buf[4..20]);
        let rounds = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        let hash_algo = u32::from_le_bytes(buf[24..28].try_into().unwrap());
        let crypt_algo = u32::from_le_bytes(buf[28..32].try_into().unwrap());
        let data = buf[32..].to_vec();

        Ok(Self {
            version,
            salt,
            rounds,
            hash_algo,
            crypt_algo,
            data,
        })
    }

    /// Decrypt the MasterKey using user key or machine key.
    ///
    /// Returns 64-byte cleartext MasterKey on success.
    pub fn decrypt(&self, key: &[u8]) -> Result<[u8; 64], CoreError> {
        let is_sha512 = self.hash_algo == CALG_SHA_512;
        let (key_len, iv_len) = match self.crypt_algo {
            CALG_AES_256 => (32usize, 16usize),
            CALG_3DES => (24usize, 8usize),
            _ => return Err(CoreError::ProtocolError(format!("unsupported crypt algo 0x{:08x}", self.crypt_algo))),
        };

        let total_kdf_len = key_len + iv_len;

        // Custom PBKDF2 iteration matching DPAPI implementation
        let derived_blob = if is_sha512 {
            Self::derive_key_sha512(key, &self.salt, total_kdf_len, self.rounds)
        } else {
            Self::derive_key_sha1(key, &self.salt, total_kdf_len, self.rounds)
        };

        let crypt_key = &derived_blob[..key_len];
        let iv = &derived_blob[key_len..total_kdf_len];

        let cleartext = match self.crypt_algo {
            CALG_AES_256 => {
                let k: [u8; 32] = crypt_key.try_into().map_err(|_| CoreError::ProtocolError("invalid key length".into()))?;
                let iv_block: [u8; 16] = iv.try_into().map_err(|_| CoreError::ProtocolError("invalid IV length".into()))?;
                aes256::decrypt_cbc(&k, &iv_block, &self.data)
            }
            CALG_3DES => {
                let k: [u8; 24] = crypt_key.try_into().map_err(|_| CoreError::ProtocolError("invalid key length".into()))?;
                let iv_block: [u8; 8] = iv.try_into().map_err(|_| CoreError::ProtocolError("invalid IV length".into()))?;
                des3_cbc_decrypt(&k, &iv_block, &self.data)
            }
            _ => return Err(CoreError::ProtocolError(format!("unsupported crypt algo 0x{:08x}", self.crypt_algo))),
        };

        if cleartext.len() < 80 {
            return Err(CoreError::ProtocolError("decrypted master key too short".into()));
        }

        let hash_len = if is_sha512 { 64 } else { 20 };
        let hmac_salt = &cleartext[..16];
        let hmac_stored = &cleartext[16..16 + hash_len];
        let decrypted_key = &cleartext[cleartext.len() - 64..];

        // Verify HMAC
        let hmac_valid = if is_sha512 {
            let hmac_key = hmac_sha512(key, hmac_salt);
            let calculated = hmac_sha512(&hmac_key, decrypted_key);
            calculated.as_slice() == hmac_stored
        } else {
            let hmac_key = hmac_sha1(key, hmac_salt);
            let calculated = hmac_sha1(&hmac_key, decrypted_key);
            calculated.as_slice() == hmac_stored
        };

        if !hmac_valid {
            return Err(CoreError::ProtocolError("invalid HMAC checksum".into()));
        }

        let mut out = [0u8; 64];
        out.copy_from_slice(decrypted_key);
        Ok(out)
    }

    fn derive_key_sha1(passphrase: &[u8], salt: &[u8], key_len: usize, count: u32) -> Vec<u8> {
        let mut key_material = Vec::with_capacity(key_len);
        let mut i = 1u32;
        while key_material.len() < key_len {
            let mut u = Vec::with_capacity(salt.len() + 4);
            u.extend_from_slice(salt);
            u.extend_from_slice(&i.to_be_bytes());
            i += 1;

            let mut derived = hmac_sha1(passphrase, &u).to_vec();
            for _ in 0..count.saturating_sub(1) {
                let actual = hmac_sha1(passphrase, &derived);
                for (d, a) in derived.iter_mut().zip(actual.iter()) {
                    *d ^= *a;
                }
            }
            key_material.extend_from_slice(&derived);
        }
        key_material.truncate(key_len);
        key_material
    }

    fn derive_key_sha512(passphrase: &[u8], salt: &[u8], key_len: usize, count: u32) -> Vec<u8> {
        let mut key_material = Vec::with_capacity(key_len);
        let mut i = 1u32;
        while key_material.len() < key_len {
            let mut u = Vec::with_capacity(salt.len() + 4);
            u.extend_from_slice(salt);
            u.extend_from_slice(&i.to_be_bytes());
            i += 1;

            let mut derived = hmac_sha512(passphrase, &u).to_vec();
            for _ in 0..count.saturating_sub(1) {
                let actual = hmac_sha512(passphrase, &derived);
                for (d, a) in derived.iter_mut().zip(actual.iter()) {
                    *d ^= *a;
                }
            }
            key_material.extend_from_slice(&derived);
        }
        key_material.truncate(key_len);
        key_material
    }
}

/// Parsed DPAPI encrypted blob (`DPAPI_BLOB`).
#[derive(Debug, Clone)]
pub struct DpapiBlob {
    pub version: u32,
    pub guid_credential: [u8; 16],
    pub master_key_version: u32,
    pub guid_master_key: [u8; 16],
    pub flags: u32,
    pub description: String,
    pub crypt_algo: u32,
    pub salt: Vec<u8>,
    pub hmac_key: Vec<u8>,
    pub hash_algo: u32,
    pub hmac: Vec<u8>,
    pub data: Vec<u8>,
    pub sign: Vec<u8>,
    raw_data: Vec<u8>,
}

impl DpapiBlob {
    pub fn parse(buf: &[u8]) -> Result<Self, CoreError> {
        if buf.len() < 56 {
            return Err(CoreError::ProtocolError("DPAPI blob too small".into()));
        }

        let version = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let mut guid_credential = [0u8; 16];
        guid_credential.copy_from_slice(&buf[4..20]);

        let master_key_version = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        let mut guid_master_key = [0u8; 16];
        guid_master_key.copy_from_slice(&buf[24..40]);

        let flags = u32::from_le_bytes(buf[40..44].try_into().unwrap());
        let desc_len = u32::from_le_bytes(buf[44..48].try_into().unwrap()) as usize;

        let mut offset = 48usize;
        let desc_end = (offset + desc_len).min(buf.len());
        let desc_bytes = if offset < buf.len() { &buf[offset..desc_end] } else { &[] };
        let desc_u16s: Vec<u16> = desc_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&u| u != 0)
            .collect();
        let description = String::from_utf16_lossy(&desc_u16s);
        offset += desc_len;

        if offset + 8 > buf.len() {
            return Err(CoreError::ProtocolError("DPAPI blob truncated at crypt algo".into()));
        }
        let crypt_algo = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
        let _crypt_algo_len = u32::from_le_bytes(buf[offset + 4..offset + 8].try_into().unwrap());
        offset += 8;

        if offset + 4 > buf.len() {
            return Err(CoreError::ProtocolError("DPAPI blob truncated at salt len".into()));
        }
        let salt_len = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let salt = if offset + salt_len <= buf.len() {
            buf[offset..offset + salt_len].to_vec()
        } else {
            return Err(CoreError::ProtocolError("DPAPI blob truncated at salt".into()));
        };
        offset += salt_len;

        if offset + 4 > buf.len() {
            return Err(CoreError::ProtocolError("DPAPI blob truncated at hmac key len".into()));
        }
        let hmac_key_len = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let hmac_key = if offset + hmac_key_len <= buf.len() {
            buf[offset..offset + hmac_key_len].to_vec()
        } else {
            return Err(CoreError::ProtocolError("DPAPI blob truncated at hmac key".into()));
        };
        offset += hmac_key_len;

        if offset + 8 > buf.len() {
            return Err(CoreError::ProtocolError("DPAPI blob truncated at hash algo".into()));
        }
        let hash_algo = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
        let _hash_algo_len = u32::from_le_bytes(buf[offset + 4..offset + 8].try_into().unwrap());
        offset += 8;

        if offset + 4 > buf.len() {
            return Err(CoreError::ProtocolError("DPAPI blob truncated at hmac len".into()));
        }
        let hmac_len = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let hmac = if offset + hmac_len <= buf.len() {
            buf[offset..offset + hmac_len].to_vec()
        } else {
            return Err(CoreError::ProtocolError("DPAPI blob truncated at hmac".into()));
        };
        offset += hmac_len;

        if offset + 4 > buf.len() {
            return Err(CoreError::ProtocolError("DPAPI blob truncated at data len".into()));
        }
        let data_len = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let data = if offset + data_len <= buf.len() {
            buf[offset..offset + data_len].to_vec()
        } else {
            return Err(CoreError::ProtocolError("DPAPI blob truncated at data".into()));
        };
        offset += data_len;

        if offset + 4 > buf.len() {
            return Err(CoreError::ProtocolError("DPAPI blob truncated at sign len".into()));
        }
        let sign_len = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let sign = if offset + sign_len <= buf.len() {
            buf[offset..offset + sign_len].to_vec()
        } else {
            return Err(CoreError::ProtocolError("DPAPI blob truncated at sign".into()));
        };

        Ok(Self {
            version,
            guid_credential,
            master_key_version,
            guid_master_key,
            flags,
            description,
            crypt_algo,
            salt,
            hmac_key,
            hash_algo,
            hmac,
            data,
            sign,
            raw_data: buf.to_vec(),
        })
    }

    pub fn raw_data(&self) -> &[u8] {
        &self.raw_data
    }

    /// Decrypt DPAPI blob payload using the 64-byte decrypted MasterKey.
    pub fn decrypt(&self, master_key: &[u8], entropy: Option<&[u8]>) -> Result<Vec<u8>, CoreError> {
        let key_hash = if master_key.len() == 20 {
            let mut h = [0u8; 20];
            h.copy_from_slice(master_key);
            h
        } else {
            sha1(master_key)
        };

        // session_key = HMAC(key_hash, salt) [+ entropy]
        let mut session_input = self.salt.clone();
        if let Some(ent) = entropy {
            session_input.extend_from_slice(ent);
        }
        let session_key = if self.hash_algo == CALG_SHA_512 {
            hmac_sha512(&key_hash, &session_input).to_vec()
        } else {
            hmac_sha1(&key_hash, &session_input).to_vec()
        };

        let (key_len, _iv_len) = match self.crypt_algo {
            CALG_AES_256 => (32usize, 16usize),
            CALG_3DES => (24usize, 8usize),
            _ => return Err(CoreError::ProtocolError(format!("unsupported crypt algo 0x{:08x}", self.crypt_algo))),
        };

        let mut derived_key = session_key;
        if derived_key.len() < key_len {
            // Pad or extend derived key if needed
            derived_key.resize(key_len, 0);
        }

        let cleartext = match self.crypt_algo {
            CALG_AES_256 => {
                let k: [u8; 32] = derived_key[..32].try_into().unwrap();
                let iv = [0u8; 16];
                aes256::decrypt_cbc(&k, &iv, &self.data)
            }
            CALG_3DES => {
                let k: [u8; 24] = derived_key[..24].try_into().unwrap();
                let iv = [0u8; 8];
                des3_cbc_decrypt(&k, &iv, &self.data)
            }
            _ => return Err(CoreError::ProtocolError(format!("unsupported crypt algo 0x{:08x}", self.crypt_algo))),
        };

        // Remove PKCS#7 padding
        if cleartext.is_empty() {
            return Err(CoreError::ProtocolError("decrypted plaintext is empty".into()));
        }
        let pad_len = cleartext[cleartext.len() - 1] as usize;
        if pad_len == 0 || pad_len > 16 || pad_len > cleartext.len() {
            return Ok(cleartext);
        }
        let unpadded_len = cleartext.len() - pad_len;
        Ok(cleartext[..unpadded_len].to_vec())
    }
}

/// Helper function to derive DPAPI user keys from cleartext password and SID.
pub fn derive_keys_from_user(sid: &str, password: &str) -> Vec<Vec<u8>> {
    let pw_utf16: Vec<u8> = password.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let sid_term = format!("{}\0", sid);
    let sid_utf16: Vec<u8> = sid_term.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let sid_raw_utf16: Vec<u8> = sid.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();

    // key1: HMAC-SHA1(SHA1(password_utf16), sid_utf16)
    let sha1_pw = sha1(&pw_utf16);
    let key1 = hmac_sha1(&sha1_pw, &sid_utf16).to_vec();

    // key2: HMAC-SHA1(MD4(password_utf16), sid_utf16)
    let md4_pw = md4(&pw_utf16);
    let key2 = hmac_sha1(&md4_pw, &sid_utf16).to_vec();

    // key3 (Protected Users): PBKDF2(MD4(password), sid, 10000) -> PBKDF2(..., 1) -> HMAC-SHA1
    let tmp = pbkdf2_hmac_sha256(&md4_pw, &sid_raw_utf16, 10000, 32);
    let tmp2 = pbkdf2_hmac_sha256(&tmp, &sid_raw_utf16, 1, 16);
    let key3 = hmac_sha1(&tmp2, &sid_utf16)[..20].to_vec();

    vec![key1, key2, key3]
}

/// Helper function to derive DPAPI user keys from NTLM hash and SID.
pub fn derive_keys_from_user_key(sid: &str, nt_hash: &[u8; 16]) -> Vec<Vec<u8>> {
    let sid_term = format!("{}\0", sid);
    let sid_utf16: Vec<u8> = sid_term.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let sid_raw_utf16: Vec<u8> = sid.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();

    let key1 = hmac_sha1(nt_hash, &sid_utf16).to_vec();

    let tmp = pbkdf2_hmac_sha256(nt_hash, &sid_raw_utf16, 10000, 32);
    let tmp2 = pbkdf2_hmac_sha256(&tmp, &sid_raw_utf16, 1, 16);
    let key2 = hmac_sha1(&tmp2, &sid_utf16)[..20].to_vec();

    vec![key1, key2]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_keys_from_user_and_user_key() {
        let sid = "S-1-5-21-1234567890-1234567890-1234567890-500";
        let password = "Password123!";
        let keys_from_pwd = derive_keys_from_user(sid, password);
        assert_eq!(keys_from_pwd.len(), 3);
        assert_eq!(keys_from_pwd[0].len(), 20);
        assert_eq!(keys_from_pwd[1].len(), 20);

        let pw_utf16: Vec<u8> = password.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let nt_hash = md4(&pw_utf16);
        let keys_from_hash = derive_keys_from_user_key(sid, &nt_hash);
        assert_eq!(keys_from_hash.len(), 2);
        // key1 from NT hash matches key2 from password!
        assert_eq!(keys_from_hash[0], keys_from_pwd[1]);
        assert_eq!(keys_from_hash[1], keys_from_pwd[2]);
    }

    #[test]
    fn test_master_key_aes256_decrypt_roundtrip() {
        let user_key = [0x22u8; 20];
        let salt = [0x33u8; 16];
        let rounds = 10u32;
        let expected_mk = [0x88u8; 64];

        // Prepare cleartext: hmac_salt (16), hmac (20), padding (44), decrypted_key (64)
        let hmac_salt = [0x44u8; 16];
        let hmac_key = hmac_sha1(&user_key, &hmac_salt);
        let calculated_hmac = hmac_sha1(&hmac_key, &expected_mk);

        let mut cleartext = Vec::new();
        cleartext.extend_from_slice(&hmac_salt);
        cleartext.extend_from_slice(&calculated_hmac);
        cleartext.extend_from_slice(&[0u8; 44]);
        cleartext.extend_from_slice(&expected_mk);
        assert_eq!(cleartext.len() % 16, 0);

        let derived_blob = MasterKey::derive_key_sha1(&user_key, &salt, 48, rounds);
        let crypt_key: [u8; 32] = derived_blob[..32].try_into().unwrap();
        let iv: [u8; 16] = derived_blob[32..48].try_into().unwrap();

        let ciphertext = aes256::encrypt_cbc(&crypt_key, &iv, &cleartext);

        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes()); // version
        payload.extend_from_slice(&salt); // salt
        payload.extend_from_slice(&rounds.to_le_bytes()); // rounds
        payload.extend_from_slice(&CALG_SHA1.to_le_bytes()); // hash_algo
        payload.extend_from_slice(&CALG_AES_256.to_le_bytes()); // crypt_algo
        payload.extend_from_slice(&ciphertext);

        let mk = MasterKey::parse(&payload).unwrap();
        let decrypted = mk.decrypt(&user_key).unwrap();
        assert_eq!(decrypted, expected_mk);
    }

    #[test]
    fn test_dpapi_blob_decrypt() {
        let master_key = [0x55u8; 64];
        let salt = [0x66u8; 16];
        let key_hash = sha1(&master_key);
        let session_key = hmac_sha1(&key_hash, &salt);

        let mut derived_key = session_key.to_vec();
        derived_key.resize(32, 0);
        let k: [u8; 32] = derived_key.try_into().unwrap();
        let iv = [0u8; 16];

        let secret = b"TargetSecretData";
        // PKCS#7 pad to 32 bytes (pad with 16 bytes of 0x10)
        let mut padded = secret.to_vec();
        padded.extend_from_slice(&[16u8; 16]);
        let ciphertext = aes256::encrypt_cbc(&k, &iv, &padded);

        // Build blob
        let mut blob_bytes = Vec::new();
        blob_bytes.extend_from_slice(&1u32.to_le_bytes()); // version
        blob_bytes.extend_from_slice(&[0u8; 16]); // guid_cred
        blob_bytes.extend_from_slice(&1u32.to_le_bytes()); // mk_ver
        blob_bytes.extend_from_slice(&[0u8; 16]); // guid_mk
        blob_bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
        blob_bytes.extend_from_slice(&0u32.to_le_bytes()); // desc_len
        blob_bytes.extend_from_slice(&CALG_AES_256.to_le_bytes()); // crypt_algo
        blob_bytes.extend_from_slice(&256u32.to_le_bytes()); // crypt_algo_len
        blob_bytes.extend_from_slice(&(salt.len() as u32).to_le_bytes());
        blob_bytes.extend_from_slice(&salt);
        blob_bytes.extend_from_slice(&0u32.to_le_bytes()); // hmac_key_len
        blob_bytes.extend_from_slice(&CALG_SHA1.to_le_bytes()); // hash_algo
        blob_bytes.extend_from_slice(&160u32.to_le_bytes()); // hash_algo_len
        blob_bytes.extend_from_slice(&0u32.to_le_bytes()); // hmac_len
        blob_bytes.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
        blob_bytes.extend_from_slice(&ciphertext);
        blob_bytes.extend_from_slice(&0u32.to_le_bytes()); // sign_len

        let blob = DpapiBlob::parse(&blob_bytes).unwrap();
        let pt = blob.decrypt(&master_key, None).unwrap();
        assert_eq!(pt, secret);
    }
}
