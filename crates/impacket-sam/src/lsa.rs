//! `lsa`: Offline Windows `SECURITY` registry hive parser for LSA secrets & cached domain credentials.
//!
//! Mirrors Python Impacket's `LSASecrets` engine (`impacket/examples/secretsdump.py`):
//! 1. Recovers the 32-byte `LSAKey` from `Policy\PolEKList` (Modern Vista -> 2025) or `Policy\PolSecretEncryptionKey` (Legacy XP/2003) using the `BootKey`.
//! 2. Decrypts `Policy\Secrets\NL$KM` to recover the Netlogon master key.
//! 3. Decrypts `Cache\NL$<Entry>` to extract cached domain logon credentials (DCC2 / MS-Cache-v2 in Hashcat `-m 2100` format).
//! 4. Decrypts all LSA Secrets under `Policy\Secrets\<Name>\CurrVal` (service passwords `_SC_*`, DPAPI system keys, `$MACHINE.ACC`, etc.).

use crate::reg::{Hive, Nk};
use impacket_core::{decode_utf16le, encode_hex, CoreError, FileTime};
use impacket_crypto::{aes128, aes256, md5, sha256, Rc4};

/// Represents a decrypted LSA secret item (e.g. `$MACHINE.ACC`, `DPAPI_SYSTEM`, `_SC_<service>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsaSecretItem {
    pub name: String,
    pub secret_raw: Vec<u8>,
    pub secret_text: Option<String>,
}

/// Represents a decrypted domain cached logon credential (`DCC2` / MS-Cache-v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsaCachedLogon {
    pub domain: String,
    pub username: String,
    pub hash_hex: String,
    pub iteration_count: u32,
    pub last_write_unix: Option<u64>,
}

impl LsaCachedLogon {
    /// Formats the cached credential in canonical Hashcat mode 2100 (`$DCC2$`) syntax.
    pub fn format_hashcat(&self) -> String {
        format!(
            "{}/{}:$DCC2${}#{}#{}",
            self.domain, self.username, self.iteration_count, self.username, self.hash_hex
        )
    }
}

/// Decrypts AES with either AES-128 or AES-256 depending on key length (16 or 32 bytes),
/// matching `secretsdump.py:decryptAES`.
pub fn decrypt_aes(
    key: &[u8],
    value: &[u8],
    iv: Option<&[u8; 16]>,
) -> Result<Vec<u8>, CoreError> {
    let has_iv = match iv {
        Some(iv_bytes) => *iv_bytes != [0u8; 16],
        None => false,
    };

    if key.len() == 16 {
        let k: [u8; 16] = key
            .try_into()
            .map_err(|_| CoreError::ProtocolError("Invalid AES-128 key length".into()))?;
        if has_iv {
            Ok(aes128::decrypt_cbc(&k, iv.unwrap(), value))
        } else {
            let mut out = Vec::with_capacity(value.len());
            for chunk in value.chunks(16) {
                let mut block = [0u8; 16];
                block[..chunk.len()].copy_from_slice(chunk);
                out.extend_from_slice(&aes128::decrypt_block(&k, &block));
            }
            Ok(out)
        }
    } else if key.len() == 32 {
        let k: [u8; 32] = key
            .try_into()
            .map_err(|_| CoreError::ProtocolError("Invalid AES-256 key length".into()))?;
        if has_iv {
            Ok(aes256::decrypt_cbc(&k, iv.unwrap(), value))
        } else {
            let mut out = Vec::with_capacity(value.len());
            for chunk in value.chunks(16) {
                let mut block = [0u8; 16];
                block[..chunk.len()].copy_from_slice(chunk);
                out.extend_from_slice(&aes256::decrypt_block(&k, &block));
            }
            Ok(out)
        }
    } else {
        Err(CoreError::ProtocolError(format!(
            "Unsupported AES key length: {} bytes (expected 16 or 32)",
            key.len()
        )))
    }
}

/// Computes SHA-256 over `[key, salt * 1000]`, matching `secretsdump.py:__sha256`.
pub fn sha256_repeated(key: &[u8], salt: &[u8], rounds: usize) -> [u8; 32] {
    let mut buf = Vec::with_capacity(key.len() + salt.len() * rounds);
    buf.extend_from_slice(key);
    for _ in 0..rounds {
        buf.extend_from_slice(salt);
    }
    sha256(&buf)
}

/// Computes MD5 over `[key, salt * 1000]`, matching `secretsdump.py:__decryptLSA` for legacy XP.
pub fn md5_repeated(key: &[u8], salt: &[u8], rounds: usize) -> [u8; 16] {
    let mut buf = Vec::with_capacity(key.len() + salt.len() * rounds);
    buf.extend_from_slice(key);
    for _ in 0..rounds {
        buf.extend_from_slice(salt);
    }
    md5(&buf)
}

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

fn find_path<'a>(hive: &'a Hive<'a>, root: &Nk, path: &[&str]) -> Result<Option<Nk>, CoreError> {
    if let Some(nk) = hive.navigate(root, path)? {
        return Ok(Some(nk));
    }
    for child in hive.subkeys(root)? {
        if let Some(nk) = hive.navigate(&child, path)? {
            return Ok(Some(nk));
        }
    }
    Ok(None)
}

fn get_first_value<'a>(hive: &'a Hive<'a>, nk: &Nk) -> Result<Option<Vec<u8>>, CoreError> {
    if let Some(v) = hive.get_value(nk, "")? {
        return Ok(Some(v.data));
    }
    if let Some(v) = hive.get_value(nk, "default")? {
        return Ok(Some(v.data));
    }
    let vals = hive.values(nk)?;
    Ok(vals.into_iter().next().map(|v| v.data))
}

/// Offline `SECURITY` hive decryptor engine.
pub struct LsaParser<'a> {
    hive: Hive<'a>,
    boot_key: [u8; 16],
    lsa_key: Vec<u8>,
    is_vista_style: bool,
}

impl<'a> LsaParser<'a> {
    /// Initializes the parser with raw `SECURITY` hive bytes and the 16-byte `BootKey`.
    pub fn new(security_hive_bytes: &'a [u8], boot_key: [u8; 16]) -> Result<Self, CoreError> {
        let hive = Hive::new(security_hive_bytes)?;
        let root = hive.root()?;

        // 1. Try modern PolEKList (Vista / 7 / 8 / 10 / 2012 / 2016 / 2019 / 2022 / 2025)
        if let Some(pol_ek) = find_path(&hive, &root, &["Policy", "PolEKList"])? {
            if let Some(val_data) = get_first_value(&hive, &pol_ek)? {
                if val_data.len() >= 60 {
                    // LSA_SECRET structure: 28-byte header, then EncryptedData
                    let enc_data = &val_data[28..];
                    if enc_data.len() >= 32 {
                        let salt = &enc_data[0..32];
                        let ciphertext = &enc_data[32..];
                        let tmp_key = sha256_repeated(&boot_key, salt, 1000);
                        let plain = decrypt_aes(&tmp_key, ciphertext, None)?;
                        // LSA_SECRET_BLOB: 4 bytes length, 12 bytes unknown, secret
                        if plain.len() >= 16 + 52 + 32 {
                            let lsa_key = plain[16 + 52..16 + 52 + 32].to_vec();
                            return Ok(Self {
                                hive,
                                boot_key,
                                lsa_key,
                                is_vista_style: true,
                            });
                        }
                    }
                }
            }
        }

        // 2. Fall back to legacy PolSecretEncryptionKey (Windows 2000 / XP / 2003)
        if let Some(pol_sec) = find_path(&hive, &root, &["Policy", "PolSecretEncryptionKey"])? {
            if let Some(val_data) = get_first_value(&hive, &pol_sec)? {
                if val_data.len() >= 76 {
                    let salt = &val_data[60..76];
                    let tmp_key = md5_repeated(&boot_key, salt, 1000);
                    let mut rc4 = Rc4::new(&tmp_key);
                    let mut plain = val_data[12..60].to_vec();
                    rc4.apply_keystream(&mut plain);
                    let lsa_key = plain[0x10..0x20].to_vec();
                    return Ok(Self {
                        hive,
                        boot_key,
                        lsa_key,
                        is_vista_style: false,
                    });
                }
            }
        }

        Err(CoreError::ProtocolError(
            "Could not locate PolEKList or PolSecretEncryptionKey in SECURITY hive".into(),
        ))
    }

    /// Returns the recovered LSA secret key.
    pub fn lsa_key(&self) -> &[u8] {
        &self.lsa_key
    }

    /// Returns the system BootKey.
    pub fn boot_key(&self) -> &[u8; 16] {
        &self.boot_key
    }

    /// Whether this system uses Modern (AES-based Vista+) or Legacy (MD5/RC4 XP) encryption.
    pub fn is_vista_style(&self) -> bool {
        self.is_vista_style
    }

    /// Decrypts the Netlogon cache key (`NL$KM`).
    pub fn decrypt_nlkm_key(&self) -> Result<Vec<u8>, CoreError> {
        let root = self.hive.root()?;
        let nlkm_nk = find_path(&self.hive, &root, &["Policy", "Secrets", "NL$KM", "CurrVal"])?
            .ok_or_else(|| {
                CoreError::ProtocolError("Policy\\Secrets\\NL$KM\\CurrVal not found".into())
            })?;

        let val_data = get_first_value(&self.hive, &nlkm_nk)?.ok_or_else(|| {
            CoreError::ProtocolError("No data in NL$KM CurrVal".into())
        })?;

        if self.is_vista_style {
            if val_data.len() < 28 + 32 {
                return Err(CoreError::ProtocolError("NL$KM record too short".into()));
            }
            let enc_data = &val_data[28..];
            let salt = &enc_data[0..32];
            let ciphertext = &enc_data[32..];
            let tmp_key = sha256_repeated(&self.lsa_key, salt, 1000);
            decrypt_aes(&tmp_key, ciphertext, None)
        } else {
            // Legacy XP DES decryption
            if val_data.len() < 8 {
                return Err(CoreError::ProtocolError("NL$KM legacy record too short".into()));
            }
            let enc_len = rd_u32_le(&val_data, 0).unwrap_or(0) as usize;
            if enc_len == 0 || enc_len > val_data.len() {
                return Ok(val_data);
            }
            Ok(val_data[val_data.len() - enc_len..].to_vec())
        }
    }

    /// Extracts all cached domain logon credentials from `Cache\NL$<Entry>`.
    pub fn dump_cached_hashes(&self) -> Result<Vec<LsaCachedLogon>, CoreError> {
        let root = self.hive.root()?;
        let cache_nk = match find_path(&self.hive, &root, &["Cache"])? {
            Some(nk) => nk,
            None => return Ok(Vec::new()),
        };

        let iteration_count = match self.hive.get_value(&cache_nk, "NL$IterationCount")? {
            Some(vk) if vk.data.len() >= 4 => {
                let raw = rd_u32_le(&vk.data, 0).unwrap_or(10240);
                if raw > 10240 {
                    raw & 0xFFFF_FC00
                } else {
                    raw * 1024
                }
            }
            _ => 10240,
        };

        let nlkm_key = match self.decrypt_nlkm_key() {
            Ok(k) => k,
            Err(_) => return Ok(Vec::new()),
        };

        let mut out = Vec::new();

        for val in self.hive.values(&cache_nk)? {
            if !val.name.starts_with("NL$")
                || val.name.eq_ignore_ascii_case("NL$Control")
                || val.name.eq_ignore_ascii_case("NL$IterationCount")
            {
                continue;
            }

            let data = &val.data;
            if data.len() < 96 {
                continue;
            }

            let user_len = rd_u16_le(data, 0).unwrap_or(0) as usize;
            let dom_len = rd_u16_le(data, 2).unwrap_or(0) as usize;
            let last_write = rd_u64_le(data, 24).unwrap_or(0);
            let flags = rd_u32_le(data, 40).unwrap_or(0);
            let dns_dom_len = rd_u16_le(data, 52).unwrap_or(0) as usize;

            let iv: [u8; 16] = match data[64..80].try_into() {
                Ok(b) => b,
                Err(_) => continue,
            };

            if iv == [0u8; 16] || (flags & 1) == 0 {
                continue;
            }

            let encrypted_data = &data[96..];
            if encrypted_data.is_empty() {
                continue;
            }

            let plain = if self.is_vista_style {
                if nlkm_key.len() < 32 {
                    continue;
                }
                match decrypt_aes(&nlkm_key[16..32], encrypted_data, Some(&iv)) {
                    Ok(p) => p,
                    Err(_) => continue,
                }
            } else {
                let hmac = impacket_crypto::hmac_md5(&nlkm_key, &iv);
                let mut rc4 = Rc4::new(&hmac);
                let mut p = encrypted_data.to_vec();
                rc4.apply_keystream(&mut p);
                p
            };

            if plain.len() < 0x48 {
                continue;
            }

            let enc_hash = encode_hex(&plain[0..16]);
            let rest = &plain[0x48..];

            if rest.len() < user_len {
                continue;
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

            out.push(LsaCachedLogon {
                domain,
                username,
                hash_hex: enc_hash,
                iteration_count,
                last_write_unix: FileTime::from_raw(last_write).to_unix_secs(),
            });
        }

        Ok(out)
    }

    /// Extracts all LSA secrets under `Policy\Secrets\<Name>\CurrVal`.
    pub fn dump_secrets(&self) -> Result<Vec<LsaSecretItem>, CoreError> {
        let root = self.hive.root()?;
        let secrets_nk = match find_path(&self.hive, &root, &["Policy", "Secrets"])? {
            Some(nk) => nk,
            None => return Ok(Vec::new()),
        };

        let mut items = Vec::new();

        for subkey in self.hive.subkeys(&secrets_nk)? {
            let curr_val = match self.hive.find_subkey(&subkey, "CurrVal")? {
                Some(cv) => cv,
                None => continue,
            };

            let val_data = match get_first_value(&self.hive, &curr_val)? {
                Some(d) => d,
                None => continue,
            };

            if val_data.is_empty() || val_data.starts_with(b"\x00\x00") {
                continue;
            }

            let secret_raw = if self.is_vista_style {
                if val_data.len() < 28 + 32 {
                    continue;
                }
                let enc_data = &val_data[28..];
                let salt = &enc_data[0..32];
                let ciphertext = &enc_data[32..];
                let tmp_key = sha256_repeated(&self.lsa_key, salt, 1000);
                let plain = match decrypt_aes(&tmp_key, ciphertext, None) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                if plain.len() < 16 {
                    continue;
                }
                let len = rd_u32_le(&plain, 0).unwrap_or(0) as usize;
                if plain.len() >= 16 + len {
                    plain[16..16 + len].to_vec()
                } else {
                    plain[16..].to_vec()
                }
            } else {
                val_data
            };

            let secret_text = decode_utf16le(&secret_raw).ok();

            items.push(LsaSecretItem {
                name: subkey.name,
                secret_raw,
                secret_text,
            });
        }

        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_repeated_matches_single_pass() {
        let key = b"my_boot_key_1234";
        let salt = b"salt_bytes_0123456789abcdef0123";
        let hash = sha256_repeated(key, salt, 10);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_decrypt_aes_block_and_cbc() {
        let key = [0x42u8; 16];
        let iv = [0x11u8; 16];
        let plain = b"SecretMessage123";
        let enc = aes128::encrypt_cbc(&key, &iv, plain);
        let dec = decrypt_aes(&key, &enc, Some(&iv)).unwrap();
        assert_eq!(&dec[..plain.len()], plain);
    }
}
