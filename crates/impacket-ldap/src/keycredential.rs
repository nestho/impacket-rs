//! `keycredential`: Active Directory Shadow Credentials ([MS-ADTS] Section 2.2.18.2).
//!
//! Provides pure-Rust binary codecs and LDAP management for `msDS-KeyCredentialLink`
//! (`KEYCREDENTIALLINK_BLOB` and `DN-Binary` syntax), enabling public key authentication,
//! Windows Hello for Business (WHfB) credential auditing, and shadow credentials manipulation.

use crate::asn1::{AttributeModification, LdapAttribute, ModifyOperation, SearchScope};
use crate::client::LdapClient;
use impacket_core::{decode_hex, encode_hex, CoreError, FileTime};
use impacket_crypto::sha256;
use std::io::{Read, Write};

pub const KEY_CREDENTIAL_LINK_ATTR: &str = "msDS-KeyCredentialLink";

// [MS-ADTS] Section 2.2.18.2 Identifiers
pub const IDENTIFIER_KEY_ID: u8 = 0x01;
pub const IDENTIFIER_KEY_HASH: u8 = 0x02;
pub const IDENTIFIER_KEY_MATERIAL: u8 = 0x03;
pub const IDENTIFIER_KEY_USAGE: u8 = 0x04;
pub const IDENTIFIER_KEY_SOURCE: u8 = 0x05;
pub const IDENTIFIER_DEVICE_ID: u8 = 0x06;
pub const IDENTIFIER_CUSTOM_KEY_INFORMATION: u8 = 0x07;
pub const IDENTIFIER_KEY_APPROX_LAST_LOGON: u8 = 0x08;
pub const IDENTIFIER_KEY_CREATION_TIME: u8 = 0x09;

// Key Usage constants
pub const KEY_USAGE_NGC: u8 = 0x01; // Next Generation Cryptography (WHfB)
pub const KEY_USAGE_FIDO: u8 = 0x02;
pub const KEY_USAGE_FEK: u8 = 0x03;

// Key Source constants
pub const KEY_SOURCE_AD: u8 = 0x00;
pub const KEY_SOURCE_AZURE_AD: u8 = 0x01;

// Windows CNG BCRYPT_RSAKEY_BLOB Magic
pub const BCRYPT_RSAPUBLIC_MAGIC: u32 = 0x3141_5352; // "RSA1"

/// Represents a Windows CNG `BCRYPT_RSAKEY_BLOB` (RSA public key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BcryptRsaPublicKey {
    pub bit_length: u32,
    pub public_exponent: Vec<u8>,
    pub modulus: Vec<u8>,
}

impl BcryptRsaPublicKey {
    pub fn new(bit_length: u32, public_exponent: Vec<u8>, modulus: Vec<u8>) -> Self {
        Self {
            bit_length,
            public_exponent,
            modulus,
        }
    }

    /// Serializes to `BCRYPT_RSAKEY_BLOB` layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24 + self.public_exponent.len() + self.modulus.len());
        out.extend_from_slice(&BCRYPT_RSAPUBLIC_MAGIC.to_le_bytes());
        out.extend_from_slice(&self.bit_length.to_le_bytes());
        out.extend_from_slice(&(self.public_exponent.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.modulus.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // cbPrime1
        out.extend_from_slice(&0u32.to_le_bytes()); // cbPrime2
        out.extend_from_slice(&self.public_exponent);
        out.extend_from_slice(&self.modulus);
        out
    }

    /// Parses from `BCRYPT_RSAKEY_BLOB` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() < 24 {
            return Err(CoreError::ProtocolError("BCRYPT_RSAKEY_BLOB too short".into()));
        }

        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != BCRYPT_RSAPUBLIC_MAGIC {
            return Err(CoreError::ProtocolError(format!(
                "Invalid BCRYPT_RSAKEY_BLOB magic: 0x{:08x} (expected 'RSA1')",
                magic
            )));
        }

        let bit_length = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let cb_exp = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let cb_mod = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;

        if bytes.len() < 24 + cb_exp + cb_mod {
            return Err(CoreError::ProtocolError(
                "BCRYPT_RSAKEY_BLOB buffer overflow for exponent/modulus".into(),
            ));
        }

        let exp_start = 24;
        let exp_end = exp_start + cb_exp;
        let public_exponent = bytes[exp_start..exp_end].to_vec();

        let mod_start = exp_end;
        let mod_end = mod_start + cb_mod;
        let modulus = bytes[mod_start..mod_end].to_vec();

        Ok(Self {
            bit_length,
            public_exponent,
            modulus,
        })
    }
}

/// Generic entry in `KEYCREDENTIALLINK_BLOB`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCredentialEntry {
    pub identifier: u8,
    pub value: Vec<u8>,
}

impl KeyCredentialEntry {
    pub fn new(identifier: u8, value: Vec<u8>) -> Self {
        Self { identifier, value }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.value.len());
        out.extend_from_slice(&(self.value.len() as u16).to_le_bytes());
        out.push(self.identifier);
        out.extend_from_slice(&self.value);
        out
    }
}

/// Parsed Active Directory `KEYCREDENTIALLINK_BLOB` structure ([MS-ADTS] 2.2.18.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCredentialLinkBlob {
    pub version: u32,
    pub key_id: [u8; 32],
    pub key_hash: Option<[u8; 32]>,
    pub key_material: Vec<u8>,
    pub key_usage: u8,
    pub key_source: u8,
    pub device_id: [u8; 16],
    pub custom_key_info: Option<Vec<u8>>,
    pub approx_last_logon: Option<u64>,
    pub creation_time: Option<u64>,
    pub raw_entries: Vec<KeyCredentialEntry>,
}

impl KeyCredentialLinkBlob {
    /// Creates a new `KeyCredentialLinkBlob` for an RSA public key.
    pub fn new_rsa(
        modulus: &[u8],
        exponent: &[u8],
        device_id: Option<[u8; 16]>,
        creation_time_opt: Option<u64>,
    ) -> Self {
        let bit_length = (modulus.len() * 8) as u32;
        let rsa_pub = BcryptRsaPublicKey::new(bit_length, exponent.to_vec(), modulus.to_vec());
        let key_material = rsa_pub.to_bytes();

        let key_id = sha256(&key_material);
        let key_usage = KEY_USAGE_NGC;
        let key_source = KEY_SOURCE_AD;
        let dev_id = device_id.unwrap_or([0u8; 16]);
        let custom_info = vec![0x01, 0x00]; // version 1, flags 0
        let creation_time = creation_time_opt.unwrap_or_else(|| {
            FileTime::from_unix_secs(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )
            .0
        });

        // Compute KeyHash = SHA256 of all entries that follow KeyHash (ID > 2)
        let mut following_entries = Vec::new();
        following_entries.push(KeyCredentialEntry::new(IDENTIFIER_KEY_MATERIAL, key_material.clone()));
        following_entries.push(KeyCredentialEntry::new(IDENTIFIER_KEY_USAGE, vec![key_usage]));
        following_entries.push(KeyCredentialEntry::new(IDENTIFIER_KEY_SOURCE, vec![key_source]));
        following_entries.push(KeyCredentialEntry::new(IDENTIFIER_DEVICE_ID, dev_id.to_vec()));
        following_entries.push(KeyCredentialEntry::new(IDENTIFIER_CUSTOM_KEY_INFORMATION, custom_info.clone()));
        following_entries.push(KeyCredentialEntry::new(IDENTIFIER_KEY_APPROX_LAST_LOGON, creation_time.to_le_bytes().to_vec()));
        following_entries.push(KeyCredentialEntry::new(IDENTIFIER_KEY_CREATION_TIME, creation_time.to_le_bytes().to_vec()));

        let mut hash_input = Vec::new();
        for entry in &following_entries {
            hash_input.extend_from_slice(&entry.to_bytes());
        }
        let key_hash = sha256(&hash_input);

        let mut raw_entries = Vec::new();
        raw_entries.push(KeyCredentialEntry::new(IDENTIFIER_KEY_ID, key_id.to_vec()));
        raw_entries.push(KeyCredentialEntry::new(IDENTIFIER_KEY_HASH, key_hash.to_vec()));
        raw_entries.extend(following_entries);

        Self {
            version: 0x0000_0200, // Version 2.0
            key_id,
            key_hash: Some(key_hash),
            key_material,
            key_usage,
            key_source,
            device_id: dev_id,
            custom_key_info: Some(custom_info),
            approx_last_logon: Some(creation_time),
            creation_time: Some(creation_time),
            raw_entries,
        }
    }

    /// Serializes the `KEYCREDENTIALLINK_BLOB` to raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());

        // Sort entries by identifier in increasing order
        let mut sorted = self.raw_entries.clone();
        sorted.sort_by_key(|e| e.identifier);

        for entry in &sorted {
            out.extend_from_slice(&entry.to_bytes());
        }
        out
    }

    /// Parses a `KEYCREDENTIALLINK_BLOB` from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() < 4 {
            return Err(CoreError::ProtocolError("KEYCREDENTIALLINK_BLOB too short".into()));
        }

        let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let mut pos = 4;
        let mut raw_entries = Vec::new();

        let mut key_id = [0u8; 32];
        let mut key_hash = None;
        let mut key_material = Vec::new();
        let mut key_usage = KEY_USAGE_NGC;
        let mut key_source = KEY_SOURCE_AD;
        let mut device_id = [0u8; 16];
        let mut custom_key_info = None;
        let mut approx_last_logon = None;
        let mut creation_time = None;

        while pos + 3 <= bytes.len() {
            let length = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
            let identifier = bytes[pos + 2];
            pos += 3;

            if pos + length > bytes.len() {
                return Err(CoreError::ProtocolError(format!(
                    "Unexpected EOF in KEYCREDENTIALLINK_ENTRY 0x{:02x}",
                    identifier
                )));
            }

            let value = bytes[pos..pos + length].to_vec();
            pos += length;

            match identifier {
                IDENTIFIER_KEY_ID => {
                    if value.len() == 32 {
                        key_id.copy_from_slice(&value);
                    }
                }
                IDENTIFIER_KEY_HASH => {
                    if value.len() == 32 {
                        let mut h = [0u8; 32];
                        h.copy_from_slice(&value);
                        key_hash = Some(h);
                    }
                }
                IDENTIFIER_KEY_MATERIAL => {
                    key_material = value.clone();
                }
                IDENTIFIER_KEY_USAGE => {
                    if !value.is_empty() {
                        key_usage = value[0];
                    }
                }
                IDENTIFIER_KEY_SOURCE => {
                    if !value.is_empty() {
                        key_source = value[0];
                    }
                }
                IDENTIFIER_DEVICE_ID => {
                    if value.len() == 16 {
                        device_id.copy_from_slice(&value);
                    }
                }
                IDENTIFIER_CUSTOM_KEY_INFORMATION => {
                    custom_key_info = Some(value.clone());
                }
                IDENTIFIER_KEY_APPROX_LAST_LOGON => {
                    if value.len() >= 8 {
                        approx_last_logon = Some(u64::from_le_bytes([
                            value[0], value[1], value[2], value[3],
                            value[4], value[5], value[6], value[7],
                        ]));
                    }
                }
                IDENTIFIER_KEY_CREATION_TIME => {
                    if value.len() >= 8 {
                        creation_time = Some(u64::from_le_bytes([
                            value[0], value[1], value[2], value[3],
                            value[4], value[5], value[6], value[7],
                        ]));
                    }
                }
                _ => {}
            }

            raw_entries.push(KeyCredentialEntry::new(identifier, value));
        }

        Ok(Self {
            version,
            key_id,
            key_hash,
            key_material,
            key_usage,
            key_source,
            device_id,
            custom_key_info,
            approx_last_logon,
            creation_time,
            raw_entries,
        })
    }

    /// Parses the underlying RSA public key from `key_material`.
    pub fn parse_rsa_key(&self) -> Result<BcryptRsaPublicKey, CoreError> {
        BcryptRsaPublicKey::from_bytes(&self.key_material)
    }

    /// Returns a hex representation of the KeyID.
    pub fn key_id_hex(&self) -> String {
        encode_hex(&self.key_id)
    }

    /// Returns a string representation of the DeviceId GUID.
    pub fn device_id_str(&self) -> String {
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.device_id[3], self.device_id[2], self.device_id[1], self.device_id[0],
            self.device_id[5], self.device_id[4],
            self.device_id[7], self.device_id[6],
            self.device_id[8], self.device_id[9],
            self.device_id[10], self.device_id[11], self.device_id[12], self.device_id[13], self.device_id[14], self.device_id[15]
        )
    }
}

/// Active Directory `Object(DN-Binary)` attribute format (`B:<len>:<hex>:<dn>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnBinary {
    pub binary: Vec<u8>,
    pub dn: String,
}

impl DnBinary {
    pub fn new(binary: Vec<u8>, dn: impl Into<String>) -> Self {
        Self {
            binary,
            dn: dn.into(),
        }
    }

    /// Parses a `DN-Binary` formatted string (`B:<len>:<hex>:<dn>`).
    pub fn from_ldap_string(s: &str) -> Result<Self, CoreError> {
        let trimmed = s.trim();
        if !trimmed.starts_with("B:") && !trimmed.starts_with("b:") {
            return Err(CoreError::ProtocolError(format!(
                "Invalid DN-Binary string: missing 'B:' prefix: {}",
                s
            )));
        }

        let parts: Vec<&str> = trimmed[2..].splitn(3, ':').collect();
        if parts.len() < 3 {
            return Err(CoreError::ProtocolError(format!(
                "Invalid DN-Binary string structure (expected B:<len>:<hex>:<dn>): {}",
                s
            )));
        }

        let hex_str = parts[1];
        let dn = parts[2].to_string();

        let binary = decode_hex(hex_str)
            .map_err(|e| CoreError::ProtocolError(format!("Invalid DN-Binary hex: {}", e)))?;

        Ok(Self { binary, dn })
    }

    /// Serializes to LDAP `DN-Binary` string format.
    pub fn to_ldap_string(&self) -> String {
        let hex_str = encode_hex(&self.binary);
        format!("B:{}:{}:{}", hex_str.len(), hex_str, self.dn)
    }
}

/// Reads all shadow credentials (`msDS-KeyCredentialLink`) configured on `target_dn`.
pub fn read_shadow_credentials<S: Read + Write>(
    client: &mut LdapClient<S>,
    target_dn: &str,
) -> Result<Vec<(DnBinary, KeyCredentialLinkBlob)>, CoreError> {
    let entries = client.search(
        target_dn,
        SearchScope::BaseObject,
        &crate::filter_present("objectClass"),
        &[KEY_CREDENTIAL_LINK_ATTR],
    )?;

    if entries.is_empty() {
        return Err(CoreError::ProtocolError(format!(
            "Target object not found: {}",
            target_dn
        )));
    }

    let mut results = Vec::new();
    let strings = entries[0].get_all_strings(KEY_CREDENTIAL_LINK_ATTR);

    for s in strings {
        match DnBinary::from_ldap_string(&s) {
            Ok(dn_bin) => match KeyCredentialLinkBlob::from_bytes(&dn_bin.binary) {
                Ok(blob) => results.push((dn_bin, blob)),
                Err(e) => eprintln!("[-] Warning: Failed to parse KeyCredentialLinkBlob: {}", e),
            },
            Err(e) => eprintln!("[-] Warning: Failed to parse DN-Binary string: {}", e),
        }
    }

    Ok(results)
}

/// Adds a shadow credential link (`KEYCREDENTIALLINK_BLOB`) to `target_dn`.
pub fn add_shadow_credential<S: Read + Write>(
    client: &mut LdapClient<S>,
    target_dn: &str,
    blob: &KeyCredentialLinkBlob,
) -> Result<String, CoreError> {
    let dn_bin = DnBinary::new(blob.to_bytes(), target_dn);
    let ldap_val = dn_bin.to_ldap_string();

    let mod_attr = AttributeModification {
        operation: ModifyOperation::Add,
        attribute: LdapAttribute {
            type_name: KEY_CREDENTIAL_LINK_ATTR.to_string(),
            values: vec![ldap_val.as_bytes().to_vec()],
        },
    };

    client.modify(target_dn, vec![mod_attr])?;
    Ok(ldap_val)
}

/// Removes a shadow credential from `target_dn` by matching its raw DN-Binary string, DeviceId, or KeyID.
pub fn remove_shadow_credential<S: Read + Write>(
    client: &mut LdapClient<S>,
    target_dn: &str,
    id_or_raw: &str,
) -> Result<bool, CoreError> {
    let creds = read_shadow_credentials(client, target_dn)?;
    let target_norm = id_or_raw.trim().replace('-', "").to_lowercase();

    for (dn_bin, blob) in creds {
        let key_id_match = blob.key_id_hex().to_lowercase() == target_norm;
        let dev_id_match = encode_hex(&blob.device_id).to_lowercase() == target_norm
            || blob.device_id_str().replace('-', "").to_lowercase() == target_norm;
        let raw_match = dn_bin.to_ldap_string().eq_ignore_ascii_case(id_or_raw.trim());

        if key_id_match || dev_id_match || raw_match {
            let ldap_val = dn_bin.to_ldap_string();
            let mod_attr = AttributeModification {
                operation: ModifyOperation::Delete,
                attribute: LdapAttribute {
                    type_name: KEY_CREDENTIAL_LINK_ATTR.to_string(),
                    values: vec![ldap_val.as_bytes().to_vec()],
                },
            };
            client.modify(target_dn, vec![mod_attr])?;
            return Ok(true);
        }
    }

    Ok(false)
}

/// Clears all shadow credentials from `target_dn`.
pub fn clear_shadow_credentials<S: Read + Write>(
    client: &mut LdapClient<S>,
    target_dn: &str,
) -> Result<usize, CoreError> {
    let creds = read_shadow_credentials(client, target_dn)?;
    let count = creds.len();

    if count == 0 {
        return Ok(0);
    }

    let mod_attr = AttributeModification {
        operation: ModifyOperation::Delete,
        attribute: LdapAttribute {
            type_name: KEY_CREDENTIAL_LINK_ATTR.to_string(),
            values: Vec::new(),
        },
    };

    client.modify(target_dn, vec![mod_attr])?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcrypt_rsa_public_key_roundtrip() {
        let modulus = vec![0x12; 256];
        let exponent = vec![0x01, 0x00, 0x01];
        let rsa = BcryptRsaPublicKey::new(2048, exponent.clone(), modulus.clone());

        let bytes = rsa.to_bytes();
        assert_eq!(bytes.len(), 24 + 3 + 256);

        let parsed = BcryptRsaPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.bit_length, 2048);
        assert_eq!(parsed.public_exponent, exponent);
        assert_eq!(parsed.modulus, modulus);
    }

    #[test]
    fn test_key_credential_link_blob_rsa_roundtrip() {
        let modulus = vec![0xAB; 256];
        let exponent = vec![0x01, 0x00, 0x01];
        let device_id = [0x77u8; 16];
        let creation_time = 133500000000000000u64;

        let blob = KeyCredentialLinkBlob::new_rsa(&modulus, &exponent, Some(device_id), Some(creation_time));
        assert_eq!(blob.version, 0x0000_0200);
        assert_eq!(blob.key_usage, KEY_USAGE_NGC);
        assert_eq!(blob.device_id, device_id);

        let bytes = blob.to_bytes();
        assert!(!bytes.is_empty());

        let parsed = KeyCredentialLinkBlob::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, blob.version);
        assert_eq!(parsed.key_id, blob.key_id);
        assert_eq!(parsed.key_hash, blob.key_hash);
        assert_eq!(parsed.key_usage, KEY_USAGE_NGC);
        assert_eq!(parsed.device_id, device_id);
        assert_eq!(parsed.creation_time, Some(creation_time));

        let rsa_key = parsed.parse_rsa_key().unwrap();
        assert_eq!(rsa_key.bit_length, 2048);
        assert_eq!(rsa_key.modulus, modulus);
        assert_eq!(rsa_key.public_exponent, exponent);
    }

    #[test]
    fn test_dn_binary_string_codec() {
        let raw_binary = vec![0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB];
        let target_dn = "CN=VictimUser,CN=Users,DC=corp,DC=local";
        let dn_bin = DnBinary::new(raw_binary.clone(), target_dn);

        let ldap_str = dn_bin.to_ldap_string();
        assert_eq!(ldap_str, "B:12:01020304aabb:CN=VictimUser,CN=Users,DC=corp,DC=local");

        let parsed = DnBinary::from_ldap_string(&ldap_str).unwrap();
        assert_eq!(parsed.binary, raw_binary);
        assert_eq!(parsed.dn, target_dn);
    }
}
