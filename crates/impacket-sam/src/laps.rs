//! `laps`: Windows LAPS v2 (`msLAPS-EncryptedPassword` and `msLAPS-EncryptedPasswordHistory`)
//! DPAPI-NG CMS EnvelopedData parser and decryption engine.
//!
//! Windows LAPS v2 stores passwords in Active Directory as CMS EnvelopedData blobs protected
//! by the Group Key Distribution Protocol (`[MS-GKDI]`). The decryption process:
//! 1. Strip the 16-byte LAPS attribute header (`FILETIME` timestamp, size, reserved).
//! 2. Parse ASN.1 DER CMS `ContentInfo` wrapping `EnvelopedData`.
//! 3. Extract `KEKRecipientInfo`:
//!    - `keyIdentifier` (28 bytes: 16-byte `RootKeyID`, 4-byte `L0`, 4-byte `L1`, 4-byte `L2`).
//!    - `encryptedKey` (RFC 3394 AES-wrapped Content Encryption Key, CEK).
//! 4. Extract `encryptedContentInfo`:
//!    - AES-GCM 12-byte nonce parameters.
//!    - AES-GCM ciphertext + 16-byte authentication tag.
//! 5. Derive Key Encryption Key (KEK) using NIST SP 800-108 Counter Mode KDF over the GKDI L2 key.
//! 6. Unwrap the CEK via RFC 3394 AES Key Unwrap.
//! 7. Decrypt the payload via AES-256-GCM.
//! 8. Parse the decrypted JSON payload (`{"n":"<account>","t":"<timestamp>","p":"<password>"}`).

use impacket_core::der::{decode_oid, decode_tlv};
use impacket_core::CoreError;
use impacket_crypto::{aes256_gcm_decrypt, aes_key_unwrap, sp800_108_counter_kdf};

/// OID constants used in CMS EnvelopedData
pub mod oids {
    /// 1.2.840.113549.1.7.3 (pkcs7-envelopedData)
    pub const ENVELOPED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03];
    /// 1.2.840.113549.1.7.1 (pkcs7-data)
    pub const DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
    /// 2.16.840.1.101.3.4.1.45 (id-aes256-wrap)
    pub const AES256_WRAP: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D];
    /// 2.16.840.1.101.3.4.1.5 (id-aes128-wrap)
    pub const AES128_WRAP: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05];
    /// 2.16.840.1.101.3.4.1.46 (id-aes256-GCM)
    pub const AES256_GCM: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2E];
    /// 2.16.840.1.101.3.4.1.6 (id-aes128-GCM)
    pub const AES128_GCM: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x06];
}

/// Parsed Windows LAPS v2 Encrypted Password attribute.
#[derive(Debug, Clone)]
pub struct LapsEncryptedBlob {
    pub timestamp: u64,
    pub root_key_id: [u8; 16],
    pub l0_index: i32,
    pub l1_index: i32,
    pub l2_index: i32,
    pub key_identifier_bytes: Vec<u8>,
    pub kek_length: usize,
    pub wrapped_cek: Vec<u8>,
    pub gcm_nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; 16],
}

/// Result of decrypting a Windows LAPS v2 password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LapsPasswordResult {
    pub account_name: String,
    pub password: String,
    pub timestamp_str: String,
    pub filetime: u64,
}

impl LapsEncryptedBlob {
    /// Parses a raw LDAP `msLAPS-EncryptedPassword` or `msLAPS-EncryptedPasswordHistory` attribute value.
    pub fn parse(raw_data: &[u8]) -> Result<Self, CoreError> {
        let (timestamp, cms_bytes) = if raw_data.len() >= 16 && raw_data[0] != 0x30 {
            // Attribute has 16-byte header:
            // - 8 bytes: PasswordUpdateTimestamp (FILETIME uint64 LE)
            // - 4 bytes: EncryptedPasswordSize (uint32 LE)
            // - 4 bytes: Reserved (uint32 LE, 0)
            let ts = u64::from_le_bytes(raw_data[0..8].try_into().unwrap());
            let size = u32::from_le_bytes(raw_data[8..12].try_into().unwrap()) as usize;
            if raw_data.len() < 16 + size {
                return Err(CoreError::BufferUnderflow {
                    needed: 16 + size,
                    available: raw_data.len(),
                });
            }
            (ts, &raw_data[16..16 + size])
        } else {
            (0, raw_data)
        };

        // Parse CMS ContentInfo (SEQUENCE)
        let (tag, content_info_val, _) = decode_tlv(cms_bytes)?;
        if tag != 0x30 {
            return Err(CoreError::ProtocolError(format!(
                "Expected ASN.1 SEQUENCE for CMS ContentInfo, got 0x{:02X}",
                tag
            )));
        }

        // 1. contentType OID
        let (oid_bytes, rest) = decode_oid(content_info_val)?;
        if oid_bytes != oids::ENVELOPED_DATA {
            return Err(CoreError::ProtocolError(format!(
                "Invalid CMS contentType OID: {:02x?}",
                oid_bytes
            )));
        }

        // 2. content [0] EXPLICIT EnvelopedData
        let (env_tag, env_data_val, _) = decode_tlv(rest)?;
        if env_tag != 0xA0 {
            return Err(CoreError::ProtocolError(format!(
                "Expected [0] EXPLICIT tag for EnvelopedData (0xA0), got 0x{:02X}",
                env_tag
            )));
        }

        // EnvelopedData is a SEQUENCE
        let (seq_tag, env_seq, _) = decode_tlv(env_data_val)?;
        if seq_tag != 0x30 {
            return Err(CoreError::ProtocolError("Expected SEQUENCE for EnvelopedData".into()));
        }

        // Version (INTEGER)
        let (ver_tag, _, after_ver) = decode_tlv(env_seq)?;
        if ver_tag != 0x02 {
            return Err(CoreError::ProtocolError("Expected INTEGER version in EnvelopedData".into()));
        }

        // RecipientInfos (SET of RecipientInfo)
        let (rcpt_tag, rcpt_set_val, after_rcpt) = decode_tlv(after_ver)?;
        if rcpt_tag != 0x31 {
            return Err(CoreError::ProtocolError("Expected SET for RecipientInfos".into()));
        }

        // KEKRecipientInfo [2]
        let (kek_info_tag, kek_info_val, _) = decode_tlv(rcpt_set_val)?;
        if (kek_info_tag & 0x1F) != 2 {
            return Err(CoreError::ProtocolError(format!(
                "Expected KEKRecipientInfo [2], got 0x{:02X}",
                kek_info_tag
            )));
        }

        // KEKRecipientInfo fields:
        // - version: INTEGER
        // - kekid: KEKIdentifier (SEQUENCE)
        // - keyEncryptionAlgorithm: AlgorithmIdentifier (SEQUENCE)
        // - encryptedKey: OCTET STRING
        let (_, _, after_kek_ver) = decode_tlv(kek_info_val)?;

        // kekid (SEQUENCE)
        let (kekid_tag, kekid_val, after_kekid) = decode_tlv(after_kek_ver)?;
        if kekid_tag != 0x30 {
            return Err(CoreError::ProtocolError("Expected SEQUENCE for KEKIdentifier".into()));
        }

        // keyIdentifier: OCTET STRING
        let (kid_str_tag, key_identifier_bytes_raw, _) = decode_tlv(kekid_val)?;
        if kid_str_tag != 0x04 || key_identifier_bytes_raw.len() < 28 {
            return Err(CoreError::ProtocolError(format!(
                "Invalid KEK keyIdentifier (must be OCTET STRING of at least 28 bytes, got len {})",
                key_identifier_bytes_raw.len()
            )));
        }

        let mut root_key_id = [0u8; 16];
        root_key_id.copy_from_slice(&key_identifier_bytes_raw[0..16]);
        let l0_index = i32::from_le_bytes(key_identifier_bytes_raw[16..20].try_into().unwrap());
        let l1_index = i32::from_le_bytes(key_identifier_bytes_raw[20..24].try_into().unwrap());
        let l2_index = i32::from_le_bytes(key_identifier_bytes_raw[24..28].try_into().unwrap());
        let key_identifier_bytes = key_identifier_bytes_raw.to_vec();

        // keyEncryptionAlgorithm: AlgorithmIdentifier (SEQUENCE)
        let (algo_tag, algo_val, after_algo) = decode_tlv(after_kekid)?;
        if algo_tag != 0x30 {
            return Err(CoreError::ProtocolError("Expected SEQUENCE for keyEncryptionAlgorithm".into()));
        }
        let (wrap_oid, _) = decode_oid(algo_val)?;
        let kek_length = if wrap_oid == oids::AES256_WRAP {
            32
        } else if wrap_oid == oids::AES128_WRAP {
            16
        } else {
            32 // default to 256-bit
        };

        // encryptedKey: OCTET STRING
        let (enc_key_tag, wrapped_cek_val, _) = decode_tlv(after_algo)?;
        if enc_key_tag != 0x04 {
            return Err(CoreError::ProtocolError("Expected OCTET STRING for encryptedKey".into()));
        }
        let wrapped_cek = wrapped_cek_val.to_vec();

        // encryptedContentInfo (SEQUENCE)
        let (enc_cont_info_tag, enc_cont_val, _) = decode_tlv(after_rcpt)?;
        if enc_cont_info_tag != 0x30 {
            return Err(CoreError::ProtocolError("Expected SEQUENCE for encryptedContentInfo".into()));
        }

        // 1. contentType OID (id-data)
        let (_data_oid, after_data_oid) = decode_oid(enc_cont_val)?;

        // 2. contentEncryptionAlgorithm (SEQUENCE)
        let (cont_enc_algo_tag, cont_enc_algo_val, after_cont_enc_algo) = decode_tlv(after_data_oid)?;
        if cont_enc_algo_tag != 0x30 {
            return Err(CoreError::ProtocolError("Expected SEQUENCE for contentEncryptionAlgorithm".into()));
        }
        let (_gcm_oid, gcm_params_rest) = decode_oid(cont_enc_algo_val)?;

        // GCM Parameters: 12-byte IV / Nonce
        let gcm_nonce = extract_gcm_nonce(gcm_params_rest)?;

        // 3. encryptedContent [0] IMPLICIT OCTET STRING
        let (enc_content_tag, enc_content_val, _) = decode_tlv(after_cont_enc_algo)?;
        if (enc_content_tag & 0x1F) != 0 {
            return Err(CoreError::ProtocolError(format!(
                "Expected [0] tag for encryptedContent, got 0x{:02X}",
                enc_content_tag
            )));
        }

        if enc_content_val.len() < 16 {
            return Err(CoreError::ProtocolError(format!(
                "encryptedContent too short: {} bytes (minimum 16)",
                enc_content_val.len()
            )));
        }

        let ct_len = enc_content_val.len() - 16;
        let ciphertext = enc_content_val[..ct_len].to_vec();
        let mut auth_tag = [0u8; 16];
        auth_tag.copy_from_slice(&enc_content_val[ct_len..]);

        Ok(Self {
            timestamp,
            root_key_id,
            l0_index,
            l1_index,
            l2_index,
            key_identifier_bytes,
            kek_length,
            wrapped_cek,
            gcm_nonce,
            ciphertext,
            auth_tag,
        })
    }
}

fn extract_gcm_nonce(params_der: &[u8]) -> Result<[u8; 12], CoreError> {
    if params_der.is_empty() {
        return Err(CoreError::ProtocolError("Missing AES-GCM parameters".into()));
    }
    let (tag, val, _) = decode_tlv(params_der)?;
    let nonce_bytes = if tag == 0x30 {
        // GCMParameters ::= SEQUENCE { aes-nonce OCTET STRING, aes-ICVLen INTEGER OPTIONAL }
        let (inner_tag, inner_val, _) = decode_tlv(val)?;
        if inner_tag != 0x04 {
            return Err(CoreError::ProtocolError("Expected OCTET STRING inside GCMParameters".into()));
        }
        inner_val
    } else if tag == 0x04 {
        val
    } else {
        return Err(CoreError::ProtocolError(format!(
            "Unexpected tag 0x{:02X} for GCMParameters",
            tag
        )));
    };

    if nonce_bytes.len() != 12 {
        return Err(CoreError::ProtocolError(format!(
            "Invalid GCM nonce length: {} bytes (expected 12)",
            nonce_bytes.len()
        )));
    }

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_bytes);
    Ok(nonce)
}

/// Decrypts a Windows LAPS v2 password blob using the MS-GKDI L2 seed key.
pub fn decrypt_laps_blob(
    blob: &LapsEncryptedBlob,
    l2_key: &[u8],
) -> Result<LapsPasswordResult, CoreError> {
    // 1. Derive KEK via NIST SP 800-108 Counter Mode KDF
    let kek = sp800_108_counter_kdf(
        l2_key,
        b"KDS service\0",
        &blob.key_identifier_bytes,
        blob.kek_length,
    );

    // 2. Unwrap Content Encryption Key (CEK) via RFC 3394
    let cek = aes_key_unwrap(&kek, &blob.wrapped_cek)?;
    let cek_arr: [u8; 32] = cek.try_into().map_err(|_| {
        CoreError::ProtocolError("Invalid unwrapped CEK length (expected 32 bytes)".into())
    })?;

    // 3. Decrypt payload via AES-256-GCM
    let plaintext_bytes = aes256_gcm_decrypt(
        &cek_arr,
        &blob.gcm_nonce,
        &[],
        &blob.ciphertext,
        &blob.auth_tag,
    )?;

    // 4. Parse JSON payload: {"n":"<name>","t":"<hex_time>","p":"<cleartext_password>"}
    let json_str = String::from_utf8(plaintext_bytes).map_err(|e| {
        CoreError::ProtocolError(format!("LAPS decrypted payload is not valid UTF-8: {}", e))
    })?;

    parse_laps_json(&json_str, blob.timestamp)
}

/// Parses the cleartext LAPS JSON payload: `{"n":"<username>","t":"<time>","p":"<password>"}`.
pub fn parse_laps_json(json: &str, fallback_filetime: u64) -> Result<LapsPasswordResult, CoreError> {
    let mut account_name = String::new();
    let mut password = String::new();
    let mut timestamp_str = String::new();

    // Lightweight robust JSON field extractor
    for (k, v) in extract_json_string_fields(json) {
        match k.as_str() {
            "n" => account_name = v,
            "p" => password = v,
            "t" => timestamp_str = v,
            _ => {}
        }
    }

    if password.is_empty() && !json.contains("\"p\":") {
        return Err(CoreError::ProtocolError(format!(
            "Missing password field 'p' in LAPS JSON: {}",
            json
        )));
    }

    Ok(LapsPasswordResult {
        account_name,
        password,
        timestamp_str,
        filetime: fallback_filetime,
    })
}

/// Helper extracting key-value string pairs from flat JSON objects.
fn extract_json_string_fields(json: &str) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    let bytes = json.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'"' {
            // Read key
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            let key = String::from_utf8_lossy(&bytes[start..i]).to_string();
            if i < bytes.len() {
                i += 1;
            }

            // Find ':'
            while i < bytes.len() && bytes[i] != b':' && bytes[i] != b'}' {
                i += 1;
            }
            if i >= bytes.len() || bytes[i] == b'}' {
                break;
            }
            i += 1; // skip ':'

            // Find value start
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }

            if i < bytes.len() && bytes[i] == b'"' {
                i += 1;
                let mut unescaped = String::new();
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        match bytes[i + 1] {
                            b'"' => unescaped.push('"'),
                            b'\\' => unescaped.push('\\'),
                            b'/' => unescaped.push('/'),
                            b'b' => unescaped.push('\x08'),
                            b'f' => unescaped.push('\x0c'),
                            b'n' => unescaped.push('\n'),
                            b'r' => unescaped.push('\r'),
                            b't' => unescaped.push('\t'),
                            _ => {
                                unescaped.push('\\');
                                unescaped.push(bytes[i + 1] as char);
                            }
                        }
                        i += 2;
                    } else {
                        unescaped.push(bytes[i] as char);
                        i += 1;
                    }
                }
                if i < bytes.len() {
                    i += 1;
                }
                fields.push((key, unescaped));
            } else {
                // Non-string or number
                let _v_start = i;
                while i < bytes.len() && bytes[i] != b',' && bytes[i] != b'}' {
                    i += 1;
                }
                let val_str = String::from_utf8_lossy(&bytes[_v_start..i]).trim().to_string();
                fields.push((key, val_str));
            }
        } else {
            i += 1;
        }
    }

    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use impacket_core::der::{
        encode_context_explicit, encode_integer, encode_octet_string, encode_oid, encode_sequence,
        encode_tlv,
    };
    use impacket_crypto::{aes256_gcm_encrypt, aes_key_wrap};

    #[test]
    fn test_parse_laps_json() {
        let json = r#"{"n":"Administrator","t":"1d9d43763f35c24","p":"SuperSecretP@ssword123!"}"#;
        let res = parse_laps_json(json, 133742).expect("parse_laps_json failed");
        assert_eq!(res.account_name, "Administrator");
        assert_eq!(res.password, "SuperSecretP@ssword123!");
        assert_eq!(res.timestamp_str, "1d9d43763f35c24");
        assert_eq!(res.filetime, 133742);
    }

    #[test]
    fn test_laps_v2_end_to_end_decryption() {
        let l2_key = [0x55u8; 64];
        let root_key_id = [0x42u8; 16];
        let l0: i32 = 10;
        let l1: i32 = 2;
        let l2: i32 = 1;

        // Build 28-byte keyIdentifier
        let mut key_id_bytes = Vec::with_capacity(28);
        key_id_bytes.extend_from_slice(&root_key_id);
        key_id_bytes.extend_from_slice(&l0.to_le_bytes());
        key_id_bytes.extend_from_slice(&l1.to_le_bytes());
        key_id_bytes.extend_from_slice(&l2.to_le_bytes());

        // Derive KEK
        let kek = sp800_108_counter_kdf(&l2_key, b"KDS service\0", &key_id_bytes, 32);

        // Generate CEK (32 bytes AES-256)
        let cek = [0x88u8; 32];
        let wrapped_cek = aes_key_wrap(&kek, &cek).expect("wrap CEK");

        // Plaintext JSON payload
        let plaintext = br#"{"n":"local-admin","t":"13378945","p":"Hunter2!LapsSecure"}"#;
        let gcm_nonce = [0x12u8; 12];
        let (ciphertext, auth_tag) =
            aes256_gcm_encrypt(&cek, &gcm_nonce, &[], plaintext).expect("gcm encrypt");

        // Construct ASN.1 DER CMS EnvelopedData
        // 1. KEKRecipientInfo [2]
        let kekid_seq = encode_sequence(&[encode_octet_string(&key_id_bytes)]);
        let kek_algo_seq = encode_sequence(&[encode_oid(oids::AES256_WRAP)]);
        let kek_recip_seq = encode_sequence(&[
            encode_integer(4),
            kekid_seq,
            kek_algo_seq,
            encode_octet_string(&wrapped_cek),
        ]);
        let kek_recip_info = encode_tlv(0xA2, &kek_recip_seq[2..]); // [2] KEKRecipientInfo

        // RecipientInfos SET
        let rcpt_infos_set = encode_tlv(0x31, &kek_recip_info);

        // 2. EncryptedContentInfo
        let mut enc_content = ciphertext.clone();
        enc_content.extend_from_slice(&auth_tag);
        let gcm_algo_seq = encode_sequence(&[
            encode_oid(oids::AES256_GCM),
            encode_octet_string(&gcm_nonce),
        ]);
        let enc_content_info_seq = encode_sequence(&[
            encode_oid(oids::DATA),
            gcm_algo_seq,
            encode_tlv(0x80, &enc_content), // [0] IMPLICIT OCTET STRING
        ]);

        // 3. EnvelopedData SEQUENCE
        let env_data_seq = encode_sequence(&[
            encode_integer(2), // version
            rcpt_infos_set,
            enc_content_info_seq,
        ]);
        let env_data_explicit = encode_context_explicit(0, &env_data_seq);

        // 4. ContentInfo SEQUENCE
        let content_info_seq = encode_sequence(&[
            encode_oid(oids::ENVELOPED_DATA),
            env_data_explicit,
        ]);

        // 5. Prepend 16-byte LAPS attribute header
        let mut raw_attr = Vec::new();
        let timestamp: u64 = 13350000000;
        raw_attr.extend_from_slice(&timestamp.to_le_bytes());
        raw_attr.extend_from_slice(&(content_info_seq.len() as u32).to_le_bytes());
        raw_attr.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        raw_attr.extend_from_slice(&content_info_seq);

        // Parse and decrypt!
        let blob = LapsEncryptedBlob::parse(&raw_attr).expect("LapsEncryptedBlob::parse failed");
        assert_eq!(blob.timestamp, timestamp);
        assert_eq!(blob.root_key_id, root_key_id);
        assert_eq!(blob.l0_index, l0);
        assert_eq!(blob.l1_index, l1);
        assert_eq!(blob.l2_index, l2);
        assert_eq!(blob.gcm_nonce, gcm_nonce);

        let res = decrypt_laps_blob(&blob, &l2_key).expect("decrypt_laps_blob failed");
        assert_eq!(res.account_name, "local-admin");
        assert_eq!(res.password, "Hunter2!LapsSecure");
        assert_eq!(res.timestamp_str, "13378945");
        assert_eq!(res.filetime, timestamp);
    }
}
