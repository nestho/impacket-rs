//! `gpp`: Group Policy Preferences (GPP) password decryption engine (`impacket/examples/Get-GPPPassword.py`).
//!
//! Implements Microsoft's published 32-byte AES-256 static decryption key for `cpassword` attributes
//! stored in SYSVOL Group Policy Preference XML configuration files (`Groups.xml`, `Services.xml`,
//! `ScheduledTasks.xml`, etc.).

use impacket_core::{decode_base64, decode_utf16le, CoreError};
use impacket_crypto::aes256;

/// Microsoft's static 32-byte AES-256 key for Group Policy Preferences `cpassword` attributes.
pub const GPP_AES_KEY: [u8; 32] = [
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
    0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
    0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
];

/// A decrypted credential from a Group Policy Preferences XML file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GppCredential {
    pub file_path: String,
    pub user_name: String,
    pub new_name: Option<String>,
    pub password: String,
    pub cpassword_raw: String,
    pub changed: Option<String>,
    pub description: Option<String>,
}

/// Decrypts a GPP `cpassword` attribute string into its UTF-16LE plaintext password.
pub fn decrypt_cpassword(cpass: &str) -> Result<String, CoreError> {
    let trimmed = cpass.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }

    // GPP base64 padding normalization
    let mut padded = trimmed.to_string();
    let rem = padded.len() % 4;
    if rem != 0 {
        for _ in 0..(4 - rem) {
            padded.push('=');
        }
    }

    let decoded = decode_base64(&padded)?;
    if decoded.is_empty() {
        return Ok(String::new());
    }
    if decoded.len() % 16 != 0 {
        return Err(CoreError::ProtocolError(format!(
            "GPP cpassword length ({}) is not a multiple of 16 AES block size",
            decoded.len()
        )));
    }

    // AES-256-CBC with null IV (16 zero bytes)
    let iv = [0u8; 16];
    let decrypted = aes256::decrypt_cbc(&GPP_AES_KEY, &iv, &decoded);

    // PKCS#7 or trailing null unpadding
    let mut unpadded = &decrypted[..];
    if let Some(&last) = unpadded.last() {
        let pad_len = last as usize;
        if pad_len >= 1 && pad_len <= 16 && unpadded.len() >= pad_len {
            if unpadded[unpadded.len() - pad_len..].iter().all(|&b| b == last) {
                unpadded = &unpadded[..unpadded.len() - pad_len];
            }
        }
    }

    // Strip any trailing 2-byte UTF-16LE null terminators
    while unpadded.len() >= 2 && unpadded[unpadded.len() - 2..] == [0, 0] {
        unpadded = &unpadded[..unpadded.len() - 2];
    }

    let pass = decode_utf16le(unpadded)?;
    Ok(pass)
}

/// Parses XML content looking for elements containing `cpassword="..."` and extracts credentials.
pub fn parse_gpp_xml(xml: &str, file_name: &str) -> Result<Vec<GppCredential>, CoreError> {
    let mut creds = Vec::new();

    // Iterate through XML tags
    let mut rest = xml;
    while let Some(start_idx) = rest.find('<') {
        rest = &rest[start_idx + 1..];
        if let Some(end_idx) = rest.find('>') {
            let tag_content = &rest[..end_idx];
            rest = &rest[end_idx + 1..];

            // Ignore XML declaration, comments, closing tags
            if tag_content.starts_with('?') || tag_content.starts_with('!') || tag_content.starts_with('/') {
                continue;
            }

            // Check if tag contains cpassword
            if let Some(cpass_val) = extract_attribute_value(tag_content, "cpassword") {
                if !cpass_val.is_empty() {
                    let password = decrypt_cpassword(&cpass_val)?;
                    let user_name = extract_attribute_value(tag_content, "userName")
                        .or_else(|| extract_attribute_value(tag_content, "accountName"))
                        .or_else(|| extract_attribute_value(tag_content, "runAs"))
                        .or_else(|| extract_attribute_value(tag_content, "username"))
                        .or_else(|| extract_attribute_value(tag_content, "name"))
                        .unwrap_or_else(|| "Unknown".to_string());
                    let new_name = extract_attribute_value(tag_content, "newName");
                    let changed = extract_attribute_value(tag_content, "changed");
                    let description = extract_attribute_value(tag_content, "description");

                    creds.push(GppCredential {
                        file_path: file_name.to_string(),
                        user_name,
                        new_name,
                        password,
                        cpassword_raw: cpass_val,
                        changed,
                        description,
                    });
                }
            }
        } else {
            break;
        }
    }

    Ok(creds)
}

/// Helper extracting an attribute value (`attr="value"` or `attr='value'`) from a tag string.
fn extract_attribute_value(tag: &str, attr_name: &str) -> Option<String> {
    let mut pos = 0;
    while let Some(idx) = tag[pos..].find(attr_name) {
        let abs_idx = pos + idx;
        let after_attr = &tag[abs_idx + attr_name.len()..];
        let trimmed_after = after_attr.trim_start();
        if trimmed_after.starts_with('=') {
            let after_eq = trimmed_after[1..].trim_start();
            if let Some(first_char) = after_eq.chars().next() {
                if first_char == '"' || first_char == '\'' {
                    let quote = first_char;
                    let val_start = &after_eq[1..];
                    if let Some(val_end) = val_start.find(quote) {
                        return Some(val_start[..val_end].to_string());
                    }
                }
            }
        }
        pos = abs_idx + attr_name.len();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_cpassword_known_vector() {
        // Real-world public GPP test vector:
        let cpass = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw";
        let plaintext = decrypt_cpassword(cpass).unwrap();
        assert_eq!(plaintext, "Local*P4ssword!");
    }

    #[test]
    fn test_parse_gpp_xml_extracts_groups_and_tasks() {
        let sample_xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{324F60FB-213E-47f6-867B-07239C4137B6}">
  <User clsid="{DF5F1855-51E5-4d66-853C-467637B1A713}" name="adminLocal" newName="superAdmin"
        userName="DOMAIN\Administrator" description="Built-in admin"
        cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
        changed="2021-05-10 12:30:00" />
</Groups>"#;

        let creds = parse_gpp_xml(sample_xml, r"\\DC01\SYSVOL\Policies\Groups.xml").unwrap();
        assert_eq!(creds.len(), 1);
        let c = &creds[0];
        assert_eq!(c.file_path, r"\\DC01\SYSVOL\Policies\Groups.xml");
        assert_eq!(c.user_name, r"DOMAIN\Administrator");
        assert_eq!(c.new_name.as_deref(), Some("superAdmin"));
        assert_eq!(c.password, "Local*P4ssword!");
        assert_eq!(c.changed.as_deref(), Some("2021-05-10 12:30:00"));
        assert_eq!(c.description.as_deref(), Some("Built-in admin"));
    }
}
