//! `gmsa`: Group Managed Service Accounts (gMSA) `msDS-ManagedPassword` (`[MS-ADTS]` Section 2.2.14)
//! codec and credential extractor (`MSDS-MANAGEDPASSWORD_BLOB`).
//!
//! Group Managed Service Accounts use automatically generated 240-byte complex passwords
//! rotated on a periodic schedule (by default 30 days). Authorized principals listed in
//! `msDS-GroupMSAMembership` query the constructed attribute `msDS-ManagedPassword` via LDAP
//! to retrieve the `MSDS-MANAGEDPASSWORD_BLOB`, which contains the active and previous
//! cleartext Unicode passwords and rotation interval metadata.

use crate::compute_nt_hash;
use impacket_core::{encode_hex, CoreError};

/// `MSDS-MANAGEDPASSWORD_BLOB` structure (`[MS-ADTS]` Section 2.2.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedPasswordBlob {
    pub version: u16,
    pub current_password: String,
    pub current_nt_hash: [u8; 16],
    pub previous_password: Option<String>,
    pub previous_nt_hash: Option<[u8; 16]>,
    pub query_interval: u64,
    pub unchanged_interval: u64,
}

impl ManagedPasswordBlob {
    /// Parses an `MSDS-MANAGEDPASSWORD_BLOB` byte slice from the `msDS-ManagedPassword` LDAP attribute.
    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 16 {
            return Err(CoreError::BufferUnderflow {
                needed: 16,
                available: data.len(),
            });
        }

        let version = u16::from_le_bytes(data[0..2].try_into().unwrap());
        let _reserved = u16::from_le_bytes(data[2..4].try_into().unwrap());
        let length = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;

        if data.len() < length {
            return Err(CoreError::BufferUnderflow {
                needed: length,
                available: data.len(),
            });
        }

        let cur_pwd_offset = u16::from_le_bytes(data[8..10].try_into().unwrap()) as usize;
        let prev_pwd_offset = u16::from_le_bytes(data[10..12].try_into().unwrap()) as usize;
        let query_interval_offset = u16::from_le_bytes(data[12..14].try_into().unwrap()) as usize;
        let unchanged_interval_offset = u16::from_le_bytes(data[14..16].try_into().unwrap()) as usize;

        if cur_pwd_offset == 0 || cur_pwd_offset >= data.len() {
            return Err(CoreError::ProtocolError(format!(
                "Invalid CurrentPasswordOffset: {}",
                cur_pwd_offset
            )));
        }

        let current_password = read_null_terminated_utf16(data, cur_pwd_offset)?;
        let current_nt_hash = compute_nt_hash(&current_password);

        let (previous_password, previous_nt_hash) = if prev_pwd_offset != 0 && prev_pwd_offset < data.len() {
            let pwd = read_null_terminated_utf16(data, prev_pwd_offset)?;
            let hash = compute_nt_hash(&pwd);
            (Some(pwd), Some(hash))
        } else {
            (None, None)
        };

        let query_interval = if query_interval_offset != 0 && query_interval_offset + 8 <= data.len() {
            u64::from_le_bytes(data[query_interval_offset..query_interval_offset + 8].try_into().unwrap())
        } else {
            0
        };

        let unchanged_interval = if unchanged_interval_offset != 0 && unchanged_interval_offset + 8 <= data.len() {
            u64::from_le_bytes(data[unchanged_interval_offset..unchanged_interval_offset + 8].try_into().unwrap())
        } else {
            0
        };

        Ok(Self {
            version,
            current_password,
            current_nt_hash,
            previous_password,
            previous_nt_hash,
            query_interval,
            unchanged_interval,
        })
    }

    /// Serializes this `ManagedPasswordBlob` into an `MSDS-MANAGEDPASSWORD_BLOB` (`[MS-ADTS]` Section 2.2.14).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        // Header placeholder (16 bytes)
        buf.resize(16, 0u8);

        // Version: 1
        buf[0..2].copy_from_slice(&self.version.to_le_bytes());
        // Reserved: 0
        buf[2..4].copy_from_slice(&0u16.to_le_bytes());

        // Write CurrentPassword
        let cur_offset = buf.len() as u16;
        buf[8..10].copy_from_slice(&cur_offset.to_le_bytes());
        for c in self.current_password.encode_utf16() {
            buf.extend_from_slice(&c.to_le_bytes());
        }
        buf.extend_from_slice(&[0, 0]); // null terminator

        // Write PreviousPassword if present
        if let Some(ref prev) = self.previous_password {
            let prev_offset = buf.len() as u16;
            buf[10..12].copy_from_slice(&prev_offset.to_le_bytes());
            for c in prev.encode_utf16() {
                buf.extend_from_slice(&c.to_le_bytes());
            }
            buf.extend_from_slice(&[0, 0]);
        } else {
            buf[10..12].copy_from_slice(&0u16.to_le_bytes());
        }

        // Align to 8-byte boundary for intervals
        while buf.len() % 8 != 0 {
            buf.push(0);
        }

        // Write QueryPasswordInterval
        let q_offset = buf.len() as u16;
        buf[12..14].copy_from_slice(&q_offset.to_le_bytes());
        buf.extend_from_slice(&self.query_interval.to_le_bytes());

        // Write UnchangedPasswordInterval
        let u_offset = buf.len() as u16;
        buf[14..16].copy_from_slice(&u_offset.to_le_bytes());
        buf.extend_from_slice(&self.unchanged_interval.to_le_bytes());

        // Total Length
        let total_len = buf.len() as u32;
        buf[4..8].copy_from_slice(&total_len.to_le_bytes());

        buf
    }

    /// Formats the current password's NT hash as lowercase hex string.
    pub fn current_nt_hash_hex(&self) -> String {
        encode_hex(&self.current_nt_hash)
    }

    /// Formats the previous password's NT hash as lowercase hex string (if present).
    pub fn previous_nt_hash_hex(&self) -> Option<String> {
        self.previous_nt_hash.as_ref().map(|h| encode_hex(h))
    }
}

fn read_null_terminated_utf16(data: &[u8], offset: usize) -> Result<String, CoreError> {
    if offset >= data.len() {
        return Err(CoreError::BufferUnderflow {
            needed: offset + 2,
            available: data.len(),
        });
    }
    let slice = &data[offset..];
    let mut u16s = Vec::new();
    for chunk in slice.as_chunks::<2>().0 {
        let code = u16::from_le_bytes([chunk[0], chunk[1]]);
        if code == 0 {
            break;
        }
        u16s.push(code);
    }
    String::from_utf16(&u16s)
        .map_err(|e| CoreError::ProtocolError(format!("Invalid UTF-16 in gMSA password: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gmsa_blob_roundtrip() {
        let blob = ManagedPasswordBlob {
            version: 1,
            current_password: "ComplexGmsaP@ssword2026!#$".into(),
            current_nt_hash: compute_nt_hash("ComplexGmsaP@ssword2026!#$"),
            previous_password: Some("OldGmsaP@ssword2025!".into()),
            previous_nt_hash: Some(compute_nt_hash("OldGmsaP@ssword2025!")),
            query_interval: 25920000000000,     // 30 days in 100ns ticks
            unchanged_interval: 25920000000000, // 30 days
        };

        let bytes = blob.to_bytes();
        assert!(bytes.len() >= 16);

        let parsed = ManagedPasswordBlob::parse(&bytes).expect("ManagedPasswordBlob parse failed");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.current_password, "ComplexGmsaP@ssword2026!#$");
        assert_eq!(parsed.current_nt_hash, blob.current_nt_hash);
        assert_eq!(parsed.previous_password.as_deref(), Some("OldGmsaP@ssword2025!"));
        assert_eq!(parsed.previous_nt_hash, blob.previous_nt_hash);
        assert_eq!(parsed.query_interval, 25920000000000);
        assert_eq!(parsed.unchanged_interval, 25920000000000);
    }

    #[test]
    fn test_gmsa_blob_without_previous_password() {
        let blob = ManagedPasswordBlob {
            version: 1,
            current_password: "OnlyCurrentPassword!123".into(),
            current_nt_hash: compute_nt_hash("OnlyCurrentPassword!123"),
            previous_password: None,
            previous_nt_hash: None,
            query_interval: 1000000,
            unchanged_interval: 2000000,
        };

        let bytes = blob.to_bytes();
        let parsed = ManagedPasswordBlob::parse(&bytes).expect("parse failed");
        assert_eq!(parsed.current_password, "OnlyCurrentPassword!123");
        assert_eq!(parsed.previous_password, None);
        assert_eq!(parsed.previous_nt_hash, None);
        assert_eq!(parsed.query_interval, 1000000);
        assert_eq!(parsed.unchanged_interval, 2000000);
    }
}
