//! Channel Binding Tokens (CBT) and Extended Protection for Authentication (EPA)
//! per RFC 5929 and [MS-NLMP] §3.1.5.1.2.
//!
//! Windows Server 2019, 2022, and 2025 enforce LDAP Channel Binding (`LdapEnforceChannelBinding = 2`),
//! rejecting NTLM authentication over LDAPS / HTTPS that lacks valid `tls-server-end-point`
//! channel binding hashes in the NTLMSSP Type 3 `AV_PAIR` block.

use impacket_crypto::{md5, sha256};
use crate::NtlmTargetInfo;

/// `MsvAvFlags` bit flag indicating channel bindings are present per [MS-NLMP] 2.2.2.1.
pub const MSV_AV_FLAG_CHANNEL_BINDING_PRESENT: u32 = 0x0000_0002;

/// Computes the 16-byte MD5 `ClientChannelBindingsHash` from a TLS server certificate's
/// DER-encoded bytes using the `tls-server-end-point` channel binding type (RFC 5929 §4).
///
/// Per RFC 5929 §4.1:
/// The channel binding application data is the SHA-256 hash of the server certificate.
///
/// Per [MS-NLMP] §3.1.5.1.2 and RFC 2743:
/// The `gss_channel_bindings_struct` is formatted as:
/// - `initiator_addrtype`: 4 bytes LE (`0x00000000`)
/// - `initiator_address_len`: 4 bytes LE (`0x00000000`)
/// - `acceptor_addrtype`: 4 bytes LE (`0x00000000`)
/// - `acceptor_address_len`: 4 bytes LE (`0x00000000`)
/// - `application_data_len`: 4 bytes LE (`0x00000020` = 32 bytes)
/// - `application_data`: 32 bytes (SHA-256 of server certificate DER)
///
/// The resulting 52-byte structure is hashed with MD5 to yield the 16-byte
/// `ClientChannelBindingsHash` placed in `MsvAvChannelBindings` (AV_PAIR 0x000A).
pub fn compute_channel_bindings_hash_from_cert(cert_der: &[u8]) -> [u8; 16] {
    let cert_sha256 = sha256(cert_der);
    compute_channel_bindings_hash_from_sha256(&cert_sha256)
}

/// Computes the 16-byte MD5 `ClientChannelBindingsHash` directly from a pre-computed
/// SHA-256 certificate digest.
pub fn compute_channel_bindings_hash_from_sha256(cert_sha256: &[u8; 32]) -> [u8; 16] {
    // 16 bytes address headers + 4 bytes length + 32 bytes SHA-256 = 52 bytes
    let mut gss_bindings = [0u8; 52];
    // application_data_len at offset 16 (4 bytes little-endian = 32)
    gss_bindings[16] = 32;
    // application_data (SHA-256 hash) at offsets 20..52
    gss_bindings[20..52].copy_from_slice(cert_sha256);
    md5(&gss_bindings)
}

/// Injects a computed channel binding hash into an `NtlmTargetInfo` block and sets
/// the `MSV_AV_FLAG_CHANNEL_BINDING_PRESENT` bit in `MsvAvFlags`.
pub fn inject_channel_bindings(
    target_info: &mut NtlmTargetInfo,
    channel_bindings_hash: [u8; 16],
) {
    target_info.channel_bindings = Some(channel_bindings_hash);
    let current_flags = target_info.flags.unwrap_or(0);
    target_info.flags = Some(current_flags | MSV_AV_FLAG_CHANNEL_BINDING_PRESENT);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_bindings_hash_calculation() {
        // Known test certificate payload
        let mock_cert = b"-----BEGIN CERTIFICATE-----\nMOCK_ACTIVE_DIRECTORY_CERTIFICATE_PAYLOAD_FOR_TESTING\n-----END CERTIFICATE-----";
        let hash = compute_channel_bindings_hash_from_cert(mock_cert);
        assert_eq!(hash.len(), 16);
        assert_ne!(hash, [0u8; 16]);

        // Verifying deterministic calculation from precomputed SHA-256
        let cert_sha = sha256(mock_cert);
        let hash2 = compute_channel_bindings_hash_from_sha256(&cert_sha);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_inject_channel_bindings_into_target_info() {
        let mut ti = NtlmTargetInfo::default();
        let mock_hash = [0xAA; 16];
        inject_channel_bindings(&mut ti, mock_hash);

        assert_eq!(ti.channel_bindings, Some(mock_hash));
        assert!(ti.flags.is_some());
        assert_eq!(
            ti.flags.unwrap() & MSV_AV_FLAG_CHANNEL_BINDING_PRESENT,
            MSV_AV_FLAG_CHANNEL_BINDING_PRESENT
        );

        // Serialize to bytes and parse back
        let bytes = ti.to_bytes();
        let parsed = NtlmTargetInfo::parse(&bytes).unwrap();
        assert_eq!(parsed.channel_bindings, Some(mock_hash));
        assert_eq!(
            parsed.flags.unwrap() & MSV_AV_FLAG_CHANNEL_BINDING_PRESENT,
            MSV_AV_FLAG_CHANNEL_BINDING_PRESENT
        );
    }
}
