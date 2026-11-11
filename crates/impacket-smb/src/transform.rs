//! `transform`: SMB 3.x Message Encryption and Decryption (`[MS-SMB2]` 2.2.41, 3.1.4.3).
//!
//! Handles `SMB2_TRANSFORM_HEADER` encapsulation, decapsulation, and cryptographic key derivation
//! for **SMB 3.0 / 3.0.2** (AES-128-CCM) and **SMB 3.1.1** (AES-128-GCM, AES-128-CCM, AES-256-GCM, AES-256-CCM).

use impacket_core::CoreError;
use impacket_crypto::{
    aes128_ccm_decrypt, aes128_ccm_encrypt, aes128_gcm_decrypt, aes128_gcm_encrypt,
    aes256_ccm_decrypt, aes256_ccm_encrypt, aes256_gcm_decrypt, aes256_gcm_encrypt,
    sp800_108_counter_kdf,
};

/// SMB 3.x Encryption Cipher Algorithms (`[MS-SMB2]` 2.2.3.1.2).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum SmbCipherAlgorithm {
    Aes128Ccm = 0x0001,
    Aes128Gcm = 0x0002,
    Aes256Ccm = 0x0003,
    Aes256Gcm = 0x0004,
}

impl SmbCipherAlgorithm {
    pub const fn from_u16(val: u16) -> Option<Self> {
        match val {
            0x0001 => Some(Self::Aes128Ccm),
            0x0002 => Some(Self::Aes128Gcm),
            0x0003 => Some(Self::Aes256Ccm),
            0x0004 => Some(Self::Aes256Gcm),
            _ => None,
        }
    }

    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Ccm | Self::Aes128Gcm => 16,
            Self::Aes256Ccm | Self::Aes256Gcm => 32,
        }
    }

    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes128Ccm | Self::Aes256Ccm => 11,
            Self::Aes128Gcm | Self::Aes256Gcm => 12,
        }
    }
}

/// 52-byte SMB2 Transform Header (`[MS-SMB2]` Section 2.2.41).
pub const SMB2_TRANSFORM_HEADER_MAGIC: [u8; 4] = [0xFD, b'S', b'M', b'B'];
pub const SMB2_TRANSFORM_HEADER_SIZE: usize = 52;

/// Checks if a buffer begins with an SMB 3.x `SMB2_TRANSFORM_HEADER`.
pub fn is_transform_header(pdu: &[u8]) -> bool {
    pdu.len() >= SMB2_TRANSFORM_HEADER_SIZE && pdu[0..4] == SMB2_TRANSFORM_HEADER_MAGIC
}

/// Active SMB 3.x session encryption state.
#[derive(Clone)]
pub struct Smb3EncryptionState {
    pub cipher: SmbCipherAlgorithm,
    /// Outgoing cipher key (Client -> Server).
    pub client_out_key: Vec<u8>,
    /// Incoming cipher key (Server -> Client).
    pub client_in_key: Vec<u8>,
    /// Monotonically incrementing nonce counter (low 8 bytes of nonce).
    pub nonce_counter: u64,
}

impl Smb3EncryptionState {
    /// Derives encryption keys for **SMB 3.0 / 3.0.2** using SP800-108 KDF (`[MS-SMB2]` 3.1.4.2).
    ///
    /// - ClientOutKey (Client -> Server): `KDF(SessionKey, "SMB2AESCCM\0", "ServerIn \0")`
    /// - ClientInKey  (Server -> Client): `KDF(SessionKey, "SMB2AESCCM\0", "ServerOut\0")`
    pub fn new_smb30(session_key: &[u8; 16]) -> Self {
        let client_out_key =
            sp800_108_counter_kdf(session_key, b"SMB2AESCCM\0", b"ServerIn \0", 16);
        let client_in_key =
            sp800_108_counter_kdf(session_key, b"SMB2AESCCM\0", b"ServerOut\0", 16);
        Self {
            cipher: SmbCipherAlgorithm::Aes128Ccm,
            client_out_key,
            client_in_key,
            nonce_counter: 1,
        }
    }

    /// Derives encryption keys for **SMB 3.1.1** using SP800-108 KDF bound to `PreauthIntegrityHash` (`[MS-SMB2]` 3.1.4.2).
    ///
    /// - ClientOutKey (Client -> Server): `KDF(SessionKey, "SMBC2SCipherKey\0", PreauthIntegrityHash)`
    /// - ClientInKey  (Server -> Client): `KDF(SessionKey, "SMBS2CCipherKey\0", PreauthIntegrityHash)`
    pub fn new_smb311(
        session_key: &[u8; 16],
        preauth_hash: &[u8; 64],
        cipher: SmbCipherAlgorithm,
    ) -> Self {
        let klen = cipher.key_len();
        let client_out_key =
            sp800_108_counter_kdf(session_key, b"SMBC2SCipherKey\0", preauth_hash, klen);
        let client_in_key =
            sp800_108_counter_kdf(session_key, b"SMBS2CCipherKey\0", preauth_hash, klen);
        Self {
            cipher,
            client_out_key,
            client_in_key,
            nonce_counter: 1,
        }
    }

    /// Generates a fresh 16-byte nonce with the leading bytes unique and remainder zeroed.
    fn generate_nonce(&mut self) -> [u8; 16] {
        let mut nonce = [0u8; 16];
        let n_len = self.cipher.nonce_len();
        let cnt = self.nonce_counter;
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        let cnt_bytes = cnt.to_le_bytes();
        let fill = cnt_bytes.len().min(n_len);
        nonce[..fill].copy_from_slice(&cnt_bytes[..fill]);
        // Put entropy in remaining active nonce bytes if any
        if n_len > fill {
            nonce[fill..n_len].fill(0xA5);
        }
        nonce
    }

    /// Encapsulates and encrypts a plaintext SMB2 message into an `SMB2_TRANSFORM_HEADER` frame (`[MS-SMB2]` 3.1.4.3).
    pub fn encrypt(&mut self, session_id: u64, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
        let nonce = self.generate_nonce();
        let n_active = self.cipher.nonce_len();

        // 1. Build partial 52-byte TRANSFORM_HEADER (signature zeroed).
        let mut hdr = [0u8; SMB2_TRANSFORM_HEADER_SIZE];
        hdr[0..4].copy_from_slice(&SMB2_TRANSFORM_HEADER_MAGIC);
        // Signature at hdr[4..20] is zero for now.
        hdr[20..36].copy_from_slice(&nonce);
        hdr[36..40].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
        hdr[40..42].copy_from_slice(&0u16.to_le_bytes()); // Reserved
        hdr[42..44].copy_from_slice(&(self.cipher as u16).to_le_bytes()); // Flags/EncryptionAlgorithm
        hdr[44..52].copy_from_slice(&session_id.to_le_bytes());

        // 2. AAD is header bytes 20..52 (32 bytes).
        let aad = &hdr[20..52];

        // 3. Encrypt payload and compute 16-byte authentication tag.
        let (ciphertext, tag) = match self.cipher {
            SmbCipherAlgorithm::Aes128Gcm => {
                let k: [u8; 16] = self.client_out_key[..16].try_into().unwrap();
                let (ct, t) = aes128_gcm_encrypt(&k, &nonce[..n_active], aad, plaintext)?;
                (ct, t.to_vec())
            }
            SmbCipherAlgorithm::Aes128Ccm => {
                let k: [u8; 16] = self.client_out_key[..16].try_into().unwrap();
                let (ct, t) = aes128_ccm_encrypt(&k, &nonce[..n_active], aad, plaintext, 16)?;
                (ct, t)
            }
            SmbCipherAlgorithm::Aes256Gcm => {
                let k: [u8; 32] = self.client_out_key[..32].try_into().unwrap();
                let (ct, t) = aes256_gcm_encrypt(&k, &nonce[..n_active], aad, plaintext)?;
                (ct, t.to_vec())
            }
            SmbCipherAlgorithm::Aes256Ccm => {
                let k: [u8; 32] = self.client_out_key[..32].try_into().unwrap();
                let (ct, t) = aes256_ccm_encrypt(&k, &nonce[..n_active], aad, plaintext, 16)?;
                (ct, t)
            }
        };

        // 4. Place tag in Signature field [4..20].
        hdr[4..20].copy_from_slice(&tag);

        let mut out = Vec::with_capacity(SMB2_TRANSFORM_HEADER_SIZE + ciphertext.len());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypts and authenticates an incoming `SMB2_TRANSFORM_HEADER` frame (`[MS-SMB2]` 3.1.5.3).
    pub fn decrypt(&self, transform_packet: &[u8]) -> Result<Vec<u8>, CoreError> {
        if transform_packet.len() < SMB2_TRANSFORM_HEADER_SIZE {
            return Err(CoreError::BufferUnderflow {
                needed: SMB2_TRANSFORM_HEADER_SIZE,
                available: transform_packet.len(),
            });
        }
        if &transform_packet[0..4] != &SMB2_TRANSFORM_HEADER_MAGIC {
            return Err(CoreError::ProtocolError(
                "Invalid SMB2_TRANSFORM_HEADER protocol id".into(),
            ));
        }

        let tag = &transform_packet[4..20];
        let nonce = &transform_packet[20..36];
        let original_size = u32::from_le_bytes([
            transform_packet[36],
            transform_packet[37],
            transform_packet[38],
            transform_packet[39],
        ]) as usize;
        let aad = &transform_packet[20..52];
        let ciphertext = &transform_packet[52..];

        let n_active = self.cipher.nonce_len();
        let plaintext = match self.cipher {
            SmbCipherAlgorithm::Aes128Gcm => {
                let k: [u8; 16] = self.client_in_key[..16].try_into().unwrap();
                let t: [u8; 16] = tag.try_into().unwrap();
                aes128_gcm_decrypt(&k, &nonce[..n_active], aad, ciphertext, &t)?
            }
            SmbCipherAlgorithm::Aes128Ccm => {
                let k: [u8; 16] = self.client_in_key[..16].try_into().unwrap();
                aes128_ccm_decrypt(&k, &nonce[..n_active], aad, ciphertext, tag)?
            }
            SmbCipherAlgorithm::Aes256Gcm => {
                let k: [u8; 32] = self.client_in_key[..32].try_into().unwrap();
                let t: [u8; 16] = tag.try_into().unwrap();
                aes256_gcm_decrypt(&k, &nonce[..n_active], aad, ciphertext, &t)?
            }
            SmbCipherAlgorithm::Aes256Ccm => {
                let k: [u8; 32] = self.client_in_key[..32].try_into().unwrap();
                aes256_ccm_decrypt(&k, &nonce[..n_active], aad, ciphertext, tag)?
            }
        };

        if plaintext.len() != original_size {
            return Err(CoreError::ProtocolError(format!(
                "Decrypted message size {} does not match transform header size {}",
                plaintext.len(),
                original_size
            )));
        }

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb3_transform_encryption_and_decryption_roundtrip() {
        let session_key = [0x42u8; 16];
        let preauth_hash = [0x77u8; 64];

        // 1. Test SMB 3.0 AES-128-CCM
        let mut enc30 = Smb3EncryptionState::new_smb30(&session_key);
        // In loopback test, incoming key matches outgoing key
        let mut dec30 = enc30.clone();
        dec30.client_in_key = enc30.client_out_key.clone();

        let plaintext = b"SMB2_WRITE_DATA_TO_SECURE_SHARE_PAYLOAD_1234567890";
        let session_id = 0x0102_0304_0506_0708;
        let transformed = enc30.encrypt(session_id, plaintext).unwrap();

        assert!(is_transform_header(&transformed));
        assert_eq!(transformed.len(), SMB2_TRANSFORM_HEADER_SIZE + plaintext.len());

        let decrypted = dec30.decrypt(&transformed).unwrap();
        assert_eq!(decrypted, plaintext);

        // 2. Test SMB 3.1.1 AES-128-GCM
        let mut enc311 = Smb3EncryptionState::new_smb311(
            &session_key,
            &preauth_hash,
            SmbCipherAlgorithm::Aes128Gcm,
        );
        let mut dec311 = enc311.clone();
        dec311.client_in_key = enc311.client_out_key.clone();

        let transformed_gcm = enc311.encrypt(session_id, plaintext).unwrap();
        assert!(is_transform_header(&transformed_gcm));
        let decrypted_gcm = dec311.decrypt(&transformed_gcm).unwrap();
        assert_eq!(decrypted_gcm, plaintext);

        // 3. Tamper test: flipped byte in ciphertext causes auth rejection
        let mut tampered = transformed_gcm.clone();
        tampered[SMB2_TRANSFORM_HEADER_SIZE + 2] ^= 0xFF;
        assert!(dec311.decrypt(&tampered).is_err());
    }
}
