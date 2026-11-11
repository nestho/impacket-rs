//! `session_security`: NTLMSSP Message Signing and Sealing (`[MS-NLMP]` Section 3.4).
//!
//! Provides `NtlmSessionSecurity` implementing `NTLMSSP_NEGOTIATE_SIGN` and `NTLMSSP_NEGOTIATE_SEAL`
//! for DCE/RPC `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` and `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` transports.

use impacket_core::CoreError;
use impacket_crypto::{hmac_md5, md5, Rc4};

const CLIENT_SIGNING_KEY_MAGIC: &[u8] =
    b"session key to client-to-server signing key magic constant\0";
const SERVER_SIGNING_KEY_MAGIC: &[u8] =
    b"session key to server-to-client signing key magic constant\0";
const CLIENT_SEALING_KEY_MAGIC: &[u8] =
    b"session key to client-to-server sealing key magic constant\0";
const SERVER_SEALING_KEY_MAGIC: &[u8] =
    b"session key to server-to-client sealing key magic constant\0";

/// Active NTLMSSP Session Security context managing signing, sealing, and sequence tracking.
pub struct NtlmSessionSecurity {
    client_sign_key: [u8; 16],
    server_sign_key: [u8; 16],
    client_rc4: Rc4,
    server_rc4: Rc4,
    client_seq_num: u32,
    server_seq_num: u32,
}

impl NtlmSessionSecurity {
    /// Initializes session security from the negotiated 16-byte NTLMSSP session key (`[MS-NLMP]` 3.4.5.2).
    pub fn new(session_key: &[u8; 16]) -> Self {
        let mut client_sign_buf = Vec::with_capacity(16 + CLIENT_SIGNING_KEY_MAGIC.len());
        client_sign_buf.extend_from_slice(session_key);
        client_sign_buf.extend_from_slice(CLIENT_SIGNING_KEY_MAGIC);
        let client_sign_key = md5(&client_sign_buf);

        let mut server_sign_buf = Vec::with_capacity(16 + SERVER_SIGNING_KEY_MAGIC.len());
        server_sign_buf.extend_from_slice(session_key);
        server_sign_buf.extend_from_slice(SERVER_SIGNING_KEY_MAGIC);
        let server_sign_key = md5(&server_sign_buf);

        let mut client_seal_buf = Vec::with_capacity(16 + CLIENT_SEALING_KEY_MAGIC.len());
        client_seal_buf.extend_from_slice(session_key);
        client_seal_buf.extend_from_slice(CLIENT_SEALING_KEY_MAGIC);
        let client_seal_key = md5(&client_seal_buf);

        let mut server_seal_buf = Vec::with_capacity(16 + SERVER_SEALING_KEY_MAGIC.len());
        server_seal_buf.extend_from_slice(session_key);
        server_seal_buf.extend_from_slice(SERVER_SEALING_KEY_MAGIC);
        let server_seal_key = md5(&server_seal_buf);

        Self {
            client_sign_key,
            server_sign_key,
            client_rc4: Rc4::new(&client_seal_key),
            server_rc4: Rc4::new(&server_seal_key),
            client_seq_num: 0,
            server_seq_num: 0,
        }
    }

    /// Computes a 16-byte NTLMSSP signature over an unencrypted message (`[MS-NLMP]` 3.4.2).
    pub fn sign_message(&mut self, message: &[u8]) -> [u8; 16] {
        let seq = self.client_seq_num;
        self.client_seq_num = self.client_seq_num.wrapping_add(1);

        let mut data = Vec::with_capacity(4 + message.len());
        data.extend_from_slice(&seq.to_le_bytes());
        data.extend_from_slice(message);
        let hmac = hmac_md5(&self.client_sign_key, &data);

        let mut enc_seq = seq.to_le_bytes();
        self.client_rc4.apply_keystream(&mut enc_seq);

        let mut sig = [0u8; 16];
        sig[0..4].copy_from_slice(&1u32.to_le_bytes()); // Version 1
        sig[4..12].copy_from_slice(&hmac[0..8]); // Checksum
        sig[12..16].copy_from_slice(&enc_seq); // Encrypted sequence number
        sig
    }

    /// Encrypts (seals) `message` and returns the ciphertext alongside its 16-byte signature (`[MS-NLMP]` 3.4.3).
    pub fn seal_message(&mut self, message: &[u8]) -> (Vec<u8>, [u8; 16]) {
        let seq = self.client_seq_num;
        self.client_seq_num = self.client_seq_num.wrapping_add(1);

        // Checksum is calculated over unencrypted plaintext.
        let mut data = Vec::with_capacity(4 + message.len());
        data.extend_from_slice(&seq.to_le_bytes());
        data.extend_from_slice(message);
        let hmac = hmac_md5(&self.client_sign_key, &data);

        let mut ciphertext = message.to_vec();
        self.client_rc4.apply_keystream(&mut ciphertext);

        let mut enc_seq = seq.to_le_bytes();
        self.client_rc4.apply_keystream(&mut enc_seq);

        let mut sig = [0u8; 16];
        sig[0..4].copy_from_slice(&1u32.to_le_bytes());
        sig[4..12].copy_from_slice(&hmac[0..8]);
        sig[12..16].copy_from_slice(&enc_seq);

        (ciphertext, sig)
    }

    /// Decrypts (unseals) incoming `ciphertext` and verifies its 16-byte signature (`[MS-NLMP]` 3.4.4).
    pub fn unseal_message(
        &mut self,
        ciphertext: &[u8],
        signature: &[u8; 16],
    ) -> Result<Vec<u8>, CoreError> {
        let mut plaintext = ciphertext.to_vec();
        self.server_rc4.apply_keystream(&mut plaintext);

        let mut dec_seq = [
            signature[12],
            signature[13],
            signature[14],
            signature[15],
        ];
        self.server_rc4.apply_keystream(&mut dec_seq);
        let seq = u32::from_le_bytes(dec_seq);

        if seq != self.server_seq_num {
            return Err(CoreError::ProtocolError(format!(
                "NTLMSSP sequence mismatch: got {}, expected {}",
                seq, self.server_seq_num
            )));
        }
        self.server_seq_num = self.server_seq_num.wrapping_add(1);

        let mut data = Vec::with_capacity(4 + plaintext.len());
        data.extend_from_slice(&seq.to_le_bytes());
        data.extend_from_slice(&plaintext);
        let expected_hmac = hmac_md5(&self.server_sign_key, &data);

        let mut diff = 0u8;
        for i in 0..8 {
            diff |= expected_hmac[i] ^ signature[4 + i];
        }
        if diff != 0 {
            return Err(CoreError::ProtocolError(
                "NTLMSSP unseal signature verification failed".into(),
            ));
        }

        Ok(plaintext)
    }

    /// Verifies the signature of an incoming unencrypted message.
    pub fn verify_signature(
        &mut self,
        message: &[u8],
        signature: &[u8; 16],
    ) -> Result<(), CoreError> {
        let mut dec_seq = [
            signature[12],
            signature[13],
            signature[14],
            signature[15],
        ];
        self.server_rc4.apply_keystream(&mut dec_seq);
        let seq = u32::from_le_bytes(dec_seq);

        if seq != self.server_seq_num {
            return Err(CoreError::ProtocolError(format!(
                "NTLMSSP sequence mismatch: got {}, expected {}",
                seq, self.server_seq_num
            )));
        }
        self.server_seq_num = self.server_seq_num.wrapping_add(1);

        let mut data = Vec::with_capacity(4 + message.len());
        data.extend_from_slice(&seq.to_le_bytes());
        data.extend_from_slice(message);
        let expected_hmac = hmac_md5(&self.server_sign_key, &data);

        let mut diff = 0u8;
        for i in 0..8 {
            diff |= expected_hmac[i] ^ signature[4 + i];
        }
        if diff != 0 {
            return Err(CoreError::ProtocolError(
                "NTLMSSP signature verification failed".into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntlm_sign_and_seal_roundtrip() {
        let session_key = [0x77u8; 16];
        let mut client = NtlmSessionSecurity::new(&session_key);
        // Emulate server peer receiving from client
        let mut server = NtlmSessionSecurity::new(&session_key);
        // Swap keys on peer so peer server keys match client client keys
        server.server_sign_key = client.client_sign_key;
        server.server_rc4 = Rc4::new(&md5(&[session_key.as_slice(), CLIENT_SEALING_KEY_MAGIC].concat()));

        let msg = b"DCE_RPC_SAMR_LOOKUP_NAMES_STUB_DATA";
        let (ct, sig) = client.seal_message(msg);
        assert_ne!(&ct[..], msg.as_slice());

        let pt = server.unseal_message(&ct, &sig).unwrap();
        assert_eq!(pt, msg);

        // Tamper test
        let (ct2, mut sig2) = client.seal_message(b"Another message");
        sig2[5] ^= 0x01; // flip checksum byte
        assert!(server.unseal_message(&ct2, &sig2).is_err());
    }
}
