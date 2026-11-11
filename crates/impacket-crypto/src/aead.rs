//! `aead`: Pure-Rust Authenticated Encryption with Associated Data (AEAD) primitives.
//!
//! Provides:
//! - **AES-GCM** (Galois/Counter Mode, NIST SP 800-38D) for SMB 3.1.1 (`SMB2_ENCRYPTION_AES128_GCM`, `SMB2_ENCRYPTION_AES256_GCM`).
//! - **AES-CCM** (Counter with CBC-MAC, NIST SP 800-38C) for SMB 3.0 / 3.0.2 / 3.1.1 (`SMB2_ENCRYPTION_AES128_CCM`, `SMB2_ENCRYPTION_AES256_CCM`).

use crate::{aes128, aes256};
use impacket_core::CoreError;

// ============================================================================
// GHASH & Galois Field GF(2^128) arithmetic (NIST SP 800-38D Algorithm 1)
// ============================================================================

/// Multiplies a 128-bit block `x` by subkey `y` in GF(2^128) modulo P(x) = x^128 + x^7 + x^2 + x + 1.
///
/// In GCM bit reflection, bit 0 of byte 0 is the most significant bit (coefficient of x^0),
/// and the reduction polynomial constant is R = 0xE1000000000000000000000000000000.
fn ghash_multiply(x: &mut [u8; 16], y: &[u8; 16]) {
    let mut z = [0u8; 16];
    let mut v = *y;

    for i in 0..128 {
        let bit = (x[i / 8] >> (7 - (i % 8))) & 1;
        if bit != 0 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }
        let lsb = v[15] & 1;
        // Shift 128-bit block right by 1 bit.
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>= 1;
        if lsb != 0 {
            v[0] ^= 0xe1;
        }
    }
    *x = z;
}

/// Computes GHASH over Additional Authenticated Data (`aad`) and Ciphertext (`ct`).
fn ghash(h: &[u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];

    // Process AAD chunks (zero-padded to 16 bytes).
    for chunk in aad.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for j in 0..16 {
            y[j] ^= block[j];
        }
        ghash_multiply(&mut y, h);
    }

    // Process Ciphertext chunks (zero-padded to 16 bytes).
    for chunk in ct.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for j in 0..16 {
            y[j] ^= block[j];
        }
        ghash_multiply(&mut y, h);
    }

    // Append length block: [len(A) in bits as u64 BE] || [len(C) in bits as u64 BE].
    let aad_bits = (aad.len() as u64).wrapping_mul(8);
    let ct_bits = (ct.len() as u64).wrapping_mul(8);
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..16].copy_from_slice(&ct_bits.to_be_bytes());
    for j in 0..16 {
        y[j] ^= len_block[j];
    }
    ghash_multiply(&mut y, h);

    y
}

/// Increments the rightmost 32 bits of a 16-byte counter block (NIST inc_32).
#[inline(always)]
fn inc32(counter: &mut [u8; 16]) {
    let mut val = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
    val = val.wrapping_add(1);
    counter[12..16].copy_from_slice(&val.to_be_bytes());
}

/// Generic AES-GCM encryption with pluggable AES block cipher.
fn aes_gcm_encrypt_generic<F>(
    encrypt_block: F,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), CoreError>
where
    F: Fn(&[u8; 16]) -> [u8; 16],
{
    // Derive subkey H = AES_K(0^128).
    let h = encrypt_block(&[0u8; 16]);

    // Format pre-counter block J0.
    let mut j0 = [0u8; 16];
    if nonce.len() == 12 {
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
    } else {
        // For non-96-bit nonces: J0 = GHASH_H(nonce || 0^(s+64) || len(nonce)_64).
        j0 = ghash(&h, &[], nonce);
    }

    // CTR mode: CB_1 = inc32(J0).
    let mut cb = j0;
    inc32(&mut cb);

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for chunk in plaintext.chunks(16) {
        let keystream = encrypt_block(&cb);
        for (p, k) in chunk.iter().zip(keystream.iter()) {
            ciphertext.push(p ^ k);
        }
        inc32(&mut cb);
    }

    // S = GHASH_H(AAD, Ciphertext).
    let s = ghash(&h, aad, &ciphertext);

    // Tag T = S ^ AES_K(J0).
    let ej0 = encrypt_block(&j0);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = s[i] ^ ej0[i];
    }

    Ok((ciphertext, tag))
}

/// Generic AES-GCM decryption with constant-time tag verification.
fn aes_gcm_decrypt_generic<F>(
    encrypt_block: F,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, CoreError>
where
    F: Fn(&[u8; 16]) -> [u8; 16],
{
    let h = encrypt_block(&[0u8; 16]);

    let mut j0 = [0u8; 16];
    if nonce.len() == 12 {
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
    } else {
        j0 = ghash(&h, &[], nonce);
    }

    let s = ghash(&h, aad, ciphertext);
    let ej0 = encrypt_block(&j0);
    let mut expected_tag = [0u8; 16];
    for i in 0..16 {
        expected_tag[i] = s[i] ^ ej0[i];
    }

    // Constant-time tag comparison.
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected_tag[i] ^ tag[i];
    }
    if diff != 0 {
        return Err(CoreError::ProtocolError(
            "AES-GCM authentication tag mismatch".into(),
        ));
    }

    let mut cb = j0;
    inc32(&mut cb);

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        let keystream = encrypt_block(&cb);
        for (c, k) in chunk.iter().zip(keystream.iter()) {
            plaintext.push(c ^ k);
        }
        inc32(&mut cb);
    }

    Ok(plaintext)
}

/// Encrypts `plaintext` using **AES-128-GCM** (NIST SP 800-38D).
pub fn aes128_gcm_encrypt(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), CoreError> {
    aes_gcm_encrypt_generic(|b| aes128::encrypt_block(key, b), nonce, aad, plaintext)
}

/// Decrypts `ciphertext` using **AES-128-GCM** (NIST SP 800-38D).
pub fn aes128_gcm_decrypt(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, CoreError> {
    aes_gcm_decrypt_generic(|b| aes128::encrypt_block(key, b), nonce, aad, ciphertext, tag)
}

/// Encrypts `plaintext` using **AES-256-GCM** (NIST SP 800-38D).
pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), CoreError> {
    aes_gcm_encrypt_generic(|b| aes256::encrypt_block(key, b), nonce, aad, plaintext)
}

/// Decrypts `ciphertext` using **AES-256-GCM** (NIST SP 800-38D).
pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, CoreError> {
    aes_gcm_decrypt_generic(|b| aes256::encrypt_block(key, b), nonce, aad, ciphertext, tag)
}

// ============================================================================
// AES-CCM (NIST SP 800-38C)
// ============================================================================

/// Generic AES-CCM encryption with pluggable AES block cipher.
fn aes_ccm_encrypt_generic<F>(
    encrypt_block: F,
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Result<(Vec<u8>, Vec<u8>), CoreError>
where
    F: Fn(&[u8; 16]) -> [u8; 16],
{
    let n = nonce.len();
    if !(7..=13).contains(&n) {
        return Err(CoreError::ProtocolError(format!(
            "Invalid CCM nonce length: {} (must be 7..=13)",
            n
        )));
    }
    if !(4..=16).contains(&tag_len) || tag_len % 2 != 0 {
        return Err(CoreError::ProtocolError(format!(
            "Invalid CCM tag length: {} (must be even 4..=16)",
            tag_len
        )));
    }
    let q = 15 - n; // length of length field in bytes

    // Check payload fits within q bytes.
    if q < 8 && (plaintext.len() as u64) >= (1u64 << (8 * q)) {
        return Err(CoreError::ProtocolError("CCM plaintext too long for nonce size".into()));
    }

    // Format B0:
    // Flags = (Adata != 0 ? 0x40 : 0) | (((tag_len - 2) / 2) << 3) | (q - 1).
    let mut b0 = [0u8; 16];
    let adata_bit = if !aad.is_empty() { 0x40 } else { 0 };
    let m_bits = (((tag_len - 2) / 2) as u8) << 3;
    let l_bits = (q - 1) as u8;
    b0[0] = adata_bit | m_bits | l_bits;
    b0[1..1 + n].copy_from_slice(nonce);
    let p_len = plaintext.len() as u64;
    let p_bytes = p_len.to_be_bytes();
    b0[16 - q..16].copy_from_slice(&p_bytes[8 - q..8]);

    // CBC-MAC calculation.
    let mut y = encrypt_block(&b0);

    // Feed AAD into CBC-MAC.
    if !aad.is_empty() {
        let mut aad_enc = Vec::new();
        if aad.len() < 0xFF00 {
            aad_enc.extend_from_slice(&(aad.len() as u16).to_be_bytes());
        } else if aad.len() <= 0xFFFF_FFFF {
            aad_enc.extend_from_slice(&[0xFF, 0xFE]);
            aad_enc.extend_from_slice(&(aad.len() as u32).to_be_bytes());
        } else {
            aad_enc.extend_from_slice(&[0xFF, 0xFF]);
            aad_enc.extend_from_slice(&(aad.len() as u64).to_be_bytes());
        }
        aad_enc.extend_from_slice(aad);
        while aad_enc.len() % 16 != 0 {
            aad_enc.push(0);
        }

        for chunk in aad_enc.chunks_exact(16) {
            for j in 0..16 {
                y[j] ^= chunk[j];
            }
            y = encrypt_block(&y);
        }
    }

    // Feed Plaintext into CBC-MAC.
    for chunk in plaintext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for j in 0..16 {
            y[j] ^= block[j];
        }
        y = encrypt_block(&y);
    }
    let t = &y[..tag_len];

    // Format Counter block A0:
    // Flags = q - 1 (bits 3..7 are 0).
    let mut a0 = [0u8; 16];
    a0[0] = (q - 1) as u8;
    a0[1..1 + n].copy_from_slice(nonce);
    // counter 0 at a0[16 - q..16] is 0

    let s0 = encrypt_block(&a0);
    let mut encrypted_tag = vec![0u8; tag_len];
    for i in 0..tag_len {
        encrypted_tag[i] = t[i] ^ s0[i];
    }

    // CTR mode encryption for plaintext: A_1, A_2, ...
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut counter = 1u64;
    for chunk in plaintext.chunks(16) {
        let mut ai = a0;
        let c_bytes = counter.to_be_bytes();
        ai[16 - q..16].copy_from_slice(&c_bytes[8 - q..8]);
        let si = encrypt_block(&ai);
        for (p, k) in chunk.iter().zip(si.iter()) {
            ciphertext.push(p ^ k);
        }
        counter = counter.wrapping_add(1);
    }

    Ok((ciphertext, encrypted_tag))
}

/// Generic AES-CCM decryption with constant-time tag verification.
fn aes_ccm_decrypt_generic<F>(
    encrypt_block: F,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, CoreError>
where
    F: Fn(&[u8; 16]) -> [u8; 16],
{
    let n = nonce.len();
    if !(7..=13).contains(&n) {
        return Err(CoreError::ProtocolError(format!(
            "Invalid CCM nonce length: {} (must be 7..=13)",
            n
        )));
    }
    let tag_len = tag.len();
    if !(4..=16).contains(&tag_len) || tag_len % 2 != 0 {
        return Err(CoreError::ProtocolError(format!(
            "Invalid CCM tag length: {} (must be even 4..=16)",
            tag_len
        )));
    }
    let q = 15 - n;

    // CTR mode decryption for ciphertext: A_1, A_2, ...
    let mut a0 = [0u8; 16];
    a0[0] = (q - 1) as u8;
    a0[1..1 + n].copy_from_slice(nonce);

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut counter = 1u64;
    for chunk in ciphertext.chunks(16) {
        let mut ai = a0;
        let c_bytes = counter.to_be_bytes();
        ai[16 - q..16].copy_from_slice(&c_bytes[8 - q..8]);
        let si = encrypt_block(&ai);
        for (c, k) in chunk.iter().zip(si.iter()) {
            plaintext.push(c ^ k);
        }
        counter = counter.wrapping_add(1);
    }

    // Recompute CBC-MAC over reconstructed plaintext.
    let mut b0 = [0u8; 16];
    let adata_bit = if !aad.is_empty() { 0x40 } else { 0 };
    let m_bits = (((tag_len - 2) / 2) as u8) << 3;
    let l_bits = (q - 1) as u8;
    b0[0] = adata_bit | m_bits | l_bits;
    b0[1..1 + n].copy_from_slice(nonce);
    let p_len = plaintext.len() as u64;
    let p_bytes = p_len.to_be_bytes();
    b0[16 - q..16].copy_from_slice(&p_bytes[8 - q..8]);

    let mut y = encrypt_block(&b0);

    if !aad.is_empty() {
        let mut aad_enc = Vec::new();
        if aad.len() < 0xFF00 {
            aad_enc.extend_from_slice(&(aad.len() as u16).to_be_bytes());
        } else if aad.len() <= 0xFFFF_FFFF {
            aad_enc.extend_from_slice(&[0xFF, 0xFE]);
            aad_enc.extend_from_slice(&(aad.len() as u32).to_be_bytes());
        } else {
            aad_enc.extend_from_slice(&[0xFF, 0xFF]);
            aad_enc.extend_from_slice(&(aad.len() as u64).to_be_bytes());
        }
        aad_enc.extend_from_slice(aad);
        while aad_enc.len() % 16 != 0 {
            aad_enc.push(0);
        }

        for chunk in aad_enc.chunks_exact(16) {
            for j in 0..16 {
                y[j] ^= chunk[j];
            }
            y = encrypt_block(&y);
        }
    }

    for chunk in plaintext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for j in 0..16 {
            y[j] ^= block[j];
        }
        y = encrypt_block(&y);
    }
    let t = &y[..tag_len];

    let s0 = encrypt_block(&a0);
    let mut expected_tag = vec![0u8; tag_len];
    for i in 0..tag_len {
        expected_tag[i] = t[i] ^ s0[i];
    }

    let mut diff = 0u8;
    for i in 0..tag_len {
        diff |= expected_tag[i] ^ tag[i];
    }
    if diff != 0 {
        return Err(CoreError::ProtocolError(
            "AES-CCM authentication tag mismatch".into(),
        ));
    }

    Ok(plaintext)
}

/// Encrypts `plaintext` using **AES-128-CCM** (NIST SP 800-38C).
pub fn aes128_ccm_encrypt(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
    aes_ccm_encrypt_generic(|b| aes128::encrypt_block(key, b), nonce, aad, plaintext, tag_len)
}

/// Decrypts `ciphertext` using **AES-128-CCM** (NIST SP 800-38C).
pub fn aes128_ccm_decrypt(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, CoreError> {
    aes_ccm_decrypt_generic(|b| aes128::encrypt_block(key, b), nonce, aad, ciphertext, tag)
}

/// Encrypts `plaintext` using **AES-256-CCM** (NIST SP 800-38C).
pub fn aes256_ccm_encrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
    aes_ccm_encrypt_generic(|b| aes256::encrypt_block(key, b), nonce, aad, plaintext, tag_len)
}

/// Decrypts `ciphertext` using **AES-256-CCM** (NIST SP 800-38C).
pub fn aes256_ccm_decrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, CoreError> {
    aes_ccm_decrypt_generic(|b| aes256::encrypt_block(key, b), nonce, aad, ciphertext, tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use impacket_core::encode_hex;

    #[test]
    fn test_aes128_gcm_nist_test_case_1() {
        // NIST SP 800-38D Test Case 1: Empty PT and AAD
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let (ct, tag) = aes128_gcm_encrypt(&key, &iv, &[], &[]).unwrap();
        assert!(ct.is_empty());
        assert_eq!(encode_hex(&tag), "58e2fccefa7e3061367f1d57a4e7455a");

        let pt = aes128_gcm_decrypt(&key, &iv, &[], &ct, &tag).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_aes128_gcm_nist_test_case_2() {
        // NIST SP 800-38D Test Case 2: 16 zero bytes PT
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let pt = [0u8; 16];
        let (ct, tag) = aes128_gcm_encrypt(&key, &iv, &[], &pt).unwrap();
        assert_eq!(encode_hex(&ct), "0388dace60b6a392f328c2b971b2fe78");
        assert_eq!(encode_hex(&tag), "ab6e47d42cec13bdf53a67b21257bddf");

        let dec = aes128_gcm_decrypt(&key, &iv, &[], &ct, &tag).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_aes128_gcm_nist_test_case_3() {
        // NIST SP 800-38D Test Case 3: 64-byte PT, empty AAD
        let key = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08,
        ];
        let iv = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let pt = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
        ];
        let (ct, tag) = aes128_gcm_encrypt(&key, &iv, &[], &pt).unwrap();
        assert_eq!(
            encode_hex(&ct),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
        );
        assert_eq!(encode_hex(&tag), "4d5c2af327cd64a62cf35abd2ba6fab4");

        let dec = aes128_gcm_decrypt(&key, &iv, &[], &ct, &tag).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_aes128_gcm_nist_test_case_4() {
        // NIST SP 800-38D Test Case 4: 60-byte PT and 20-byte AAD
        let key = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08,
        ];
        let iv = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let pt = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let aad = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let (ct, tag) = aes128_gcm_encrypt(&key, &iv, &aad, &pt).unwrap();
        assert_eq!(
            encode_hex(&ct),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
        );
        assert_eq!(encode_hex(&tag), "5bc94fbc3221a5db94fae95ae7121a47");

        let dec = aes128_gcm_decrypt(&key, &iv, &aad, &ct, &tag).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_aes256_gcm_nist_test_case_14() {
        // NIST SP 800-38D Test Case 14
        let key = [0u8; 32];
        let iv = [0u8; 12];
        let (ct, tag) = aes256_gcm_encrypt(&key, &iv, &[], &[]).unwrap();
        assert!(ct.is_empty());
        assert_eq!(encode_hex(&tag), "530f8afbc74536b9a963b4f1c4cb738b");

        let dec = aes256_gcm_decrypt(&key, &iv, &[], &ct, &tag).unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    fn test_aes_ccm_roundtrip_various_sizes() {
        let key128 = [0x55u8; 16];
        let key256 = [0xAAu8; 32];
        let nonce = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b]; // 11 bytes (SMB standard)
        let aad = b"SMB2_TRANSFORM_HEADER_AAD_TEST";

        for len in [0, 1, 15, 16, 17, 64, 255, 512] {
            let pt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(13)).collect();

            // AES-128-CCM
            let (ct128, tag128) = aes128_ccm_encrypt(&key128, &nonce, aad, &pt, 16).unwrap();
            assert_eq!(ct128.len(), pt.len());
            assert_eq!(tag128.len(), 16);
            let dec128 = aes128_ccm_decrypt(&key128, &nonce, aad, &ct128, &tag128).unwrap();
            assert_eq!(dec128, pt);

            // Tamper test
            let mut bad_tag = tag128;
            bad_tag[0] ^= 0x01;
            assert!(aes128_ccm_decrypt(&key128, &nonce, aad, &ct128, &bad_tag).is_err());

            // AES-256-CCM
            let (ct256, tag256) = aes256_ccm_encrypt(&key256, &nonce, aad, &pt, 16).unwrap();
            assert_eq!(ct256.len(), pt.len());
            let dec256 = aes256_ccm_decrypt(&key256, &nonce, aad, &ct256, &tag256).unwrap();
            assert_eq!(dec256, pt);
        }
    }
}
