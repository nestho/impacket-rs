//! `crypto`: Kerberos v5 encryption types (`impacket/krb5/crypto.py`).
//!
//! Implemented: **RC4-HMAC** (etype 23, RFC 4757) — key = the NT hash (`MD4(UTF-16LE(password))`), so it
//! needs no string-to-key salt. Used for `PA-ENC-TIMESTAMP` pre-authentication and AS-REP/TGS-REP
//! enc-part decryption on RC4-enabled AD.
//!
//! AES128/256-CTS-HMAC-SHA1-96 (etypes 17/18) is the next addition (PBKDF2 string-to-key + AES-CTS +
//! HMAC-SHA1-96).

use impacket_crypto::{hmac_md5, Rc4};

/// Maps a Kerberos key-usage number to the RC4-HMAC "T" value (`[MS-KILE]`/RFC 4757): the AS-REP and
/// TGS-REP encrypted parts (usages 3 and 9) use 8; all others are identity.
fn rc4_usage(keyusage: i32) -> u32 {
    match keyusage {
        3 | 9 => 8,
        u => u as u32,
    }
}

/// RC4-HMAC (etype 23) encryption (RFC 4757 §4). `key` is the 16-byte NT hash. `confounder` must be 8
/// bytes (caller-supplied for determinism/testing). Returns `Checksum(16) || RC4(confounder||plaintext)`.
pub fn rc4_hmac_encrypt(key: &[u8; 16], keyusage: i32, plaintext: &[u8], confounder: &[u8; 8]) -> Vec<u8> {
    let ki = hmac_md5(key, &rc4_usage(keyusage).to_le_bytes());
    let mut data = Vec::with_capacity(8 + plaintext.len());
    data.extend_from_slice(confounder);
    data.extend_from_slice(plaintext);
    let checksum = hmac_md5(&ki, &data);
    let ke = hmac_md5(&ki, &checksum);
    let mut enc = data;
    Rc4::new(&ke).apply_keystream(&mut enc);
    let mut out = Vec::with_capacity(16 + enc.len());
    out.extend_from_slice(&checksum);
    out.extend_from_slice(&enc);
    out
}

/// RC4-HMAC (etype 23) decryption. Verifies the integrity checksum and strips the 8-byte confounder.
pub fn rc4_hmac_decrypt(key: &[u8; 16], keyusage: i32, ciphertext: &[u8]) -> Result<Vec<u8>, impacket_core::CoreError> {
    use impacket_core::CoreError;
    if ciphertext.len() < 24 {
        return Err(CoreError::BufferUnderflow { needed: 24, available: ciphertext.len() });
    }
    let checksum = &ciphertext[..16];
    let ki = hmac_md5(key, &rc4_usage(keyusage).to_le_bytes());
    let ke = hmac_md5(&ki, checksum);
    let mut dec = ciphertext[16..].to_vec();
    Rc4::new(&ke).apply_keystream(&mut dec);
    let actual = hmac_md5(&ki, &dec);
    if actual != *checksum {
        return Err(CoreError::ProtocolError("RC4-HMAC checksum mismatch (wrong key?)".into()));
    }
    Ok(dec[8..].to_vec())
}

/// RC4-HMAC checksum (RFC 4757 / MS-KILE §3.1.5.9).
/// Calculates HMAC-MD5(Ksign, MD5(msusage || data)) where Ksign = HMAC-MD5(key, "signaturekey\0").
pub fn rc4_hmac_checksum(key: &[u8; 16], keyusage: i32, data: &[u8]) -> [u8; 16] {
    let ksign = hmac_md5(key, b"signaturekey\0");
    let msusage = match keyusage {
        3 => 8u32,
        23 => 13u32,
        other => other as u32,
    };
    let mut hasher_data = Vec::with_capacity(4 + data.len());
    hasher_data.extend_from_slice(&msusage.to_le_bytes());
    hasher_data.extend_from_slice(data);
    let md5hash = impacket_crypto::md5(&hasher_data);
    hmac_md5(&ksign, &md5hash)
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// RFC 3961 §5.1 `n-fold` operation: folds an arbitrary-length byte sequence into an `nbytes` output.
pub fn nfold(input: &[u8], nbytes: usize) -> Vec<u8> {
    if input.is_empty() || nbytes == 0 {
        return vec![0u8; nbytes];
    }
    let in_len = input.len();
    let lcm = (nbytes * in_len) / gcd(nbytes, in_len);
    let mut bigstr = Vec::with_capacity(lcm);

    let reps = lcm / in_len;
    for i in 0..reps {
        let nbits = 13 * i;
        let rot_bytes = (nbits / 8) % in_len;
        let remain = nbits % 8;
        for j in 0..in_len {
            let idx1 = (j + in_len - rot_bytes) % in_len;
            let idx2 = (j + in_len - rot_bytes + in_len - 1) % in_len;
            let val = if remain == 0 {
                input[idx1]
            } else {
                (input[idx1] >> remain) | (input[idx2] << (8 - remain))
            };
            bigstr.push(val);
        }
    }

    let mut result = vec![0u32; nbytes];
    for chunk in bigstr.chunks_exact(nbytes) {
        for (r, &b) in result.iter_mut().zip(chunk.iter()) {
            *r += b as u32;
        }
    }

    while result.iter().any(|&x| (x & !0xFF) != 0) {
        let mut next = vec![0u32; nbytes];
        for i in 0..nbytes {
            let carry_from = (i + 1) % nbytes;
            let carry = result[carry_from] >> 8;
            next[i] = (result[i] & 0xFF) + carry;
        }
        result = next;
    }

    result.into_iter().map(|x| x as u8).collect()
}

/// RFC 3961 key derivation for AES-128: `Kc = AES-ECB(key, nfold(constant, 16))`.
pub fn derive_key_rfc3961_aes128(key: &[u8; 16], constant: &[u8]) -> [u8; 16] {
    let folded = nfold(constant, 16);
    let mut block = [0u8; 16];
    block.copy_from_slice(&folded[..16]);
    impacket_crypto::aes128::encrypt_block(key, &block)
}

/// RFC 3961 key derivation for AES-256: derives 32-byte key via chained AES-ECB blocks.
pub fn derive_key_rfc3961_aes256(key: &[u8; 32], constant: &[u8]) -> [u8; 32] {
    let folded = nfold(constant, 16);
    let mut block = [0u8; 16];
    block.copy_from_slice(&folded[..16]);
    let b1 = impacket_crypto::aes256::encrypt_block(key, &block);
    let b2 = impacket_crypto::aes256::encrypt_block(key, &b1);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&b1);
    out[16..].copy_from_slice(&b2);
    out
}

/// RFC 3962 Section 4.3 string-to-key for AES-128:
/// `tkey = PBKDF2(password, salt, iter_count, 16); key = derive_key_rfc3961_aes128(tkey, "kerberos")`
pub fn string_to_key_aes128(password: &str, salt: &str, iter_count: u32) -> [u8; 16] {
    let tkey = impacket_crypto::pbkdf2_hmac_sha1(password.as_bytes(), salt.as_bytes(), iter_count, 16);
    let mut tkey_arr = [0u8; 16];
    tkey_arr.copy_from_slice(&tkey);
    derive_key_rfc3961_aes128(&tkey_arr, b"kerberos")
}

/// RFC 3962 Section 4.3 string-to-key for AES-256:
/// `tkey = PBKDF2(password, salt, iter_count, 32); key = derive_key_rfc3961_aes256(tkey, "kerberos")`
pub fn string_to_key_aes256(password: &str, salt: &str, iter_count: u32) -> [u8; 32] {
    let tkey = impacket_crypto::pbkdf2_hmac_sha1(password.as_bytes(), salt.as_bytes(), iter_count, 32);
    let mut tkey_arr = [0u8; 32];
    tkey_arr.copy_from_slice(&tkey);
    derive_key_rfc3961_aes256(&tkey_arr, b"kerberos")
}

/// AES-128-CTS-HMAC-SHA1-96 checksum (RFC 3961 §5.1 / RFC 4120).
pub fn aes128_cts_hmac_sha1_96_checksum(key: &[u8; 16], keyusage: i32, data: &[u8]) -> [u8; 12] {
    let mut constant = [0u8; 5];
    constant[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    constant[4] = 0x99;
    let kc = derive_key_rfc3961_aes128(key, &constant);
    impacket_crypto::hmac_sha1_96(&kc, data)
}

/// AES-256-CTS-HMAC-SHA1-96 checksum (RFC 3961 §5.1 / RFC 4120).
pub fn aes256_cts_hmac_sha1_96_checksum(key: &[u8; 32], keyusage: i32, data: &[u8]) -> [u8; 12] {
    let mut constant = [0u8; 5];
    constant[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    constant[4] = 0x99;
    let kc = derive_key_rfc3961_aes256(key, &constant);
    impacket_crypto::hmac_sha1_96(&kc, data)
}

/// RFC 3962 Kerberos AES-128-CTS-HMAC-SHA1-96 encryption.
/// `confounder` must be 16 bytes.
/// Layout: Ciphertext(AES-CTS(Ke, confounder || plaintext)) || HMAC-SHA1-96(Ki, confounder || plaintext).
pub fn aes128_cts_hmac_sha1_96_encrypt(
    key: &[u8; 16],
    keyusage: i32,
    plaintext: &[u8],
    confounder: &[u8; 16],
) -> Result<Vec<u8>, impacket_core::CoreError> {
    let mut c_ke = [0u8; 5];
    c_ke[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    c_ke[4] = 0xAA;
    let ke = derive_key_rfc3961_aes128(key, &c_ke);

    let mut c_ki = [0u8; 5];
    c_ki[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    c_ki[4] = 0x55;
    let ki = derive_key_rfc3961_aes128(key, &c_ki);

    let mut data = Vec::with_capacity(16 + plaintext.len());
    data.extend_from_slice(confounder);
    data.extend_from_slice(plaintext);

    let checksum = impacket_crypto::hmac_sha1_96(&ki, &data);
    let iv = [0u8; 16];
    let ciphertext = impacket_crypto::aes128_cts_encrypt(&ke, &iv, &data)?;

    let mut out = Vec::with_capacity(ciphertext.len() + 12);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&checksum);
    Ok(out)
}

/// RFC 3962 Kerberos AES-128-CTS-HMAC-SHA1-96 decryption.
pub fn aes128_cts_hmac_sha1_96_decrypt(
    key: &[u8; 16],
    keyusage: i32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, impacket_core::CoreError> {
    if ciphertext.len() < 16 + 12 {
        return Err(impacket_core::CoreError::BufferUnderflow {
            needed: 28,
            available: ciphertext.len(),
        });
    }
    let ct_len = ciphertext.len() - 12;
    let ct = &ciphertext[..ct_len];
    let expected_cksum = &ciphertext[ct_len..];

    let mut c_ke = [0u8; 5];
    c_ke[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    c_ke[4] = 0xAA;
    let ke = derive_key_rfc3961_aes128(key, &c_ke);

    let mut c_ki = [0u8; 5];
    c_ki[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    c_ki[4] = 0x55;
    let ki = derive_key_rfc3961_aes128(key, &c_ki);

    let iv = [0u8; 16];
    let decrypted = impacket_crypto::aes128_cts_decrypt(&ke, &iv, ct)?;
    let actual_cksum = impacket_crypto::hmac_sha1_96(&ki, &decrypted);
    if actual_cksum != expected_cksum {
        return Err(impacket_core::CoreError::ProtocolError(
            "AES-128-CTS checksum mismatch".into(),
        ));
    }
    Ok(decrypted[16..].to_vec())
}

/// RFC 3962 Kerberos AES-256-CTS-HMAC-SHA1-96 encryption.
pub fn aes256_cts_hmac_sha1_96_encrypt(
    key: &[u8; 32],
    keyusage: i32,
    plaintext: &[u8],
    confounder: &[u8; 16],
) -> Result<Vec<u8>, impacket_core::CoreError> {
    let mut c_ke = [0u8; 5];
    c_ke[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    c_ke[4] = 0xAA;
    let ke = derive_key_rfc3961_aes256(key, &c_ke);

    let mut c_ki = [0u8; 5];
    c_ki[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    c_ki[4] = 0x55;
    let ki = derive_key_rfc3961_aes256(key, &c_ki);

    let mut data = Vec::with_capacity(16 + plaintext.len());
    data.extend_from_slice(confounder);
    data.extend_from_slice(plaintext);

    let checksum = impacket_crypto::hmac_sha1_96(&ki, &data);
    let iv = [0u8; 16];
    let ciphertext = impacket_crypto::aes256_cts_encrypt(&ke, &iv, &data)?;

    let mut out = Vec::with_capacity(ciphertext.len() + 12);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&checksum);
    Ok(out)
}

/// RFC 3962 Kerberos AES-256-CTS-HMAC-SHA1-96 decryption.
pub fn aes256_cts_hmac_sha1_96_decrypt(
    key: &[u8; 32],
    keyusage: i32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, impacket_core::CoreError> {
    if ciphertext.len() < 16 + 12 {
        return Err(impacket_core::CoreError::BufferUnderflow {
            needed: 28,
            available: ciphertext.len(),
        });
    }
    let ct_len = ciphertext.len() - 12;
    let ct = &ciphertext[..ct_len];
    let expected_cksum = &ciphertext[ct_len..];

    let mut c_ke = [0u8; 5];
    c_ke[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    c_ke[4] = 0xAA;
    let ke = derive_key_rfc3961_aes256(key, &c_ke);

    let mut c_ki = [0u8; 5];
    c_ki[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    c_ki[4] = 0x55;
    let ki = derive_key_rfc3961_aes256(key, &c_ki);

    let iv = [0u8; 16];
    let decrypted = impacket_crypto::aes256_cts_decrypt(&ke, &iv, ct)?;
    let actual_cksum = impacket_crypto::hmac_sha1_96(&ki, &decrypted);
    if actual_cksum != expected_cksum {
        return Err(impacket_core::CoreError::ProtocolError(
            "AES-256-CTS checksum mismatch".into(),
        ));
    }
    Ok(decrypted[16..].to_vec())
}

/// RFC 8009 Key Derivation Function (KDF-HMAC-SHA2).
/// Uses NIST SP 800-108 counter mode with HMAC-SHA256:
/// `[i]_4 || label || 0x00 || context || [k * 8]_4`
pub fn kdf_hmac_sha256(key: &[u8], label: &[u8], context: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len);
    let mut i = 1u32;
    let k_bits = (key_len * 8) as u32;

    while out.len() < key_len {
        let mut msg = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
        msg.extend_from_slice(&i.to_be_bytes());
        msg.extend_from_slice(label);
        msg.push(0x00);
        msg.extend_from_slice(context);
        msg.extend_from_slice(&k_bits.to_be_bytes());

        let block = impacket_crypto::hmac_sha256(key, &msg);
        let take = std::cmp::min(key_len - out.len(), 32);
        out.extend_from_slice(&block[..take]);
        i += 1;
    }
    out
}

/// RFC 8009 Key Derivation Function (KDF-HMAC-SHA2).
/// Uses NIST SP 800-108 counter mode with HMAC-SHA384:
/// `[i]_4 || label || 0x00 || context || [k * 8]_4`
pub fn kdf_hmac_sha384(key: &[u8], label: &[u8], context: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len);
    let mut i = 1u32;
    let k_bits = (key_len * 8) as u32;

    while out.len() < key_len {
        let mut msg = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
        msg.extend_from_slice(&i.to_be_bytes());
        msg.extend_from_slice(label);
        msg.push(0x00);
        msg.extend_from_slice(context);
        msg.extend_from_slice(&k_bits.to_be_bytes());

        let block = impacket_crypto::hmac_sha384(key, &msg);
        let take = std::cmp::min(key_len - out.len(), 48);
        out.extend_from_slice(&block[..take]);
        i += 1;
    }
    out
}

/// RFC 8009 Section 5 string-to-key for `aes128-cts-hmac-sha256-128` (etype 19).
pub fn string_to_key_rfc8009_aes128(password: &[u8], salt: &[u8], iter_count: u32) -> [u8; 16] {
    let mut saltp = Vec::with_capacity(28 + salt.len());
    saltp.extend_from_slice(b"aes128-cts-hmac-sha256-128\0");
    saltp.extend_from_slice(salt);

    let iters = if iter_count == 0 { 32768 } else { iter_count };
    let tkey = impacket_crypto::pbkdf2_hmac_sha256(password, &saltp, iters, 16);
    let derived = kdf_hmac_sha256(&tkey, b"kerberos", b"", 16);

    let mut out = [0u8; 16];
    out.copy_from_slice(&derived);
    out
}

/// RFC 8009 Section 5 string-to-key for `aes256-cts-hmac-sha384-192` (etype 20).
pub fn string_to_key_rfc8009_aes256(password: &[u8], salt: &[u8], iter_count: u32) -> [u8; 32] {
    let mut saltp = Vec::with_capacity(28 + salt.len());
    saltp.extend_from_slice(b"aes256-cts-hmac-sha384-192\0");
    saltp.extend_from_slice(salt);

    let iters = if iter_count == 0 { 32768 } else { iter_count };
    let tkey = impacket_crypto::pbkdf2_hmac_sha384(password, &saltp, iters, 32);
    let derived = kdf_hmac_sha384(&tkey, b"kerberos", b"", 32);

    let mut out = [0u8; 32];
    out.copy_from_slice(&derived);
    out
}

/// RFC 8009 checksum for `aes128-cts-hmac-sha256-128` (etype 19).
pub fn aes128_cts_hmac_sha256_128_checksum(key: &[u8; 16], keyusage: i32, data: &[u8]) -> [u8; 16] {
    let mut label = [0u8; 5];
    label[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    label[4] = 0x99;

    let kc = kdf_hmac_sha256(key, &label, b"", 16);
    let hash = impacket_crypto::hmac_sha256(&kc, data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash[..16]);
    out
}

/// RFC 8009 checksum for `aes256-cts-hmac-sha384-192` (etype 20).
pub fn aes256_cts_hmac_sha384_192_checksum(key: &[u8; 32], keyusage: i32, data: &[u8]) -> [u8; 24] {
    let mut label = [0u8; 5];
    label[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    label[4] = 0x99;

    let kc = kdf_hmac_sha384(key, &label, b"", 24);
    let hash = impacket_crypto::hmac_sha384(&kc, data);
    let mut out = [0u8; 24];
    out.copy_from_slice(&hash[..24]);
    out
}

/// RFC 8009 encryption for `aes128-cts-hmac-sha256-128` (etype 19).
pub fn aes128_cts_hmac_sha256_128_encrypt(
    key: &[u8; 16],
    keyusage: i32,
    plaintext: &[u8],
    confounder: &[u8; 16],
) -> Result<Vec<u8>, impacket_core::CoreError> {
    let mut l_ke = [0u8; 5];
    l_ke[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    l_ke[4] = 0xAA;
    let ke = kdf_hmac_sha256(key, &l_ke, b"", 16);

    let mut l_ki = [0u8; 5];
    l_ki[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    l_ki[4] = 0x55;
    let ki = kdf_hmac_sha256(key, &l_ki, b"", 16);

    let mut data = Vec::with_capacity(16 + plaintext.len());
    data.extend_from_slice(confounder);
    data.extend_from_slice(plaintext);

    let iv = [0u8; 16];
    let mut ke_arr = [0u8; 16];
    ke_arr.copy_from_slice(&ke);
    let ciphertext = impacket_crypto::aes128_cts_encrypt(&ke_arr, &iv, &data)?;

    let mut hmac_input = Vec::with_capacity(16 + ciphertext.len());
    hmac_input.extend_from_slice(&iv);
    hmac_input.extend_from_slice(&ciphertext);
    let mac = impacket_crypto::hmac_sha256(&ki, &hmac_input);

    let mut out = Vec::with_capacity(ciphertext.len() + 16);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&mac[..16]);
    Ok(out)
}

/// RFC 8009 decryption for `aes128-cts-hmac-sha256-128` (etype 19).
pub fn aes128_cts_hmac_sha256_128_decrypt(
    key: &[u8; 16],
    keyusage: i32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, impacket_core::CoreError> {
    if ciphertext.len() < 16 + 16 {
        return Err(impacket_core::CoreError::BufferUnderflow {
            needed: 32,
            available: ciphertext.len(),
        });
    }
    let ct_len = ciphertext.len() - 16;
    let ct = &ciphertext[..ct_len];
    let expected_mac = &ciphertext[ct_len..];

    let mut l_ke = [0u8; 5];
    l_ke[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    l_ke[4] = 0xAA;
    let ke = kdf_hmac_sha256(key, &l_ke, b"", 16);

    let mut l_ki = [0u8; 5];
    l_ki[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    l_ki[4] = 0x55;
    let ki = kdf_hmac_sha256(key, &l_ki, b"", 16);

    let iv = [0u8; 16];
    let mut hmac_input = Vec::with_capacity(16 + ct.len());
    hmac_input.extend_from_slice(&iv);
    hmac_input.extend_from_slice(ct);
    let actual_mac = impacket_crypto::hmac_sha256(&ki, &hmac_input);
    if &actual_mac[..16] != expected_mac {
        return Err(impacket_core::CoreError::ProtocolError(
            "RFC 8009 AES-128-CTS checksum mismatch".into(),
        ));
    }

    let mut ke_arr = [0u8; 16];
    ke_arr.copy_from_slice(&ke);
    let decrypted = impacket_crypto::aes128_cts_decrypt(&ke_arr, &iv, ct)?;
    Ok(decrypted[16..].to_vec())
}

/// RFC 8009 encryption for `aes256-cts-hmac-sha384-192` (etype 20).
pub fn aes256_cts_hmac_sha384_192_encrypt(
    key: &[u8; 32],
    keyusage: i32,
    plaintext: &[u8],
    confounder: &[u8; 16],
) -> Result<Vec<u8>, impacket_core::CoreError> {
    let mut l_ke = [0u8; 5];
    l_ke[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    l_ke[4] = 0xAA;
    let ke = kdf_hmac_sha384(key, &l_ke, b"", 32);

    let mut l_ki = [0u8; 5];
    l_ki[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    l_ki[4] = 0x55;
    let ki = kdf_hmac_sha384(key, &l_ki, b"", 24);

    let mut data = Vec::with_capacity(16 + plaintext.len());
    data.extend_from_slice(confounder);
    data.extend_from_slice(plaintext);

    let iv = [0u8; 16];
    let mut ke_arr = [0u8; 32];
    ke_arr.copy_from_slice(&ke);
    let ciphertext = impacket_crypto::aes256_cts_encrypt(&ke_arr, &iv, &data)?;

    let mut hmac_input = Vec::with_capacity(16 + ciphertext.len());
    hmac_input.extend_from_slice(&iv);
    hmac_input.extend_from_slice(&ciphertext);
    let mac = impacket_crypto::hmac_sha384(&ki, &hmac_input);

    let mut out = Vec::with_capacity(ciphertext.len() + 24);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&mac[..24]);
    Ok(out)
}

/// RFC 8009 decryption for `aes256-cts-hmac-sha384-192` (etype 20).
pub fn aes256_cts_hmac_sha384_192_decrypt(
    key: &[u8; 32],
    keyusage: i32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, impacket_core::CoreError> {
    if ciphertext.len() < 16 + 24 {
        return Err(impacket_core::CoreError::BufferUnderflow {
            needed: 40,
            available: ciphertext.len(),
        });
    }
    let ct_len = ciphertext.len() - 24;
    let ct = &ciphertext[..ct_len];
    let expected_mac = &ciphertext[ct_len..];

    let mut l_ke = [0u8; 5];
    l_ke[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    l_ke[4] = 0xAA;
    let ke = kdf_hmac_sha384(key, &l_ke, b"", 32);

    let mut l_ki = [0u8; 5];
    l_ki[..4].copy_from_slice(&(keyusage as u32).to_be_bytes());
    l_ki[4] = 0x55;
    let ki = kdf_hmac_sha384(key, &l_ki, b"", 24);

    let iv = [0u8; 16];
    let mut hmac_input = Vec::with_capacity(16 + ct.len());
    hmac_input.extend_from_slice(&iv);
    hmac_input.extend_from_slice(ct);
    let actual_mac = impacket_crypto::hmac_sha384(&ki, &hmac_input);
    if &actual_mac[..24] != expected_mac {
        return Err(impacket_core::CoreError::ProtocolError(
            "RFC 8009 AES-256-CTS checksum mismatch".into(),
        ));
    }

    let mut ke_arr = [0u8; 32];
    ke_arr.copy_from_slice(&ke);
    let decrypted = impacket_crypto::aes256_cts_decrypt(&ke_arr, &iv, ct)?;
    Ok(decrypted[16..].to_vec())
}

/// Converts Unix seconds to a Kerberos `GeneralizedTime` string `YYYYMMDDHHMMSSZ` (UTC), without any
/// external date library (civil-from-days, Howard Hinnant's algorithm).
pub fn unix_to_kerberos_time(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let ss = secs_of_day % 60;
    format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", year, m, d, hh, mm, ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4_hmac_roundtrip() {
        let key = [0x31u8; 16]; // stand-in NT hash
        let plaintext = b"kerberos PA-ENC-TIMESTAMP payload";
        let conf = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02];
        let ct = rc4_hmac_encrypt(&key, 1, plaintext, &conf);
        assert!(ct.len() >= 24);
        let pt = rc4_hmac_decrypt(&key, 1, &ct).unwrap();
        assert_eq!(pt, plaintext);
        // Wrong usage must fail the checksum (different Ki).
        assert!(rc4_hmac_decrypt(&key, 2, &ct).is_err());
    }

    #[test]
    fn test_kerberos_time_format() {
        // 2025-11-05 00:00:00 UTC.
        assert_eq!(unix_to_kerberos_time(1_762_300_800), "20251105000000Z");
        // Epoch.
        assert_eq!(unix_to_kerberos_time(0), "19700101000000Z");
    }

    #[test]
    fn test_nfold_vector_and_checksums() {
        use impacket_core::encode_hex;
        let constant = [0x00, 0x00, 0x00, 0x11, 0x99]; // usage 17 + 0x99
        let folded = nfold(&constant, 16);
        assert_eq!(encode_hex(&folded), "1ddb6db6d324cc488843a1d0e642343a");

        let key16 = [0x11u8; 16];
        let key32 = [0x22u8; 32];
        let data = b"Sample PAC buffer for checksumming";

        let ck1 = rc4_hmac_checksum(&key16, 17, data);
        assert_ne!(ck1, [0u8; 16]);

        let ck_aes128 = aes128_cts_hmac_sha1_96_checksum(&key16, 17, data);
        assert_eq!(ck_aes128.len(), 12);

        let ck_aes256 = aes256_cts_hmac_sha1_96_checksum(&key32, 17, data);
        assert_eq!(ck_aes256.len(), 12);
    }

    #[test]
    fn test_aes_cts_hmac_sha1_96_roundtrip() {
        let key128 = [0x42u8; 16];
        let key256 = [0x55u8; 32];
        let conf = [0xAA; 16];
        let plain = b"Kerberos RFC 3962 Ticket Plaintext Data";

        let enc128 = aes128_cts_hmac_sha1_96_encrypt(&key128, 2, plain, &conf).unwrap();
        let dec128 = aes128_cts_hmac_sha1_96_decrypt(&key128, 2, &enc128).unwrap();
        assert_eq!(dec128, plain);

        // Tamper test
        let mut tampered = enc128.clone();
        tampered[0] ^= 0x01;
        assert!(aes128_cts_hmac_sha1_96_decrypt(&key128, 2, &tampered).is_err());

        let enc256 = aes256_cts_hmac_sha1_96_encrypt(&key256, 2, plain, &conf).unwrap();
        let dec256 = aes256_cts_hmac_sha1_96_decrypt(&key256, 2, &enc256).unwrap();
        assert_eq!(dec256, plain);

        let mut tampered256 = enc256.clone();
        let last = tampered256.len() - 1;
        tampered256[last] ^= 0x01;
        assert!(aes256_cts_hmac_sha1_96_decrypt(&key256, 2, &tampered256).is_err());
    }

    #[test]
    fn test_rfc3962_string_to_key_vectors() {
        use impacket_core::encode_hex;
        let pass = "password";
        let salt = "ATHENA.MIT.EDUraeburn";

        // Iteration count = 1
        let k128_1 = string_to_key_aes128(pass, salt, 1);
        assert_eq!(encode_hex(&k128_1), "42263c6e89f4fc28b8df68ee09799f15");
        let k256_1 = string_to_key_aes256(pass, salt, 1);
        assert_eq!(
            encode_hex(&k256_1),
            "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161"
        );

        // Iteration count = 2
        let k128_2 = string_to_key_aes128(pass, salt, 2);
        assert_eq!(encode_hex(&k128_2), "c651bf29e2300ac27fa469d693bdda13");

        // Iteration count = 1200
        let k128_1200 = string_to_key_aes128(pass, salt, 1200);
        assert_eq!(encode_hex(&k128_1200), "4c01cd46d632d01e6dbe230a01ed642a");
        let k256_1200 = string_to_key_aes256(pass, salt, 1200);
        assert_eq!(
            encode_hex(&k256_1200),
            "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a"
        );
    }

    #[test]
    fn test_rfc8009_test_vectors() {
        use impacket_core::encode_hex;
        // RFC 8009 Appendix A test vectors
        let pw = b"password";
        let mut salt = [0u8; 37];
        let salt_prefix = [0x10, 0xDF, 0x9D, 0xD7, 0x83, 0xE5, 0xBC, 0x8A, 0xCE, 0xA1, 0x73, 0x0E, 0x74, 0x35, 0x5F, 0x61];
        salt[..16].copy_from_slice(&salt_prefix);
        salt[16..].copy_from_slice(b"ATHENA.MIT.EDUraeburn");

        let k128 = string_to_key_rfc8009_aes128(pw, &salt, 32768);
        assert_eq!(encode_hex(&k128), "089bca48b105ea6ea77ca5d2f39dc5e7");

        let k256 = string_to_key_rfc8009_aes256(pw, &salt, 32768);
        assert_eq!(
            encode_hex(&k256),
            "45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467"
        );

        // Checksums
        let base_key128 = [
            0x37, 0x05, 0xD9, 0x60, 0x80, 0xC1, 0x77, 0x28,
            0xA0, 0xE8, 0x00, 0xEA, 0xB6, 0xE0, 0xD2, 0x3C,
        ];
        let plaintext: Vec<u8> = (0..21).collect();
        let cs128 = aes128_cts_hmac_sha256_128_checksum(&base_key128, 2, &plaintext);
        assert_eq!(encode_hex(&cs128), "d78367186643d67b411cba9139fc1dee");

        let base_key256 = [
            0x6D, 0x40, 0x4D, 0x37, 0xFA, 0xF7, 0x9F, 0x9D,
            0xF0, 0xD3, 0x35, 0x68, 0xD3, 0x20, 0x66, 0x98,
            0x00, 0xEB, 0x48, 0x36, 0x47, 0x2E, 0xA8, 0xA0,
            0x26, 0xD1, 0x6B, 0x71, 0x82, 0x46, 0x0C, 0x52,
        ];
        let cs256 = aes256_cts_hmac_sha384_192_checksum(&base_key256, 2, &plaintext);
        assert_eq!(
            encode_hex(&cs256),
            "45ee791567eefca37f4ac1e0222de80d43c3bfa06699672a"
        );

        // Encryption and decryption roundtrip
        let confounder = [0x5au8; 16];
        let secret_msg = b"Top Secret Windows Server 2025 Payload";

        let enc128 = aes128_cts_hmac_sha256_128_encrypt(&base_key128, 2, secret_msg, &confounder).unwrap();
        let dec128 = aes128_cts_hmac_sha256_128_decrypt(&base_key128, 2, &enc128).unwrap();
        assert_eq!(dec128, secret_msg);

        let enc256 = aes256_cts_hmac_sha384_192_encrypt(&base_key256, 2, secret_msg, &confounder).unwrap();
        let dec256 = aes256_cts_hmac_sha384_192_decrypt(&base_key256, 2, &enc256).unwrap();
        assert_eq!(dec256, secret_msg);
    }
}
