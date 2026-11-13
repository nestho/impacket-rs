#![allow(
    clippy::manual_is_multiple_of,
    clippy::chunks_exact_to_as_chunks,
    clippy::manual_div_ceil,
    clippy::needless_range_loop
)]

//! `impacket-crypto`: Pure-Rust cryptographic primitives required across legacy (Windows NT4/2000/2003)
//! and modern (Windows Server 2008 R2 -> 2025) Active Directory environments.
//!
//! Includes:
//! - RFC 1320 **MD4** (`NTOWFv1` / NT Hash calculation)
//! - RFC 1321 **MD5** and RFC 2104 **HMAC-MD5** (`NTOWFv2`, NTLMv2 Challenge Response, Kerberos `RC4-HMAC` EType 23)
//! - **DES-56 / DES-ECB** with 7-to-8 byte parity expansion (`LM` hash calculation, `LMv1`/`NTLMv1` 24-byte response,
//!   and `[MS-SAMR]` Section 2.2.11.1.1 RID-key encryption/decryption for `secretsdump`)
//! - **FIPS 197 AES-128** (ECB & CBC encrypt/decrypt) for Modern Windows Server 2016–2025 `SAM_KEY_DATA_AES` and `SAM_HASH_AES`
//! - **RC4 (ARCFOUR)** stream cipher (NTLMSSP Session Security, Kerberos `RC4-HMAC`, and Legacy SAM Revision 1 decryption)
//! - **CRC32** (IEEE 802.3) for NTLMSSP/RPC integrity checks
//! - **AES-GCM & AES-CCM** (NIST SP 800-38D & 800-38C) for SMB 3.x authenticated transport encryption

pub mod aead;
pub mod bignum;

pub use aead::{
    aes128_ccm_decrypt, aes128_ccm_encrypt, aes128_gcm_decrypt, aes128_gcm_encrypt,
    aes256_ccm_decrypt, aes256_ccm_encrypt, aes256_gcm_decrypt, aes256_gcm_encrypt,
};
pub use bignum::BigUint;

use impacket_core::zeroize_slice;

/// Pure-Rust RFC 1320 MD4 implementation.
pub fn md4(input: &[u8]) -> [u8; 16] {
    #[inline(always)]
    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }
    #[inline(always)]
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }
    #[inline(always)]
    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    let bit_len = (input.len() as u64) * 8;
    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    for chunk in padded.chunks_exact(64) {
        let mut x = [0u32; 16];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            x[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for &(i, s) in &[
            (0, 3), (1, 7), (2, 11), (3, 19),
            (4, 3), (5, 7), (6, 11), (7, 19),
            (8, 3), (9, 7), (10, 11), (11, 19),
            (12, 3), (13, 7), (14, 11), (15, 19),
        ] {
            let t = a.wrapping_add(f(b, c, d)).wrapping_add(x[i]).rotate_left(s);
            a = d; d = c; c = b; b = t;
        }

        for &(i, s) in &[
            (0, 3), (4, 5), (8, 9), (12, 13),
            (1, 3), (5, 5), (9, 9), (13, 13),
            (2, 3), (6, 5), (10, 9), (14, 13),
            (3, 3), (7, 5), (11, 9), (15, 13),
        ] {
            let t = a
                .wrapping_add(g(b, c, d))
                .wrapping_add(x[i])
                .wrapping_add(0x5a82_7999)
                .rotate_left(s);
            a = d; d = c; c = b; b = t;
        }

        for &(i, s) in &[
            (0, 3), (8, 9), (4, 11), (12, 15),
            (2, 3), (10, 9), (6, 11), (14, 15),
            (1, 3), (9, 9), (5, 11), (13, 15),
            (3, 3), (11, 9), (7, 11), (15, 15),
        ] {
            let t = a
                .wrapping_add(h(b, c, d))
                .wrapping_add(x[i])
                .wrapping_add(0x6ed9_eba1)
                .rotate_left(s);
            a = d; d = c; c = b; b = t;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// Pure-Rust RFC 1321 MD5 implementation.
pub fn md5(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let bit_len = (input.len() as u64) * 8;
    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    for chunk in padded.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                a.wrapping_add(f)
                    .wrapping_add(K[i])
                    .wrapping_add(m[g])
                    .rotate_left(S[i]),
            );
            a = temp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

/// Pure-Rust RFC 2104 HMAC-MD5 implementation.
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = md5(key);
        k_block[..16].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    zeroize_slice(&mut k_block);

    let mut inner_input = Vec::with_capacity(64 + data.len());
    inner_input.extend_from_slice(&ipad);
    inner_input.extend_from_slice(data);
    let inner_hash = md5(&inner_input);

    let mut outer_input = [0u8; 80];
    outer_input[..64].copy_from_slice(&opad);
    outer_input[64..80].copy_from_slice(&inner_hash);
    md5(&outer_input)
}

/// Pure-Rust RC4 (ARCFOUR) stream cipher for NTLMSSP sealing, Kerberos `RC4-HMAC`, and SAM Revision 1 decryption.
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (idx, val) in s.iter_mut().enumerate() {
            *val = idx as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

impl Drop for Rc4 {
    fn drop(&mut self) {
        zeroize_slice(&mut self.s);
    }
}

/// Expands a 7-byte (56-bit) Windows DES key into an 8-byte (64-bit) DES key with odd parity
/// (`transformKey` in `impacket/crypto.py`).
pub fn expand_des_key_56_to_64(key7: &[u8; 7]) -> [u8; 8] {
    let raw = [
        key7[0] >> 1,
        ((key7[0] & 0x01) << 6) | (key7[1] >> 2),
        ((key7[1] & 0x03) << 5) | (key7[2] >> 3),
        ((key7[2] & 0x07) << 4) | (key7[3] >> 4),
        ((key7[3] & 0x0F) << 3) | (key7[4] >> 5),
        ((key7[4] & 0x1F) << 2) | (key7[5] >> 6),
        ((key7[5] & 0x3F) << 1) | (key7[6] >> 7),
        key7[6] & 0x7F,
    ];
    let mut out = [0u8; 8];
    for i in 0..8 {
        let b = (raw[i] << 1) & 0xFE;
        let ones = b.count_ones();
        out[i] = if ones % 2 == 0 { b | 1 } else { b };
    }
    out
}

/// Internal FIPS 46-3 DES block crypt using 8-byte key with odd parity.
pub fn des_crypt_block_raw8(key8: &[u8; 8], block: &[u8; 8], decrypt: bool) -> [u8; 8] {
    const IP: [u8; 64] = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
    ];
    const FP: [u8; 64] = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
    ];
    const PC1: [u8; 56] = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
    ];
    const PC2: [u8; 48] = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    ];
    const E: [u8; 48] = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
        12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
        22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
    ];
    const P: [u8; 32] = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
    ];
    const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
    const SBOX: [[[u8; 16]; 4]; 8] = [
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        ],
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
        ],
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
        ],
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
        ],
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
        ],
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
        ],
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
        ],
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
        ],
    ];

    #[inline(always)]
    fn permute(src: u64, table: &[u8], src_bits: u8) -> u64 {
        let mut out = 0u64;
        for (i, &pos) in table.iter().enumerate() {
            let bit = (src >> (src_bits - pos)) & 1;
            out |= bit << (table.len() - 1 - i);
        }
        out
    }

    let key_u64 = u64::from_be_bytes(*key8);
    let cd = permute(key_u64, &PC1, 64);
    let mut c = ((cd >> 28) & 0x0FFF_FFFF) as u32;
    let mut d = (cd & 0x0FFF_FFFF) as u32;

    let mut subkeys = [0u64; 16];
    for round in 0..16 {
        let s = SHIFTS[round];
        c = ((c << s) | (c >> (28 - s))) & 0x0FFF_FFFF;
        d = ((d << s) | (d >> (28 - s))) & 0x0FFF_FFFF;
        let combined = ((c as u64) << 28) | (d as u64);
        subkeys[round] = permute(combined, &PC2, 56);
    }

    let block_u64 = u64::from_be_bytes(*block);
    let ip = permute(block_u64, &IP, 64);
    let mut l = (ip >> 32) as u32;
    let mut r = (ip & 0xFFFF_FFFF) as u32;

    for round in 0..16 {
        let k_idx = if decrypt { 15 - round } else { round };
        let expanded = permute(r as u64, &E, 32) ^ subkeys[k_idx];
        let mut s_out = 0u32;
        for box_idx in 0..8 {
            let six = ((expanded >> (42 - box_idx * 6)) & 0x3F) as u8;
            let row = (((six & 0x20) >> 4) | (six & 0x01)) as usize;
            let col = ((six >> 1) & 0x0F) as usize;
            s_out = (s_out << 4) | (SBOX[box_idx][row][col] as u32);
        }
        let f_val = permute(s_out as u64, &P, 32) as u32;
        let next_r = l ^ f_val;
        l = r;
        r = next_r;
    }

    let pre_fp = ((r as u64) << 32) | (l as u64);
    let fp = permute(pre_fp, &FP, 64);
    fp.to_be_bytes()
}

/// Internal FIPS 46-3 DES-ECB core supporting both encryption (`decrypt = false`) and decryption (`decrypt = true`).
fn des_ecb_crypt_block(key7: &[u8; 7], block: &[u8; 8], decrypt: bool) -> [u8; 8] {
    let key8 = expand_des_key_56_to_64(key7);
    des_crypt_block_raw8(&key8, block, decrypt)
}

/// Standard FIPS 46-3 single-block DES-ECB encryption.
pub fn des_ecb_encrypt_block(key7: &[u8; 7], block: &[u8; 8]) -> [u8; 8] {
    des_ecb_crypt_block(key7, block, false)
}

/// Standard FIPS 46-3 single-block DES-ECB decryption (used for `[MS-SAMR]` RID-key hash unwrapping).
pub fn des_ecb_decrypt_block(key7: &[u8; 7], block: &[u8; 8]) -> [u8; 8] {
    des_ecb_crypt_block(key7, block, true)
}

/// FIPS 46-3 Triple-DES (3DES / EDE3) single-block encryption: C = E_k3(D_k2(E_k1(P))).
pub fn des3_ede_encrypt_block(key24: &[u8; 24], block: &[u8; 8]) -> [u8; 8] {
    let k1: [u8; 8] = key24[0..8].try_into().unwrap();
    let k2: [u8; 8] = key24[8..16].try_into().unwrap();
    let k3: [u8; 8] = key24[16..24].try_into().unwrap();
    let b1 = des_crypt_block_raw8(&k1, block, false);
    let b2 = des_crypt_block_raw8(&k2, &b1, true);
    des_crypt_block_raw8(&k3, &b2, false)
}

/// FIPS 46-3 Triple-DES (3DES / EDE3) single-block decryption: P = D_k1(E_k2(D_k3(C))).
pub fn des3_ede_decrypt_block(key24: &[u8; 24], block: &[u8; 8]) -> [u8; 8] {
    let k1: [u8; 8] = key24[0..8].try_into().unwrap();
    let k2: [u8; 8] = key24[8..16].try_into().unwrap();
    let k3: [u8; 8] = key24[16..24].try_into().unwrap();
    let b1 = des_crypt_block_raw8(&k3, block, true);
    let b2 = des_crypt_block_raw8(&k2, &b1, false);
    des_crypt_block_raw8(&k1, &b2, true)
}

/// Triple-DES (3DES-CBC) decryption with 8-byte IV. Ciphertext length must be multiple of 8.
pub fn des3_cbc_decrypt(key24: &[u8; 24], iv: &[u8; 8], ciphertext: &[u8]) -> Vec<u8> {
    if (ciphertext.len() % 8) != 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(ciphertext.len());
    let mut prev_block = *iv;
    for chunk in ciphertext.chunks_exact(8) {
        let block: [u8; 8] = chunk.try_into().unwrap();
        let decrypted = des3_ede_decrypt_block(key24, &block);
        let mut pt = [0u8; 8];
        for i in 0..8 {
            pt[i] = decrypted[i] ^ prev_block[i];
        }
        prev_block = block;
        out.extend_from_slice(&pt);
    }
    out
}

/// Triple-DES (3DES-CBC) encryption with 8-byte IV. Plaintext length must be multiple of 8.
pub fn des3_cbc_encrypt(key24: &[u8; 24], iv: &[u8; 8], plaintext: &[u8]) -> Vec<u8> {
    if (plaintext.len() % 8) != 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(plaintext.len());
    let mut prev_block = *iv;
    for chunk in plaintext.chunks_exact(8) {
        let mut block = [0u8; 8];
        for i in 0..8 {
            block[i] = chunk[i] ^ prev_block[i];
        }
        let ct = des3_ede_encrypt_block(key24, &block);
        prev_block = ct;
        out.extend_from_slice(&ct);
    }
    out
}

/// `[MS-SAMR]` Section 2.2.11.1.3: Derives two 7-byte DES keys (`Key1`, `Key2`) from a 32-bit user RID
/// (`CryptoCommon.deriveKey` in `impacket/examples/secretsdump.py`).
pub fn derive_sam_des_keys_from_rid(rid: u32) -> ([u8; 7], [u8; 7]) {
    let i = rid.to_le_bytes();
    let key1 = [i[0], i[1], i[2], i[3], i[0], i[1], i[2]];
    let key2 = [i[3], i[0], i[1], i[2], i[3], i[0], i[1]];
    (key1, key2)
}

/// `[MS-SAMR]` Section 2.2.11.1.1: Encrypts a 16-byte NT or LM hash with the user's RID-derived DES keys.
pub fn sam_des_encrypt_hash_with_rid(rid: u32, plain_hash: &[u8; 16]) -> [u8; 16] {
    let (k1, k2) = derive_sam_des_keys_from_rid(rid);
    let b1: [u8; 8] = plain_hash[0..8].try_into().unwrap();
    let b2: [u8; 8] = plain_hash[8..16].try_into().unwrap();
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&des_ecb_encrypt_block(&k1, &b1));
    out[8..16].copy_from_slice(&des_ecb_encrypt_block(&k2, &b2));
    out
}

/// `[MS-SAMR]` Section 2.2.11.1.1: Unwraps the inner RID-derived DES layer from a 16-byte SAM hash block
/// (`SamDecryptNTLMHash` in `impacket/crypto.py`).
pub fn sam_des_decrypt_hash_with_rid(rid: u32, wrapped_hash: &[u8; 16]) -> [u8; 16] {
    let (k1, k2) = derive_sam_des_keys_from_rid(rid);
    let b1: [u8; 8] = wrapped_hash[0..8].try_into().unwrap();
    let b2: [u8; 8] = wrapped_hash[8..16].try_into().unwrap();
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&des_ecb_decrypt_block(&k1, &b1));
    out[8..16].copy_from_slice(&des_ecb_decrypt_block(&k2, &b2));
    out
}

/// Computes the 24-byte `DESL` response used in NTLMv1 and LMv1 (`__DESL` in `impacket/ntlm.py`).
pub fn des_long_response(hash16: &[u8; 16], challenge8: &[u8; 8]) -> [u8; 24] {
    let mut k21 = [0u8; 21];
    k21[..16].copy_from_slice(hash16);

    let k1: [u8; 7] = k21[0..7].try_into().unwrap();
    let k2: [u8; 7] = k21[7..14].try_into().unwrap();
    let k3: [u8; 7] = k21[14..21].try_into().unwrap();

    let mut out = [0u8; 24];
    out[0..8].copy_from_slice(&des_ecb_encrypt_block(&k1, challenge8));
    out[8..16].copy_from_slice(&des_ecb_encrypt_block(&k2, challenge8));
    out[16..24].copy_from_slice(&des_ecb_encrypt_block(&k3, challenge8));
    zeroize_slice(&mut k21);
    out
}

/// Computes the Legacy Windows LAN Manager (LM) 16-byte hash for passwords up to 14 OEM characters.
pub fn compute_lm_hash(password: &str) -> [u8; 16] {
    const LM_MAGIC: [u8; 8] = *b"KGS!@#$%";
    let mut upper = [0u8; 14];
    for (i, b) in password.bytes().take(14).enumerate() {
        upper[i] = b.to_ascii_uppercase();
    }
    let k1: [u8; 7] = upper[0..7].try_into().unwrap();
    let k2: [u8; 7] = upper[7..14].try_into().unwrap();

    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&des_ecb_encrypt_block(&k1, &LM_MAGIC));
    out[8..16].copy_from_slice(&des_ecb_encrypt_block(&k2, &LM_MAGIC));
    zeroize_slice(&mut upper);
    out
}

/// Pure-Rust FIPS 197 AES-128 implementation (ECB & CBC modes) for Modern Windows Server 2016–2025
/// `SAM_KEY_DATA_AES` and `SAM_HASH_AES` decryption (`CryptoCommon.decryptAES` in `secretsdump.py`).
pub mod aes128 {
    pub(crate) const SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ];

    pub(crate) const INV_SBOX: [u8; 256] = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    ];

    pub(crate) const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

    #[inline(always)]
    pub(crate) fn gmul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        for _ in 0..8 {
            if (b & 1) != 0 {
                p ^= a;
            }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 {
                a ^= 0x1B;
            }
            b >>= 1;
        }
        p
    }

    pub fn expand_key(key: &[u8; 16]) -> [[u8; 16]; 11] {
        let mut w = [[0u8; 4]; 44];
        for i in 0..4 {
            w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
        }
        for i in 4..44 {
            let mut temp = w[i - 1];
            if i % 4 == 0 {
                temp = [
                    SBOX[temp[1] as usize] ^ RCON[(i / 4) - 1],
                    SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize],
                    SBOX[temp[0] as usize],
                ];
            }
            for j in 0..4 {
                w[i][j] = w[i - 4][j] ^ temp[j];
            }
        }
        let mut round_keys = [[0u8; 16]; 11];
        for r in 0..11 {
            for c in 0..4 {
                round_keys[r][4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            }
        }
        round_keys
    }

    pub fn encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
        let rk = expand_key(key);
        let mut s = *block;
        for i in 0..16 {
            s[i] ^= rk[0][i];
        }
        for round in 1..=10 {
            for i in 0..16 {
                s[i] = SBOX[s[i] as usize];
            }
            // ShiftRows
            let t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
            let t1 = s[2]; let t2 = s[6]; s[2] = s[10]; s[6] = s[14]; s[10] = t1; s[14] = t2;
            let t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;

            if round < 10 {
                for c in 0..4 {
                    let i = 4 * c;
                    let (s0, s1, s2, s3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
                    s[i] = gmul(2, s0) ^ gmul(3, s1) ^ s2 ^ s3;
                    s[i + 1] = s0 ^ gmul(2, s1) ^ gmul(3, s2) ^ s3;
                    s[i + 2] = s0 ^ s1 ^ gmul(2, s2) ^ gmul(3, s3);
                    s[i + 3] = gmul(3, s0) ^ s1 ^ s2 ^ gmul(2, s3);
                }
            }
            for i in 0..16 {
                s[i] ^= rk[round][i];
            }
        }
        s
    }

    pub fn decrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
        let rk = expand_key(key);
        let mut s = *block;
        for i in 0..16 {
            s[i] ^= rk[10][i];
        }
        for round in (0..10).rev() {
            // InvShiftRows
            let t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
            let t1 = s[2]; let t2 = s[6]; s[2] = s[10]; s[6] = s[14]; s[10] = t1; s[14] = t2;
            let t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;

            for i in 0..16 {
                s[i] = INV_SBOX[s[i] as usize];
            }
            for i in 0..16 {
                s[i] ^= rk[round][i];
            }
            if round > 0 {
                for c in 0..4 {
                    let i = 4 * c;
                    let (s0, s1, s2, s3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
                    s[i] = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3);
                    s[i + 1] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3);
                    s[i + 2] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3);
                    s[i + 3] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3);
                }
            }
        }
        s
    }

    /// AES-128-CBC encryption (`CryptoCommon.encryptAES` in `secretsdump.py`).
    pub fn encrypt_cbc(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity((plaintext.len() + 15) & !15);
        let mut prev = *iv;
        for chunk in plaintext.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            for i in 0..16 {
                block[i] ^= prev[i];
            }
            let enc = encrypt_block(key, &block);
            out.extend_from_slice(&enc);
            prev = enc;
        }
        out
    }

    /// AES-128-CBC decryption (`CryptoCommon.decryptAES` in `secretsdump.py`).
    pub fn decrypt_cbc(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(ciphertext.len());
        let mut prev = *iv;
        for chunk in ciphertext.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            let mut dec = decrypt_block(key, &block);
            for i in 0..16 {
                dec[i] ^= prev[i];
            }
            out.extend_from_slice(&dec);
            prev = block;
        }
        out
    }
}

/// Pure-Rust FIPS 197 AES-256 implementation (256-bit key, 14 rounds, ECB & CBC modes).
pub mod aes256 {
    use super::aes128::{gmul, INV_SBOX, RCON, SBOX};

    pub fn expand_key(key: &[u8; 32]) -> [[u8; 16]; 15] {
        let mut w = [[0u8; 4]; 60];
        for i in 0..8 {
            w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
        }
        for i in 8..60 {
            let mut temp = w[i - 1];
            if i % 8 == 0 {
                temp = [
                    SBOX[temp[1] as usize] ^ RCON[(i / 8) - 1],
                    SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize],
                    SBOX[temp[0] as usize],
                ];
            } else if i % 8 == 4 {
                temp = [
                    SBOX[temp[0] as usize],
                    SBOX[temp[1] as usize],
                    SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize],
                ];
            }
            for j in 0..4 {
                w[i][j] = w[i - 8][j] ^ temp[j];
            }
        }
        let mut round_keys = [[0u8; 16]; 15];
        for r in 0..15 {
            for c in 0..4 {
                round_keys[r][4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            }
        }
        round_keys
    }

    pub fn encrypt_block(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16] {
        let rk = expand_key(key);
        let mut s = *block;
        for i in 0..16 {
            s[i] ^= rk[0][i];
        }
        for round in 1..=14 {
            for i in 0..16 {
                s[i] = SBOX[s[i] as usize];
            }
            let t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
            let t1 = s[2]; let t2 = s[6]; s[2] = s[10]; s[6] = s[14]; s[10] = t1; s[14] = t2;
            let t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;

            if round < 14 {
                for c in 0..4 {
                    let i = 4 * c;
                    let (s0, s1, s2, s3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
                    s[i] = gmul(2, s0) ^ gmul(3, s1) ^ s2 ^ s3;
                    s[i + 1] = s0 ^ gmul(2, s1) ^ gmul(3, s2) ^ s3;
                    s[i + 2] = s0 ^ s1 ^ gmul(2, s2) ^ gmul(3, s3);
                    s[i + 3] = gmul(3, s0) ^ s1 ^ s2 ^ gmul(2, s3);
                }
            }
            for i in 0..16 {
                s[i] ^= rk[round][i];
            }
        }
        s
    }

    pub fn decrypt_block(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16] {
        let rk = expand_key(key);
        let mut s = *block;
        for i in 0..16 {
            s[i] ^= rk[14][i];
        }
        for round in (0..14).rev() {
            let t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
            let t1 = s[2]; let t2 = s[6]; s[2] = s[10]; s[6] = s[14]; s[10] = t1; s[14] = t2;
            let t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;

            for i in 0..16 {
                s[i] = INV_SBOX[s[i] as usize];
            }
            for i in 0..16 {
                s[i] ^= rk[round][i];
            }
            if round > 0 {
                for c in 0..4 {
                    let i = 4 * c;
                    let (s0, s1, s2, s3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
                    s[i] = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3);
                    s[i + 1] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3);
                    s[i + 2] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3);
                    s[i + 3] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3);
                }
            }
        }
        s
    }

    pub fn encrypt_cbc(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity((plaintext.len() + 15) & !15);
        let mut prev = *iv;
        for chunk in plaintext.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            for i in 0..16 {
                block[i] ^= prev[i];
            }
            let enc = encrypt_block(key, &block);
            out.extend_from_slice(&enc);
            prev = enc;
        }
        out
    }

    pub fn decrypt_cbc(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(ciphertext.len());
        let mut prev = *iv;
        for chunk in ciphertext.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            let mut dec = decrypt_block(key, &block);
            for i in 0..16 {
                dec[i] ^= prev[i];
            }
            out.extend_from_slice(&dec);
            prev = block;
        }
        out
    }
}

/// Generic Ciphertext Stealing (CTS-CBC, CS3 mode, RFC 3962 / NIST SP 800-38A Addendum) encryption.
pub fn aes_cts_encrypt<F>(plaintext: &[u8], iv: &[u8; 16], mut encrypt_block: F) -> Result<Vec<u8>, impacket_core::CoreError>
where
    F: FnMut(&[u8; 16]) -> [u8; 16],
{
    if plaintext.len() < 16 {
        return Err(impacket_core::CoreError::BufferUnderflow {
            needed: 16,
            available: plaintext.len(),
        });
    }

    if plaintext.len() == 16 {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = plaintext[i] ^ iv[i];
        }
        return Ok(encrypt_block(&block).to_vec());
    }

    let n = (plaintext.len() + 15) / 16;
    let last_len = plaintext.len() - (n - 1) * 16;

    let mut padded = plaintext.to_vec();
    while padded.len() % 16 != 0 {
        padded.push(0);
    }

    let mut ctext = Vec::with_capacity(padded.len());
    let mut prev = *iv;
    for chunk in padded.chunks_exact(16) {
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = chunk[i] ^ prev[i];
        }
        let enc = encrypt_block(&block);
        ctext.extend_from_slice(&enc);
        prev = enc;
    }

    let mut result = ctext[..ctext.len() - 32].to_vec();
    result.extend_from_slice(&ctext[ctext.len() - 16..]);
    result.extend_from_slice(&ctext[ctext.len() - 32..ctext.len() - 32 + last_len]);
    Ok(result)
}

/// Generic Ciphertext Stealing (CTS-CBC, CS3 mode, RFC 3962 / NIST SP 800-38A Addendum) decryption.
pub fn aes_cts_decrypt<F>(ciphertext: &[u8], iv: &[u8; 16], mut decrypt_block: F) -> Result<Vec<u8>, impacket_core::CoreError>
where
    F: FnMut(&[u8; 16]) -> [u8; 16],
{
    if ciphertext.len() < 16 {
        return Err(impacket_core::CoreError::BufferUnderflow {
            needed: 16,
            available: ciphertext.len(),
        });
    }

    if ciphertext.len() == 16 {
        let mut block = [0u8; 16];
        block.copy_from_slice(ciphertext);
        let dec = decrypt_block(&block);
        let mut out = [0u8; 16];
        for i in 0..16 {
            out[i] = dec[i] ^ iv[i];
        }
        return Ok(out.to_vec());
    }

    let n = (ciphertext.len() + 15) / 16;
    let last_len = ciphertext.len() - (n - 1) * 16;

    let mut out = Vec::with_capacity(ciphertext.len());
    let mut prev = *iv;

    let full_blocks = n - 2;
    for i in 0..full_blocks {
        let mut block = [0u8; 16];
        block.copy_from_slice(&ciphertext[i * 16..(i + 1) * 16]);
        let dec = decrypt_block(&block);
        for j in 0..16 {
            out.push(dec[j] ^ prev[j]);
        }
        prev = block;
    }

    let mut cn_minus_1 = [0u8; 16];
    cn_minus_1.copy_from_slice(&ciphertext[(n - 2) * 16..(n - 1) * 16]);
    let bb = decrypt_block(&cn_minus_1);

    let cn = &ciphertext[(n - 1) * 16..];
    let mut last_plaintext = Vec::with_capacity(last_len);
    for j in 0..last_len {
        last_plaintext.push(bb[j] ^ cn[j]);
    }
    let omitted = &bb[last_len..];

    let mut final_block = [0u8; 16];
    final_block[..last_len].copy_from_slice(cn);
    final_block[last_len..].copy_from_slice(omitted);

    let dec_final = decrypt_block(&final_block);
    for j in 0..16 {
        out.push(dec_final[j] ^ prev[j]);
    }
    out.extend_from_slice(&last_plaintext);

    Ok(out)
}

/// AES-128-CTS encryption (RFC 3962 Kerberos etype 17).
pub fn aes128_cts_encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, impacket_core::CoreError> {
    aes_cts_encrypt(plaintext, iv, |b| aes128::encrypt_block(key, b))
}

/// AES-128-CTS decryption (RFC 3962 Kerberos etype 17).
pub fn aes128_cts_decrypt(key: &[u8; 16], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, impacket_core::CoreError> {
    aes_cts_decrypt(ciphertext, iv, |b| aes128::decrypt_block(key, b))
}

/// AES-256-CTS encryption (RFC 3962 Kerberos etype 18).
pub fn aes256_cts_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, impacket_core::CoreError> {
    aes_cts_encrypt(plaintext, iv, |b| aes256::encrypt_block(key, b))
}

/// AES-256-CTS decryption (RFC 3962 Kerberos etype 18).
pub fn aes256_cts_decrypt(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, impacket_core::CoreError> {
    aes_cts_decrypt(ciphertext, iv, |b| aes256::decrypt_block(key, b))
}

/// Pure-Rust RFC 3174 / FIPS 180-1 SHA-1.
pub fn sha1(input: &[u8]) -> [u8; 20] {
    let bit_len = (input.len() as u64) * 8;
    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Pure-Rust RFC 2104 HMAC-SHA1.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha1(key);
        key_block[..20].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut k_ipad = [0u8; 64];
    let mut k_opad = [0u8; 64];
    for i in 0..64 {
        k_ipad[i] = key_block[i] ^ 0x36;
        k_opad[i] = key_block[i] ^ 0x5C;
    }

    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&k_ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha1(&inner);

    let mut outer = Vec::with_capacity(64 + 20);
    outer.extend_from_slice(&k_opad);
    outer.extend_from_slice(&inner_hash);
    sha1(&outer)
}

/// RFC 3962 Kerberos 96-bit (12-byte) truncated HMAC-SHA1 checksum.
pub fn hmac_sha1_96(key: &[u8], data: &[u8]) -> [u8; 12] {
    let full = hmac_sha1(key, data);
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}

/// RFC 2898 PBKDF2 with HMAC-SHA1 pseudorandom function.
pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len);
    let mut block_idx = 1u32;
    while out.len() < key_len {
        let mut salt_idx = Vec::with_capacity(salt.len() + 4);
        salt_idx.extend_from_slice(salt);
        salt_idx.extend_from_slice(&block_idx.to_be_bytes());
        let mut u = hmac_sha1(password, &salt_idx);
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha1(password, &u);
            for j in 0..20 {
                t[j] ^= u[j];
            }
        }
        let take = (key_len - out.len()).min(20);
        out.extend_from_slice(&t[..take]);
        block_idx += 1;
    }
    out
}

/// Pure-Rust FIPS 180-4 SHA-256 (SMB2 signing/preauth, NTLMv2 session hardening, KDF).
pub fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    let bit_len = (input.len() as u64) * 8;
    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Pure-Rust FIPS 180-4 SHA-512 (SMB 3.1.1 preauth-integrity hash).
pub fn sha512(input: &[u8]) -> [u8; 64] {
    const K: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ];
    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ];

    let bit_len = (input.len() as u128) * 8;
    let mut padded = Vec::with_capacity(input.len() + 144);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while (padded.len() % 128) != 112 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(128) {
        let mut w = [0u64; 80];
        for (i, word) in chunk.chunks_exact(8).enumerate() {
            w[i] = u64::from_be_bytes(word.try_into().unwrap());
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 64];
    for (i, word) in h.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Pure-Rust RFC 4231 HMAC-SHA256 (SMB 2.x message signing).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        k_block[..32].copy_from_slice(&sha256(key));
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    zeroize_slice(&mut k_block);

    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// Pure-Rust RFC 4231 HMAC-SHA512.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut k_block = [0u8; 128];
    if key.len() > 128 {
        k_block[..64].copy_from_slice(&sha512(key));
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 128];
    let mut opad = [0x5cu8; 128];
    for i in 0..128 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    zeroize_slice(&mut k_block);

    let mut inner = Vec::with_capacity(128 + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = sha512(&inner);

    let mut outer = Vec::with_capacity(192);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha512(&outer)
}

/// RFC 2898 PBKDF2 with HMAC-SHA256 pseudorandom function.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len);
    let mut block_index = 1u32;
    while out.len() < key_len {
        let mut u_prev = {
            let mut init = Vec::with_capacity(salt.len() + 4);
            init.extend_from_slice(salt);
            init.extend_from_slice(&block_index.to_be_bytes());
            hmac_sha256(password, &init)
        };
        let mut f_block = u_prev;
        for _ in 1..iterations {
            u_prev = hmac_sha256(password, &u_prev);
            for i in 0..32 {
                f_block[i] ^= u_prev[i];
            }
        }
        let take = std::cmp::min(key_len - out.len(), 32);
        out.extend_from_slice(&f_block[..take]);
        block_index += 1;
    }
    out
}

/// RFC 2898 PBKDF2 with HMAC-SHA512 pseudorandom function.
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len);
    let mut block_index = 1u32;
    while out.len() < key_len {
        let mut u_prev = {
            let mut init = Vec::with_capacity(salt.len() + 4);
            init.extend_from_slice(salt);
            init.extend_from_slice(&block_index.to_be_bytes());
            hmac_sha512(password, &init)
        };
        let mut f_block = u_prev;
        for _ in 1..iterations {
            u_prev = hmac_sha512(password, &u_prev);
            for i in 0..64 {
                f_block[i] ^= u_prev[i];
            }
        }
        let take = std::cmp::min(key_len - out.len(), 64);
        out.extend_from_slice(&f_block[..take]);
        block_index += 1;
    }
    out
}

/// Pure-Rust NIST SP800-38B AES-128-CMAC (SMB 3.x message signing).
pub fn aes128_cmac(key: &[u8; 16], msg: &[u8]) -> [u8; 16] {
    // Subkey generation.
    fn shl1(block: &[u8; 16]) -> ([u8; 16], u8) {
        let mut out = [0u8; 16];
        let mut carry = 0u8;
        for i in (0..16).rev() {
            out[i] = (block[i] << 1) | carry;
            carry = block[i] >> 7;
        }
        (out, carry)
    }
    let l = aes128::encrypt_block(key, &[0u8; 16]);
    let (mut k1, c1) = shl1(&l);
    if c1 != 0 {
        k1[15] ^= 0x87;
    }
    let (mut k2, c2) = shl1(&k1);
    if c2 != 0 {
        k2[15] ^= 0x87;
    }

    let n = msg.len();
    let complete = n > 0 && n % 16 == 0;
    let num_blocks = if n == 0 { 1 } else { (n + 15) / 16 };

    let mut last = [0u8; 16];
    let last_start = (num_blocks - 1) * 16;
    if complete {
        last.copy_from_slice(&msg[last_start..last_start + 16]);
        for i in 0..16 {
            last[i] ^= k1[i];
        }
    } else {
        let rem = &msg[last_start..];
        last[..rem.len()].copy_from_slice(rem);
        last[rem.len()] = 0x80;
        for i in 0..16 {
            last[i] ^= k2[i];
        }
    }

    let mut x = [0u8; 16];
    for blk in 0..num_blocks - 1 {
        let mut y = [0u8; 16];
        for i in 0..16 {
            y[i] = x[i] ^ msg[blk * 16 + i];
        }
        x = aes128::encrypt_block(key, &y);
    }
    for i in 0..16 {
        last[i] ^= x[i];
    }
    aes128::encrypt_block(key, &last)
}

/// NIST SP800-108 counter-mode KDF with HMAC-SHA256 as the PRF (SMB 3.x signing/encryption key
/// derivation; `[MS-SMB2] 3.1.4.2`). Returns `length` bytes (SMB2 uses 16).
pub fn sp800_108_counter_kdf(key: &[u8], label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    let total_bits = (length as u32) * 8;
    let mut counter: u32 = 1;
    while out.len() < length {
        let mut input = Vec::with_capacity(4 + label.len() + 1 + context.len() + 4);
        input.extend_from_slice(&counter.to_be_bytes());
        input.extend_from_slice(label);
        input.push(0x00);
        input.extend_from_slice(context);
        input.extend_from_slice(&total_bits.to_be_bytes());
        let block = hmac_sha256(key, &input);
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(length);
    out
}

/// Standard IEEE 802.3 CRC32 checksum.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use impacket_core::{encode_hex, EMPTY_LM_HASH};

    #[test]
    fn test_empty_lm_hash_matches_windows_constant() {
        let lm = compute_lm_hash("");
        assert_eq!(lm, EMPTY_LM_HASH);
        assert_eq!(encode_hex(&lm), "aad3b435b51404eeaad3b435b51404ee");
    }

    #[test]
    fn test_des_encrypt_and_decrypt_roundtrip_and_sam_rid_unwrap() {
        let orig_nt: [u8; 16] = [
            0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17,
            0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c,
        ];
        let wrapped = sam_des_encrypt_hash_with_rid(500, &orig_nt);
        assert_ne!(wrapped, orig_nt);
        let unwrapped = sam_des_decrypt_hash_with_rid(500, &wrapped);
        assert_eq!(unwrapped, orig_nt);
    }

    #[test]
    fn test_sha256_and_hmac_sha256_vectors() {
        // FIPS 180-4 "abc".
        assert_eq!(
            encode_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // RFC 4231 Test Case 2: key "Jefe", data "what do ya want for nothing?".
        assert_eq!(
            encode_hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // FIPS 180-4 SHA-512("abc").
        assert_eq!(
            encode_hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn test_aes128_cmac_nist_vectors() {
        // NIST SP800-38B examples, key 2b7e1516...
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        // Empty message.
        assert_eq!(
            encode_hex(&aes128_cmac(&key, &[])),
            "bb1d6929e9593728 7fa37d129b756746".replace(' ', "")
        );
        // 16-byte message (Mlen=128): 6bc1bee2...
        let msg: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        ];
        assert_eq!(
            encode_hex(&aes128_cmac(&key, &msg)),
            "070a16b46b4d4144f79bdd9dd04a287c"
        );
    }

    #[test]
    fn test_aes128_fips197_vector_and_cbc_roundtrip() {
        // FIPS 197 Appendix B test vector
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let plain: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        ];
        let ct = aes128::encrypt_block(&key, &plain);
        assert_eq!(encode_hex(&ct), "3925841d02dc09fbdc118597196a0b32");
        let pt = aes128::decrypt_block(&key, &ct);
        assert_eq!(pt, plain);

        let iv = [0x11u8; 16];
        let cbc_ct = aes128::encrypt_cbc(&key, &iv, &plain);
        let cbc_pt = aes128::decrypt_cbc(&key, &iv, &cbc_ct);
        assert_eq!(cbc_pt, plain);
    }

    #[test]
    fn test_sha1_and_hmac_sha1_vectors() {
        assert_eq!(
            encode_hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            encode_hex(&sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );

        let key = [0x0bu8; 20];
        let hmac = hmac_sha1(&key, b"Hi There");
        assert_eq!(
            encode_hex(&hmac),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        let hmac96 = hmac_sha1_96(&key, b"Hi There");
        assert_eq!(encode_hex(&hmac96), "b617318655057264e28bc0b6");
    }

    #[test]
    fn test_pbkdf2_hmac_sha1_vector() {
        // RFC 6070 Test 2: password="password", salt="salt", c=2, dkLen=20
        let dk = pbkdf2_hmac_sha1(b"password", b"salt", 2, 20);
        assert_eq!(encode_hex(&dk), "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
    }

    #[test]
    fn test_aes256_fips197_vector_and_cbc_roundtrip() {
        // FIPS 197 Appendix C.2
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let plain: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let ct = aes256::encrypt_block(&key, &plain);
        assert_eq!(encode_hex(&ct), "8ea2b7ca516745bfeafc49904b496089");
        let pt = aes256::decrypt_block(&key, &ct);
        assert_eq!(pt, plain);

        let iv = [0x55u8; 16];
        let cbc_ct = aes256::encrypt_cbc(&key, &iv, &plain);
        let cbc_pt = aes256::decrypt_cbc(&key, &iv, &cbc_ct);
        assert_eq!(cbc_pt, plain);
    }

    #[test]
    fn test_aes_cts_roundtrip() {
        let key128: [u8; 16] = [0x12; 16];
        let key256: [u8; 32] = [0x34; 32];
        let iv = [0x77u8; 16];

        for &len in &[16, 17, 31, 32, 45, 64] {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();

            // AES-128 CTS
            let ct128 = aes128_cts_encrypt(&key128, &iv, &plain).unwrap();
            assert_eq!(ct128.len(), plain.len());
            let pt128 = aes128_cts_decrypt(&key128, &iv, &ct128).unwrap();
            assert_eq!(pt128, plain);

            // AES-256 CTS
            let ct256 = aes256_cts_encrypt(&key256, &iv, &plain).unwrap();
            assert_eq!(ct256.len(), plain.len());
            let pt256 = aes256_cts_decrypt(&key256, &iv, &ct256).unwrap();
            assert_eq!(pt256, plain);
        }
    }

    #[test]
    fn test_des3_cbc_roundtrip() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
            0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
        ];
        let iv = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
        let plaintext = b"Hello Triple-DES DPAPI Block Encryption!";
        let ct = des3_cbc_encrypt(&key, &iv, plaintext);
        assert_eq!(ct.len(), plaintext.len());
        let pt = des3_cbc_decrypt(&key, &iv, &ct);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_hmac_sha512_vector() {
        let key = [0x0bu8; 20];
        let hmac = hmac_sha512(&key, b"Hi There");
        assert_eq!(
            encode_hex(&hmac),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }
}
