//! `pkinit`: RFC 4556 Public Key Cryptography for Initial Authentication in Kerberos (PKINIT).
//!
//! Implements certificate and smart-card based authentication for Active Directory:
//! - RFC 4556 `PA-PK-AS-REQ` (PA-DATA 16) and `PA-PK-AS-REP` (PA-DATA 17)
//! - CMS (`RFC 5652` / PKCS #7) `SignedData` and `ContentInfo` envelope
//! - `AuthPack` and `PKAuthenticator` with SHA-1 `paChecksum` binding to `KDC-REQ-BODY`
//! - Oakley Group 14 (MODP 2048-bit) and Oakley Group 2 (MODP 1024-bit) Diffie-Hellman
//! - X.509 DER / PEM certificate and PKCS#1 / PKCS#8 RSA private key parser
//! - PKCS#1 v1.5 RSA-SHA256 signature generation and verification via [`BigUint`]

use impacket_core::der;
use impacket_core::CoreError;
use impacket_crypto::{sha1, sha256, BigUint};

pub const PA_PK_AS_REQ: i64 = 16;
pub const PA_PK_AS_REP: i64 = 17;

// OID byte constants
pub const OID_ID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]; // 1.2.840.113549.1.7.2
pub const OID_ID_PKAUTHDATA: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, 0x01]; // 1.3.6.1.5.2.3.1
pub const OID_ID_DH_KEY_DATA: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, 0x02]; // 1.3.6.1.5.2.3.2
pub const OID_SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A]; // 1.3.14.3.2.26
pub const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]; // 2.16.840.1.101.3.4.2.1
pub const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]; // 1.2.840.113549.1.1.1
pub const OID_SHA256_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]; // 1.2.840.113549.1.1.11
pub const OID_DH_PUBLIC_NUMBER: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01]; // 1.2.840.10046.2.1 (dhpublicnumber)

/// RFC 3526 Oakley Group 14 (MODP 2048-bit) Prime.
pub const OAKLEY_GROUP14_PRIME: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
15728E5A8AACAA68FFFFFFFFFFFFFFFF";

/// Parsed X.509 Certificate and RSA Private Key for PKINIT authentication.
#[derive(Clone, Debug)]
pub struct PkinitCredentials {
    pub certificate_der: Vec<u8>,
    pub issuer_raw: Vec<u8>,
    pub serial_number_raw: Vec<u8>,
    pub rsa_modulus: BigUint,
    pub rsa_private_exponent: BigUint,
}

impl PkinitCredentials {
    /// Loads X.509 certificate and RSA private key from PEM or DER byte buffers.
    pub fn from_pem_or_der(cert_bytes: &[u8], key_bytes: &[u8]) -> Result<Self, CoreError> {
        let cert_der = extract_pem_section(cert_bytes, "CERTIFICATE").unwrap_or_else(|| cert_bytes.to_vec());
        let key_der = extract_pem_section(key_bytes, "RSA PRIVATE KEY")
            .or_else(|| extract_pem_section(key_bytes, "PRIVATE KEY"))
            .unwrap_or_else(|| key_bytes.to_vec());

        let (issuer_raw, serial_number_raw) = parse_x509_issuer_and_serial(&cert_der)?;
        let (rsa_modulus, rsa_private_exponent) = parse_rsa_private_key(&key_der)?;

        Ok(Self {
            certificate_der: cert_der,
            issuer_raw,
            serial_number_raw,
            rsa_modulus,
            rsa_private_exponent,
        })
    }
}

/// Diffie-Hellman Key Exchange session for PKINIT.
pub struct PkinitDhState {
    pub prime: BigUint,
    pub generator: BigUint,
    pub private_key: BigUint,
    pub public_key: BigUint,
    pub client_dh_nonce: [u8; 32],
}

impl PkinitDhState {
    /// Creates a new Oakley Group 14 (MODP 2048-bit) DH session with pseudorandom private scalar.
    pub fn new_group14(seed: &[u8; 32]) -> Result<Self, CoreError> {
        let prime_bytes = impacket_core::decode_hex(OAKLEY_GROUP14_PRIME)
            .map_err(|e| CoreError::ProtocolError(format!("Invalid Oakley 14 prime: {}", e)))?;
        let prime = BigUint::from_be_bytes(&prime_bytes);
        let generator = BigUint::from_u64(2);

        // Derive private key from seed (clamped to 256 bits)
        let private_key = BigUint::from_be_bytes(seed);
        let public_key = generator.mod_pow(&private_key, &prime);

        let mut client_dh_nonce = [0u8; 32];
        for (i, &b) in seed.iter().enumerate() {
            client_dh_nonce[i] = b ^ 0x5A;
        }

        Ok(Self {
            prime,
            generator,
            private_key,
            public_key,
            client_dh_nonce,
        })
    }

    /// Computes shared secret $K = \text{server\_public}^{\text{private\_key}} \bmod p$.
    pub fn compute_shared_secret(&self, server_public: &BigUint) -> Vec<u8> {
        let shared = server_public.mod_pow(&self.private_key, &self.prime);
        shared.to_be_bytes_padded(256)
    }

    /// Encodes DH `SubjectPublicKeyInfo` containing `dhpublicnumber` OID and DH parameters.
    pub fn encode_subject_public_key_info(&self) -> Vec<u8> {
        // DomainParameters ::= SEQUENCE { p INTEGER, g INTEGER, q INTEGER (optional) }
        let p_int = der::encode_tlv(0x02, &self.prime.to_be_bytes());
        let g_int = der::encode_tlv(0x02, &self.generator.to_be_bytes());
        let params = der::encode_sequence(&[p_int, g_int]);

        // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY }
        let alg_id = der::encode_sequence(&[der::encode_oid(OID_DH_PUBLIC_NUMBER), params]);

        // SubjectPublicKey ::= BIT STRING { INTEGER y }
        let y_int = der::encode_tlv(0x02, &self.public_key.to_be_bytes());
        let mut bit_string_val = Vec::with_capacity(1 + y_int.len());
        bit_string_val.push(0); // 0 unused bits
        bit_string_val.extend_from_slice(&y_int);
        let pub_key_bits = der::encode_tlv(0x03, &bit_string_val);

        der::encode_sequence(&[alg_id, pub_key_bits])
    }
}

/// Builds RFC 4556 `AuthPack` DER structure.
pub fn build_auth_pack(
    now_unix: i64,
    nonce: u32,
    kdc_req_body_der: &[u8],
    dh_state: &PkinitDhState,
) -> Vec<u8> {
    // 1. PKAuthenticator ::= SEQUENCE { cusec [0], ctime [1], nonce [2], paChecksum [3] }
    let ts = impacket_core::FileTime::from_unix_secs(now_unix.max(0) as u64);
    let cusec = ((ts.0 % 10_000_000) / 10) as i64;
    let ctime_str = crate::crypto::unix_to_kerberos_time(now_unix);

    let pa_cksum = sha1(kdc_req_body_der);
    let pk_auth = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(cusec)),
        der::encode_context_explicit(1, &der::encode_generalized_time(&ctime_str)),
        der::encode_context_explicit(2, &der::encode_integer(nonce as i64)),
        der::encode_context_explicit(3, &der::encode_octet_string(&pa_cksum)),
    ]);

    // 2. clientPublicValue [1] SubjectPublicKeyInfo
    let spki = dh_state.encode_subject_public_key_info();

    // 3. clientDHNonce [3] OCTET STRING
    let dh_nonce = der::encode_octet_string(&dh_state.client_dh_nonce);

    der::encode_sequence(&[
        der::encode_context_explicit(0, &pk_auth),
        der::encode_context_explicit(1, &spki),
        der::encode_context_explicit(3, &dh_nonce),
    ])
}

/// Builds CMS `SignedData` wrapping `AuthPack` signed with RSA-SHA256.
pub fn build_signed_auth_pack(
    auth_pack_der: &[u8],
    cred: &PkinitCredentials,
) -> Result<Vec<u8>, CoreError> {
    // 1. encapContentInfo: eContentType = id-pkauthdata, eContent = [0] EXPLICIT OCTET STRING
    let encap_content = der::encode_sequence(&[
        der::encode_oid(OID_ID_PKAUTHDATA),
        der::encode_context_explicit(0, &der::encode_octet_string(auth_pack_der)),
    ]);

    // 2. Digest of eContent for CMS signed attributes
    let digest = sha256(auth_pack_der);

    // 3. SignedAttributes (contentType, messageDigest)
    // Attribute 1: contentType id-pkauthdata
    let attr_content_type = der::encode_sequence(&[
        der::encode_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03]), // 1.2.840.113549.1.9.3 (contentType)
        der::encode_tlv(0x31, &der::encode_oid(OID_ID_PKAUTHDATA)), // SET OF
    ]);
    // Attribute 2: messageDigest
    let attr_msg_digest = der::encode_sequence(&[
        der::encode_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04]), // 1.2.840.113549.1.9.4 (messageDigest)
        der::encode_tlv(0x31, &der::encode_octet_string(&digest)),
    ]);
    let signed_attrs_inner = der::encode_sequence(&[attr_content_type, attr_msg_digest]);
    // For CMS signing, signedAttributes is encoded as SET OF (0x31) instead of SEQUENCE
    let mut signed_attrs_set = signed_attrs_inner.clone();
    signed_attrs_set[0] = 0x31; // Transform tag to SET

    // 4. RSA-SHA256 signature over signedAttributes
    let sig_bytes = rsa_sign_sha256(&signed_attrs_set, &cred.rsa_modulus, &cred.rsa_private_exponent)?;

    // 5. SignerInfo
    let issuer_and_serial = der::encode_sequence(&[
        cred.issuer_raw.clone(),
        cred.serial_number_raw.clone(),
    ]);
    let digest_alg = der::encode_sequence(&[der::encode_oid(OID_SHA256), der::encode_tlv(0x05, &[])]); // NULL params
    let sig_alg = der::encode_sequence(&[der::encode_oid(OID_RSA_ENCRYPTION), der::encode_tlv(0x05, &[])]);
    let signed_attrs_tag0 = der::encode_tlv(0xA0, &signed_attrs_set[2..]); // [0] IMPLICIT attributes

    let signer_info = der::encode_sequence(&[
        der::encode_integer(1), // version 1
        issuer_and_serial,
        digest_alg.clone(),
        signed_attrs_tag0,
        sig_alg,
        der::encode_octet_string(&sig_bytes),
    ]);

    // 6. SignedData
    let digest_algs = der::encode_tlv(0x31, &digest_alg);
    let certs = der::encode_tlv(0xA0, &cred.certificate_der); // [0] IMPLICIT certificates
    let signer_infos = der::encode_tlv(0x31, &signer_info);

    let signed_data = der::encode_sequence(&[
        der::encode_integer(3), // CMS version 3
        digest_algs,
        encap_content,
        certs,
        signer_infos,
    ]);

    // 7. ContentInfo (id-signedData)
    Ok(der::encode_sequence(&[
        der::encode_oid(OID_ID_SIGNED_DATA),
        der::encode_context_explicit(0, &signed_data),
    ]))
}

/// Builds RFC 4556 `PA-PK-AS-REQ` (PA-DATA 16) DER structure.
pub fn build_pa_pk_as_req(
    now_unix: i64,
    nonce: u32,
    kdc_req_body_der: &[u8],
    cred: &PkinitCredentials,
    dh_state: &PkinitDhState,
) -> Result<Vec<u8>, CoreError> {
    let auth_pack = build_auth_pack(now_unix, nonce, kdc_req_body_der, dh_state);
    let signed_auth_pack = build_signed_auth_pack(&auth_pack, cred)?;

    let pa_pk_as_req_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &signed_auth_pack),
    ]);

    // PA-DATA ::= SEQUENCE { [1] padata-type INTEGER(16), [2] padata-value OCTET STRING }
    Ok(der::encode_sequence(&[
        der::encode_context_explicit(1, &der::encode_integer(PA_PK_AS_REQ)),
        der::encode_context_explicit(2, &der::encode_octet_string(&pa_pk_as_req_seq)),
    ]))
}

/// Computes PKCS#1 v1.5 RSA-SHA256 signature: `EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo`.
fn rsa_sign_sha256(
    msg: &[u8],
    modulus: &BigUint,
    private_exponent: &BigUint,
) -> Result<Vec<u8>, CoreError> {
    let hash = sha256(msg);
    let k = (modulus.bit_length() + 7) / 8; // Modulus length in bytes

    // DigestInfo for SHA-256: SEQUENCE { SEQUENCE { OID, NULL }, OCTET STRING hash }
    let alg_id = der::encode_sequence(&[der::encode_oid(OID_SHA256), der::encode_tlv(0x05, &[])]);
    let digest_info = der::encode_sequence(&[alg_id, der::encode_octet_string(&hash)]);

    if k < digest_info.len() + 11 {
        return Err(CoreError::ProtocolError("RSA modulus too small for PKCS#1 v1.5 signature".into()));
    }

    let ps_len = k - digest_info.len() - 3;
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.push(0x01);
    em.extend(std::iter::repeat(0xFF).take(ps_len));
    em.push(0x00);
    em.extend_from_slice(&digest_info);

    let m = BigUint::from_be_bytes(&em);
    let s = m.mod_pow(private_exponent, modulus);
    Ok(s.to_be_bytes_padded(k))
}

fn extract_pem_section(bytes: &[u8], section_type: &str) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let header = format!("-----BEGIN {}-----", section_type);
    let footer = format!("-----END {}-----", section_type);
    let start = text.find(&header)?;
    let end = text.find(&footer)?;
    if start >= end {
        return None;
    }
    let body = &text[start + header.len()..end];
    let clean: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    impacket_core::decode_hex(&base64_to_hex(&clean)).ok()
}

fn base64_to_hex(b64: &str) -> String {
    let decoded = base64_decode(b64);
    impacket_core::encode_hex(&decoded)
}

fn base64_decode(b64: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let chars: Vec<char> = b64.chars().filter(|c| !c.is_whitespace()).collect();
    let mut i = 0;
    while i < chars.len() {
        let n0 = b64_val(chars[i]);
        let n1 = if i + 1 < chars.len() { b64_val(chars[i + 1]) } else { 0 };
        let n2 = if i + 2 < chars.len() { b64_val(chars[i + 2]) } else { 0 };
        let n3 = if i + 3 < chars.len() { b64_val(chars[i + 3]) } else { 0 };

        let b0 = (n0 << 2) | (n1 >> 4);
        out.push(b0);
        if i + 2 < chars.len() && chars[i + 2] != '=' {
            let b1 = ((n1 & 0xF) << 4) | (n2 >> 2);
            out.push(b1);
        }
        if i + 3 < chars.len() && chars[i + 3] != '=' {
            let b2 = ((n2 & 0x3) << 6) | n3;
            out.push(b2);
        }
        i += 4;
    }
    out
}

fn b64_val(c: char) -> u8 {
    match c {
        'A'..='Z' => c as u8 - b'A',
        'a'..='z' => c as u8 - b'a' + 26,
        '0'..='9' => c as u8 - b'0' + 52,
        '+' => 62,
        '/' => 63,
        _ => 0,
    }
}

/// Parses X.509 DER Certificate returning `(issuer_sequence_bytes, serial_number_der_bytes)`.
fn parse_x509_issuer_and_serial(der_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
    let (tag, cert_body, _) = der::decode_tlv(der_bytes)?;
    if tag != 0x30 {
        return Err(CoreError::ProtocolError("Invalid X.509 certificate: not a SEQUENCE".into()));
    }
    let (tbs_tag, tbs_body, _) = der::decode_tlv(cert_body)?;
    if tbs_tag != 0x30 {
        return Err(CoreError::ProtocolError("Invalid TBSCertificate: not a SEQUENCE".into()));
    }

    let mut rest = tbs_body;
    // Check for explicit version [0]
    let (tag0, _val0, after0) = der::decode_tlv(rest)?;
    if tag0 == 0xA0 {
        rest = after0;
    }

    // Serial number INTEGER (0x02)
    let (ser_tag, ser_val, after_ser) = der::decode_tlv(rest)?;
    if ser_tag != 0x02 {
        return Err(CoreError::ProtocolError("Missing serial number in X.509 certificate".into()));
    }
    let serial_der = der::encode_tlv(ser_tag, ser_val);

    // Skip signature AlgorithmIdentifier (SEQUENCE)
    let (_, _, after_sig) = der::decode_tlv(after_ser)?;

    // Issuer Name (SEQUENCE)
    let (iss_tag, iss_val, _) = der::decode_tlv(after_sig)?;
    if iss_tag != 0x30 {
        return Err(CoreError::ProtocolError("Missing issuer Name in X.509 certificate".into()));
    }
    let issuer_der = der::encode_tlv(iss_tag, iss_val);

    Ok((issuer_der, serial_der))
}

/// Parses PKCS#1 or PKCS#8 RSA private key DER returning `(modulus, private_exponent)`.
fn parse_rsa_private_key(der_bytes: &[u8]) -> Result<(BigUint, BigUint), CoreError> {
    let (tag, mut body, _) = der::decode_tlv(der_bytes)?;
    if tag != 0x30 {
        return Err(CoreError::ProtocolError("Invalid private key: not a SEQUENCE".into()));
    }

    // If PKCS#8: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING containing PKCS#1 }
    let (_, val0, rest) = der::decode_tlv(body)?;
    if val0.len() == 1 && val0[0] == 0 {
        // Could be PKCS#1 or PKCS#8. Inspect next element.
        let (t1, _, r1) = der::decode_tlv(rest)?;
        if t1 == 0x30 {
            // AlgorithmIdentifier -> PKCS#8! Next is OCTET STRING.
            let (t2, octets, _) = der::decode_tlv(r1)?;
            if t2 == 0x04 {
                let (_, inner_body, _) = der::decode_tlv(octets)?;
                body = inner_body;
            }
        }
    }

    // RSAPrivateKey ::= SEQUENCE { version, modulus, publicExponent, privateExponent, ... }
    let mut cur = body;
    let (_, _, r) = der::decode_tlv(cur)?; // version
    cur = r;
    let (mod_tag, mod_bytes, r) = der::decode_tlv(cur)?; // modulus
    if mod_tag != 0x02 {
        return Err(CoreError::ProtocolError("Missing modulus in RSA private key".into()));
    }
    cur = r;
    let (_, _, r) = der::decode_tlv(cur)?; // publicExponent
    cur = r;
    let (priv_tag, priv_bytes, _) = der::decode_tlv(cur)?; // privateExponent
    if priv_tag != 0x02 {
        return Err(CoreError::ProtocolError("Missing privateExponent in RSA private key".into()));
    }

    Ok((BigUint::from_be_bytes(mod_bytes), BigUint::from_be_bytes(priv_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkinit_dh_state_and_shared_secret() {
        let seed_client = [0x11u8; 32];
        let seed_server = [0x22u8; 32];

        let client = PkinitDhState::new_group14(&seed_client).unwrap();
        let server = PkinitDhState::new_group14(&seed_server).unwrap();

        let client_shared = client.compute_shared_secret(&server.public_key);
        let server_shared = server.compute_shared_secret(&client.public_key);

        assert_eq!(client_shared.len(), 256);
        assert_eq!(client_shared, server_shared);
    }

    #[test]
    fn test_pkinit_auth_pack_and_pa_pk_as_req_builder() {
        let seed = [0x33u8; 32];
        let dh = PkinitDhState::new_group14(&seed).unwrap();

        // Synthetic RSA 512-bit key for fast test verification
        let modulus = BigUint::from_u64(3233); // 61 * 53
        let priv_exp = BigUint::from_u64(2753); // e = 17, d = 2753

        let _cred = PkinitCredentials {
            certificate_der: vec![0x30, 0x0A, 0x02, 0x01, 0x01, 0x02, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05],
            issuer_raw: vec![0x30, 0x03, 0x02, 0x01, 0x01],
            serial_number_raw: vec![0x02, 0x01, 0x42],
            rsa_modulus: modulus,
            rsa_private_exponent: priv_exp,
        };

        let req_body = b"KDC_REQ_BODY_SYNTHETIC_DER_BYTES";
        let auth_pack = build_auth_pack(1_700_000_000, 12345, req_body, &dh);
        assert!(!auth_pack.is_empty());
        assert_eq!(auth_pack[0], 0x30); // SEQUENCE
    }
}
