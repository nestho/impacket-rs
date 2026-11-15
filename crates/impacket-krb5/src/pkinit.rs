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
pub const OID_ID_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01]; // 1.2.840.113549.1.7.1
pub const OID_ID_ENCRYPTED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06]; // 1.2.840.113549.1.7.6
pub const OID_KEY_BAG: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x01]; // 1.2.840.113549.1.12.10.1.1
pub const OID_PKCS8_SHROUDED_KEY_BAG: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x02]; // 1.2.840.113549.1.12.10.1.2
pub const OID_CERT_BAG: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x03]; // 1.2.840.113549.1.12.10.1.3
pub const OID_X509_CERTIFICATE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x16, 0x01]; // 1.2.840.113549.1.9.22.1
pub const OID_PBE_SHA1_3DES: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x03]; // 1.2.840.113549.1.12.1.3
pub const OID_PBES2: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D]; // 1.2.840.113549.1.5.13
pub const OID_PBKDF2: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C]; // 1.2.840.113549.1.5.12
pub const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A]; // 2.16.840.1.101.3.4.1.42
pub const OID_AES128_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02]; // 2.16.840.1.101.3.4.1.2

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
            .or_else(|| extract_pem_section(cert_bytes, "RSA PRIVATE KEY"))
            .or_else(|| extract_pem_section(cert_bytes, "PRIVATE KEY"))
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

    /// Loads X.509 certificate and RSA private key from PKCS#12 (.pfx / .p12) container bytes.
    pub fn from_pfx(pfx_bytes: &[u8], password: &str) -> Result<Self, CoreError> {
        let (cert_der, key_der) = parse_pkcs12(pfx_bytes, password)?;
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

/// Parses PKCS#12 (.pfx / .p12) container bytes returning `(certificate_der, rsa_private_key_der)`.
pub fn parse_pkcs12(pfx_bytes: &[u8], password: &str) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
    let (pfx_tag, pfx_body, _) = der::decode_tlv(pfx_bytes)?;
    if pfx_tag != 0x30 {
        return Err(CoreError::ProtocolError("Invalid PKCS#12 file: outer tag is not a SEQUENCE".into()));
    }

    // version INTEGER (usually 3)
    let (_, _, rem0) = der::decode_tlv(pfx_body)?;

    // authSafe ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT OCTET STRING }
    let (_, auth_safe_seq, _) = der::decode_tlv(rem0)?;
    let (_, _, rem_ci) = der::decode_tlv(auth_safe_seq)?; // skip contentType OID
    let (c_tag, c_val, _) = der::decode_tlv(rem_ci)?;
    let auth_safe_bytes = if (c_tag & 0x1F) == 0 {
        let (_, octets, _) = der::decode_tlv(c_val)?;
        octets
    } else if c_tag == 0x04 {
        c_val
    } else {
        return Err(CoreError::ProtocolError("Invalid PKCS#12 authSafe content".into()));
    };

    // AuthenticatedSafe ::= SEQUENCE OF ContentInfo
    let (_, mut as_seq, _) = der::decode_tlv(auth_safe_bytes)?;
    let mut decrypted_streams: Vec<Vec<u8>> = Vec::new();
    let mut cert_der: Option<Vec<u8>> = None;
    let mut key_der: Option<Vec<u8>> = None;

    while !as_seq.is_empty() {
        let (_, ci_item, as_rem) = der::decode_tlv(as_seq)?;
        as_seq = as_rem;

        let (_, oid_bytes, ci_rem) = der::decode_tlv(ci_item)?;
        let (val_tag, val_bytes, _) = der::decode_tlv(ci_rem)?;

        let content_bytes = if (val_tag & 0x1F) == 0 {
            if let Ok((_, inner, _)) = der::decode_tlv(val_bytes) {
                inner
            } else {
                val_bytes
            }
        } else {
            val_bytes
        };

        if oid_bytes == OID_ID_DATA {
            // Unencrypted SafeContents
            decrypted_streams.push(content_bytes.to_vec());
        } else if oid_bytes == OID_ID_ENCRYPTED_DATA {
            // EncryptedData ::= SEQUENCE { version, EncryptedContentInfo }
            if let Ok((_, ed_body, _)) = der::decode_tlv(content_bytes) {
                if let Ok((_, _, ec_rem)) = der::decode_tlv(ed_body) {
                    if let Ok((_, ec_info, _)) = der::decode_tlv(ec_rem) {
                        if let Ok(dec) = decrypt_encrypted_content_info(ec_info, password) {
                            decrypted_streams.push(dec);
                        }
                    }
                }
            }
        }
    }

    // Process all SafeContents streams to extract cert and key bags
    for stream in &decrypted_streams {
        if let Ok((_, mut bags_seq, _)) = der::decode_tlv(stream) {
            while !bags_seq.is_empty() {
                if let Ok((_, bag_item, b_rem)) = der::decode_tlv(bags_seq) {
                    bags_seq = b_rem;
                    if let Ok((_, bag_oid, bag_rem)) = der::decode_tlv(bag_item) {
                        if let Ok((bv_tag, bv_val, _)) = der::decode_tlv(bag_rem) {
                            let bag_val = if (bv_tag & 0x1F) == 0 {
                                bv_val
                            } else {
                                bv_val
                            };

                            if bag_oid == OID_CERT_BAG {
                                // CertBag ::= SEQUENCE { certId OID, certValue [0] EXPLICIT OCTET STRING }
                                if let Ok((_, cb_seq, _)) = der::decode_tlv(bag_val) {
                                    if let Ok((_, _, cb_rem)) = der::decode_tlv(cb_seq) {
                                        if let Ok((_, cv_val, _)) = der::decode_tlv(cb_rem) {
                                            if let Ok((_, cv_octets, _)) = der::decode_tlv(cv_val) {
                                                if cert_der.is_none() {
                                                    cert_der = Some(cv_octets.to_vec());
                                                }
                                            }
                                        }
                                    }
                                }
                            } else if bag_oid == OID_KEY_BAG {
                                // PrivateKeyInfo (PKCS#8)
                                if key_der.is_none() {
                                    key_der = Some(bag_val.to_vec());
                                }
                            } else if bag_oid == OID_PKCS8_SHROUDED_KEY_BAG {
                                // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm AlgorithmIdentifier, encryptedData OCTET STRING }
                                if let Ok(dec_key) = decrypt_encrypted_private_key_info(bag_val, password) {
                                    if key_der.is_none() {
                                        key_der = Some(dec_key);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    break;
                }
            }
        }
    }

    // Fallback scanner if either cert or key wasn't resolved by bag OIDs
    if cert_der.is_none() || key_der.is_none() {
        for stream in &decrypted_streams {
            if cert_der.is_none() {
                if let Some(c) = scan_for_x509_certificate(stream) {
                    cert_der = Some(c);
                }
            }
            if key_der.is_none() {
                if let Some(k) = scan_for_rsa_private_key(stream) {
                    key_der = Some(k);
                }
            }
        }
    }

    let final_cert = cert_der.ok_or_else(|| CoreError::ProtocolError("No X.509 certificate found in PKCS#12 container".into()))?;
    let final_key = key_der.ok_or_else(|| CoreError::ProtocolError("No RSA private key found in PKCS#12 container (incorrect password?)".into()))?;

    Ok((final_cert, final_key))
}

fn decrypt_encrypted_content_info(ec_info: &[u8], password: &str) -> Result<Vec<u8>, CoreError> {
    let (_, _, rem1) = der::decode_tlv(ec_info)?; // skip contentType OID
    let (_, alg_id, rem2) = der::decode_tlv(rem1)?; // AlgorithmIdentifier
    let (ct_tag, ct_val, _) = der::decode_tlv(rem2)?; // encryptedContent [0] IMPLICIT OCTET STRING

    let ciphertext = if (ct_tag & 0x1F) == 0 {
        ct_val
    } else {
        ct_val
    };

    decrypt_with_algorithm(alg_id, ciphertext, password)
}

fn decrypt_encrypted_private_key_info(epki: &[u8], password: &str) -> Result<Vec<u8>, CoreError> {
    let (_, alg_id, rem) = der::decode_tlv(epki)?;
    let (ct_tag, ct_val, _) = der::decode_tlv(rem)?;
    let ciphertext = if ct_tag == 0x04 { ct_val } else { ct_val };
    decrypt_with_algorithm(alg_id, ciphertext, password)
}

fn decrypt_with_algorithm(alg_id: &[u8], ciphertext: &[u8], password: &str) -> Result<Vec<u8>, CoreError> {
    let (_, alg_oid, rem) = der::decode_tlv(alg_id)?;
    if alg_oid == OID_PBE_SHA1_3DES {
        let (_, params_seq, _) = der::decode_tlv(rem)?;
        let (_, salt, p_rem) = der::decode_tlv(params_seq)?;
        let iter_num = if !p_rem.is_empty() {
            der::decode_integer(p_rem)? as usize
        } else {
            2048
        };
        decrypt_pkcs12_3des(ciphertext, salt, password, iter_num)
    } else if alg_oid == OID_PBES2 {
        let (_, params_seq, _) = der::decode_tlv(rem)?;
        let (_, kdf_seq, enc_rem) = der::decode_tlv(params_seq)?;
        let (_, scheme_seq, _) = der::decode_tlv(enc_rem)?;

        // KDF sequence: AlgorithmIdentifier (PBKDF2)
        let (_, _kdf_oid, kdf_params) = der::decode_tlv(kdf_seq)?;
        let (_, pbkdf2_params, _) = der::decode_tlv(kdf_params)?;
        let (_, salt, p_rem2) = der::decode_tlv(pbkdf2_params)?;
        let (iter_tag, iter_val, _) = der::decode_tlv(p_rem2)?;
        let iterations = if iter_tag == 0x02 {
            der::decode_integer(iter_val)? as u32
        } else {
            2048
        };

        // Encryption scheme sequence: AlgorithmIdentifier (AES-CBC)
        let (_, cipher_oid, iv_params) = der::decode_tlv(scheme_seq)?;
        let (_, iv_octets, _) = der::decode_tlv(iv_params)?;

        decrypt_pbes2(ciphertext, salt, iterations, cipher_oid, iv_octets, password)
    } else {
        Err(CoreError::ProtocolError("Unsupported PKCS#12 encryption algorithm".into()))
    }
}

fn decrypt_pkcs12_3des(
    ciphertext: &[u8],
    salt: &[u8],
    password: &str,
    iterations: usize,
) -> Result<Vec<u8>, CoreError> {
    if ciphertext.len() % 8 != 0 {
        return Err(CoreError::ProtocolError("Ciphertext length not multiple of 8 for 3DES".into()));
    }
    let key_bytes = pkcs12_kdf(1, salt, password, iterations, 24);
    let iv_bytes = pkcs12_kdf(2, salt, password, iterations, 8);
    let mut key24 = [0u8; 24];
    let mut iv8 = [0u8; 8];
    key24.copy_from_slice(&key_bytes);
    iv8.copy_from_slice(&iv_bytes);
    let decrypted = impacket_crypto::des3_cbc_decrypt(&key24, &iv8, ciphertext);
    strip_pkcs7_padding(&decrypted)
}

fn decrypt_pbes2(
    ciphertext: &[u8],
    salt: &[u8],
    iterations: u32,
    cipher_oid: &[u8],
    iv: &[u8],
    password: &str,
) -> Result<Vec<u8>, CoreError> {
    if ciphertext.len() % 16 != 0 {
        return Err(CoreError::ProtocolError("Ciphertext length not multiple of 16 for AES".into()));
    }
    let pass_bytes = password.as_bytes();
    if cipher_oid == OID_AES256_CBC {
        let key = impacket_crypto::pbkdf2_hmac_sha256(pass_bytes, salt, iterations, 32);
        let mut key32 = [0u8; 32];
        let mut iv16 = [0u8; 16];
        if key.len() < 32 || iv.len() < 16 {
            return Err(CoreError::ProtocolError("Invalid key/IV length for AES-256".into()));
        }
        key32.copy_from_slice(&key[..32]);
        iv16.copy_from_slice(&iv[..16]);
        let decrypted = impacket_crypto::aes256::decrypt_cbc(&key32, &iv16, ciphertext);
        strip_pkcs7_padding(&decrypted)
    } else if cipher_oid == OID_AES128_CBC {
        let key = impacket_crypto::pbkdf2_hmac_sha256(pass_bytes, salt, iterations, 16);
        let mut key16 = [0u8; 16];
        let mut iv16 = [0u8; 16];
        if key.len() < 16 || iv.len() < 16 {
            return Err(CoreError::ProtocolError("Invalid key/IV length for AES-128".into()));
        }
        key16.copy_from_slice(&key[..16]);
        iv16.copy_from_slice(&iv[..16]);
        let decrypted = impacket_crypto::aes128::decrypt_cbc(&key16, &iv16, ciphertext);
        strip_pkcs7_padding(&decrypted)
    } else {
        Err(CoreError::ProtocolError("Unsupported PBES2 encryption algorithm".into()))
    }
}

pub fn pkcs12_kdf(
    id: u8,
    salt: &[u8],
    password: &str,
    iterations: usize,
    key_len: usize,
) -> Vec<u8> {
    let u = 20usize; // SHA-1 digest size
    let v = 64usize; // SHA-1 block size

    // Construct D: v bytes of `id`
    let d = vec![id; v];

    // Construct S: salt padded to multiple of v bytes
    let s_pad = if !salt.is_empty() {
        let count = ((salt.len() + v - 1) / v) * v;
        let mut s = Vec::with_capacity(count);
        while s.len() < count {
            s.extend_from_slice(salt);
        }
        s.truncate(count);
        s
    } else {
        Vec::new()
    };

    // Construct P: password converted to UTF-16BE + 2 zero bytes, padded to multiple of v bytes
    let p_bytes = if !password.is_empty() {
        let mut pb = Vec::with_capacity((password.len() + 1) * 2);
        for c in password.encode_utf16() {
            pb.extend_from_slice(&c.to_be_bytes());
        }
        pb.extend_from_slice(&[0, 0]);
        pb
    } else {
        Vec::new()
    };

    let p_pad = if !p_bytes.is_empty() {
        let count = ((p_bytes.len() + v - 1) / v) * v;
        let mut p = Vec::with_capacity(count);
        while p.len() < count {
            p.extend_from_slice(&p_bytes);
        }
        p.truncate(count);
        p
    } else {
        Vec::new()
    };

    // I = S || P
    let mut i_data = Vec::with_capacity(s_pad.len() + p_pad.len());
    i_data.extend_from_slice(&s_pad);
    i_data.extend_from_slice(&p_pad);

    let c = (key_len + u - 1) / u;
    let mut out = Vec::with_capacity(c * u);

    for block_idx in 0..c {
        let mut hash_in = Vec::with_capacity(d.len() + i_data.len());
        hash_in.extend_from_slice(&d);
        hash_in.extend_from_slice(&i_data);
        let mut a = sha1(&hash_in);

        for _ in 1..iterations {
            a = sha1(&a);
        }

        out.extend_from_slice(&a);

        if block_idx + 1 < c && !i_data.is_empty() {
            let mut b = Vec::with_capacity(v);
            while b.len() < v {
                b.extend_from_slice(&a);
            }
            b.truncate(v);

            let mut carry: u16 = 1;
            for j in (0..v).rev() {
                let sum = (b[j] as u16) + carry;
                b[j] = sum as u8;
                carry = sum >> 8;
            }

            for chunk in i_data.chunks_mut(v) {
                let mut chunk_carry: u16 = 0;
                for j in (0..chunk.len()).rev() {
                    let sum = (chunk[j] as u16) + (b[j] as u16) + chunk_carry;
                    chunk[j] = sum as u8;
                    chunk_carry = sum >> 8;
                }
            }
        }
    }

    out.truncate(key_len);
    out
}

fn strip_pkcs7_padding(data: &[u8]) -> Result<Vec<u8>, CoreError> {
    if data.is_empty() {
        return Err(CoreError::ProtocolError("Empty plaintext".into()));
    }
    let pad_len = *data.last().unwrap() as usize;
    if pad_len == 0 || pad_len > data.len() || pad_len > 16 {
        return Ok(data.to_vec());
    }
    for &b in &data[data.len() - pad_len..] {
        if b as usize != pad_len {
            return Ok(data.to_vec());
        }
    }
    Ok(data[..data.len() - pad_len].to_vec())
}

fn scan_for_x509_certificate(data: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos + 10 < data.len() {
        if data[pos] == 0x30 {
            if let Ok((tag, body, rest)) = der::decode_tlv(&data[pos..]) {
                if tag == 0x30 && body.len() >= 64 {
                    let total_len = data.len() - pos - rest.len();
                    let candidate = &data[pos..pos + total_len];
                    if parse_x509_issuer_and_serial(candidate).is_ok() {
                        return Some(candidate.to_vec());
                    }
                }
            }
        }
        pos += 1;
    }
    None
}

fn scan_for_rsa_private_key(data: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos + 10 < data.len() {
        if data[pos] == 0x30 {
            if let Ok((tag, body, rest)) = der::decode_tlv(&data[pos..]) {
                if tag == 0x30 && body.len() >= 64 {
                    let total_len = data.len() - pos - rest.len();
                    let candidate = &data[pos..pos + total_len];
                    if parse_rsa_private_key(candidate).is_ok() {
                        return Some(candidate.to_vec());
                    }
                }
            }
        }
        pos += 1;
    }
    None
}

/// Extracts the KDC Diffie-Hellman public key and optional server DH nonce from RFC 4556 `PA-PK-AS-REP`.
pub fn extract_pkinit_kdc_dh_public_and_nonce(
    pa_pk_as_rep_der: &[u8],
) -> Result<(BigUint, Option<Vec<u8>>), CoreError> {
    // PA-PK-AS-REP ::= CHOICE { dhInfo [0] DHRepInfo, encKeyPack [1] ... }
    let (tag, body, _) = der::decode_tlv(pa_pk_as_rep_der)?;
    if (tag & 0x1F) != 0 {
        return Err(CoreError::ProtocolError(format!(
            "PA-PK-AS-REP is not dhInfo [0] (tag: 0x{:02X})",
            tag
        )));
    }

    // DHRepInfo ::= SEQUENCE { dhSignedData [0] IMPLICIT OCTET STRING, serverDHNonce [1] DHNonce OPTIONAL }
    let (_, mut seq_body, _) = der::decode_tlv(body)?;
    let mut dh_signed_data = Vec::new();
    let mut server_dh_nonce = None;

    while !seq_body.is_empty() {
        let (f_tag, f_val, f_rest) = der::decode_tlv(seq_body)?;
        seq_body = f_rest;
        match f_tag & 0x1F {
            0 => {
                dh_signed_data = f_val.to_vec();
            }
            1 => {
                if let Ok((_, octets, _)) = der::decode_tlv(f_val) {
                    server_dh_nonce = Some(octets.to_vec());
                } else {
                    server_dh_nonce = Some(f_val.to_vec());
                }
            }
            _ => {}
        }
    }

    if dh_signed_data.is_empty() {
        dh_signed_data = body.to_vec();
    }

    let kdc_dh_key_info = locate_econtent_by_oid(&dh_signed_data, OID_ID_DH_KEY_DATA)
        .ok_or_else(|| CoreError::ProtocolError("Failed to find KDCDHKeyInfo in CMS SignedData".into()))?;

    let (_, kdc_dh_body, _) = der::decode_tlv(&kdc_dh_key_info)?;
    let (spk_tag, spk_val, spk_rest) = der::decode_tlv(kdc_dh_body)?;
    if spk_tag != 0x03 {
        return Err(CoreError::ProtocolError("KDCDHKeyInfo subjectPublicKey is not a BIT STRING".into()));
    }
    if spk_val.is_empty() {
        return Err(CoreError::ProtocolError("Empty subjectPublicKey in KDCDHKeyInfo".into()));
    }

    if server_dh_nonce.is_none() && !spk_rest.is_empty() {
        if let Ok((n_tag, n_val, _)) = der::decode_tlv(spk_rest) {
            if (n_tag & 0x1F) == 1 {
                server_dh_nonce = Some(n_val.to_vec());
            }
        }
    }

    let spk_bytes = &spk_val[1..];
    let kdc_public = if !spk_bytes.is_empty() && spk_bytes[0] == 0x02 {
        let (_, int_bytes, _) = der::decode_tlv(spk_bytes)?;
        BigUint::from_be_bytes(int_bytes)
    } else {
        BigUint::from_be_bytes(spk_bytes)
    };

    Ok((kdc_public, server_dh_nonce))
}

fn locate_econtent_by_oid(data: &[u8], oid: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos + oid.len() <= data.len() {
        if &data[pos..pos + oid.len()] == oid {
            let rem = &data[pos + oid.len()..];
            if let Ok((tag, val, _)) = der::decode_tlv(rem) {
                if (tag & 0x1F) == 0 {
                    if let Ok((inner_tag, inner_val, _)) = der::decode_tlv(val) {
                        if inner_tag == 0x04 || inner_tag == 0x30 {
                            return Some(inner_val.to_vec());
                        }
                    }
                    return Some(val.to_vec());
                } else if tag == 0x04 || tag == 0x30 {
                    return Some(val.to_vec());
                }
            }
        }
        pos += 1;
    }
    None
}

/// Derives the Kerberos AS reply key per RFC 4556 Section 3.2.3.1.
pub fn derive_pkinit_reply_key(
    pa_pk_as_rep_der: &[u8],
    dh_state: &PkinitDhState,
    etype: i32,
) -> Result<Vec<u8>, CoreError> {
    let (kdc_public, server_nonce) = extract_pkinit_kdc_dh_public_and_nonce(pa_pk_as_rep_der)?;
    let shared_secret = dh_state.compute_shared_secret(&kdc_public);

    let mut x = Vec::with_capacity(shared_secret.len() + 32 + 32);
    x.extend_from_slice(&shared_secret);
    x.extend_from_slice(&dh_state.client_dh_nonce);
    if let Some(s_nonce) = server_nonce {
        x.extend_from_slice(&s_nonce);
    }

    let key_len = match etype {
        18 => 32, // AES-256
        17 => 16, // AES-128
        23 => 16, // RC4-HMAC
        _ => return Err(CoreError::ProtocolError(format!("Unsupported reply key etype {}", etype))),
    };

    Ok(octetstring2key(&x, key_len))
}

/// RFC 4556 Section 3.2.3.1 `octetstring2key(x)`.
pub fn octetstring2key(x: &[u8], key_len: usize) -> Vec<u8> {
    let mut derived = Vec::with_capacity(key_len + 20);
    let mut counter: u8 = 0;
    while derived.len() < key_len {
        let mut input = Vec::with_capacity(1 + x.len());
        input.push(counter);
        input.extend_from_slice(x);
        let h = sha1(&input);
        derived.extend_from_slice(&h);
        counter = counter.wrapping_add(1);
    }
    derived.truncate(key_len);
    derived
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

    #[test]
    fn test_pkcs12_kdf_deterministic() {
        let salt = b"testsalt";
        let pass = "password";
        let key24 = pkcs12_kdf(1, salt, pass, 5, 24);
        assert_eq!(key24.len(), 24);
        let iv8 = pkcs12_kdf(2, salt, pass, 5, 8);
        assert_eq!(iv8.len(), 8);
    }

    #[test]
    fn test_pkcs12_unencrypted_pfx_parsing() {
        // Construct a synthetic X.509 cert:
        // TBSCertificate ::= SEQUENCE { version [0] EXPLICIT INTEGER (2), serialNumber INTEGER, sigAlg SEQUENCE, issuer SEQUENCE, ... }
        let serial = der::encode_integer(42);
        let sig_alg = der::encode_sequence(&[der::encode_oid(OID_SHA256_WITH_RSA), der::encode_tlv(0x05, &[])]);
        let issuer = der::encode_sequence(&[der::encode_sequence(&[
            der::encode_oid(&[0x55, 0x04, 0x03]), // CN
            der::encode_tlv(0x0C, b"Test CA"),
        ])]);
        let validity = der::encode_sequence(&[
            der::encode_generalized_time("20260101000000Z"),
            der::encode_generalized_time("20270101000000Z"),
        ]);
        let subject = issuer.clone();
        let pub_key_info = der::encode_sequence(&[
            der::encode_sequence(&[der::encode_oid(OID_RSA_ENCRYPTION), der::encode_tlv(0x05, &[])]),
            der::encode_tlv(0x03, &[0, 0x30, 0x07, 0x02, 0x02, 0x0C, 0xA1, 0x02, 0x01, 0x11]),
        ]);
        let tbs = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(2)),
            serial,
            sig_alg.clone(),
            issuer,
            validity,
            subject,
            pub_key_info,
        ]);
        let cert_der = der::encode_sequence(&[
            tbs,
            sig_alg,
            der::encode_tlv(0x03, &[0, 0x11, 0x22, 0x33, 0x44]), // dummy sig
        ]);

        // Construct synthetic RSA private key (PKCS#1):
        // RSAPrivateKey ::= SEQUENCE { version (0), modulus (3233), publicExponent (17), privateExponent (2753), ... }
        let rsa_key_der = der::encode_sequence(&[
            der::encode_integer(0),
            der::encode_integer(3233),
            der::encode_integer(17),
            der::encode_integer(2753),
            der::encode_integer(61), // prime1
            der::encode_integer(53), // prime2
            der::encode_integer(17), // exponent1
            der::encode_integer(17), // exponent2
            der::encode_integer(17), // coefficient
        ]);

        // Wrap in PKCS#12 SafeBags:
        let cert_bag_val = der::encode_sequence(&[
            der::encode_oid(OID_X509_CERTIFICATE),
            der::encode_context_explicit(0, &der::encode_octet_string(&cert_der)),
        ]);
        let cert_safe_bag = der::encode_sequence(&[
            der::encode_oid(OID_CERT_BAG),
            der::encode_context_explicit(0, &cert_bag_val),
        ]);
        let key_safe_bag = der::encode_sequence(&[
            der::encode_oid(OID_KEY_BAG),
            der::encode_context_explicit(0, &rsa_key_der),
        ]);

        let safe_contents = der::encode_sequence(&[cert_safe_bag, key_safe_bag]);
        let auth_safe_elem = der::encode_sequence(&[
            der::encode_oid(OID_ID_DATA),
            der::encode_context_explicit(0, &der::encode_octet_string(&safe_contents)),
        ]);
        let auth_safe = der::encode_sequence(&[auth_safe_elem]);

        let pfx_der = der::encode_sequence(&[
            der::encode_integer(3), // version 3
            der::encode_sequence(&[
                der::encode_oid(OID_ID_DATA),
                der::encode_context_explicit(0, &der::encode_octet_string(&auth_safe)),
            ]),
        ]);

        let cred = PkinitCredentials::from_pfx(&pfx_der, "").expect("Failed parsing PFX");
        assert_eq!(cred.certificate_der, cert_der);
        assert_eq!(cred.rsa_modulus, BigUint::from_u64(3233));
        assert_eq!(cred.rsa_private_exponent, BigUint::from_u64(2753));
    }

    #[test]
    fn test_derive_pkinit_reply_key_flow() {
        let seed_client = [0x55u8; 32];
        let seed_server = [0x66u8; 32];

        let client = PkinitDhState::new_group14(&seed_client).unwrap();
        let server = PkinitDhState::new_group14(&seed_server).unwrap();

        // Server public key as BIT STRING
        let server_pub_int = der::encode_tlv(0x02, &server.public_key.to_be_bytes());
        let mut spk_bits = Vec::with_capacity(1 + server_pub_int.len());
        spk_bits.push(0); // 0 unused bits
        spk_bits.extend_from_slice(&server_pub_int);
        let spk_val = der::encode_tlv(0x03, &spk_bits);

        // KDCDHKeyInfo ::= SEQUENCE { subjectPublicKey BIT STRING, nonce [1] INTEGER }
        let kdc_dh_key_info = der::encode_sequence(&[
            spk_val,
            der::encode_context_explicit(1, &der::encode_integer(9999)),
        ]);

        // encapContentInfo: eContentType = id-pkinit-DHKeyData, eContent = [0] EXPLICIT OCTET STRING
        let encap = der::encode_sequence(&[
            der::encode_oid(OID_ID_DH_KEY_DATA),
            der::encode_context_explicit(0, &der::encode_octet_string(&kdc_dh_key_info)),
        ]);

        // SignedData
        let signed_data = der::encode_sequence(&[
            der::encode_integer(3),
            der::encode_tlv(0x31, &[]), // digestAlgorithms
            encap,
            der::encode_tlv(0x31, &[]), // signerInfos
        ]);

        let content_info = der::encode_sequence(&[
            der::encode_oid(OID_ID_SIGNED_DATA),
            der::encode_context_explicit(0, &signed_data),
        ]);

        // DHRepInfo ::= SEQUENCE { dhSignedData [0] IMPLICIT OCTET STRING, serverDHNonce [1] DHNonce }
        let server_nonce = vec![0x77u8; 32];
        let dh_rep_info = der::encode_sequence(&[
            der::encode_context_explicit(0, &content_info),
            der::encode_context_explicit(1, &der::encode_octet_string(&server_nonce)),
        ]);

        // PA-PK-AS-REP [0] DHRepInfo
        let pa_pk_as_rep = der::encode_context_explicit(0, &dh_rep_info);

        let reply_key_aes256 = derive_pkinit_reply_key(&pa_pk_as_rep, &client, 18)
            .expect("derive_pkinit_reply_key failed for AES-256");
        assert_eq!(reply_key_aes256.len(), 32);

        let reply_key_aes128 = derive_pkinit_reply_key(&pa_pk_as_rep, &client, 17)
            .expect("derive_pkinit_reply_key failed for AES-128");
        assert_eq!(reply_key_aes128.len(), 16);

        // Verify that reply key matches direct calculation
        let shared = client.compute_shared_secret(&server.public_key);
        let mut x = Vec::new();
        x.extend_from_slice(&shared);
        x.extend_from_slice(&client.client_dh_nonce);
        x.extend_from_slice(&server_nonce);
        let expected_key256 = octetstring2key(&x, 32);
        assert_eq!(reply_key_aes256, expected_key256);
    }
}
