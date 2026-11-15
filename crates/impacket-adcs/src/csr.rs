//! `csr`: ASN.1 DER PKCS#10 Certificate Signing Request (CSR) generator (RFC 2986).
//!
//! Generates pure-Rust PKCS#10 certificate signing requests with customizable
//! Subject Alternative Name (SAN: UPN or DNS) extensions for Active Directory
//! Certificate Services (ADCS) enrollment and testing.

use impacket_core::der;
use impacket_core::CoreError;
use impacket_crypto::{sha256, BigUint};

// OID constants
pub const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03]; // 2.5.4.3 (CN)
pub const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]; // 1.2.840.113549.1.1.1
pub const OID_SHA256_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]; // 1.2.840.113549.1.1.11
pub const OID_EXTENSION_REQUEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E]; // 1.2.840.113549.1.9.14
pub const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11]; // 2.5.29.17
pub const OID_NT_PRINCIPAL_NAME: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03]; // 1.3.6.1.4.1.311.20.2.3 (szOID_NT_PRINCIPAL_NAME / UPN)

/// Configuration options for generating a PKCS#10 Certificate Request.
#[derive(Debug, Clone)]
pub struct CsrOptions {
    pub common_name: String,
    pub san_upn: Option<String>,
    pub san_dns: Option<String>,
}

impl CsrOptions {
    pub fn new(common_name: impl Into<String>) -> Self {
        Self {
            common_name: common_name.into(),
            san_upn: None,
            san_dns: None,
        }
    }

    pub fn with_san_upn(mut self, upn: impl Into<String>) -> Self {
        self.san_upn = Some(upn.into());
        self
    }

    pub fn with_san_dns(mut self, dns: impl Into<String>) -> Self {
        self.san_dns = Some(dns.into());
        self
    }
}

/// Generates a DER-encoded Subject distinguished name (`CN=<CommonName>`).
fn encode_subject_name(common_name: &str) -> Vec<u8> {
    // AttributeTypeAndValue: SEQUENCE { OID(CN), UTF8String(common_name) }
    let attr_type = der::encode_oid(OID_COMMON_NAME);
    let attr_val = der::encode_tlv(0x0C, common_name.as_bytes()); // UTF8String
    let rdn_seq = der::encode_sequence(&[attr_type, attr_val]);
    // RelativeDistinguishedName: SET OF
    let rdn_set = der::encode_tlv(0x31, &rdn_seq);
    // Name: SEQUENCE OF
    der::encode_sequence(&[rdn_set])
}

/// Encodes Subject Alternative Name (SAN) extension value containing UPN and/or DNS.
fn encode_san_extension_value(upn: Option<&str>, dns: Option<&str>) -> Vec<u8> {
    let mut names = Vec::new();

    // 1. otherName with UPN: [0] IMPLICIT SEQUENCE { type-id OID(UPN), value [0] EXPLICIT UTF8String }
    if let Some(u) = upn {
        let oid = der::encode_oid(OID_NT_PRINCIPAL_NAME);
        let utf8 = der::encode_tlv(0x0C, u.as_bytes());
        let val_explicit = der::encode_context_explicit(0, &utf8);
        let other_name_seq = der::encode_sequence(&[oid, val_explicit]);
        let other_name = der::encode_context_explicit(0, &other_name_seq);
        names.push(other_name);
    }

    // 2. dNSName: [2] IMPLICIT IA5String
    if let Some(d) = dns {
        let dns_val = der::encode_tlv(0x82, d.as_bytes());
        names.push(dns_val);
    }

    // GeneralNames: SEQUENCE OF GeneralName
    der::encode_sequence(&names)
}

/// Builds the `attributes [0] IMPLICIT Attributes` block of CertificationRequestInfo.
fn encode_attributes_block(upn: Option<&str>, dns: Option<&str>) -> Vec<u8> {
    if upn.is_none() && dns.is_none() {
        return der::encode_context_explicit(0, &[]);
    }

    let san_bytes = encode_san_extension_value(upn, dns);
    let san_ext = der::encode_sequence(&[
        der::encode_oid(OID_SUBJECT_ALT_NAME),
        der::encode_octet_string(&san_bytes),
    ]);

    let extensions_seq = der::encode_sequence(&[san_ext]);
    let ext_req_attr = der::encode_sequence(&[
        der::encode_oid(OID_EXTENSION_REQUEST),
        der::encode_tlv(0x31, &extensions_seq), // SET OF
    ]);

    // [0] IMPLICIT Attributes
    der::encode_tlv(0xA0, &ext_req_attr)
}

/// Creates a PKCS#10 Certificate Signing Request (DER) with an RSA public key and dummy/self signature.
pub fn generate_pkcs10_csr(
    opts: &CsrOptions,
    rsa_modulus: &BigUint,
    rsa_public_exponent: &BigUint,
    rsa_private_exponent: Option<&BigUint>,
) -> Result<Vec<u8>, CoreError> {
    // 1. Version: 0
    let version = der::encode_integer(0);

    // 2. Subject: CN=...
    let subject = encode_subject_name(&opts.common_name);

    // 3. SubjectPublicKeyInfo
    let alg_id = der::encode_sequence(&[der::encode_oid(OID_RSA_ENCRYPTION), der::encode_tlv(0x05, &[])]); // NULL params
    let pk_der = der::encode_sequence(&[
        der::encode_tlv(0x02, &rsa_modulus.to_be_bytes()),
        der::encode_tlv(0x02, &rsa_public_exponent.to_be_bytes()),
    ]);
    let mut pk_bitstring = vec![0x00]; // 0 unused bits
    pk_bitstring.extend_from_slice(&pk_der);
    let pk_info = der::encode_sequence(&[alg_id, der::encode_tlv(0x03, &pk_bitstring)]);

    // 4. Attributes (SAN: UPN, DNS)
    let attributes = encode_attributes_block(opts.san_upn.as_deref(), opts.san_dns.as_deref());

    // CertificationRequestInfo
    let cri_seq = der::encode_sequence(&[version, subject, pk_info, attributes]);

    // Signature algorithm: sha256WithRSAEncryption
    let sig_alg = der::encode_sequence(&[der::encode_oid(OID_SHA256_WITH_RSA), der::encode_tlv(0x05, &[])]);

    // Generate Signature (PKCS#1 v1.5 RSA-SHA256 or placeholder)
    let sig_bytes = if let Some(d) = rsa_private_exponent {
        let digest = sha256(&cri_seq);
        // PKCS#1 v1.5 DigestInfo for SHA-256
        let digest_info = der::encode_sequence(&[
            der::encode_sequence(&[
                der::encode_oid(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]),
                der::encode_tlv(0x05, &[]),
            ]),
            der::encode_octet_string(&digest),
        ]);
        let k = 256; // 2048-bit key length in bytes
        if digest_info.len() + 11 > k {
            return Err(CoreError::ProtocolError("DigestInfo exceeds RSA modulus length".into()));
        }
        let mut em = vec![0xFF; k];
        em[0] = 0x00;
        em[1] = 0x01;
        let pad_len = k - 3 - digest_info.len();
        em[2..2 + pad_len].fill(0xFF);
        em[2 + pad_len] = 0x00;
        em[3 + pad_len..].copy_from_slice(&digest_info);

        let m = BigUint::from_be_bytes(&em);
        m.mod_pow(d, rsa_modulus).to_be_bytes()
    } else {
        vec![0x42; 256]
    };

    let mut sig_bitstring = vec![0x00];
    sig_bitstring.extend_from_slice(&sig_bytes);
    let sig_der = der::encode_tlv(0x03, &sig_bitstring);

    // Final CertificationRequest: SEQUENCE { cri, sig_alg, sig }
    Ok(der::encode_sequence(&[cri_seq, sig_alg, sig_der]))
}

/// Parses an RSA private key (PKCS#1 or PKCS#8 DER) and extracts modulus and private exponent.
pub fn parse_rsa_private_key(der_bytes: &[u8]) -> Result<(BigUint, BigUint), CoreError> {
    let (tag, mut body, _) = der::decode_tlv(der_bytes)?;
    if tag != 0x30 {
        return Err(CoreError::ProtocolError("Invalid private key: not a SEQUENCE".into()));
    }

    // Handle PKCS#8 wrapper: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING containing PKCS#1 }
    let (_, val0, rest) = der::decode_tlv(body)?;
    if val0.len() == 1 && val0[0] == 0 {
        let (t1, _, r1) = der::decode_tlv(rest)?;
        if t1 == 0x30 {
            let (t2, octets, _) = der::decode_tlv(r1)?;
            if t2 == 0x04 {
                let (_, inner_body, _) = der::decode_tlv(octets)?;
                body = inner_body;
            }
        }
    }

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
    fn test_encode_csr_with_upn_and_dns() {
        let opts = CsrOptions::new("Administrator")
            .with_san_upn("admin@corp.local")
            .with_san_dns("dc01.corp.local");

        let n = BigUint::from_be_bytes(&[0x01; 256]);
        let e = BigUint::from_be_bytes(&[0x01, 0x00, 0x01]);
        let csr = generate_pkcs10_csr(&opts, &n, &e, None).unwrap();

        assert!(!csr.is_empty());
        assert_eq!(csr[0], 0x30); // SEQUENCE
        let csr_str = String::from_utf8_lossy(&csr);
        assert!(csr_str.contains("admin@corp.local") || csr.windows(16).any(|w| w == b"admin@corp.local"));
    }
}
