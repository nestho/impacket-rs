//! RFC 6113: Kerberos Flexible Authentication Secure Tunneling (FAST) Implementation.
//!
//! Provides protocol structures, key derivation functions (`KRB-FX-CF2`, `PRF+`),
//! armor generation (`FX_FAST_ARMOR_AP_REQUEST`), armored `AS-REQ` construction, and
//! response unwrapping (`PA-FX-FAST`, `PA-FX-COOKIE`).

use impacket_core::der;
use impacket_core::CoreError;
use crate::ccache::CCache;
use crate::crypto;
use crate::{Krb5AsReq, TgtSession};

/// FAST Pre-Authentication Data Types (RFC 6113 §7.1).
pub const PA_FX_COOKIE: i32 = 133;
pub const PA_FX_FAST: i32 = 136;
pub const PA_FX_ERROR: i32 = 137;

/// FAST Armor Types (RFC 6113 §7.2).
pub const FX_FAST_ARMOR_AP_REQUEST: i32 = 1;

/// FAST Key Usage Numbers (RFC 6113 §7.3).
pub const KEY_USAGE_FAST_REQ_CHKSUM: i32 = 51;
pub const KEY_USAGE_FAST_ENC: i32 = 52;
pub const KEY_USAGE_FAST_REP: i32 = 53;
pub const KEY_USAGE_FAST_FINISHED: i32 = 54;
pub const KEY_USAGE_ENC_CHKSUM: i32 = 55;

/// Key Usage 7 for AP-REQ Authenticator.
const KU_AP_REQ_AUTHENTICATOR: i32 = 7;

// ============================================================================
// Cryptographic Primitives: RFC 3961 PRF, PRF+, and RFC 6113 KRB-FX-CF2
// ============================================================================

/// Computes the RFC 3961 PRF for AES-128:
/// `PRF(K, input) = AES-128-ECB(K_prf, SHA1(input)[..16])` where `K_prf = DK(K, "prf")`.
pub fn prf_aes128(key: &[u8; 16], input: &[u8]) -> [u8; 16] {
    let k_prf = crypto::derive_key_rfc3961_aes128(key, b"prf");
    let sha = impacket_crypto::sha1(input);
    let mut block = [0u8; 16];
    block.copy_from_slice(&sha[..16]);
    impacket_crypto::aes128::encrypt_block(&k_prf, &block)
}

/// Computes the RFC 3961 PRF for AES-256:
/// `PRF(K, input) = AES-256-ECB(K_prf, SHA1(input)[..16])` where `K_prf = DK(K, "prf")`.
pub fn prf_aes256(key: &[u8; 32], input: &[u8]) -> [u8; 16] {
    let k_prf = crypto::derive_key_rfc3961_aes256(key, b"prf");
    let sha = impacket_crypto::sha1(input);
    let mut block = [0u8; 16];
    block.copy_from_slice(&sha[..16]);
    impacket_crypto::aes256::encrypt_block(&k_prf, &block)
}

/// Variable-length PRF+ generator for AES-128 (RFC 6113 §5.1):
/// Iteratively concatenates `PRF(key, counter || pepper)` until `out_len` octets are produced.
pub fn prf_plus_aes128(key: &[u8; 16], pepper: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut counter = 1u8;
    while out.len() < out_len {
        let mut msg = Vec::with_capacity(1 + pepper.len());
        msg.push(counter);
        msg.extend_from_slice(pepper);
        let block = prf_aes128(key, &msg);
        out.extend_from_slice(&block);
        counter = counter.wrapping_add(1);
    }
    out.truncate(out_len);
    out
}

/// Variable-length PRF+ generator for AES-256 (RFC 6113 §5.1):
/// Iteratively concatenates `PRF(key, counter || pepper)` until `out_len` octets are produced.
pub fn prf_plus_aes256(key: &[u8; 32], pepper: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut counter = 1u8;
    while out.len() < out_len {
        let mut msg = Vec::with_capacity(1 + pepper.len());
        msg.push(counter);
        msg.extend_from_slice(pepper);
        let block = prf_aes256(key, &msg);
        out.extend_from_slice(&block);
        counter = counter.wrapping_add(1);
    }
    out.truncate(out_len);
    out
}

/// RFC 6113 §5.1 `KRB-FX-CF2` key combining function for AES-256:
/// `CF2(K1, K2, pepper1, pepper2) = PRF+(K1, pepper1) XOR PRF+(K2, pepper2)`
pub fn krb_fx_cf2_aes256(
    k1: &[u8; 32],
    k2: &[u8; 32],
    pepper1: &[u8],
    pepper2: &[u8],
) -> [u8; 32] {
    let p1 = prf_plus_aes256(k1, pepper1, 32);
    let p2 = prf_plus_aes256(k2, pepper2, 32);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = p1[i] ^ p2[i];
    }
    out
}

/// RFC 6113 §5.1 `KRB-FX-CF2` key combining function for AES-128:
/// `CF2(K1, K2, pepper1, pepper2) = PRF+(K1, pepper1) XOR PRF+(K2, pepper2)`
pub fn krb_fx_cf2_aes128(
    k1: &[u8; 16],
    k2: &[u8; 16],
    pepper1: &[u8],
    pepper2: &[u8],
) -> [u8; 16] {
    let p1 = prf_plus_aes128(k1, pepper1, 16);
    let p2 = prf_plus_aes128(k2, pepper2, 16);
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = p1[i] ^ p2[i];
    }
    out
}

// ============================================================================
// Data Structures: FastArmorConfig, ArmoredReq, ArmoredRep
// ============================================================================

/// Configuration for FAST armoring an AS-REQ exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastArmorConfig {
    /// The DER-encoded armor ticket (`[APPLICATION 1]`).
    pub armor_ticket: Vec<u8>,
    /// The session key associated with the armor ticket.
    pub armor_key: Vec<u8>,
    /// The encryption type of the armor ticket session key (18=AES256, 17=AES128, 23=RC4).
    pub armor_etype: i32,
    /// Realm of the armor principal.
    pub armor_realm: String,
    /// Username or service name of the armor principal.
    pub armor_client_name: String,
    /// Optional explicitly defined subkey to inject into Authenticator.
    pub subkey: Option<Vec<u8>>,
}

impl FastArmorConfig {
    /// Creates a new FAST armor configuration from raw components.
    pub fn new(
        armor_ticket: Vec<u8>,
        armor_key: Vec<u8>,
        armor_etype: i32,
        armor_realm: impl Into<String>,
        armor_client_name: impl Into<String>,
    ) -> Self {
        Self {
            armor_ticket,
            armor_key,
            armor_etype,
            armor_realm: armor_realm.into().to_uppercase(),
            armor_client_name: armor_client_name.into(),
            subkey: None,
        }
    }

    /// Loads armor configuration from an unmarshaled `CCache`.
    pub fn from_ccache(ccache: &CCache) -> Result<Self, CoreError> {
        let cred = ccache
            .find_tgt_credential()
            .ok_or_else(|| CoreError::ProtocolError("CCache does not contain a valid TGT credential".into()))?;

        let armor_client_name = cred
            .client
            .components
            .first()
            .cloned()
            .unwrap_or_else(|| "armor$".to_string());

        Ok(Self {
            armor_ticket: cred.ticket.clone(),
            armor_key: cred.key.keyvalue.clone(),
            armor_etype: cred.key.keytype as i32,
            armor_realm: cred.client.realm.to_uppercase(),
            armor_client_name,
            subkey: None,
        })
    }

    /// Loads armor configuration from raw `.kirbi` bytes.
    pub fn from_kirbi_bytes(kirbi_bytes: &[u8]) -> Result<Self, CoreError> {
        let ccache = CCache::from_kirbi(kirbi_bytes)?;
        Self::from_ccache(&ccache)
    }

    /// Loads armor configuration from a `TgtSession`.
    pub fn from_tgt_session(tgt: &TgtSession, raw_key: Option<&[u8]>) -> Result<Self, CoreError> {
        let armor_key = if let Some(k) = raw_key {
            k.to_vec()
        } else if !tgt.session_key_bytes.is_empty() {
            tgt.session_key_bytes.clone()
        } else {
            tgt.session_key.to_vec()
        };

        Ok(Self {
            armor_ticket: tgt.tgt_ticket.clone(),
            armor_key,
            armor_etype: tgt.session_key_etype,
            armor_realm: tgt.realm.to_uppercase(),
            armor_client_name: tgt.username.clone(),
            subkey: None,
        })
    }
}

/// RFC 6113 `KrbFastArmor` structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrbFastArmor {
    pub armor_type: i32,
    pub armor_value: Vec<u8>,
}

impl KrbFastArmor {
    pub fn to_der(&self) -> Vec<u8> {
        der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(self.armor_type as i64)),
            der::encode_context_explicit(1, &der::encode_octet_string(&self.armor_value)),
        ])
    }
}

/// RFC 6113 `EncKrbFastReq` decrypted structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncKrbFastReq {
    pub fast_options: u32,
    pub padata: Vec<(i32, Vec<u8>)>,
    pub req_body: Vec<u8>,
}

impl EncKrbFastReq {
    pub fn to_der(&self) -> Vec<u8> {
        let fast_options_der = der::encode_bit_string_u32(self.fast_options);
        let mut pa_seqs = Vec::with_capacity(self.padata.len());
        for (patype, paval) in &self.padata {
            pa_seqs.push(der::encode_sequence(&[
                der::encode_context_explicit(1, &der::encode_integer(*patype as i64)),
                der::encode_context_explicit(2, &der::encode_octet_string(paval)),
            ]));
        }
        let padata_der = der::encode_sequence(&pa_seqs);

        der::encode_sequence(&[
            der::encode_context_explicit(0, &fast_options_der),
            der::encode_context_explicit(1, &padata_der),
            der::encode_context_explicit(2, &self.req_body),
        ])
    }

    pub fn parse(der_bytes: &[u8]) -> Result<Self, CoreError> {
        let (tag, val, _) = der::decode_tlv(der_bytes)?;
        if tag != 0x30 {
            return Err(CoreError::ProtocolError("Invalid EncKrbFastReq SEQUENCE tag".into()));
        }

        let mut fast_options = 0u32;
        let mut padata = Vec::new();
        let mut req_body = Vec::new();

        let mut rem = val;
        while !rem.is_empty() {
            let (tag, elem_val, next) = der::decode_tlv(rem)?;
            rem = next;
            match tag & 0x1F {
                0 => {
                    // [0] fast-options FastOptions
                    let (_, bs, _) = der::decode_tlv(elem_val)?;
                    if bs.len() >= 2 {
                        let mut num = 0u32;
                        for b in &bs[1..] {
                            num = (num << 8) | (*b as u32);
                        }
                        fast_options = num;
                    }
                }
                1 => {
                    // [1] padata SEQUENCE OF PA-DATA
                    let (_, p_seq, _) = der::decode_tlv(elem_val)?;
                    let mut p_rem = p_seq;
                    while !p_rem.is_empty() {
                        let (_, pa_elem, pa_next) = der::decode_tlv(p_rem)?;
                        p_rem = pa_next;
                        let mut patype = 0i32;
                        let mut paval = Vec::new();
                        let mut pe_rem = pa_elem;
                        while !pe_rem.is_empty() {
                            let (ptag, pval, pnext) = der::decode_tlv(pe_rem)?;
                            pe_rem = pnext;
                            match ptag & 0x1F {
                                1 => patype = der::decode_integer(pval)? as i32,
                                2 => {
                                    let (_, octets, _) = der::decode_tlv(pval)?;
                                    paval = octets.to_vec();
                                }
                                _ => {}
                            }
                        }
                        padata.push((patype, paval));
                    }
                }
                2 => {
                    // [2] req-body KdcReqBody
                    req_body = elem_val.to_vec();
                }
                _ => {}
            }
        }

        Ok(Self {
            fast_options,
            padata,
            req_body,
        })
    }
}

/// RFC 6113 `EncKrbFastRep` decrypted reply structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncKrbFastRep {
    pub padata: Vec<(i32, Vec<u8>)>,
    pub strengthen_key: Option<(i32, Vec<u8>)>,
    pub nonce: u32,
}

impl EncKrbFastRep {
    pub fn parse(der_bytes: &[u8]) -> Result<Self, CoreError> {
        let (tag, val, _) = der::decode_tlv(der_bytes)?;
        if tag != 0x30 {
            return Err(CoreError::ProtocolError("Invalid EncKrbFastRep SEQUENCE tag".into()));
        }

        let mut padata = Vec::new();
        let mut strengthen_key = None;
        let mut nonce = 0u32;

        let mut rem = val;
        while !rem.is_empty() {
            let (tag, elem_val, next) = der::decode_tlv(rem)?;
            rem = next;
            match tag & 0x1F {
                0 => {
                    // [0] padata SEQUENCE OF PA-DATA
                    let (_, p_seq, _) = der::decode_tlv(elem_val)?;
                    let mut p_rem = p_seq;
                    while !p_rem.is_empty() {
                        let (_, pa_elem, pa_next) = der::decode_tlv(p_rem)?;
                        p_rem = pa_next;
                        let mut patype = 0i32;
                        let mut paval = Vec::new();
                        let mut pe_rem = pa_elem;
                        while !pe_rem.is_empty() {
                            let (ptag, pval, pnext) = der::decode_tlv(pe_rem)?;
                            pe_rem = pnext;
                            match ptag & 0x1F {
                                1 => patype = der::decode_integer(pval)? as i32,
                                2 => {
                                    let (_, octets, _) = der::decode_tlv(pval)?;
                                    paval = octets.to_vec();
                                }
                                _ => {}
                            }
                        }
                        padata.push((patype, paval));
                    }
                }
                1 => {
                    // [1] strengthen-key EncryptionKey OPTIONAL
                    let (_, k_seq, _) = der::decode_tlv(elem_val)?;
                    let mut k_rem = k_seq;
                    let mut k_etype = 0i32;
                    let mut k_val = Vec::new();
                    while !k_rem.is_empty() {
                        let (ktag, kval, knext) = der::decode_tlv(k_rem)?;
                        k_rem = knext;
                        match ktag & 0x1F {
                            0 => k_etype = der::decode_integer(kval)? as i32,
                            1 => {
                                let (_, octets, _) = der::decode_tlv(kval)?;
                                k_val = octets.to_vec();
                            }
                            _ => {}
                        }
                    }
                    if !k_val.is_empty() {
                        strengthen_key = Some((k_etype, k_val));
                    }
                }
                3 => {
                    // [3] nonce UInt32
                    nonce = der::decode_integer(elem_val)? as u32;
                }
                _ => {}
            }
        }

        Ok(Self {
            padata,
            strengthen_key,
            nonce,
        })
    }
}

// ============================================================================
// Core FAST Wire Construction & Response Processing
// ============================================================================

/// Builds a complete RFC 6113 FAST-Armored `AS-REQ` (Application 10) packet.
///
/// Encapsulates inner pre-authentication and `KdcReqBody` inside `EncKrbFastReq`, calculates
/// the keyed `req-checksum` over the inner request body with usage 51, encrypts `EncKrbFastReq`
/// with usage 52 under the armor key, and wraps into `PA-FX-FAST` (136).
///
/// Returns `(armored_as_req_der, effective_armor_key)`.
pub fn build_fast_armored_as_req(
    config: &FastArmorConfig,
    inner_as_req: &Krb5AsReq,
    fast_cookie: Option<&[u8]>,
    now_unix: i64,
) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
    // 1. Determine effective armor key and build AP-REQ Authenticator
    let (effective_armor_key, subkey_opt) = if let Some(ref sk) = config.subkey {
        (sk.clone(), Some(sk.clone()))
    } else {
        (config.armor_key.clone(), None)
    };

    // Authenticator cname: armor principal
    let cname_der = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(1)),
        der::encode_context_explicit(
            1,
            &der::encode_sequence(&[der::encode_general_string(&config.armor_client_name)]),
        ),
    ]);
    let ctime_der = der::encode_generalized_time(&crypto::unix_to_kerberos_time(now_unix));

    let mut auth_fields = vec![
        der::encode_context_explicit(0, &der::encode_integer(5)),
        der::encode_context_explicit(1, &der::encode_general_string(&config.armor_realm)),
        der::encode_context_explicit(2, &cname_der),
        der::encode_context_explicit(4, &der::encode_integer(0)), // cusec
        der::encode_context_explicit(5, &ctime_der),
    ];

    if let Some(ref sk) = subkey_opt {
        let subkey_seq = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(config.armor_etype as i64)),
            der::encode_context_explicit(1, &der::encode_octet_string(sk)),
        ]);
        auth_fields.push(der::encode_context_explicit(6, &subkey_seq));
    }

    let auth_seq = der::encode_sequence(&auth_fields);
    let authenticator_der = der::encode_application(2, &auth_seq);

    // Encrypt Authenticator under armor session key with KU_AP_REQ_AUTHENTICATOR (7)
    let enc_authenticator = if config.armor_etype == 18 {
        let key32: [u8; 32] = config.armor_key.as_slice().try_into().map_err(|_| {
            CoreError::ProtocolError("Armor AES-256 session key must be exactly 32 bytes".into())
        })?;
        let conf16 = [0x42u8; 16];
        let cipher = crypto::aes256_cts_hmac_sha1_96_encrypt(&key32, KU_AP_REQ_AUTHENTICATOR, &authenticator_der, &conf16)?;
        der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(18)),
            der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
        ])
    } else if config.armor_etype == 17 {
        let key16: [u8; 16] = config.armor_key.as_slice().try_into().map_err(|_| {
            CoreError::ProtocolError("Armor AES-128 session key must be exactly 16 bytes".into())
        })?;
        let conf16 = [0x42u8; 16];
        let cipher = crypto::aes128_cts_hmac_sha1_96_encrypt(&key16, KU_AP_REQ_AUTHENTICATOR, &authenticator_der, &conf16)?;
        der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(17)),
            der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
        ])
    } else if config.armor_etype == 23 {
        let key16: [u8; 16] = config.armor_key.as_slice().try_into().map_err(|_| {
            CoreError::ProtocolError("Armor RC4 session key must be exactly 16 bytes".into())
        })?;
        let conf8 = [0x42u8; 8];
        let cipher = crypto::rc4_hmac_encrypt(&key16, KU_AP_REQ_AUTHENTICATOR, &authenticator_der, &conf8);
        der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(23)),
            der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
        ])
    } else {
        return Err(CoreError::ProtocolError(format!(
            "Unsupported armor encryption type: {}",
            config.armor_etype
        )));
    };

    // AP-REQ ::= [APPLICATION 14] SEQUENCE
    let ap_options = der::encode_bit_string_u32(0);
    let ap_req_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(5)),
        der::encode_context_explicit(1, &der::encode_integer(14)),
        der::encode_context_explicit(2, &ap_options),
        der::encode_context_explicit(3, &config.armor_ticket),
        der::encode_context_explicit(4, &enc_authenticator),
    ]);
    let ap_req_der = der::encode_application(14, &ap_req_seq);

    let krb_fast_armor = KrbFastArmor {
        armor_type: FX_FAST_ARMOR_AP_REQUEST,
        armor_value: ap_req_der,
    };

    // 2. Assemble inner EncKrbFastReq
    let inner_req_body = inner_as_req.encode_req_body();
    let mut inner_padata = Vec::new();
    if let Some(ref pa_ts) = inner_as_req.pa_enc_timestamp {
        // Parse inner padata elements from the timestamp der
        let (_, ts_body, _) = der::decode_tlv(pa_ts)?;
        let mut ts_rem = ts_body;
        let mut patype = 2i32;
        let mut paval = Vec::new();
        while !ts_rem.is_empty() {
            let (ptag, pval, pnext) = der::decode_tlv(ts_rem)?;
            ts_rem = pnext;
            match ptag & 0x1F {
                1 => patype = der::decode_integer(pval)? as i32,
                2 => {
                    let (_, octets, _) = der::decode_tlv(pval)?;
                    paval = octets.to_vec();
                }
                _ => {}
            }
        }
        inner_padata.push((patype, paval));
    }

    // Always include PA-PAC-REQUEST (128)
    let bool_val = der::encode_tlv(0x01, &[if inner_as_req.include_pac { 0xFF } else { 0x00 }]);
    let pac_req_seq = der::encode_sequence(&[der::encode_context_explicit(0, &bool_val)]);
    inner_padata.push((128, pac_req_seq));

    let enc_krb_fast_req = EncKrbFastReq {
        fast_options: 0,
        padata: inner_padata,
        req_body: inner_req_body.clone(),
    };
    let enc_krb_fast_req_der = enc_krb_fast_req.to_der();

    // 3. Calculate req-checksum over inner KdcReqBody with KEY_USAGE_FAST_REQ_CHKSUM (51)
    let (cksumtype, checksum_bytes) = if config.armor_etype == 18 {
        let key32: [u8; 32] = effective_armor_key.as_slice().try_into().map_err(|_| {
            CoreError::ProtocolError("Armor AES-256 key must be 32 bytes".into())
        })?;
        let ck = crypto::aes256_cts_hmac_sha1_96_checksum(&key32, KEY_USAGE_FAST_REQ_CHKSUM, &inner_req_body);
        (16i32, ck.to_vec())
    } else if config.armor_etype == 17 {
        let key16: [u8; 16] = effective_armor_key.as_slice().try_into().map_err(|_| {
            CoreError::ProtocolError("Armor AES-128 key must be 16 bytes".into())
        })?;
        let ck = crypto::aes128_cts_hmac_sha1_96_checksum(&key16, KEY_USAGE_FAST_REQ_CHKSUM, &inner_req_body);
        (15i32, ck.to_vec())
    } else if config.armor_etype == 23 {
        let key16: [u8; 16] = effective_armor_key.as_slice().try_into().map_err(|_| {
            CoreError::ProtocolError("Armor RC4 key must be 16 bytes".into())
        })?;
        let ck = crypto::rc4_hmac_checksum(&key16, KEY_USAGE_FAST_REQ_CHKSUM, &inner_req_body);
        (-138i32, ck.to_vec())
    } else {
        return Err(CoreError::ProtocolError("Unsupported armor etype for checksum".into()));
    };

    let req_checksum_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(cksumtype as i64)),
        der::encode_context_explicit(1, &der::encode_octet_string(&checksum_bytes)),
    ]);

    // 4. Encrypt EncKrbFastReq with KEY_USAGE_FAST_ENC (52)
    let enc_fast_req = if config.armor_etype == 18 {
        let key32: [u8; 32] = effective_armor_key.as_slice().try_into().map_err(|_| {
            CoreError::ProtocolError("Armor AES-256 key must be 32 bytes".into())
        })?;
        let conf16 = [0x2Au8; 16];
        let cipher = crypto::aes256_cts_hmac_sha1_96_encrypt(&key32, KEY_USAGE_FAST_ENC, &enc_krb_fast_req_der, &conf16)?;
        der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(18)),
            der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
        ])
    } else if config.armor_etype == 17 {
        let key16: [u8; 16] = effective_armor_key.as_slice().try_into().map_err(|_| {
            CoreError::ProtocolError("Armor AES-128 key must be 16 bytes".into())
        })?;
        let conf16 = [0x2Au8; 16];
        let cipher = crypto::aes128_cts_hmac_sha1_96_encrypt(&key16, KEY_USAGE_FAST_ENC, &enc_krb_fast_req_der, &conf16)?;
        der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(17)),
            der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
        ])
    } else if config.armor_etype == 23 {
        let key16: [u8; 16] = effective_armor_key.as_slice().try_into().map_err(|_| {
            CoreError::ProtocolError("Armor RC4 key must be 16 bytes".into())
        })?;
        let conf8 = [0x2Au8; 8];
        let cipher = crypto::rc4_hmac_encrypt(&key16, KEY_USAGE_FAST_ENC, &enc_krb_fast_req_der, &conf8);
        der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(23)),
            der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
        ])
    } else {
        return Err(CoreError::ProtocolError("Unsupported armor etype for enc_fast_req".into()));
    };

    // 5. Build KrbFastArmoredReq and PA-FX-FAST-REQUEST
    let krb_fast_armored_req_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &krb_fast_armor.to_der()),
        der::encode_context_explicit(1, &req_checksum_seq),
        der::encode_context_explicit(2, &enc_fast_req),
    ]);
    // PA-FX-FAST-REQUEST ::= [0] KrbFastArmoredReq
    let pa_fx_fast_req_der = der::encode_context_explicit(0, &krb_fast_armored_req_seq);

    let pa_fx_fast = der::encode_sequence(&[
        der::encode_context_explicit(1, &der::encode_integer(PA_FX_FAST as i64)),
        der::encode_context_explicit(2, &der::encode_octet_string(&pa_fx_fast_req_der)),
    ]);

    let mut outer_padata_els = vec![pa_fx_fast];
    if let Some(cookie) = fast_cookie {
        outer_padata_els.push(der::encode_sequence(&[
            der::encode_context_explicit(1, &der::encode_integer(PA_FX_COOKIE as i64)),
            der::encode_context_explicit(2, &der::encode_octet_string(cookie)),
        ]));
    }
    let outer_padata_seq = der::encode_sequence(&outer_padata_els);

    // 6. Build outer AS-REQ with Anonymous or Client Principal
    let outer_kdc_options = der::encode_bit_string_u32(0x4081_0010);
    // Wellknown Anonymous principal: NT-WELLKNOWN (11), ["WELLKNOWN", "ANONYMOUS"]
    let anon_cname = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(11)),
        der::encode_context_explicit(
            1,
            &der::encode_sequence(&[
                der::encode_general_string("WELLKNOWN"),
                der::encode_general_string("ANONYMOUS"),
            ]),
        ),
    ]);
    let outer_realm = der::encode_general_string(&inner_as_req.realm);
    let outer_sname = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(2)),
        der::encode_context_explicit(
            1,
            &der::encode_sequence(&[
                der::encode_general_string("krbtgt"),
                der::encode_general_string(&inner_as_req.realm),
            ]),
        ),
    ]);
    let outer_till = der::encode_generalized_time("20370913024805Z");
    let outer_rtime = der::encode_generalized_time("20370913024805Z");
    let outer_nonce = der::encode_integer(inner_as_req.nonce as i64);

    let etype_els: Vec<Vec<u8>> = inner_as_req
        .etypes
        .iter()
        .map(|&e| der::encode_integer(e as i64))
        .collect();
    let etype_seq = der::encode_sequence(&etype_els);

    let outer_req_body = der::encode_sequence(&[
        der::encode_context_explicit(0, &outer_kdc_options),
        der::encode_context_explicit(1, &anon_cname),
        der::encode_context_explicit(2, &outer_realm),
        der::encode_context_explicit(3, &outer_sname),
        der::encode_context_explicit(5, &outer_till),
        der::encode_context_explicit(6, &outer_rtime),
        der::encode_context_explicit(7, &outer_nonce),
        der::encode_context_explicit(8, &etype_seq),
    ]);

    let outer_kdc_req = der::encode_sequence(&[
        der::encode_context_explicit(1, &der::encode_integer(5)),
        der::encode_context_explicit(2, &der::encode_integer(10)), // AS-REQ
        der::encode_context_explicit(3, &outer_padata_seq),
        der::encode_context_explicit(4, &outer_req_body),
    ]);

    let app10 = der::encode_application(10, &outer_kdc_req);
    let mut tcp_pdu = Vec::with_capacity(4 + app10.len());
    tcp_pdu.extend_from_slice(&(app10.len() as u32).to_be_bytes());
    tcp_pdu.extend_from_slice(&app10);

    Ok((tcp_pdu, effective_armor_key))
}

/// Decrypts a `PA-FX-FAST` reply from an `AS-REP` or `KRB-ERROR` using the effective armor key.
pub fn decrypt_fast_rep(
    pa_fx_fast_val: &[u8],
    effective_armor_key: &[u8],
    armor_etype: i32,
) -> Result<EncKrbFastRep, CoreError> {
    // PA-FX-FAST-REPLY ::= CHOICE { [0] KrbFastArmoredRep }
    let (choice_tag, choice_val, _) = der::decode_tlv(pa_fx_fast_val)?;
    if (choice_tag & 0x1F) != 0 {
        return Err(CoreError::ProtocolError("Invalid PA-FX-FAST-REPLY choice tag".into()));
    }

    // KrbFastArmoredRep ::= SEQUENCE { enc-fast-rep [0] EncryptedData }
    let (_, rep_body, _) = der::decode_tlv(choice_val)?;
    let mut enc_etype = 0i32;
    let mut cipher = Vec::new();

    let mut rem = rep_body;
    while !rem.is_empty() {
        let (tag, elem_val, next) = der::decode_tlv(rem)?;
        rem = next;
        if (tag & 0x1F) == 0 {
            // [0] enc-fast-rep EncryptedData
            let (_, enc_seq, _) = der::decode_tlv(elem_val)?;
            let mut enc_rem = enc_seq;
            while !enc_rem.is_empty() {
                let (etag, eval, enext) = der::decode_tlv(enc_rem)?;
                enc_rem = enext;
                match etag & 0x1F {
                    0 => enc_etype = der::decode_integer(eval)? as i32,
                    2 => {
                        let (_, octets, _) = der::decode_tlv(eval)?;
                        cipher = octets.to_vec();
                    }
                    _ => {}
                }
            }
        }
    }

    if cipher.is_empty() {
        return Err(CoreError::ProtocolError("Empty enc-fast-rep cipher in FAST reply".into()));
    }

    // Decrypt enc-fast-rep with KEY_USAGE_FAST_REP (53)
    let plaintext = if enc_etype == 18 || armor_etype == 18 {
        let key32: [u8; 32] = effective_armor_key.try_into().map_err(|_| {
            CoreError::ProtocolError("Effective armor AES-256 key must be 32 bytes".into())
        })?;
        crypto::aes256_cts_hmac_sha1_96_decrypt(&key32, KEY_USAGE_FAST_REP, &cipher)?
    } else if enc_etype == 17 || armor_etype == 17 {
        let key16: [u8; 16] = effective_armor_key.try_into().map_err(|_| {
            CoreError::ProtocolError("Effective armor AES-128 key must be 16 bytes".into())
        })?;
        crypto::aes128_cts_hmac_sha1_96_decrypt(&key16, KEY_USAGE_FAST_REP, &cipher)?
    } else if enc_etype == 23 || armor_etype == 23 {
        let key16: [u8; 16] = effective_armor_key.try_into().map_err(|_| {
            CoreError::ProtocolError("Effective armor RC4 key must be 16 bytes".into())
        })?;
        crypto::rc4_hmac_decrypt(&key16, KEY_USAGE_FAST_REP, &cipher)?
    } else {
        return Err(CoreError::ProtocolError(format!(
            "Unsupported FAST reply encryption type: {}",
            enc_etype
        )));
    };

    EncKrbFastRep::parse(&plaintext)
}

/// Scans raw KDC response bytes for a `PA-FX-COOKIE` (133).
pub fn extract_fast_cookie(raw_response: &[u8]) -> Option<Vec<u8>> {
    let raw = if raw_response.len() > 4 && u32::from_be_bytes([raw_response[0], raw_response[1], raw_response[2], raw_response[3]]) as usize == raw_response.len() - 4 {
        &raw_response[4..]
    } else {
        raw_response
    };

    let Ok((_, app_body, _)) = der::decode_tlv(raw) else {
        return None;
    };
    let inner_seq = if let Ok((0x30, s_body, _)) = der::decode_tlv(app_body) {
        s_body
    } else {
        app_body
    };

    let mut rem = inner_seq;
    while !rem.is_empty() {
        let Ok((tag, val, next)) = der::decode_tlv(rem) else {
            break;
        };
        rem = next;
        // Check for padata sequence under [3] or [12] (e-data)
        if (tag & 0x1F) == 3 || (tag & 0x1F) == 12 {
            let mut pa_seq = val;
            if let Ok((0x04, octets, _)) = der::decode_tlv(val) {
                pa_seq = octets;
            }
            if let Ok((0x30, inner, _)) = der::decode_tlv(pa_seq) {
                pa_seq = inner;
            }
            while !pa_seq.is_empty() {
                let Ok((_, elem, pnext)) = der::decode_tlv(pa_seq) else {
                    break;
                };
                pa_seq = pnext;
                let mut p_rem = elem;
                let mut is_cookie = false;
                let mut cookie_bytes = None;
                while !p_rem.is_empty() {
                    let Ok((ptag, pval, penext)) = der::decode_tlv(p_rem) else {
                        break;
                    };
                    p_rem = penext;
                    if (ptag & 0x1F) == 1 {
                        if let Ok(num) = der::decode_integer(pval) {
                            if num == PA_FX_COOKIE as i64 {
                                is_cookie = true;
                            }
                        }
                    } else if (ptag & 0x1F) == 2 {
                        if let Ok((_, octets, _)) = der::decode_tlv(pval) {
                            cookie_bytes = Some(octets.to_vec());
                        }
                    }
                }
                if is_cookie && cookie_bytes.is_some() {
                    return cookie_bytes;
                }
            }
        }
    }
    None
}

/// Scans raw KDC response bytes for a `PA-FX-FAST` reply (136).
pub fn extract_pa_fx_fast_reply(raw_response: &[u8]) -> Option<Vec<u8>> {
    let raw = if raw_response.len() > 4 && u32::from_be_bytes([raw_response[0], raw_response[1], raw_response[2], raw_response[3]]) as usize == raw_response.len() - 4 {
        &raw_response[4..]
    } else {
        raw_response
    };

    let Ok((_, app_body, _)) = der::decode_tlv(raw) else {
        return None;
    };
    let inner_seq = if let Ok((0x30, s_body, _)) = der::decode_tlv(app_body) {
        s_body
    } else {
        app_body
    };

    let mut rem = inner_seq;
    while !rem.is_empty() {
        let Ok((tag, val, next)) = der::decode_tlv(rem) else {
            break;
        };
        rem = next;
        if (tag & 0x1F) == 3 || (tag & 0x1F) == 12 {
            let mut pa_seq = val;
            if let Ok((0x04, octets, _)) = der::decode_tlv(val) {
                pa_seq = octets;
            }
            if let Ok((0x30, inner, _)) = der::decode_tlv(pa_seq) {
                pa_seq = inner;
            }
            while !pa_seq.is_empty() {
                let Ok((_, elem, pnext)) = der::decode_tlv(pa_seq) else {
                    break;
                };
                pa_seq = pnext;
                let mut p_rem = elem;
                let mut is_fast = false;
                let mut fast_bytes = None;
                while !p_rem.is_empty() {
                    let Ok((ptag, pval, penext)) = der::decode_tlv(p_rem) else {
                        break;
                    };
                    p_rem = penext;
                    if (ptag & 0x1F) == 1 {
                        if let Ok(num) = der::decode_integer(pval) {
                            if num == PA_FX_FAST as i64 {
                                is_fast = true;
                            }
                        }
                    } else if (ptag & 0x1F) == 2 {
                        if let Ok((_, octets, _)) = der::decode_tlv(pval) {
                            fast_bytes = Some(octets.to_vec());
                        }
                    }
                }
                if is_fast && fast_bytes.is_some() {
                    return fast_bytes;
                }
            }
        }
    }
    None
}

/// Connects to a live KDC (TCP/88) and executes an RFC 6113 FAST-Armored `AS-REQ` exchange.
pub fn send_fast_armored_as_req_live(
    kdc_host: &str,
    kdc_port: u16,
    config: &FastArmorConfig,
    inner_req: &Krb5AsReq,
    fast_cookie: Option<&[u8]>,
    timeout: std::time::Duration,
) -> Result<(crate::KdcAsResponse, Option<EncKrbFastRep>), CoreError> {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let (tcp_pdu, effective_armor_key) = build_fast_armored_as_req(config, inner_req, fast_cookie, now)?;

    let addr_str = format!("{}:{}", kdc_host, kdc_port);
    let sock_addr: SocketAddr = addr_str
        .to_socket_addrs()
        .map_err(|e| CoreError::ProtocolError(format!("Failed resolving KDC {}: {}", addr_str, e)))?
        .next()
        .ok_or_else(|| CoreError::ProtocolError(format!("No address found for KDC {}", addr_str)))?;
    let stream = TcpStream::connect_timeout(&sock_addr, timeout)
        .map_err(|e| CoreError::ProtocolError(format!("TCP connect to KDC {} failed: {}", addr_str, e)))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let mut rx = stream
        .try_clone()
        .map_err(|e| CoreError::ProtocolError(format!("Socket clone failed: {}", e)))?;
    let mut tx = stream;

    tx.write_all(&tcp_pdu)
        .map_err(|e| CoreError::ProtocolError(format!("Failed sending FAST-Armored AS-REQ: {}", e)))?;

    let mut len_buf = [0u8; 4];
    rx.read_exact(&mut len_buf)
        .map_err(|e| CoreError::ProtocolError(format!("Failed reading KDC TCP length prefix: {}", e)))?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;
    if msg_len > 4 * 1024 * 1024 {
        return Err(CoreError::ProtocolError("Oversized Kerberos TCP reply".into()));
    }
    let mut der_buf = vec![0u8; msg_len];
    rx.read_exact(&mut der_buf)
        .map_err(|e| CoreError::ProtocolError(format!("Failed reading KDC reply body: {}", e)))?;

    let maybe_fast_rep = extract_pa_fx_fast_reply(&der_buf)
        .and_then(|val| decrypt_fast_rep(&val, &effective_armor_key, config.armor_etype).ok());

    let kdc_resp = crate::KdcAsResponse::from_der_bytes(&der_buf, &inner_req.realm, &inner_req.username)?;
    Ok((kdc_resp, maybe_fast_rep))
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf_aes128_and_aes256_deterministic() {
        let key16 = [0x11u8; 16];
        let p16 = prf_aes128(&key16, b"KerberosFAST");
        assert_ne!(p16, [0u8; 16]);

        let key32 = [0x22u8; 32];
        let p32 = prf_aes256(&key32, b"KerberosFAST");
        assert_ne!(p32, [0u8; 16]);
    }

    #[test]
    fn test_prf_plus_and_krb_fx_cf2_aes256() {
        let k1 = [0x33u8; 32];
        let k2 = [0x44u8; 32];
        let cf2 = krb_fx_cf2_aes256(&k1, &k2, b"KerberosFAST", b"strengthenkey");
        assert_ne!(cf2, [0u8; 32]);
        assert_ne!(cf2, k1);
        assert_ne!(cf2, k2);

        // Symmetric check with identical parameters
        let cf2_dup = krb_fx_cf2_aes256(&k1, &k2, b"KerberosFAST", b"strengthenkey");
        assert_eq!(cf2, cf2_dup);
    }

    #[test]
    fn test_prf_plus_and_krb_fx_cf2_aes128() {
        let k1 = [0x55u8; 16];
        let k2 = [0x66u8; 16];
        let cf2 = krb_fx_cf2_aes128(&k1, &k2, b"KerberosFAST", b"replykey");
        assert_ne!(cf2, [0u8; 16]);
        assert_ne!(cf2, k1);
        assert_ne!(cf2, k2);
    }

    #[test]
    fn test_enc_krb_fast_req_der_roundtrip() {
        let req = EncKrbFastReq {
            fast_options: 0x4000_0000,
            padata: vec![
                (128, vec![0x30, 0x03, 0x02, 0x01, 0x01]),
                (133, vec![0xDE, 0xAD, 0xBE, 0xEF]),
            ],
            req_body: vec![0x30, 0x05, 0x02, 0x01, 0x42, 0x00, 0x00],
        };
        let der_bytes = req.to_der();
        let parsed = EncKrbFastReq::parse(&der_bytes).expect("Failed to parse EncKrbFastReq");
        assert_eq!(parsed.fast_options, req.fast_options);
        assert_eq!(parsed.padata.len(), 2);
        assert_eq!(parsed.padata[0].0, 128);
        assert_eq!(parsed.padata[1].0, 133);
        assert_eq!(parsed.padata[1].1, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_build_fast_armored_as_req_aes256_flow() {
        // Mock armor ticket
        let armor_ticket = der::encode_application(
            1,
            &der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(5)),
                der::encode_context_explicit(1, &der::encode_general_string("CORP.LOCAL")),
            ]),
        );
        let armor_key = vec![0x77u8; 32];
        let config = FastArmorConfig::new(
            armor_ticket,
            armor_key.clone(),
            18,
            "CORP.LOCAL",
            "DC01$",
        );

        let nt_hash = [0x88u8; 16];
        let inner_req = Krb5AsReq::with_rc4_preauth("CORP.LOCAL", "alice", &nt_hash, 1_700_000_000);

        let (tcp_pdu, effective_key) = build_fast_armored_as_req(&config, &inner_req, Some(b"cookie123"), 1_700_000_000)
            .expect("Failed building FAST AS-REQ");

        assert_eq!(effective_key, armor_key);
        assert!(tcp_pdu.len() > 100);

        // Verify TCP prefix matches body length
        let pdu_len = u32::from_be_bytes([tcp_pdu[0], tcp_pdu[1], tcp_pdu[2], tcp_pdu[3]]) as usize;
        assert_eq!(pdu_len, tcp_pdu.len() - 4);
    }

    #[test]
    fn test_decrypt_fast_rep_and_cookie_extraction() {
        // Construct EncKrbFastRep
        let enc_rep_inner = der::encode_sequence(&[
            der::encode_context_explicit(
                0,
                &der::encode_sequence(&[
                    der::encode_sequence(&[
                        der::encode_context_explicit(1, &der::encode_integer(19)), // PA-ETYPE-INFO2
                        der::encode_context_explicit(2, &der::encode_octet_string(b"etype_info")),
                    ]),
                ]),
            ),
            der::encode_context_explicit(
                1,
                &der::encode_sequence(&[
                    der::encode_context_explicit(0, &der::encode_integer(18)),
                    der::encode_context_explicit(1, &der::encode_octet_string(&[0xAA; 32])),
                ]),
            ),
            der::encode_context_explicit(3, &der::encode_integer(0x1337)),
        ]);

        let armor_key32 = [0x99u8; 32];
        let conf16 = [0x55u8; 16];
        let cipher = crypto::aes256_cts_hmac_sha1_96_encrypt(&armor_key32, KEY_USAGE_FAST_REP, &enc_rep_inner, &conf16)
            .expect("Encrypt fast rep failed");

        let enc_data = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(18)),
            der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
        ]);
        let krb_fast_armored_rep = der::encode_sequence(&[
            der::encode_context_explicit(0, &enc_data),
        ]);
        let pa_fx_fast_rep_choice = der::encode_context_explicit(0, &krb_fast_armored_rep);

        let parsed_rep = decrypt_fast_rep(&pa_fx_fast_rep_choice, &armor_key32, 18)
            .expect("Failed to decrypt FAST reply");

        assert_eq!(parsed_rep.nonce, 0x1337);
        assert_eq!(parsed_rep.padata.len(), 1);
        assert_eq!(parsed_rep.padata[0].0, 19);
        assert!(parsed_rep.strengthen_key.is_some());
        let (sk_etype, sk_bytes) = parsed_rep.strengthen_key.unwrap();
        assert_eq!(sk_etype, 18);
        assert_eq!(sk_bytes, vec![0xAA; 32]);

        // Test cookie extraction from dummy KRB-ERROR
        let error_body = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(5)),
            der::encode_context_explicit(1, &der::encode_integer(30)),
            der::encode_context_explicit(9, &der::encode_integer(25)), // KDC_ERR_PREAUTH_REQUIRED
            der::encode_context_explicit(
                12, // e-data
                &der::encode_sequence(&[
                    der::encode_sequence(&[
                        der::encode_context_explicit(1, &der::encode_integer(PA_FX_COOKIE as i64)),
                        der::encode_context_explicit(2, &der::encode_octet_string(b"SECRET_FAST_COOKIE")),
                    ]),
                ]),
            ),
        ]);
        let krb_error_app30 = der::encode_application(30, &error_body);
        let extracted_cookie = extract_fast_cookie(&krb_error_app30);
        assert_eq!(extracted_cookie, Some(b"SECRET_FAST_COOKIE".to_vec()));
    }
}
