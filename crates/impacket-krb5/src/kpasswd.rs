//! `kpasswd`: RFC 3244 Kerberos Version 5 Password Changing Protocol (UDP/TCP port 464).
//!
//! Provides `change_password_kpasswd_live`, `build_kpasswd_request`, and `parse_kpasswd_response`.
//! Constructs authenticating `AP-REQ` ([APPLICATION 14], Key Usage 11) and encrypted `KRB-PRIV`
//! ([APPLICATION 21], Key Usage 13) envelopes.

use crate::crypto::{
    aes128_cts_hmac_sha1_96_decrypt, aes128_cts_hmac_sha1_96_encrypt,
    aes256_cts_hmac_sha1_96_decrypt, aes256_cts_hmac_sha1_96_encrypt, rc4_hmac_decrypt,
    rc4_hmac_encrypt, unix_to_kerberos_time,
};
use impacket_core::der;
use impacket_core::CoreError;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

pub const KPASSWD_DEFAULT_PORT: u16 = 464;

/// RFC 3244 Section 3.2 KPASSWD result codes.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum KpasswdResultCode {
    Success = 0,
    Malformed = 1,
    HardError = 2,
    AuthError = 3,
    SoftError = 4,
    AccessDenied = 5,
    BadVersion = 6,
    InitialFlagNeeded = 7,
    Unknown(u16),
}

impl KpasswdResultCode {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0 => Self::Success,
            1 => Self::Malformed,
            2 => Self::HardError,
            3 => Self::AuthError,
            4 => Self::SoftError,
            5 => Self::AccessDenied,
            6 => Self::BadVersion,
            7 => Self::InitialFlagNeeded,
            n => Self::Unknown(n),
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Success => "Success",
            Self::Malformed => "Malformed request",
            Self::HardError => "Server error (hard failure)",
            Self::AuthError => "Authentication error",
            Self::SoftError => "Password rejected by policy (soft failure)",
            Self::AccessDenied => "Access denied",
            Self::BadVersion => "Protocol version unsupported",
            Self::InitialFlagNeeded => "Initial ticket required",
            Self::Unknown(_) => "Unknown error code",
        }
    }
}

/// Decoded response from KPASSWD service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KpasswdResponse {
    pub result_code: KpasswdResultCode,
    pub result_string: String,
}

/// Builds an authenticating `AP-REQ` for KPASSWD (`KeyUsage = 11`).
pub fn build_kpasswd_ap_req(
    ticket: &[u8],
    session_key: &[u8],
    session_key_etype: i32,
    username: &str,
    realm: &str,
    now_unix: i64,
) -> Result<Vec<u8>, CoreError> {
    let ts = unix_to_kerberos_time(now_unix);

    // Authenticator ::= [APPLICATION 2] SEQUENCE
    let cname = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(1)),
        der::encode_context_explicit(
            1,
            &der::encode_sequence(&[der::encode_general_string(username)]),
        ),
    ]);

    let auth_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(5)),
        der::encode_context_explicit(1, &der::encode_general_string(realm)),
        der::encode_context_explicit(2, &cname),
        der::encode_context_explicit(4, &der::encode_integer(0)),
        der::encode_context_explicit(5, &der::encode_generalized_time(&ts)),
    ]);
    let authenticator_der = der::encode_application(2, &auth_seq);

    // Encrypt Authenticator with Key Usage 11 (KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR)
    let enc_authenticator = match session_key_etype {
        23 => {
            let key16: [u8; 16] = session_key.try_into().map_err(|_| {
                CoreError::ProtocolError("RC4 session key must be 16 bytes".into())
            })?;
            let mut confounder = [0u8; 8];
            for (i, b) in ts.as_bytes().iter().take(8).enumerate() {
                confounder[i] = *b;
            }
            let cipher = rc4_hmac_encrypt(&key16, 11, &authenticator_der, &confounder);
            der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(23)),
                der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
            ])
        }
        17 => {
            let key16: [u8; 16] = session_key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-128 session key must be 16 bytes".into())
            })?;
            let conf16 = [0x54; 16];
            let cipher = aes128_cts_hmac_sha1_96_encrypt(&key16, 11, &authenticator_der, &conf16)?;
            der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(17)),
                der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
            ])
        }
        18 => {
            let key32: [u8; 32] = session_key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-256 session key must be 32 bytes".into())
            })?;
            let conf16 = [0x54; 16];
            let cipher = aes256_cts_hmac_sha1_96_encrypt(&key32, 11, &authenticator_der, &conf16)?;
            der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(18)),
                der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
            ])
        }
        other => {
            return Err(CoreError::ProtocolError(format!(
                "Unsupported session key etype {}",
                other
            )));
        }
    };

    // AP-REQ ::= [APPLICATION 14] SEQUENCE
    let ap_options = der::encode_bit_string_u32(0);
    let ap_req_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(5)),
        der::encode_context_explicit(1, &der::encode_integer(14)),
        der::encode_context_explicit(2, &ap_options),
        der::encode_context_explicit(3, ticket),
        der::encode_context_explicit(4, &enc_authenticator),
    ]);
    Ok(der::encode_application(14, &ap_req_seq))
}

/// Builds an encrypted `KRB-PRIV` message for KPASSWD (`KeyUsage = 13`).
pub fn build_kpasswd_krb_priv(
    new_password: &str,
    session_key: &[u8],
    session_key_etype: i32,
    now_unix: i64,
) -> Result<Vec<u8>, CoreError> {
    let ts = unix_to_kerberos_time(now_unix);

    // EncKrbPrivPart ::= [APPLICATION 28] SEQUENCE
    let enc_priv_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_octet_string(new_password.as_bytes())),
        der::encode_context_explicit(1, &der::encode_generalized_time(&ts)),
        der::encode_context_explicit(2, &der::encode_integer(0)),
    ]);
    let enc_priv_der = der::encode_application(28, &enc_priv_seq);

    // Encrypt with Key Usage 13 (KRB_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART)
    let enc_part = match session_key_etype {
        23 => {
            let key16: [u8; 16] = session_key.try_into().map_err(|_| {
                CoreError::ProtocolError("RC4 session key must be 16 bytes".into())
            })?;
            let mut confounder = [0u8; 8];
            for (i, b) in ts.as_bytes().iter().take(8).enumerate() {
                confounder[i] = *b;
            }
            let cipher = rc4_hmac_encrypt(&key16, 13, &enc_priv_der, &confounder);
            der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(23)),
                der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
            ])
        }
        17 => {
            let key16: [u8; 16] = session_key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-128 session key must be 16 bytes".into())
            })?;
            let conf16 = [0x54; 16];
            let cipher = aes128_cts_hmac_sha1_96_encrypt(&key16, 13, &enc_priv_der, &conf16)?;
            der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(17)),
                der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
            ])
        }
        18 => {
            let key32: [u8; 32] = session_key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-256 session key must be 32 bytes".into())
            })?;
            let conf16 = [0x54; 16];
            let cipher = aes256_cts_hmac_sha1_96_encrypt(&key32, 13, &enc_priv_der, &conf16)?;
            der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(18)),
                der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
            ])
        }
        other => {
            return Err(CoreError::ProtocolError(format!(
                "Unsupported session key etype {}",
                other
            )));
        }
    };

    // KRB-PRIV ::= [APPLICATION 21] SEQUENCE
    let krb_priv_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(5)),
        der::encode_context_explicit(1, &der::encode_integer(21)),
        der::encode_context_explicit(3, &enc_part),
    ]);
    Ok(der::encode_application(21, &krb_priv_seq))
}

/// Builds the complete RFC 3244 kpasswd request packet with optional 4-byte TCP prefix.
pub fn build_kpasswd_request(
    ticket: &[u8],
    session_key: &[u8],
    session_key_etype: i32,
    username: &str,
    realm: &str,
    new_password: &str,
    now_unix: i64,
    with_tcp_prefix: bool,
) -> Result<Vec<u8>, CoreError> {
    let ap_req = build_kpasswd_ap_req(
        ticket,
        session_key,
        session_key_etype,
        username,
        realm,
        now_unix,
    )?;
    let krb_priv = build_kpasswd_krb_priv(new_password, session_key, session_key_etype, now_unix)?;

    let message_len = (4 + ap_req.len() + krb_priv.len()) as u16;
    let mut pkt = Vec::with_capacity(message_len as usize + 6);

    if with_tcp_prefix {
        let total_tcp_len = (2 + message_len) as u32;
        pkt.extend_from_slice(&total_tcp_len.to_be_bytes());
    }

    pkt.extend_from_slice(&message_len.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // Protocol version = 1
    pkt.extend_from_slice(&(ap_req.len() as u16).to_be_bytes());
    pkt.extend_from_slice(&ap_req);
    pkt.extend_from_slice(&krb_priv);

    Ok(pkt)
}

/// Parses an RFC 3244 kpasswd response packet.
pub fn parse_kpasswd_response(
    resp_bytes: &[u8],
    session_key: &[u8],
    session_key_etype: i32,
) -> Result<KpasswdResponse, CoreError> {
    if resp_bytes.len() < 6 {
        return Err(CoreError::BufferUnderflow {
            needed: 6,
            available: resp_bytes.len(),
        });
    }

    let _msg_len = u16::from_be_bytes([resp_bytes[0], resp_bytes[1]]) as usize;
    let version = u16::from_be_bytes([resp_bytes[2], resp_bytes[3]]);
    if version != 1 {
        return Err(CoreError::ProtocolError(format!(
            "Unsupported KPASSWD version {}",
            version
        )));
    }
    let ap_rep_len = u16::from_be_bytes([resp_bytes[4], resp_bytes[5]]) as usize;

    let krb_msg_start = 6 + ap_rep_len;
    if resp_bytes.len() < krb_msg_start {
        return Err(CoreError::BufferUnderflow {
            needed: krb_msg_start,
            available: resp_bytes.len(),
        });
    }

    let krb_msg = &resp_bytes[krb_msg_start..];
    let (app_tag, app_body, _) = der::decode_tlv(krb_msg)?;

    if app_tag == 0x7E {
        // KRB-ERROR (Application 30)
        let (_, mut seq_body, _) = der::decode_tlv(app_body)?;
        let mut err_code = 0u32;
        let mut e_text = String::new();
        while !seq_body.is_empty() {
            let (ctx_tag, ctx_val, rest) = der::decode_tlv(seq_body)?;
            seq_body = rest;
            match ctx_tag & 0x1F {
                6 => err_code = der::decode_integer(ctx_val)? as u32,
                9 => {
                    let (_, text_bytes, _) = der::decode_tlv(ctx_val)?;
                    e_text = String::from_utf8_lossy(text_bytes).into_owned();
                }
                _ => {}
            }
        }
        return Err(CoreError::ProtocolError(format!(
            "KDC returned KRB-ERROR 0x{:X}: {}",
            err_code, e_text
        )));
    } else if app_tag != 0x75 {
        // Expected KRB-PRIV (Application 21)
        return Err(CoreError::ProtocolError(format!(
            "Expected KRB-PRIV (tag 0x75), got 0x{:02X}",
            app_tag
        )));
    }

    // Parse KRB-PRIV sequence
    let (_, mut priv_body, _) = der::decode_tlv(app_body)?;
    let mut enc_part_cipher = Vec::new();
    let mut enc_part_etype = session_key_etype;

    while !priv_body.is_empty() {
        let (ctx_tag, ctx_val, rest) = der::decode_tlv(priv_body)?;
        priv_body = rest;
        if (ctx_tag & 0x1F) == 3 {
            // enc-part [3] EncryptedData
            let (_, enc_seq, _) = der::decode_tlv(ctx_val)?;
            let mut enc_rem = enc_seq;
            while !enc_rem.is_empty() {
                let (e_tag, e_val, e_rest) = der::decode_tlv(enc_rem)?;
                enc_rem = e_rest;
                match e_tag & 0x1F {
                    0 => enc_part_etype = der::decode_integer(e_val)? as i32,
                    2 => {
                        let (_, c_b, _) = der::decode_tlv(e_val)?;
                        enc_part_cipher = c_b.to_vec();
                    }
                    _ => {}
                }
            }
        }
    }

    // Decrypt EncKrbPrivPart using session_key with Key Usage 13
    let pt = match enc_part_etype {
        23 => {
            let k16: [u8; 16] = session_key.try_into().map_err(|_| {
                CoreError::ProtocolError("RC4 key must be 16 bytes".into())
            })?;
            rc4_hmac_decrypt(&k16, 13, &enc_part_cipher)?
        }
        17 => {
            let k16: [u8; 16] = session_key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-128 key must be 16 bytes".into())
            })?;
            aes128_cts_hmac_sha1_96_decrypt(&k16, 13, &enc_part_cipher)?
        }
        18 => {
            let k32: [u8; 32] = session_key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-256 key must be 32 bytes".into())
            })?;
            aes256_cts_hmac_sha1_96_decrypt(&k32, 13, &enc_part_cipher)?
        }
        other => {
            return Err(CoreError::ProtocolError(format!(
                "Unsupported enc-part etype {}",
                other
            )));
        }
    };

    // Parse EncKrbPrivPart ([APPLICATION 28])
    let (p_app, p_body, _) = der::decode_tlv(&pt)?;
    let priv_seq = if p_app == 0x7C {
        let (_, b, _) = der::decode_tlv(p_body)?;
        b
    } else {
        p_body
    };

    let mut user_data = Vec::new();
    let mut rem = priv_seq;
    while !rem.is_empty() {
        let (tag, val, next) = der::decode_tlv(rem)?;
        rem = next;
        if (tag & 0x1F) == 0 {
            // user-data [0] OCTET STRING
            let (_, octets, _) = der::decode_tlv(val)?;
            user_data = octets.to_vec();
        }
    }

    if user_data.len() < 2 {
        return Err(CoreError::ProtocolError(
            "Truncated user-data in KPASSWD response".into(),
        ));
    }

    let code_u16 = u16::from_be_bytes([user_data[0], user_data[1]]);
    let result_code = KpasswdResultCode::from_u16(code_u16);
    let result_string = String::from_utf8_lossy(&user_data[2..]).trim().to_string();

    Ok(KpasswdResponse {
        result_code,
        result_string,
    })
}

/// Changes a Kerberos user's password over live TCP/464.
pub fn change_password_kpasswd_live(
    kdc_host: &str,
    kdc_port: u16,
    ticket: &[u8],
    session_key: &[u8],
    session_key_etype: i32,
    username: &str,
    realm: &str,
    new_password: &str,
    now_unix: i64,
    timeout: Duration,
) -> Result<KpasswdResponse, CoreError> {
    let req_bytes = build_kpasswd_request(
        ticket,
        session_key,
        session_key_etype,
        username,
        realm,
        new_password,
        now_unix,
        true, // with TCP prefix
    )?;

    let addr_str = format!("{}:{}", kdc_host, kdc_port);
    let sock_addr: SocketAddr = addr_str
        .to_socket_addrs()
        .map_err(|e| CoreError::ProtocolError(format!("Failed resolving {}: {}", addr_str, e)))?
        .next()
        .ok_or_else(|| CoreError::ProtocolError(format!("No address found for {}", addr_str)))?;

    let mut stream = TcpStream::connect_timeout(&sock_addr, timeout).map_err(|e| {
        CoreError::ProtocolError(format!("TCP connect to KPASSWD {} failed: {}", addr_str, e))
    })?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    stream
        .write_all(&req_bytes)
        .map_err(|e| CoreError::ProtocolError(format!("Failed sending KPASSWD request: {}", e)))?;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| CoreError::ProtocolError(format!("Failed reading KPASSWD TCP length: {}", e)))?;
    let tcp_len = u32::from_be_bytes(len_buf) as usize;
    if tcp_len > 65_536 {
        return Err(CoreError::ProtocolError(format!(
            "Unreasonable KPASSWD response length: {}",
            tcp_len
        )));
    }

    let mut resp_buf = vec![0u8; tcp_len];
    stream
        .read_exact(&mut resp_buf)
        .map_err(|e| CoreError::ProtocolError(format!("Failed reading KPASSWD body: {}", e)))?;

    parse_kpasswd_response(&resp_buf, session_key, session_key_etype)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kpasswd_request_and_response_roundtrip_rc4() {
        let session_key = [0x55u8; 16];
        let ticket = der::encode_application(1, &der::encode_sequence(&[]));
        let now = 1700000000i64;

        let req = build_kpasswd_request(
            &ticket,
            &session_key,
            23,
            "Administrator",
            "CORP.LOCAL",
            "NewP@ss2026!",
            now,
            false,
        )
        .unwrap();

        assert!(req.len() > 6);
        let msg_len = u16::from_be_bytes([req[0], req[1]]) as usize;
        assert_eq!(req.len(), msg_len + 2);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 1); // version

        // Mock a success response from KDC
        // user_data: 2 bytes code = 0 (Success) + "Password changed successfully"
        let mut user_data = vec![0, 0];
        user_data.extend_from_slice(b"Password changed successfully");

        // EncKrbPrivPart [APPLICATION 28]
        let enc_priv_seq = der::encode_sequence(&[der::encode_context_explicit(
            0,
            &der::encode_octet_string(&user_data),
        )]);
        let enc_priv_der = der::encode_application(28, &enc_priv_seq);
        let cipher = rc4_hmac_encrypt(&session_key, 13, &enc_priv_der, &[0x42; 8]);

        // KRB-PRIV [APPLICATION 21]
        let enc_part = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(23)),
            der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
        ]);
        let krb_priv_seq = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(5)),
            der::encode_context_explicit(1, &der::encode_integer(21)),
            der::encode_context_explicit(3, &enc_part),
        ]);
        let krb_priv = der::encode_application(21, &krb_priv_seq);

        let mut resp = Vec::new();
        let resp_len = (4 + krb_priv.len()) as u16;
        resp.extend_from_slice(&resp_len.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes()); // version = 1
        resp.extend_from_slice(&0u16.to_be_bytes()); // ap_rep_len = 0
        resp.extend_from_slice(&krb_priv);

        let parsed = parse_kpasswd_response(&resp, &session_key, 23).unwrap();
        assert_eq!(parsed.result_code, KpasswdResultCode::Success);
        assert_eq!(parsed.result_string, "Password changed successfully");
    }

    #[test]
    fn test_kpasswd_policy_error_response() {
        let session_key = [0x55u8; 16];

        // user_data: 2 bytes code = 4 (SoftError / Policy) + "Password is too short"
        let mut user_data = vec![0, 4];
        user_data.extend_from_slice(b"Password is too short");

        let enc_priv_seq = der::encode_sequence(&[der::encode_context_explicit(
            0,
            &der::encode_octet_string(&user_data),
        )]);
        let enc_priv_der = der::encode_application(28, &enc_priv_seq);
        let cipher = rc4_hmac_encrypt(&session_key, 13, &enc_priv_der, &[0x11; 8]);

        let enc_part = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(23)),
            der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
        ]);
        let krb_priv = der::encode_application(
            21,
            &der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(5)),
                der::encode_context_explicit(1, &der::encode_integer(21)),
                der::encode_context_explicit(3, &enc_part),
            ]),
        );

        let mut resp = Vec::new();
        let resp_len = (4 + krb_priv.len()) as u16;
        resp.extend_from_slice(&resp_len.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&krb_priv);

        let parsed = parse_kpasswd_response(&resp, &session_key, 23).unwrap();
        assert_eq!(parsed.result_code, KpasswdResultCode::SoftError);
        assert_eq!(parsed.result_string, "Password is too short");
        assert_eq!(
            parsed.result_code.description(),
            "Password rejected by policy (soft failure)"
        );
    }
}
