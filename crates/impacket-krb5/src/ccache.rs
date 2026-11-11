//! `ccache`: MIT Kerberos Credential Cache (`.ccache` v4, `0x0504`) and Windows Mimikatz `.kirbi`
//! (`KRB-CRED`, RFC 4120 `[APPLICATION 22]`) parser & converter (`impacket/krb5/ccache.py`).

use crate::crypto::unix_to_kerberos_time;
use crate::der;
use impacket_core::CoreError;

/// Kerberos Principal specification within `.ccache` or `.kirbi`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub name_type: u32,
    pub realm: String,
    pub components: Vec<String>,
}

impl Principal {
    pub fn new(realm: &str, components: &[&str]) -> Self {
        Self {
            name_type: 1, // NT-PRINCIPAL
            realm: realm.to_string(),
            components: components.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn to_display_string(&self) -> String {
        format!("{}/{}@{}", self.components.join("/"), self.realm, self.realm)
    }
}

/// KeyBlock holding session key metadata and bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlock {
    pub keytype: u16,
    pub keyvalue: Vec<u8>,
}

/// Validity lifecycle timestamps in seconds since Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Times {
    pub authtime: u32,
    pub starttime: u32,
    pub endtime: u32,
    pub renew_till: u32,
}

/// A single ticket entry within a `.ccache` or `.kirbi` container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub client: Principal,
    pub server: Principal,
    pub key: KeyBlock,
    pub times: Times,
    pub is_skey: u8,
    pub ticket_flags: u32,
    pub ticket: Vec<u8>,
    pub second_ticket: Vec<u8>,
}

/// MIT Kerberos Credential Cache file representation (`.ccache` v4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CCache {
    pub version: u16,
    pub primary_principal: Principal,
    pub credentials: Vec<Credential>,
}

impl CCache {
    pub const V4: u16 = 0x0504;

    pub fn new(primary_principal: Principal) -> Self {
        Self {
            version: Self::V4,
            primary_principal,
            credentials: Vec::new(),
        }
    }

    /// Parses a raw `.ccache` v4 buffer into structured credentials.
    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 12 {
            return Err(CoreError::BufferUnderflow { needed: 12, available: data.len() });
        }
        let version = u16::from_be_bytes([data[0], data[1]]);
        if version != 0x0504 && version != 0x0503 {
            return Err(CoreError::ProtocolError(format!("Unsupported ccache version: 0x{:04x}", version)));
        }
        let mut pos = 2;
        if version == 0x0504 {
            let hdr_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2 + hdr_len;
        }

        let primary_principal = Self::read_principal(data, &mut pos)?;
        let mut credentials = Vec::new();

        while pos < data.len() {
            let client = Self::read_principal(data, &mut pos)?;
            let server = Self::read_principal(data, &mut pos)?;

            if pos + 6 > data.len() {
                return Err(CoreError::BufferUnderflow { needed: pos + 6, available: data.len() });
            }
            let keytype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let _etype = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            let keylen = u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
            pos += 6;

            if pos + keylen > data.len() {
                return Err(CoreError::BufferUnderflow { needed: pos + keylen, available: data.len() });
            }
            let keyvalue = data[pos..pos + keylen].to_vec();
            pos += keylen;

            if pos + 16 > data.len() {
                return Err(CoreError::BufferUnderflow { needed: pos + 16, available: data.len() });
            }
            let authtime = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            let starttime = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
            let endtime = u32::from_be_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]]);
            let renew_till = u32::from_be_bytes([data[pos + 12], data[pos + 13], data[pos + 14], data[pos + 15]]);
            pos += 16;

            if pos + 5 > data.len() {
                return Err(CoreError::BufferUnderflow { needed: pos + 5, available: data.len() });
            }
            let is_skey = data[pos];
            let ticket_flags = u32::from_be_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]]);
            pos += 5;

            // Skip addresses if present
            if pos + 4 > data.len() {
                return Err(CoreError::BufferUnderflow { needed: pos + 4, available: data.len() });
            }
            let num_address = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            for _ in 0..num_address {
                pos += 2; // addrtype
                let _ = Self::read_counted_bytes(data, &mut pos)?;
            }

            // Skip authdata if present
            if pos + 4 > data.len() {
                return Err(CoreError::BufferUnderflow { needed: pos + 4, available: data.len() });
            }
            let num_authdata = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            for _ in 0..num_authdata {
                pos += 2; // authtype
                let _ = Self::read_counted_bytes(data, &mut pos)?;
            }

            let ticket = Self::read_counted_bytes(data, &mut pos)?;
            let second_ticket = Self::read_counted_bytes(data, &mut pos)?;

            credentials.push(Credential {
                client,
                server,
                key: KeyBlock { keytype, keyvalue },
                times: Times { authtime, starttime, endtime, renew_till },
                is_skey,
                ticket_flags,
                ticket,
                second_ticket,
            });
        }

        Ok(Self {
            version,
            primary_principal,
            credentials,
        })
    }

    /// Finds the first Ticket Granting Ticket (krbtgt/<REALM>@<REALM>) in this cache.
    pub fn find_tgt_credential(&self) -> Option<&Credential> {
        self.credentials.iter().find(|c| {
            c.server.components.len() >= 2
                && c.server.components[0] == "krbtgt"
                && c.server.components[1].eq_ignore_ascii_case(&c.server.realm)
        })
    }

    /// Extracts a ready-to-use TGT session key and ticket for Kerberos exchanges.
    pub fn find_tgt_session(&self) -> Option<crate::TgtSession> {
        let cred = self.find_tgt_credential()?;
        let mut session_key = [0u8; 16];
        if cred.key.keyvalue.len() >= 16 {
            session_key.copy_from_slice(&cred.key.keyvalue[..16]);
        }
        let username = cred.client.components.first().cloned().unwrap_or_default();
        Some(crate::TgtSession {
            realm: cred.client.realm.clone(),
            username,
            session_key,
            session_key_etype: cred.key.keytype as i32,
            tgt_ticket: cred.ticket.clone(),
            session_key_bytes: cred.key.keyvalue.clone(),
        })
    }

    /// Serializes this CCache to raw `.ccache` v4 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1024);
        out.extend_from_slice(&self.version.to_be_bytes());
        // Header length + header tag (tag 1, taglen 8, dummy delta)
        out.extend_from_slice(&12u16.to_be_bytes()); // header_len = 12
        out.extend_from_slice(&1u16.to_be_bytes());  // tag 1
        out.extend_from_slice(&8u16.to_be_bytes());  // taglen 8
        out.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00]); // tagdata

        Self::write_principal(&mut out, &self.primary_principal);

        for c in &self.credentials {
            Self::write_principal(&mut out, &c.client);
            Self::write_principal(&mut out, &c.server);
            out.extend_from_slice(&c.key.keytype.to_be_bytes());
            out.extend_from_slice(&c.key.keytype.to_be_bytes()); // etype repeats keytype
            out.extend_from_slice(&(c.key.keyvalue.len() as u16).to_be_bytes());
            out.extend_from_slice(&c.key.keyvalue);

            out.extend_from_slice(&c.times.authtime.to_be_bytes());
            out.extend_from_slice(&c.times.starttime.to_be_bytes());
            out.extend_from_slice(&c.times.endtime.to_be_bytes());
            out.extend_from_slice(&c.times.renew_till.to_be_bytes());

            out.push(c.is_skey);
            out.extend_from_slice(&c.ticket_flags.to_be_bytes());

            out.extend_from_slice(&0u32.to_be_bytes()); // num_address = 0
            out.extend_from_slice(&0u32.to_be_bytes()); // num_authdata = 0

            Self::write_counted_bytes(&mut out, &c.ticket);
            Self::write_counted_bytes(&mut out, &c.second_ticket);
        }

        out
    }

    /// Parses a Windows Mimikatz `.kirbi` file (ASN.1 DER `KRB-CRED`, Application 22) into a `CCache`.
    pub fn from_kirbi(data: &[u8]) -> Result<Self, CoreError> {
        let (tag, cred_seq, _) = der::decode_tlv(data)?;
        if tag != 0x76 {
            return Err(CoreError::ProtocolError(format!("Expected KRB-CRED [APPLICATION 22] (0x76), got 0x{:02X}", tag)));
        }
        let (_, cred_body, _) = der::decode_tlv(cred_seq)?;

        // Decode KRB-CRED fields: pvno [0], msg-type [1], tickets [2], enc-part [3]
        let mut tickets_raw: Vec<Vec<u8>> = Vec::new();
        let mut cipher_bytes: &[u8] = &[];

        let mut rem = cred_body;
        while !rem.is_empty() {
            let (ctx_tag, ctx_val, next_rem) = der::decode_tlv(rem)?;
            rem = next_rem;
            match ctx_tag {
                0xA2 => {
                    // tickets [2] SEQUENCE OF Ticket
                    let (_, tkt_seq, _) = der::decode_tlv(ctx_val)?;
                    let mut tkt_rem = tkt_seq;
                    while !tkt_rem.is_empty() {
                        let (_, _tkt_val, next_tkt) = der::decode_tlv(tkt_rem)?;
                        let tkt_full_len = tkt_rem.len() - next_tkt.len();
                        tickets_raw.push(tkt_rem[..tkt_full_len].to_vec());
                        tkt_rem = next_tkt;
                    }
                }
                0xA3 => {
                    // enc-part [3] EncryptedData
                    let (_, enc_seq, _) = der::decode_tlv(ctx_val)?;
                    let mut enc_rem = enc_seq;
                    while !enc_rem.is_empty() {
                        let (inner_tag, inner_val, next_enc) = der::decode_tlv(enc_rem)?;
                        enc_rem = next_enc;
                        if inner_tag == 0xA2 {
                            // cipher [2] OCTET STRING
                            let (_, c_octets, _) = der::decode_tlv(inner_val)?;
                            cipher_bytes = c_octets;
                        }
                    }
                }
                _ => {}
            }
        }

        if cipher_bytes.is_empty() {
            return Err(CoreError::ProtocolError("KRB-CRED enc-part cipher is empty".into()));
        }

        // Decode EncKrbCredPart (Application 29 or plain sequence)
        let (enc_tag, enc_body, _) = der::decode_tlv(cipher_bytes)?;
        let enc_part_data = if enc_tag == 0x7D {
            let (_, inner, _) = der::decode_tlv(enc_body)?;
            inner
        } else {
            enc_body
        };

        // Find ticket-info [0]
        let mut ticket_infos: Vec<KrbCredInfoParsed> = Vec::new();
        let mut enc_rem = enc_part_data;
        while !enc_rem.is_empty() {
            let (tag, val, next) = der::decode_tlv(enc_rem)?;
            enc_rem = next;
            if tag == 0xA0 {
                let (_, info_seq, _) = der::decode_tlv(val)?;
                let mut info_rem = info_seq;
                while !info_rem.is_empty() {
                    let (_, info_item, next_item) = der::decode_tlv(info_rem)?;
                    ticket_infos.push(Self::parse_krb_cred_info(info_item)?);
                    info_rem = next_item;
                }
            }
        }

        if ticket_infos.is_empty() {
            return Err(CoreError::ProtocolError("No ticket-info found in KRB-CRED".into()));
        }

        let primary_principal = ticket_infos[0].client.clone();
        let mut credentials = Vec::new();

        for (i, info) in ticket_infos.into_iter().enumerate() {
            let ticket = if i < tickets_raw.len() {
                tickets_raw[i].clone()
            } else {
                Vec::new()
            };

            credentials.push(Credential {
                client: info.client,
                server: info.server,
                key: info.key,
                times: info.times,
                is_skey: 0,
                ticket_flags: info.flags,
                ticket,
                second_ticket: Vec::new(),
            });
        }

        Ok(Self {
            version: Self::V4,
            primary_principal,
            credentials,
        })
    }

    /// Converts this `CCache` into a Windows Mimikatz `.kirbi` file (ASN.1 DER `KRB-CRED`).
    pub fn to_kirbi(&self) -> Result<Vec<u8>, CoreError> {
        let mut tickets_der = Vec::new();
        let mut ticket_infos_der = Vec::new();

        for c in &self.credentials {
            tickets_der.extend_from_slice(&c.ticket);

            let key_seq = der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(c.key.keytype as i64)),
                der::encode_context_explicit(1, &der::encode_octet_string(&c.key.keyvalue)),
            ]);

            let pname_seq = der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(c.client.name_type as i64)),
                der::encode_context_explicit(
                    1,
                    &der::encode_sequence(
                        &c.client.components.iter().map(|s| der::encode_general_string(s)).collect::<Vec<_>>(),
                    ),
                ),
            ]);

            let sname_seq = der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(c.server.name_type as i64)),
                der::encode_context_explicit(
                    1,
                    &der::encode_sequence(
                        &c.server.components.iter().map(|s| der::encode_general_string(s)).collect::<Vec<_>>(),
                    ),
                ),
            ]);

            let mut info_elements = vec![
                der::encode_context_explicit(0, &key_seq),
                der::encode_context_explicit(1, &der::encode_general_string(&c.client.realm)),
                der::encode_context_explicit(2, &pname_seq),
                der::encode_context_explicit(3, &der::encode_bit_string_u32(c.ticket_flags)),
            ];

            if c.times.starttime > 0 {
                info_elements.push(der::encode_context_explicit(
                    5,
                    &der::encode_generalized_time(&unix_to_kerberos_time(c.times.starttime as i64)),
                ));
            }
            if c.times.endtime > 0 {
                info_elements.push(der::encode_context_explicit(
                    6,
                    &der::encode_generalized_time(&unix_to_kerberos_time(c.times.endtime as i64)),
                ));
            }
            if c.times.renew_till > 0 {
                info_elements.push(der::encode_context_explicit(
                    7,
                    &der::encode_generalized_time(&unix_to_kerberos_time(c.times.renew_till as i64)),
                ));
            }

            info_elements.push(der::encode_context_explicit(8, &der::encode_general_string(&c.server.realm)));
            info_elements.push(der::encode_context_explicit(9, &sname_seq));

            ticket_infos_der.push(der::encode_sequence(&info_elements));
        }

        // EncKrbCredPart
        let enc_krb_cred_part = der::encode_application(
            29,
            &der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_sequence(&ticket_infos_der)),
            ]),
        );

        // EncryptedData (etype 0 null)
        let enc_part = der::encode_context_explicit(
            3,
            &der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(0)), // etype 0
                der::encode_context_explicit(2, &der::encode_octet_string(&enc_krb_cred_part)),
            ]),
        );

        // Tickets [2]
        let tickets_ctx = der::encode_context_explicit(2, &der::encode_tlv(0x30, &tickets_der));

        // KRB-CRED
        let krb_cred = der::encode_application(
            22,
            &der::encode_sequence(&[
                der::encode_context_explicit(0, &der::encode_integer(5)),
                der::encode_context_explicit(1, &der::encode_integer(22)),
                tickets_ctx,
                enc_part,
            ]),
        );

        Ok(krb_cred)
    }

    fn read_principal(data: &[u8], pos: &mut usize) -> Result<Principal, CoreError> {
        if *pos + 8 > data.len() {
            return Err(CoreError::BufferUnderflow { needed: *pos + 8, available: data.len() });
        }
        let name_type = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
        let num_components = u32::from_be_bytes([data[*pos + 4], data[*pos + 5], data[*pos + 6], data[*pos + 7]]) as usize;
        *pos += 8;

        let realm = Self::read_counted_string(data, pos)?;
        let mut components = Vec::with_capacity(num_components.min(16));
        for _ in 0..num_components {
            components.push(Self::read_counted_string(data, pos)?);
        }
        Ok(Principal { name_type, realm, components })
    }

    fn write_principal(out: &mut Vec<u8>, p: &Principal) {
        out.extend_from_slice(&p.name_type.to_be_bytes());
        out.extend_from_slice(&(p.components.len() as u32).to_be_bytes());
        Self::write_counted_string(out, &p.realm);
        for comp in &p.components {
            Self::write_counted_string(out, comp);
        }
    }

    fn read_counted_string(data: &[u8], pos: &mut usize) -> Result<String, CoreError> {
        let bytes = Self::read_counted_bytes(data, pos)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn write_counted_string(out: &mut Vec<u8>, s: &str) {
        Self::write_counted_bytes(out, s.as_bytes());
    }

    fn read_counted_bytes(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, CoreError> {
        if *pos + 4 > data.len() {
            return Err(CoreError::BufferUnderflow { needed: *pos + 4, available: data.len() });
        }
        let len = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]) as usize;
        *pos += 4;
        if *pos + len > data.len() {
            return Err(CoreError::BufferUnderflow { needed: *pos + len, available: data.len() });
        }
        let b = data[*pos..*pos + len].to_vec();
        *pos += len;
        Ok(b)
    }

    fn write_counted_bytes(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }

    fn parse_krb_cred_info(data: &[u8]) -> Result<KrbCredInfoParsed, CoreError> {
        let mut key = KeyBlock { keytype: 0, keyvalue: Vec::new() };
        let mut prealm = String::new();
        let mut pname_type = 1u32;
        let mut pname_comps = Vec::new();
        let mut srealm = String::new();
        let mut sname_type = 2u32;
        let mut sname_comps = Vec::new();
        let mut flags = 0u32;
        let mut times = Times::default();

        let mut rem = data;
        while !rem.is_empty() {
            let (tag, val, next) = der::decode_tlv(rem)?;
            rem = next;
            match tag {
                0xA0 => {
                    // key [0]
                    let (_, k_seq, _) = der::decode_tlv(val)?;
                    let mut k_rem = k_seq;
                    while !k_rem.is_empty() {
                        let (ktag, kval, knext) = der::decode_tlv(k_rem)?;
                        k_rem = knext;
                        if ktag == 0xA0 {
                            key.keytype = der::decode_integer(kval)? as u16;
                        } else if ktag == 0xA1 {
                            let (_, octets, _) = der::decode_tlv(kval)?;
                            key.keyvalue = octets.to_vec();
                        }
                    }
                }
                0xA1 => {
                    // prealm [1]
                    let (_, s_bytes, _) = der::decode_tlv(val)?;
                    prealm = String::from_utf8_lossy(s_bytes).into_owned();
                }
                0xA2 => {
                    // pname [2]
                    let (nt, comps) = Self::parse_principal_name(val)?;
                    pname_type = nt;
                    pname_comps = comps;
                }
                0xA3 => {
                    // flags [3] BIT STRING
                    let (_, b_bytes, _) = der::decode_tlv(val)?;
                    if b_bytes.len() >= 5 {
                        flags = u32::from_be_bytes([b_bytes[1], b_bytes[2], b_bytes[3], b_bytes[4]]);
                    }
                }
                0xA5 => {
                    // starttime [5]
                    let (_, t_bytes, _) = der::decode_tlv(val)?;
                    let s = String::from_utf8_lossy(t_bytes);
                    if let Some(u) = kerberos_time_to_unix(&s) {
                        times.starttime = u;
                        times.authtime = u;
                    }
                }
                0xA6 => {
                    // endtime [6]
                    let (_, t_bytes, _) = der::decode_tlv(val)?;
                    let s = String::from_utf8_lossy(t_bytes);
                    if let Some(u) = kerberos_time_to_unix(&s) {
                        times.endtime = u;
                    }
                }
                0xA7 => {
                    // renew-till [7]
                    let (_, t_bytes, _) = der::decode_tlv(val)?;
                    let s = String::from_utf8_lossy(t_bytes);
                    if let Some(u) = kerberos_time_to_unix(&s) {
                        times.renew_till = u;
                    }
                }
                0xA8 => {
                    // srealm [8]
                    let (_, s_bytes, _) = der::decode_tlv(val)?;
                    srealm = String::from_utf8_lossy(s_bytes).into_owned();
                }
                0xA9 => {
                    // sname [9]
                    let (nt, comps) = Self::parse_principal_name(val)?;
                    sname_type = nt;
                    sname_comps = comps;
                }
                _ => {}
            }
        }

        Ok(KrbCredInfoParsed {
            key,
            client: Principal { name_type: pname_type, realm: prealm, components: pname_comps },
            server: Principal { name_type: sname_type, realm: srealm, components: sname_comps },
            flags,
            times,
        })
    }

    fn parse_principal_name(data: &[u8]) -> Result<(u32, Vec<String>), CoreError> {
        let (_, seq, _) = der::decode_tlv(data)?;
        let mut name_type = 1u32;
        let mut components = Vec::new();
        let mut rem = seq;
        while !rem.is_empty() {
            let (tag, val, next) = der::decode_tlv(rem)?;
            rem = next;
            if tag == 0xA0 {
                name_type = der::decode_integer(val)? as u32;
            } else if tag == 0xA1 {
                let (_, comp_seq, _) = der::decode_tlv(val)?;
                let mut c_rem = comp_seq;
                while !c_rem.is_empty() {
                    let (_, c_val, next_c) = der::decode_tlv(c_rem)?;
                    components.push(String::from_utf8_lossy(c_val).into_owned());
                    c_rem = next_c;
                }
            }
        }
        Ok((name_type, components))
    }
}

struct KrbCredInfoParsed {
    key: KeyBlock,
    client: Principal,
    server: Principal,
    flags: u32,
    times: Times,
}

pub fn kerberos_time_to_unix(s: &str) -> Option<u32> {
    if s.len() < 14 {
        return None;
    }
    let year: i64 = s[0..4].parse().ok()?;
    let month: u32 = s[4..6].parse().ok()?;
    let day: u32 = s[6..8].parse().ok()?;
    let hh: u64 = s[8..10].parse().ok()?;
    let mm: u64 = s[10..12].parse().ok()?;
    let ss: u64 = s[12..14].parse().ok()?;

    let (y, m) = if month <= 2 { (year - 1, month + 9) } else { (year, month - 3) };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + (doe as i64) - 719468;
    if days < 0 {
        return None;
    }
    let total_secs = (days as u64) * 86400 + hh * 3600 + mm * 60 + ss;
    Some(total_secs as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ccache_binary_roundtrip() {
        let mut ccache = CCache::new(Principal::new("CORP.LOCAL", &["Administrator"]));
        ccache.credentials.push(Credential {
            client: Principal::new("CORP.LOCAL", &["Administrator"]),
            server: Principal::new("CORP.LOCAL", &["krbtgt", "CORP.LOCAL"]),
            key: KeyBlock {
                keytype: 23, // RC4
                keyvalue: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00],
            },
            times: Times {
                authtime: 1_700_000_000,
                starttime: 1_700_000_000,
                endtime: 1_700_036_000,
                renew_till: 1_700_604_800,
            },
            is_skey: 0,
            ticket_flags: 0x40E00000,
            ticket: vec![0x61, 0x05, 0x30, 0x03, 0x02, 0x01, 0x05], // fake ticket
            second_ticket: Vec::new(),
        });

        let serialized = ccache.to_bytes();
        assert_eq!(&serialized[0..2], &[0x05, 0x04]);

        let parsed = CCache::parse(&serialized).expect("should parse ccache");
        assert_eq!(parsed.version, 0x0504);
        assert_eq!(parsed.primary_principal.realm, "CORP.LOCAL");
        assert_eq!(parsed.primary_principal.components, vec!["Administrator"]);
        assert_eq!(parsed.credentials.len(), 1);
        assert_eq!(parsed.credentials[0].key.keytype, 23);
        assert_eq!(parsed.credentials[0].times.starttime, 1_700_000_000);
    }

    #[test]
    fn test_ccache_to_kirbi_and_from_kirbi_roundtrip() {
        let mut ccache = CCache::new(Principal::new("CONTOSO.LOCAL", &["svc_sql"]));
        ccache.credentials.push(Credential {
            client: Principal::new("CONTOSO.LOCAL", &["svc_sql"]),
            server: Principal::new("CONTOSO.LOCAL", &["MSSQLSvc", "sql01.contoso.local:1433"]),
            key: KeyBlock {
                keytype: 23,
                keyvalue: vec![0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C],
            },
            times: Times {
                authtime: 1_762_300_800,
                starttime: 1_762_300_800,
                endtime: 1_762_336_800,
                renew_till: 1_762_905_600,
            },
            is_skey: 0,
            ticket_flags: 0x40A00000,
            ticket: vec![0x61, 0x08, 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x01],
            second_ticket: Vec::new(),
        });

        let kirbi_bytes = ccache.to_kirbi().expect("should encode kirbi");
        assert_eq!(kirbi_bytes[0], 0x76); // Application 22

        let decoded_ccache = CCache::from_kirbi(&kirbi_bytes).expect("should decode kirbi");
        assert_eq!(decoded_ccache.primary_principal.realm, "CONTOSO.LOCAL");
        assert_eq!(decoded_ccache.primary_principal.components, vec!["svc_sql"]);
        assert_eq!(decoded_ccache.credentials.len(), 1);

        let cred = &decoded_ccache.credentials[0];
        assert_eq!(cred.server.realm, "CONTOSO.LOCAL");
        assert_eq!(cred.server.components, vec!["MSSQLSvc", "sql01.contoso.local:1433"]);
        assert_eq!(cred.key.keytype, 23);
        assert_eq!(cred.key.keyvalue, vec![0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]);
        assert_eq!(cred.times.starttime, 1_762_300_800);
        assert_eq!(cred.times.endtime, 1_762_336_800);
        assert_eq!(cred.ticket, vec![0x61, 0x08, 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x01]);
    }
}
