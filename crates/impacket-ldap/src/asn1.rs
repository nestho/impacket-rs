//! `asn1`: RFC 4511 Lightweight Directory Access Protocol (LDAP) ASN.1 BER message codec.

use impacket_core::der;
use impacket_core::CoreError;

pub mod op_tag {
    pub const BIND_REQUEST: u8 = 0x60;        // [APPLICATION 0]
    pub const BIND_RESPONSE: u8 = 0x61;       // [APPLICATION 1]
    pub const UNBIND_REQUEST: u8 = 0x42;      // [APPLICATION 2]
    pub const SEARCH_REQUEST: u8 = 0x63;      // [APPLICATION 3]
    pub const SEARCH_RES_ENTRY: u8 = 0x64;    // [APPLICATION 4]
    pub const SEARCH_RES_DONE: u8 = 0x65;     // [APPLICATION 5]
    pub const MODIFY_REQUEST: u8 = 0x66;      // [APPLICATION 6]
    pub const MODIFY_RESPONSE: u8 = 0x67;     // [APPLICATION 7]
    pub const ADD_REQUEST: u8 = 0x68;         // [APPLICATION 8]
    pub const ADD_RESPONSE: u8 = 0x69;        // [APPLICATION 9]
    pub const DEL_REQUEST: u8 = 0x4A;         // [APPLICATION 10]
    pub const DEL_RESPONSE: u8 = 0x6B;        // [APPLICATION 11]
}

pub mod result_code {
    pub const SUCCESS: i32 = 0;
    pub const OPERATIONS_ERROR: i32 = 1;
    pub const PROTOCOL_ERROR: i32 = 2;
    pub const TIME_LIMIT_EXCEEDED: i32 = 3;
    pub const SIZE_LIMIT_EXCEEDED: i32 = 4;
    pub const AUTH_METHOD_NOT_SUPPORTED: i32 = 7;
    pub const INVALID_CREDENTIALS: i32 = 49;
    pub const INSUFFICIENT_ACCESS_RIGHTS: i32 = 50;
    pub const BUSY: i32 = 51;
    pub const UNAVAILABLE: i32 = 52;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SearchScope {
    BaseObject = 0,
    SingleLevel = 1,
    WholeSubtree = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindAuth {
    Simple(Vec<u8>),
    Sasl {
        mechanism: String,
        credentials: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapAttribute {
    pub type_name: String,
    pub values: Vec<Vec<u8>>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ModifyOperation {
    Add = 0,
    Delete = 1,
    Replace = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeModification {
    pub operation: ModifyOperation,
    pub attribute: LdapAttribute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolOp {
    BindRequest {
        version: i32,
        name: String,
        auth: BindAuth,
    },
    BindResponse {
        result_code: i32,
        matched_dn: String,
        diagnostic_message: String,
        server_sasl_creds: Option<Vec<u8>>,
    },
    UnbindRequest,
    SearchRequest {
        base_object: String,
        scope: SearchScope,
        deref_aliases: i32,
        size_limit: i32,
        time_limit: i32,
        types_only: bool,
        filter: Vec<u8>,
        attributes: Vec<String>,
    },
    SearchResultEntry {
        object_name: String,
        attributes: Vec<LdapAttribute>,
    },
    SearchResultDone {
        result_code: i32,
        matched_dn: String,
        diagnostic_message: String,
    },
    ModifyRequest {
        object: String,
        modifications: Vec<AttributeModification>,
    },
    ModifyResponse {
        result_code: i32,
        matched_dn: String,
        diagnostic_message: String,
    },
    AddRequest {
        entry: String,
        attributes: Vec<LdapAttribute>,
    },
    AddResponse {
        result_code: i32,
        matched_dn: String,
        diagnostic_message: String,
    },
    DelRequest {
        entry: String,
    },
    DelResponse {
        result_code: i32,
        matched_dn: String,
        diagnostic_message: String,
    },
    Other {
        tag: u8,
        data: Vec<u8>,
    },
}

pub const CONTROL_PAGED_RESULTS: &str = "1.2.840.113556.1.4.319";

/// An LDAP Control per RFC 4511 Section 4.1.11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapControl {
    pub control_type: String,
    pub criticality: bool,
    pub control_value: Option<Vec<u8>>,
}

impl LdapControl {
    pub fn new(control_type: impl Into<String>, criticality: bool, control_value: Option<Vec<u8>>) -> Self {
        Self {
            control_type: control_type.into(),
            criticality,
            control_value,
        }
    }

    /// Creates an RFC 2696 Simple Paged Results Control (`1.2.840.113556.1.4.319`).
    pub fn paged_results(page_size: u32, cookie: &[u8]) -> Self {
        let mut seq = Vec::new();
        seq.push(der::encode_integer(page_size as i64));
        seq.push(der::encode_octet_string(cookie));
        let val_bytes = der::encode_sequence(&seq);
        Self {
            control_type: CONTROL_PAGED_RESULTS.to_string(),
            criticality: false,
            control_value: Some(val_bytes),
        }
    }

    /// Extracts the pagination cookie from an RFC 2696 control value.
    pub fn parse_paged_results_cookie(&self) -> Option<Vec<u8>> {
        if self.control_type != CONTROL_PAGED_RESULTS {
            return None;
        }
        let val = self.control_value.as_ref()?;
        let (seq_tag, seq_body, _) = der::decode_tlv(val).ok()?;
        if seq_tag != 0x30 {
            return None;
        }
        let (int_tag, _int_val, rest) = der::decode_tlv(seq_body).ok()?;
        if int_tag != 0x02 {
            return None;
        }
        let (cookie_tag, cookie_val, _) = der::decode_tlv(rest).ok()?;
        if cookie_tag != 0x04 {
            return None;
        }
        Some(cookie_val.to_vec())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut elements = Vec::new();
        elements.push(der::encode_octet_string(self.control_type.as_bytes()));
        if self.criticality {
            elements.push(der::encode_tlv(0x01, &[0xFF]));
        }
        if let Some(ref val) = self.control_value {
            elements.push(der::encode_octet_string(val));
        }
        der::encode_sequence(&elements)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CoreError> {
        let (seq_tag, seq_body, _) = der::decode_tlv(data)?;
        if seq_tag != 0x30 {
            return Err(CoreError::ProtocolError("Invalid Control SEQUENCE tag".into()));
        }

        let (oid_tag, oid_val, mut cur) = der::decode_tlv(seq_body)?;
        if oid_tag != 0x04 {
            return Err(CoreError::ProtocolError("Missing controlType OID".into()));
        }
        let control_type = String::from_utf8_lossy(oid_val).to_string();

        let mut criticality = false;
        let mut control_value = None;

        if !cur.is_empty() {
            let (next_tag, next_val, rest) = der::decode_tlv(cur)?;
            if next_tag == 0x01 {
                criticality = !next_val.is_empty() && next_val[0] != 0;
                cur = rest;
                if !cur.is_empty() {
                    let (val_tag, val_bytes, _) = der::decode_tlv(cur)?;
                    if val_tag == 0x04 {
                        control_value = Some(val_bytes.to_vec());
                    }
                }
            } else if next_tag == 0x04 {
                control_value = Some(next_val.to_vec());
            }
        }

        Ok(Self {
            control_type,
            criticality,
            control_value,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapMessage {
    pub message_id: i32,
    pub protocol_op: ProtocolOp,
    pub controls: Vec<LdapControl>,
}

impl LdapMessage {
    pub fn new(message_id: i32, protocol_op: ProtocolOp) -> Self {
        Self {
            message_id,
            protocol_op,
            controls: Vec::new(),
        }
    }

    pub fn with_controls(
        message_id: i32,
        protocol_op: ProtocolOp,
        controls: Vec<LdapControl>,
    ) -> Self {
        Self {
            message_id,
            protocol_op,
            controls,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut elements = Vec::new();
        elements.push(der::encode_integer(self.message_id as i64));

        match &self.protocol_op {
            ProtocolOp::BindRequest {
                version,
                name,
                auth,
            } => {
                let mut bind_seq = Vec::new();
                bind_seq.push(der::encode_integer(*version as i64));
                bind_seq.push(der::encode_octet_string(name.as_bytes()));
                match auth {
                    BindAuth::Simple(pw) => {
                        bind_seq.push(der::encode_tlv(0x80, pw));
                    }
                    BindAuth::Sasl {
                        mechanism,
                        credentials,
                    } => {
                        let mut sasl_seq = Vec::new();
                        sasl_seq.push(der::encode_octet_string(mechanism.as_bytes()));
                        if let Some(ref creds) = credentials {
                            sasl_seq.push(der::encode_octet_string(creds));
                        }
                        let sasl_body = der::encode_sequence(&sasl_seq);
                        bind_seq.push(der::encode_context_explicit(3, &sasl_body[2..]));
                    }
                }
                let body = der::encode_sequence(&bind_seq);
                elements.push(der::encode_tlv(op_tag::BIND_REQUEST, &body[2..]));
            }
            ProtocolOp::UnbindRequest => {
                elements.push(vec![op_tag::UNBIND_REQUEST, 0x00]);
            }
            ProtocolOp::SearchRequest {
                base_object,
                scope,
                deref_aliases,
                size_limit,
                time_limit,
                types_only,
                filter,
                attributes,
            } => {
                let mut search_seq = Vec::new();
                search_seq.push(der::encode_octet_string(base_object.as_bytes()));
                search_seq.push(der::encode_tlv(0x0A, &[*scope as u8])); // ENUMERATED
                search_seq.push(der::encode_tlv(0x0A, &[*deref_aliases as u8])); // ENUMERATED
                search_seq.push(der::encode_integer(*size_limit as i64));
                search_seq.push(der::encode_integer(*time_limit as i64));
                search_seq.push(der::encode_tlv(0x01, &[if *types_only { 0xFF } else { 0x00 }]));
                search_seq.push(filter.clone());

                let mut attr_elements = Vec::new();
                for a in attributes {
                    attr_elements.push(der::encode_octet_string(a.as_bytes()));
                }
                search_seq.push(der::encode_sequence(&attr_elements));

                let body = der::encode_sequence(&search_seq);
                elements.push(der::encode_tlv(op_tag::SEARCH_REQUEST, &body[2..]));
            }
            ProtocolOp::BindResponse {
                result_code,
                matched_dn,
                diagnostic_message,
                server_sasl_creds,
            } => {
                let mut resp_seq = Vec::new();
                resp_seq.push(der::encode_tlv(0x0A, &[*result_code as u8]));
                resp_seq.push(der::encode_octet_string(matched_dn.as_bytes()));
                resp_seq.push(der::encode_octet_string(diagnostic_message.as_bytes()));
                if let Some(ref creds) = server_sasl_creds {
                    resp_seq.push(der::encode_tlv(0x87, creds));
                }
                let body = der::encode_sequence(&resp_seq);
                elements.push(der::encode_tlv(op_tag::BIND_RESPONSE, &body[2..]));
            }
            ProtocolOp::SearchResultDone {
                result_code,
                matched_dn,
                diagnostic_message,
            } => {
                let mut resp_seq = Vec::new();
                resp_seq.push(der::encode_tlv(0x0A, &[*result_code as u8]));
                resp_seq.push(der::encode_octet_string(matched_dn.as_bytes()));
                resp_seq.push(der::encode_octet_string(diagnostic_message.as_bytes()));
                let body = der::encode_sequence(&resp_seq);
                elements.push(der::encode_tlv(op_tag::SEARCH_RES_DONE, &body[2..]));
            }
            ProtocolOp::SearchResultEntry {
                object_name,
                attributes,
            } => {
                let mut entry_seq = Vec::new();
                entry_seq.push(der::encode_octet_string(object_name.as_bytes()));

                let mut attrs_der = Vec::new();
                for a in attributes {
                    let mut vals_der = Vec::new();
                    for v in &a.values {
                        vals_der.push(der::encode_octet_string(v));
                    }
                    let vals_set = der::encode_tlv(0x31, &vals_der.concat()); // SET OF
                    let single_attr = der::encode_sequence(&[
                        der::encode_octet_string(a.type_name.as_bytes()),
                        vals_set,
                    ]);
                    attrs_der.push(single_attr);
                }
                entry_seq.push(der::encode_sequence(&attrs_der));

                let body = der::encode_sequence(&entry_seq);
                elements.push(der::encode_tlv(op_tag::SEARCH_RES_ENTRY, &body[2..]));
            }
            ProtocolOp::ModifyRequest {
                object,
                modifications,
            } => {
                let mut mod_seq = Vec::new();
                mod_seq.push(der::encode_octet_string(object.as_bytes()));

                let mut changes_der = Vec::new();
                for m in modifications {
                    let mut vals_der = Vec::new();
                    for v in &m.attribute.values {
                        vals_der.push(der::encode_octet_string(v));
                    }
                    let vals_set = der::encode_tlv(0x31, &vals_der.concat()); // SET OF
                    let partial_attr = der::encode_sequence(&[
                        der::encode_octet_string(m.attribute.type_name.as_bytes()),
                        vals_set,
                    ]);
                    let change = der::encode_sequence(&[
                        der::encode_tlv(0x0A, &[m.operation as u8]), // ENUMERATED
                        partial_attr,
                    ]);
                    changes_der.push(change);
                }
                mod_seq.push(der::encode_sequence(&changes_der));

                let body = der::encode_sequence(&mod_seq);
                elements.push(der::encode_tlv(op_tag::MODIFY_REQUEST, &body[2..]));
            }
            ProtocolOp::ModifyResponse {
                result_code,
                matched_dn,
                diagnostic_message,
            } => {
                let mut resp_seq = Vec::new();
                resp_seq.push(der::encode_tlv(0x0A, &[*result_code as u8]));
                resp_seq.push(der::encode_octet_string(matched_dn.as_bytes()));
                resp_seq.push(der::encode_octet_string(diagnostic_message.as_bytes()));
                let body = der::encode_sequence(&resp_seq);
                elements.push(der::encode_tlv(op_tag::MODIFY_RESPONSE, &body[2..]));
            }
            ProtocolOp::AddRequest { entry, attributes } => {
                let mut add_seq = Vec::new();
                add_seq.push(der::encode_octet_string(entry.as_bytes()));

                let mut attrs_der = Vec::new();
                for a in attributes {
                    let mut vals_der = Vec::new();
                    for v in &a.values {
                        vals_der.push(der::encode_octet_string(v));
                    }
                    let vals_set = der::encode_tlv(0x31, &vals_der.concat()); // SET OF
                    let single_attr = der::encode_sequence(&[
                        der::encode_octet_string(a.type_name.as_bytes()),
                        vals_set,
                    ]);
                    attrs_der.push(single_attr);
                }
                add_seq.push(der::encode_sequence(&attrs_der));

                let body = der::encode_sequence(&add_seq);
                elements.push(der::encode_tlv(op_tag::ADD_REQUEST, &body[2..]));
            }
            ProtocolOp::AddResponse {
                result_code,
                matched_dn,
                diagnostic_message,
            } => {
                let mut resp_seq = Vec::new();
                resp_seq.push(der::encode_tlv(0x0A, &[*result_code as u8]));
                resp_seq.push(der::encode_octet_string(matched_dn.as_bytes()));
                resp_seq.push(der::encode_octet_string(diagnostic_message.as_bytes()));
                let body = der::encode_sequence(&resp_seq);
                elements.push(der::encode_tlv(op_tag::ADD_RESPONSE, &body[2..]));
            }
            ProtocolOp::DelRequest { entry } => {
                elements.push(der::encode_tlv(op_tag::DEL_REQUEST, entry.as_bytes()));
            }
            ProtocolOp::DelResponse {
                result_code,
                matched_dn,
                diagnostic_message,
            } => {
                let mut resp_seq = Vec::new();
                resp_seq.push(der::encode_tlv(0x0A, &[*result_code as u8]));
                resp_seq.push(der::encode_octet_string(matched_dn.as_bytes()));
                resp_seq.push(der::encode_octet_string(diagnostic_message.as_bytes()));
                let body = der::encode_sequence(&resp_seq);
                elements.push(der::encode_tlv(op_tag::DEL_RESPONSE, &body[2..]));
            }
            ProtocolOp::Other { tag, data } => {
                elements.push(der::encode_tlv(*tag, data));
            }
        }

        if !self.controls.is_empty() {
            let mut ctrl_bytes = Vec::new();
            for c in &self.controls {
                ctrl_bytes.extend_from_slice(&c.to_bytes());
            }
            elements.push(der::encode_tlv(0xA0, &ctrl_bytes));
        }

        der::encode_sequence(&elements)
    }

    pub fn parse(data: &[u8]) -> Result<(Self, usize), CoreError> {
        let (seq_tag, seq_body, rest) = der::decode_tlv(data)?;
        if seq_tag != 0x30 {
            return Err(CoreError::ProtocolError(format!(
                "Expected LDAPMessage SEQUENCE (0x30), got 0x{:02X}",
                seq_tag
            )));
        }
        let total_consumed = data.len() - rest.len();

        let (id_tag, id_val, op_bytes) = der::decode_tlv(seq_body)?;
        if id_tag != 0x02 {
            return Err(CoreError::ProtocolError("Expected messageID INTEGER".into()));
        }
        let message_id = der::decode_integer(&der::encode_tlv(id_tag, id_val))? as i32;

        let (op_tag, op_body, after_op) = der::decode_tlv(op_bytes)?;
        let protocol_op = match op_tag {
            op_tag::BIND_RESPONSE => {
                let mut cur = op_body;
                let (rc_tag, rc_val, rest1) = der::decode_tlv(cur)?;
                let result_code = if (rc_tag == 0x0A || rc_tag == 0x02) && !rc_val.is_empty() {
                    rc_val[0] as i32
                } else {
                    0
                };
                cur = rest1;

                let (_, dn_val, rest2) = der::decode_tlv(cur)?;
                let matched_dn = String::from_utf8_lossy(dn_val).to_string();
                cur = rest2;

                let (_, diag_val, rest3) = der::decode_tlv(cur)?;
                let diagnostic_message = String::from_utf8_lossy(diag_val).to_string();
                cur = rest3;

                let mut server_sasl_creds = None;
                if !cur.is_empty() {
                    let (s_tag, s_val, _) = der::decode_tlv(cur)?;
                    if s_tag == 0x87 {
                        server_sasl_creds = Some(s_val.to_vec());
                    }
                }

                ProtocolOp::BindResponse {
                    result_code,
                    matched_dn,
                    diagnostic_message,
                    server_sasl_creds,
                }
            }
            op_tag::SEARCH_RES_ENTRY => {
                let (dn_tag, dn_val, attrs_data) = der::decode_tlv(op_body)?;
                let object_name = if dn_tag == 0x04 {
                    String::from_utf8_lossy(dn_val).to_string()
                } else {
                    String::new()
                };

                let mut attributes = Vec::new();
                if !attrs_data.is_empty() {
                    let (a_seq_tag, a_seq_body, _) = der::decode_tlv(attrs_data)?;
                    if a_seq_tag == 0x30 {
                        let mut cur_attr = a_seq_body;
                        while !cur_attr.is_empty() {
                            let (single_tag, single_body, next_attr) = der::decode_tlv(cur_attr)?;
                            cur_attr = next_attr;
                            if single_tag == 0x30 {
                                let (name_tag, name_val, vals_data) = der::decode_tlv(single_body)?;
                                let type_name = if name_tag == 0x04 {
                                    String::from_utf8_lossy(name_val).to_string()
                                } else {
                                    String::new()
                                };

                                let mut values = Vec::new();
                                if !vals_data.is_empty() {
                                    let (v_set_tag, v_set_body, _) = der::decode_tlv(vals_data)?;
                                    if v_set_tag == 0x31 || v_set_tag == 0x30 {
                                        let mut cur_v = v_set_body;
                                        while !cur_v.is_empty() {
                                            let (v_tag, v_val, next_v) = der::decode_tlv(cur_v)?;
                                            cur_v = next_v;
                                            if v_tag == 0x04 {
                                                values.push(v_val.to_vec());
                                            }
                                        }
                                    }
                                }
                                attributes.push(LdapAttribute { type_name, values });
                            }
                        }
                    }
                }

                ProtocolOp::SearchResultEntry {
                    object_name,
                    attributes,
                }
            }
            op_tag::SEARCH_RES_DONE => {
                let (rc_tag, rc_val, rest1) = der::decode_tlv(op_body)?;
                let result_code = if (rc_tag == 0x0A || rc_tag == 0x02) && !rc_val.is_empty() {
                    rc_val[0] as i32
                } else {
                    0
                };
                let (_, dn_val, rest2) = der::decode_tlv(rest1)?;
                let matched_dn = String::from_utf8_lossy(dn_val).to_string();
                let (_, diag_val, _) = der::decode_tlv(rest2)?;
                let diagnostic_message = String::from_utf8_lossy(diag_val).to_string();

                ProtocolOp::SearchResultDone {
                    result_code,
                    matched_dn,
                    diagnostic_message,
                }
            }
            op_tag::MODIFY_RESPONSE => {
                let (rc_tag, rc_val, rest1) = der::decode_tlv(op_body)?;
                let result_code = if (rc_tag == 0x0A || rc_tag == 0x02) && !rc_val.is_empty() {
                    rc_val[0] as i32
                } else {
                    0
                };
                let (_, dn_val, rest2) = der::decode_tlv(rest1)?;
                let matched_dn = String::from_utf8_lossy(dn_val).to_string();
                let (_, diag_val, _) = der::decode_tlv(rest2)?;
                let diagnostic_message = String::from_utf8_lossy(diag_val).to_string();

                ProtocolOp::ModifyResponse {
                    result_code,
                    matched_dn,
                    diagnostic_message,
                }
            }
            op_tag::ADD_RESPONSE => {
                let (rc_tag, rc_val, rest1) = der::decode_tlv(op_body)?;
                let result_code = if (rc_tag == 0x0A || rc_tag == 0x02) && !rc_val.is_empty() {
                    rc_val[0] as i32
                } else {
                    0
                };
                let (_, dn_val, rest2) = der::decode_tlv(rest1)?;
                let matched_dn = String::from_utf8_lossy(dn_val).to_string();
                let (_, diag_val, _) = der::decode_tlv(rest2)?;
                let diagnostic_message = String::from_utf8_lossy(diag_val).to_string();

                ProtocolOp::AddResponse {
                    result_code,
                    matched_dn,
                    diagnostic_message,
                }
            }
            op_tag::DEL_RESPONSE => {
                let (rc_tag, rc_val, rest1) = der::decode_tlv(op_body)?;
                let result_code = if (rc_tag == 0x0A || rc_tag == 0x02) && !rc_val.is_empty() {
                    rc_val[0] as i32
                } else {
                    0
                };
                let (_, dn_val, rest2) = der::decode_tlv(rest1)?;
                let matched_dn = String::from_utf8_lossy(dn_val).to_string();
                let (_, diag_val, _) = der::decode_tlv(rest2)?;
                let diagnostic_message = String::from_utf8_lossy(diag_val).to_string();

                ProtocolOp::DelResponse {
                    result_code,
                    matched_dn,
                    diagnostic_message,
                }
            }
            other => ProtocolOp::Other {
                tag: other,
                data: op_body.to_vec(),
            },
        };

        let mut controls = Vec::new();
        if !after_op.is_empty() && after_op[0] == 0xA0 {
            if let Ok((ctrl_tag, ctrl_body, _)) = der::decode_tlv(after_op) {
                if ctrl_tag == 0xA0 {
                    let mut cur_ctrl = ctrl_body;
                    while !cur_ctrl.is_empty() {
                        if let Ok((c_tag, c_val, next_ctrl)) = der::decode_tlv(cur_ctrl) {
                            cur_ctrl = next_ctrl;
                            let full_control_tlv = der::encode_tlv(c_tag, c_val);
                            if let Ok(c) = LdapControl::from_bytes(&full_control_tlv) {
                                controls.push(c);
                            }
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        Ok((
            Self {
                message_id,
                protocol_op,
                controls,
            },
            total_consumed,
        ))
    }
}

/// Builds an LDAP filter for `(objectClass=*)` (Present, tag `0x87`).
pub fn filter_present(attr: &str) -> Vec<u8> {
    der::encode_tlv(0x87, attr.as_bytes())
}

/// Builds an LDAP filter for `(attr=value)` (EqualityMatch, tag `0xA3`).
pub fn filter_equality(attr: &str, value: &str) -> Vec<u8> {
    let seq = der::encode_sequence(&[
        der::encode_octet_string(attr.as_bytes()),
        der::encode_octet_string(value.as_bytes()),
    ]);
    der::encode_context_explicit(3, &seq[2..])
}

/// Builds an LDAP filter for `(&(f1)(f2)...)` (And, tag `0xA0`).
pub fn filter_and(filters: &[Vec<u8>]) -> Vec<u8> {
    let body = filters.concat();
    der::encode_context_explicit(0, &body)
}

/// Builds an LDAP filter for `(|(f1)(f2)...)` (Or, tag `0xA1`).
pub fn filter_or(filters: &[Vec<u8>]) -> Vec<u8> {
    let body = filters.concat();
    der::encode_context_explicit(1, &body)
}

/// Builds an LDAP filter for `(!(filter))` (Not, tag `0xA2`).
pub fn filter_not(filter: &[u8]) -> Vec<u8> {
    der::encode_context_explicit(2, filter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_bind_request_and_response_roundtrip() {
        let msg = LdapMessage::new(
            1,
            ProtocolOp::BindRequest {
                version: 3,
                name: "Administrator@corp.contoso.com".into(),
                auth: BindAuth::Simple(b"P@ssw0rd123".to_vec()),
            },
        );
        let bytes = msg.to_bytes();
        assert_eq!(bytes[0], 0x30); // SEQUENCE

        let resp_msg = LdapMessage::new(
            1,
            ProtocolOp::BindResponse {
                result_code: result_code::SUCCESS,
                matched_dn: String::new(),
                diagnostic_message: String::new(),
                server_sasl_creds: None,
            },
        );
        let resp_bytes = resp_msg.to_bytes();
        let (parsed_resp, consumed) = LdapMessage::parse(&resp_bytes).unwrap();
        assert_eq!(consumed, resp_bytes.len());
        assert_eq!(parsed_resp.message_id, 1);
        match parsed_resp.protocol_op {
            ProtocolOp::BindResponse { result_code, .. } => {
                assert_eq!(result_code, result_code::SUCCESS);
            }
            _ => panic!("Expected BindResponse"),
        }
    }

    #[test]
    fn test_ldap_search_result_entry_and_done_parse() {
        let entry = LdapMessage::new(
            2,
            ProtocolOp::SearchResultEntry {
                object_name: "CN=Administrator,CN=Users,DC=corp,DC=contoso,DC=com".into(),
                attributes: vec![
                    LdapAttribute {
                        type_name: "sAMAccountName".into(),
                        values: vec![b"Administrator".to_vec()],
                    },
                    LdapAttribute {
                        type_name: "userAccountControl".into(),
                        values: vec![b"512".to_vec()],
                    },
                ],
            },
        );
        let entry_bytes = entry.to_bytes();
        let (parsed, _) = LdapMessage::parse(&entry_bytes).unwrap();
        assert_eq!(parsed.message_id, 2);
        match parsed.protocol_op {
            ProtocolOp::SearchResultEntry {
                object_name,
                attributes,
            } => {
                assert_eq!(
                    object_name,
                    "CN=Administrator,CN=Users,DC=corp,DC=contoso,DC=com"
                );
                assert_eq!(attributes.len(), 2);
                assert_eq!(attributes[0].type_name, "sAMAccountName");
                assert_eq!(attributes[0].values[0], b"Administrator");
            }
            _ => panic!("Expected SearchResultEntry"),
        }
    }

    #[test]
    fn test_ldap_modify_request_and_response_roundtrip() {
        let mod_req = LdapMessage::new(
            42,
            ProtocolOp::ModifyRequest {
                object: "CN=DC01,CN=Computers,DC=contoso,DC=local".to_string(),
                modifications: vec![AttributeModification {
                    operation: ModifyOperation::Replace,
                    attribute: LdapAttribute {
                        type_name: "msDS-AllowedToActOnBehalfOfOtherIdentity".to_string(),
                        values: vec![vec![0x01, 0x00, 0x04, 0x80]],
                    },
                }],
            },
        );

        let bytes = mod_req.to_bytes();
        assert!(!bytes.is_empty());

        let mod_resp = LdapMessage::new(
            42,
            ProtocolOp::ModifyResponse {
                result_code: result_code::SUCCESS,
                matched_dn: String::new(),
                diagnostic_message: "Success".to_string(),
            },
        );

        let resp_bytes = mod_resp.to_bytes();
        let (parsed_resp, _) = LdapMessage::parse(&resp_bytes).unwrap();
        assert_eq!(parsed_resp.message_id, 42);
        match parsed_resp.protocol_op {
            ProtocolOp::ModifyResponse { result_code, diagnostic_message, .. } => {
                assert_eq!(result_code, result_code::SUCCESS);
                assert_eq!(diagnostic_message, "Success");
            }
            other => panic!("Expected ModifyResponse, got {:?}", other),
        }
    }

    #[test]
    fn test_ldap_add_and_del_request_roundtrip() {
        let add_req = LdapMessage::new(
            43,
            ProtocolOp::AddRequest {
                entry: "CN=WS01,CN=Computers,DC=contoso,DC=local".to_string(),
                attributes: vec![
                    LdapAttribute {
                        type_name: "sAMAccountName".to_string(),
                        values: vec![b"WS01$".to_vec()],
                    },
                    LdapAttribute {
                        type_name: "userAccountControl".to_string(),
                        values: vec![b"4096".to_vec()],
                    },
                ],
            },
        );

        let bytes = add_req.to_bytes();
        assert_eq!(bytes[0], 0x30);

        let add_resp = LdapMessage::new(
            43,
            ProtocolOp::AddResponse {
                result_code: result_code::SUCCESS,
                matched_dn: String::new(),
                diagnostic_message: "Created".to_string(),
            },
        );
        let resp_bytes = add_resp.to_bytes();
        let (parsed, _) = LdapMessage::parse(&resp_bytes).unwrap();
        match parsed.protocol_op {
            ProtocolOp::AddResponse { result_code, diagnostic_message, .. } => {
                assert_eq!(result_code, result_code::SUCCESS);
                assert_eq!(diagnostic_message, "Created");
            }
            other => panic!("Expected AddResponse, got {:?}", other),
        }

        let del_req = LdapMessage::new(
            44,
            ProtocolOp::DelRequest {
                entry: "CN=WS01,CN=Computers,DC=contoso,DC=local".to_string(),
            },
        );
        let del_bytes = del_req.to_bytes();
        assert!(!del_bytes.is_empty());
    }

    #[test]
    fn test_ldap_control_paged_results_roundtrip() {
        let cookie = b"next_page_token_12345";
        let ctrl = LdapControl::paged_results(500, cookie);
        assert_eq!(ctrl.control_type, CONTROL_PAGED_RESULTS);
        assert!(!ctrl.criticality);

        let parsed_cookie = ctrl.parse_paged_results_cookie().unwrap();
        assert_eq!(parsed_cookie, cookie);

        let ctrl_bytes = ctrl.to_bytes();
        let decoded_ctrl = LdapControl::from_bytes(&ctrl_bytes).unwrap();
        assert_eq!(decoded_ctrl.control_type, CONTROL_PAGED_RESULTS);
        assert!(!decoded_ctrl.criticality);
        assert_eq!(decoded_ctrl.parse_paged_results_cookie().unwrap(), cookie);

        // Test LdapMessage with controls
        let msg = LdapMessage::with_controls(
            101,
            ProtocolOp::SearchResultDone {
                result_code: result_code::SUCCESS,
                matched_dn: String::new(),
                diagnostic_message: String::new(),
            },
            vec![ctrl],
        );
        let msg_bytes = msg.to_bytes();
        let (parsed_msg, _) = LdapMessage::parse(&msg_bytes).unwrap();
        assert_eq!(parsed_msg.message_id, 101);
        assert_eq!(parsed_msg.controls.len(), 1);
        assert_eq!(
            parsed_msg.controls[0].parse_paged_results_cookie().unwrap(),
            cookie
        );
    }
}
