//! `client`: Active Directory LDAP client engine supporting RFC 4511 BER protocol operations.

use crate::asn1::{op_tag, result_code, BindAuth, LdapMessage, ProtocolOp, SearchScope};
use impacket_core::CoreError;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// An LDAP directory entry returned from a search query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapEntry {
    pub dn: String,
    pub attributes: HashMap<String, Vec<Vec<u8>>>,
}

impl LdapEntry {
    /// Returns the raw binary values for an attribute (case-insensitive name).
    pub fn get_raw(&self, name: &str) -> Option<&[Vec<u8>]> {
        for (k, v) in &self.attributes {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.as_slice());
            }
        }
        None
    }

    /// Returns the first raw value for an attribute.
    pub fn get_first_raw(&self, name: &str) -> Option<&[u8]> {
        self.get_raw(name).and_then(|vals| vals.first().map(|v| v.as_slice()))
    }

    /// Returns the first value of an attribute decoded as a UTF-8 string.
    pub fn get_string(&self, name: &str) -> Option<String> {
        self.get_first_raw(name).map(|b| String::from_utf8_lossy(b).into_owned())
    }

    /// Returns all values of an attribute decoded as UTF-8 strings.
    pub fn get_all_strings(&self, name: &str) -> Vec<String> {
        self.get_raw(name)
            .map(|vals| {
                vals.iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Reads a complete RFC 4511 LDAP BER message from a stream.
pub fn read_ldap_message<R: Read>(reader: &mut R) -> Result<LdapMessage, CoreError> {
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).map_err(|e| {
        CoreError::IoError(format!("Failed to read LDAP message sequence header: {}", e))
    })?;

    if header[0] != 0x30 {
        return Err(CoreError::ProtocolError(format!(
            "Invalid LDAP BER tag: expected 0x30 (SEQUENCE), got 0x{:02X}",
            header[0]
        )));
    }

    let (body_len, mut full_pdu) = if header[1] < 0x80 {
        let len = header[1] as usize;
        let pdu = vec![header[0], header[1]];
        (len, pdu)
    } else {
        let num_octets = (header[1] & 0x7F) as usize;
        if num_octets == 0 || num_octets > 4 {
            return Err(CoreError::ProtocolError(format!(
                "Unsupported BER length octet count: {}",
                num_octets
            )));
        }
        let mut len_bytes = vec![0u8; num_octets];
        reader.read_exact(&mut len_bytes).map_err(|e| {
            CoreError::IoError(format!("Failed to read BER multi-byte length: {}", e))
        })?;

        let mut len: usize = 0;
        for &b in &len_bytes {
            len = (len << 8) | (b as usize);
        }

        let mut pdu = Vec::with_capacity(2 + num_octets + len);
        pdu.push(header[0]);
        pdu.push(header[1]);
        pdu.extend_from_slice(&len_bytes);
        (len, pdu)
    };

    let pdu_header_len = full_pdu.len();
    full_pdu.resize(pdu_header_len + body_len, 0);
    reader
        .read_exact(&mut full_pdu[pdu_header_len..])
        .map_err(|e| {
            CoreError::IoError(format!(
                "Failed to read LDAP message body (expected {} bytes): {}",
                body_len, e
            ))
        })?;

    let (msg, _) = LdapMessage::parse(&full_pdu)?;
    Ok(msg)
}

/// Client session for Active Directory LDAP.
pub struct LdapClient<S: Read + Write> {
    stream: S,
    next_msg_id: i32,
}

impl LdapClient<TcpStream> {
    /// Connects to an LDAP server over TCP (default port 389).
    pub fn connect(target: &str, timeout: Duration) -> Result<Self, CoreError> {
        let addr_str = if target.contains(':') {
            target.to_string()
        } else {
            format!("{}:389", target)
        };

        let addrs: Vec<_> = addr_str
            .to_socket_addrs()
            .map_err(|e| CoreError::IoError(format!("Failed to resolve LDAP host '{}': {}", target, e)))?
            .collect();

        if addrs.is_empty() {
            return Err(CoreError::IoError(format!(
                "No socket addresses resolved for '{}'",
                target
            )));
        }

        let stream = TcpStream::connect_timeout(&addrs[0], timeout).map_err(|e| {
            CoreError::IoError(format!("Failed to connect to LDAP server at '{}': {}", addr_str, e))
        })?;

        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();

        Ok(Self::new(stream))
    }
}

impl<S: Read + Write> LdapClient<S> {
    /// Creates an LDAP client over an existing stream (e.g. TCP or TLS).
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            next_msg_id: 1,
        }
    }

    fn next_id(&mut self) -> i32 {
        let id = self.next_msg_id;
        self.next_msg_id += 1;
        id
    }

    /// Sends a simple bind request with plaintext DN and password.
    pub fn bind_simple(&mut self, bind_dn: &str, password: &str) -> Result<(), CoreError> {
        let msg_id = self.next_id();
        let req = LdapMessage::new(
            msg_id,
            ProtocolOp::BindRequest {
                version: 3,
                name: bind_dn.to_string(),
                auth: BindAuth::Simple(password.as_bytes().to_vec()),
            },
        );

        self.stream
            .write_all(&req.to_bytes())
            .map_err(|e| CoreError::IoError(format!("Failed to send LDAP BindRequest: {}", e)))?;
        self.stream
            .flush()
            .map_err(|e| CoreError::IoError(format!("Failed to flush stream: {}", e)))?;

        let resp = read_ldap_message(&mut self.stream)?;
        match resp.protocol_op {
            ProtocolOp::BindResponse {
                result_code: rc,
                diagnostic_message,
                ..
            } => {
                if rc == result_code::SUCCESS {
                    Ok(())
                } else {
                    Err(CoreError::ProtocolError(format!(
                        "LDAP Bind failed with result code {} ({}): {}",
                        rc,
                        ldap_result_string(rc),
                        diagnostic_message
                    )))
                }
            }
            other => Err(CoreError::ProtocolError(format!(
                "Unexpected LDAP response to BindRequest: {:?}",
                other
            ))),
        }
    }

    /// Sends a SASL GSS-SPNEGO bind request.
    pub fn bind_sasl_spnego(
        &mut self,
        spnego_token: &[u8],
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let msg_id = self.next_id();
        let req = LdapMessage::new(
            msg_id,
            ProtocolOp::BindRequest {
                version: 3,
                name: String::new(),
                auth: BindAuth::Sasl {
                    mechanism: "GSS-SPNEGO".to_string(),
                    credentials: Some(spnego_token.to_vec()),
                },
            },
        );

        self.stream
            .write_all(&req.to_bytes())
            .map_err(|e| CoreError::IoError(format!("Failed to send SASL BindRequest: {}", e)))?;
        self.stream
            .flush()
            .map_err(|e| CoreError::IoError(format!("Failed to flush stream: {}", e)))?;

        let resp = read_ldap_message(&mut self.stream)?;
        match resp.protocol_op {
            ProtocolOp::BindResponse {
                result_code: rc,
                diagnostic_message,
                server_sasl_creds,
                ..
            } => {
                const SASL_BIND_IN_PROGRESS: i32 = 14;
                if rc == result_code::SUCCESS || rc == SASL_BIND_IN_PROGRESS {
                    Ok(server_sasl_creds)
                } else {
                    Err(CoreError::ProtocolError(format!(
                        "LDAP SASL Bind failed with result code {} ({}): {}",
                        rc,
                        ldap_result_string(rc),
                        diagnostic_message
                    )))
                }
            }
            other => Err(CoreError::ProtocolError(format!(
                "Unexpected response to SASL BindRequest: {:?}",
                other
            ))),
        }
    }

    /// Performs an LDAP search query and collects all matching entries.
    ///
    /// Automatically employs RFC 2696 Simple Paged Results (page size 1,000) so large
    /// directories (e.g. >1,000 users or computers) are seamlessly enumerated without
    /// triggering Active Directory's `LDAP_SIZE_LIMIT_EXCEEDED` (error 4).
    pub fn search(
        &mut self,
        base_dn: &str,
        scope: SearchScope,
        filter: &[u8],
        attributes: &[&str],
    ) -> Result<Vec<LdapEntry>, CoreError> {
        self.search_paged(base_dn, scope, filter, attributes, 1000)
    }

    /// Performs an unpaged, single-shot LDAP search query.
    pub fn search_unpaged(
        &mut self,
        base_dn: &str,
        scope: SearchScope,
        filter: &[u8],
        attributes: &[&str],
    ) -> Result<Vec<LdapEntry>, CoreError> {
        let msg_id = self.next_id();
        let req = LdapMessage::new(
            msg_id,
            ProtocolOp::SearchRequest {
                base_object: base_dn.to_string(),
                scope,
                deref_aliases: 0, // neverDerefAliases
                size_limit: 0,    // no limit
                time_limit: 0,    // no limit
                types_only: false,
                filter: filter.to_vec(),
                attributes: attributes.iter().map(|s| s.to_string()).collect(),
            },
        );

        self.stream
            .write_all(&req.to_bytes())
            .map_err(|e| CoreError::IoError(format!("Failed to send LDAP SearchRequest: {}", e)))?;
        self.stream
            .flush()
            .map_err(|e| CoreError::IoError(format!("Failed to flush stream: {}", e)))?;

        let mut entries = Vec::new();

        loop {
            let msg = read_ldap_message(&mut self.stream)?;
            if msg.message_id != msg_id {
                continue;
            }

            match msg.protocol_op {
                ProtocolOp::SearchResultEntry {
                    object_name,
                    attributes: raw_attrs,
                } => {
                    let mut attr_map: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
                    for a in raw_attrs {
                        attr_map.insert(a.type_name, a.values);
                    }
                    entries.push(LdapEntry {
                        dn: object_name,
                        attributes: attr_map,
                    });
                }
                ProtocolOp::SearchResultDone {
                    result_code: rc,
                    diagnostic_message,
                    ..
                } => {
                    if rc == result_code::SUCCESS {
                        break;
                    } else {
                        return Err(CoreError::ProtocolError(format!(
                            "LDAP search completed with error {} ({}): {}",
                            rc,
                            ldap_result_string(rc),
                            diagnostic_message
                        )));
                    }
                }
                ProtocolOp::Other { tag, .. } => {
                    if tag == op_tag::SEARCH_RES_DONE {
                        break;
                    }
                }
                _ => {}
            }
        }

        Ok(entries)
    }

    /// Performs an LDAP search query using RFC 2696 Simple Paged Results to retrieve
    /// all matching entries without hitting Active Directory's 1,000-object limit.
    pub fn search_paged(
        &mut self,
        base_dn: &str,
        scope: SearchScope,
        filter: &[u8],
        attributes: &[&str],
        page_size: u32,
    ) -> Result<Vec<LdapEntry>, CoreError> {
        let mut all_entries = Vec::new();
        let mut cookie = Vec::new();

        loop {
            let msg_id = self.next_id();
            let paged_ctrl = crate::asn1::LdapControl::paged_results(page_size, &cookie);
            let req = LdapMessage::with_controls(
                msg_id,
                ProtocolOp::SearchRequest {
                    base_object: base_dn.to_string(),
                    scope,
                    deref_aliases: 0, // neverDerefAliases
                    size_limit: 0,    // no limit
                    time_limit: 0,    // no limit
                    types_only: false,
                    filter: filter.to_vec(),
                    attributes: attributes.iter().map(|s| s.to_string()).collect(),
                },
                vec![paged_ctrl],
            );

            self.stream
                .write_all(&req.to_bytes())
                .map_err(|e| CoreError::IoError(format!("Failed to send LDAP SearchRequest: {}", e)))?;
            self.stream
                .flush()
                .map_err(|e| CoreError::IoError(format!("Failed to flush stream: {}", e)))?;

            let mut next_cookie: Option<Vec<u8>> = None;

            loop {
                let msg = read_ldap_message(&mut self.stream)?;
                if msg.message_id != msg_id {
                    continue;
                }

                match msg.protocol_op {
                    ProtocolOp::SearchResultEntry {
                        object_name,
                        attributes: raw_attrs,
                    } => {
                        let mut attr_map: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
                        for a in raw_attrs {
                            attr_map.insert(a.type_name, a.values);
                        }
                        all_entries.push(LdapEntry {
                            dn: object_name,
                            attributes: attr_map,
                        });
                    }
                    ProtocolOp::SearchResultDone {
                        result_code: rc,
                        diagnostic_message,
                        ..
                    } => {
                        if rc == result_code::SUCCESS {
                            for ctrl in &msg.controls {
                                if let Some(c) = ctrl.parse_paged_results_cookie() {
                                    next_cookie = Some(c);
                                    break;
                                }
                            }
                            break;
                        } else {
                            return Err(CoreError::ProtocolError(format!(
                                "LDAP search completed with error {} ({}): {}",
                                rc,
                                ldap_result_string(rc),
                                diagnostic_message
                            )));
                        }
                    }
                    ProtocolOp::Other { tag, .. } => {
                        if tag == op_tag::SEARCH_RES_DONE {
                            for ctrl in &msg.controls {
                                if let Some(c) = ctrl.parse_paged_results_cookie() {
                                    next_cookie = Some(c);
                                    break;
                                }
                            }
                            break;
                        }
                    }
                    _ => {}
                }
            }

            match next_cookie {
                Some(c) if !c.is_empty() => {
                    cookie = c;
                }
                _ => break,
            }
        }

        Ok(all_entries)
    }

    /// Modifies attributes of an existing LDAP directory object using RFC 4511 ModifyRequest.
    pub fn modify(
        &mut self,
        object_dn: &str,
        modifications: Vec<crate::asn1::AttributeModification>,
    ) -> Result<(), CoreError> {
        let msg_id = self.next_id();
        let req = LdapMessage::new(
            msg_id,
            ProtocolOp::ModifyRequest {
                object: object_dn.to_string(),
                modifications,
            },
        );

        self.stream
            .write_all(&req.to_bytes())
            .map_err(|e| CoreError::IoError(format!("Failed to send LDAP ModifyRequest: {}", e)))?;
        self.stream
            .flush()
            .map_err(|e| CoreError::IoError(format!("Failed to flush stream: {}", e)))?;

        let resp = read_ldap_message(&mut self.stream)?;
        match resp.protocol_op {
            ProtocolOp::ModifyResponse {
                result_code: rc,
                diagnostic_message,
                ..
            } => {
                if rc == result_code::SUCCESS {
                    Ok(())
                } else {
                    Err(CoreError::ProtocolError(format!(
                        "LDAP Modify failed with result code {} ({}): {}",
                        rc,
                        ldap_result_string(rc),
                        diagnostic_message
                    )))
                }
            }
            other => Err(CoreError::ProtocolError(format!(
                "Unexpected LDAP response to ModifyRequest: {:?}",
                other
            ))),
        }
    }

    /// Creates a new directory entry using RFC 4511 AddRequest.
    pub fn add(&mut self, entry_dn: &str, attributes: Vec<crate::asn1::LdapAttribute>) -> Result<(), CoreError> {
        let msg_id = self.next_id();
        let req = LdapMessage::new(
            msg_id,
            ProtocolOp::AddRequest {
                entry: entry_dn.to_string(),
                attributes,
            },
        );
        self.stream
            .write_all(&req.to_bytes())
            .map_err(|e| CoreError::IoError(format!("Failed to send LDAP AddRequest: {}", e)))?;
        self.stream
            .flush()
            .map_err(|e| CoreError::IoError(format!("Failed to flush stream: {}", e)))?;

        let resp = read_ldap_message(&mut self.stream)?;
        match resp.protocol_op {
            ProtocolOp::AddResponse {
                result_code: rc,
                diagnostic_message,
                ..
            } => {
                if rc == result_code::SUCCESS {
                    Ok(())
                } else {
                    Err(CoreError::ProtocolError(format!(
                        "LDAP Add failed with result code {} ({}): {}",
                        rc,
                        ldap_result_string(rc),
                        diagnostic_message
                    )))
                }
            }
            other => Err(CoreError::ProtocolError(format!(
                "Unexpected LDAP response to AddRequest: {:?}",
                other
            ))),
        }
    }

    /// Removes a directory entry using RFC 4511 DelRequest.
    pub fn delete(&mut self, entry_dn: &str) -> Result<(), CoreError> {
        let msg_id = self.next_id();
        let req = LdapMessage::new(
            msg_id,
            ProtocolOp::DelRequest {
                entry: entry_dn.to_string(),
            },
        );
        self.stream
            .write_all(&req.to_bytes())
            .map_err(|e| CoreError::IoError(format!("Failed to send LDAP DelRequest: {}", e)))?;
        self.stream
            .flush()
            .map_err(|e| CoreError::IoError(format!("Failed to flush stream: {}", e)))?;

        let resp = read_ldap_message(&mut self.stream)?;
        match resp.protocol_op {
            ProtocolOp::DelResponse {
                result_code: rc,
                diagnostic_message,
                ..
            } => {
                if rc == result_code::SUCCESS {
                    Ok(())
                } else {
                    Err(CoreError::ProtocolError(format!(
                        "LDAP Delete failed with result code {} ({}): {}",
                        rc,
                        ldap_result_string(rc),
                        diagnostic_message
                    )))
                }
            }
            other => Err(CoreError::ProtocolError(format!(
                "Unexpected LDAP response to DelRequest: {:?}",
                other
            ))),
        }
    }

    /// Closes the LDAP session gracefully by sending an UnbindRequest.
    pub fn unbind(&mut self) -> Result<(), CoreError> {
        let msg_id = self.next_id();
        let req = LdapMessage::new(msg_id, ProtocolOp::UnbindRequest);
        self.stream
            .write_all(&req.to_bytes())
            .map_err(|e| CoreError::IoError(format!("Failed to send UnbindRequest: {}", e)))?;
        self.stream
            .flush()
            .map_err(|e| CoreError::IoError(format!("Failed to flush stream: {}", e)))?;
        Ok(())
    }
}

fn ldap_result_string(code: i32) -> &'static str {
    match code {
        result_code::SUCCESS => "Success",
        result_code::OPERATIONS_ERROR => "OperationsError",
        result_code::PROTOCOL_ERROR => "ProtocolError",
        result_code::TIME_LIMIT_EXCEEDED => "TimeLimitExceeded",
        result_code::SIZE_LIMIT_EXCEEDED => "SizeLimitExceeded",
        result_code::AUTH_METHOD_NOT_SUPPORTED => "AuthMethodNotSupported",
        result_code::INVALID_CREDENTIALS => "InvalidCredentials",
        result_code::INSUFFICIENT_ACCESS_RIGHTS => "InsufficientAccessRights",
        result_code::BUSY => "Busy",
        result_code::UNAVAILABLE => "Unavailable",
        14 => "SaslBindInProgress",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_ldap_message_roundtrip() {
        let orig = LdapMessage::new(
            42,
            ProtocolOp::SearchResultDone {
                result_code: result_code::SUCCESS,
                matched_dn: String::new(),
                diagnostic_message: String::new(),
            },
        );
        let bytes = orig.to_bytes();
        let mut cursor = Cursor::new(bytes);

        let read_back = read_ldap_message(&mut cursor).unwrap();
        assert_eq!(read_back.message_id, 42);
        match read_back.protocol_op {
            ProtocolOp::SearchResultDone { result_code, .. } => {
                assert_eq!(result_code, result_code::SUCCESS);
            }
            _ => panic!("Expected SearchResultDone"),
        }
    }

    #[test]
    fn test_ldap_entry_attribute_helpers() {
        let mut attrs = HashMap::new();
        attrs.insert("sAMAccountName".to_string(), vec![b"jdoe".to_vec()]);
        attrs.insert(
            "mail".to_string(),
            vec![b"jdoe@corp.contoso.com".to_vec(), b"john.doe@corp.contoso.com".to_vec()],
        );

        let entry = LdapEntry {
            dn: "CN=John Doe,CN=Users,DC=corp,DC=contoso,DC=com".to_string(),
            attributes: attrs,
        };

        assert_eq!(entry.get_string("samaccountname").as_deref(), Some("jdoe"));
        assert_eq!(entry.get_string("mail").as_deref(), Some("jdoe@corp.contoso.com"));
        let mails = entry.get_all_strings("mail");
        assert_eq!(mails.len(), 2);
        assert_eq!(mails[1], "john.doe@corp.contoso.com");
        assert_eq!(entry.get_string("nonexistent"), None);
    }
}
