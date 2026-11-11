//! `ldap`: LDAP protocol adapter for NTLM authentication relaying (`impacket/examples/ntlmrelayx/clients/ldaprelayclient.py`).

use impacket_core::CoreError;
use impacket_ldap::{BindAuth, LdapMessage, ProtocolOp};

/// Wraps an NTLM / SPNEGO authentication token into an LDAP SASL GSS-SPNEGO BindRequest.
pub fn build_ldap_sasl_bind_request(message_id: i32, spnego_token: &[u8]) -> Vec<u8> {
    let msg = LdapMessage {
        message_id,
        protocol_op: ProtocolOp::BindRequest {
            version: 3,
            name: String::new(),
            auth: BindAuth::Sasl {
                mechanism: "GSS-SPNEGO".to_string(),
                credentials: Some(spnego_token.to_vec()),
            },
        },
        controls: Vec::new(),
    };
    msg.to_bytes()
}

/// Extracts the server's SPNEGO challenge credentials from an LDAP SASL BindResponse (`[APPLICATION 1]`).
pub fn extract_spnego_from_ldap_bind_response(resp_bytes: &[u8]) -> Result<Vec<u8>, CoreError> {
    let (msg, _) = LdapMessage::parse(resp_bytes)?;
    match msg.protocol_op {
        ProtocolOp::BindResponse {
            server_sasl_creds: Some(creds),
            ..
        } => Ok(creds),
        _ => Err(CoreError::ProtocolError(
            "No server_sasl_creds found in LDAP BindResponse".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_sasl_bind_request_and_response() {
        let token = b"SPNEGO_TOKEN_SAMPLE";
        let req = build_ldap_sasl_bind_request(1, token);
        assert!(!req.is_empty());

        let (parsed_msg, _) = LdapMessage::parse(&req).unwrap();
        assert_eq!(parsed_msg.message_id, 1);
        match parsed_msg.protocol_op {
            ProtocolOp::Other { tag, data } => {
                assert_eq!(tag, 0x60); // Application 0 (BindRequest)
                assert!(!data.is_empty());
            }
            _ => panic!("Expected BindRequest (Application 0)"),
        }

        // Test response extraction
        let resp_msg = LdapMessage {
            message_id: 1,
            protocol_op: ProtocolOp::BindResponse {
                result_code: 0,
                matched_dn: String::new(),
                diagnostic_message: String::new(),
                server_sasl_creds: Some(token.to_vec()),
            },
            controls: Vec::new(),
        };
        let resp_bytes = resp_msg.to_bytes();
        let extracted = extract_spnego_from_ldap_bind_response(&resp_bytes).unwrap();
        assert_eq!(extracted, token);
    }
}
