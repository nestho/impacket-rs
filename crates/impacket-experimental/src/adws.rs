//! Active Directory Web Services (ADWS) Protocol Definitions.
//!
//! Implements SOAP XML structures and WCF endpoints operating on TCP port 9389.
//! Used for stealthy Active Directory enumeration that bypasses LDAP telemetry (ports 389/636)
//! and logs on Domain Controllers under the loopback address (127.0.0.1).

/// Default TCP port for Active Directory Web Services.
pub const ADWS_DEFAULT_PORT: u16 = 9389;

/// Standard WS-Addressing and ADWS XML Namespaces.
pub mod ns {
    pub const SOAP_ENV: &str = "http://www.w3.org/2003/05/soap-envelope";
    pub const WS_ADDRESSING: &str = "http://www.w3.org/2005/08/addressing";
    pub const WS_ENUMERATION: &str = "http://schemas.xmlsoap.org/ws/2004/09/enumeration";
    pub const WS_TRANSFER: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer";
    pub const ADWS_INSTANCE: &str = "http://schemas.microsoft.com/2008/1/ActiveDirectory";
    pub const ADWS_DATA: &str = "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data";
}

/// Standard Actions supported by ADWS endpoints.
pub mod action {
    pub const ENUMERATE: &str = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate";
    pub const PULL: &str = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull";
    pub const GET: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get";
}

/// A builder for ADWS SOAP request envelopes.
#[derive(Debug, Clone)]
pub struct AdwsSoapEnvelope {
    pub action: String,
    pub to_endpoint: String,
    pub message_id: String,
    pub body_content: String,
}

impl AdwsSoapEnvelope {
    /// Create a new SOAP request envelope.
    pub fn new(
        action: impl Into<String>,
        to_endpoint: impl Into<String>,
        message_id: impl Into<String>,
        body_content: impl Into<String>,
    ) -> Self {
        Self {
            action: action.into(),
            to_endpoint: to_endpoint.into(),
            message_id: message_id.into(),
            body_content: body_content.into(),
        }
    }

    /// Build a SOAP Enumerate request for an LDAP filter.
    pub fn build_enumerate_ldap_filter(
        dc_hostname: &str,
        message_id: &str,
        ldap_filter: &str,
    ) -> Self {
        let to = format!("net.tcp://{}:{}/ActiveDirectoryWebServices/Windows/ResourceFactory", dc_hostname, ADWS_DEFAULT_PORT);
        let body = format!(
            r#"<wsen:Enumerate xmlns:wsen="{}" xmlns:ad="{}">
                <wsen:Filter Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data/ldap">{}</wsen:Filter>
            </wsen:Enumerate>"#,
            ns::WS_ENUMERATION,
            ns::ADWS_INSTANCE,
            ldap_filter
        );
        Self::new(action::ENUMERATE, to, message_id, body)
    }

    /// Render full XML payload string.
    pub fn to_xml(&self) -> String {
        format!(
            r#"<s:Envelope xmlns:s="{}" xmlns:a="{}">
  <s:Header>
    <a:Action s:mustUnderstand="1">{}</a:Action>
    <a:MessageID>urn:uuid:{}</a:MessageID>
    <a:To s:mustUnderstand="1">{}</a:To>
  </s:Header>
  <s:Body>
    {}
  </s:Body>
</s:Envelope>"#,
            ns::SOAP_ENV,
            ns::WS_ADDRESSING,
            self.action,
            self.message_id,
            self.to_endpoint,
            self.body_content.trim()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adws_soap_envelope_xml() {
        let env = AdwsSoapEnvelope::build_enumerate_ldap_filter(
            "dc01.corp.local",
            "550e8400-e29b-41d4-a716-446655440000",
            "(objectClass=user)",
        );
        let xml = env.to_xml();
        assert!(xml.contains(action::ENUMERATE));
        assert!(xml.contains("urn:uuid:550e8400-e29b-41d4-a716-446655440000"));
        assert!(xml.contains("(objectClass=user)"));
    }
}
