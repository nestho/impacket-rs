//! Stealth Kerberos Sapphire Ticket Generator.
//!
//! Sapphire Tickets solve the detection flaws of Golden and Diamond tickets by obtaining
//! a genuine, unmodified Privilege Attribute Certificate (PAC) directly from the KDC using
//! S4U2Self combined with User-to-User (U2U) authentication.
//!
//! Because the PAC is issued natively by Active Directory for the privileged account,
//! there are zero discrepancies between the ticket's group memberships and AD database records.

/// Represents a Sapphire Ticket construction state.
#[derive(Debug, Clone)]
pub struct SapphireTicketRequest {
    /// Low-privileged domain user who initiates the baseline AS-REQ.
    pub client_account: String,
    /// High-privileged target account whose PAC should be transplanted (e.g. "Administrator").
    pub target_account: String,
    /// Domain FQDN (e.g. "CORP.LOCAL").
    pub domain: String,
    /// Domain SID.
    pub domain_sid: String,
}

impl SapphireTicketRequest {
    /// Create a new Sapphire Ticket request specification.
    pub fn new(
        client_account: impl Into<String>,
        target_account: impl Into<String>,
        domain: impl Into<String>,
        domain_sid: impl Into<String>,
    ) -> Self {
        Self {
            client_account: client_account.into(),
            target_account: target_account.into(),
            domain: domain.into(),
            domain_sid: domain_sid.into(),
        }
    }

    /// Verifies prerequisites for a Sapphire Ticket exchange.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.client_account.is_empty() {
            return Err("client_account cannot be empty");
        }
        if self.target_account.is_empty() {
            return Err("target_account cannot be empty");
        }
        if self.domain.is_empty() {
            return Err("domain cannot be empty");
        }
        if !self.domain_sid.starts_with("S-1-5-21-") {
            return Err("invalid domain SID format");
        }
        Ok(())
    }
}

/// Helper to graft an authentic PAC buffer into an existing ticket's encrypted authorization-data.
#[derive(Debug, Clone)]
pub struct PacTransplant {
    pub raw_pac: Vec<u8>,
}

impl PacTransplant {
    /// Wrap a raw KDC-issued PAC buffer.
    pub fn from_bytes(raw_pac: &[u8]) -> Result<Self, &'static str> {
        if raw_pac.is_empty() {
            return Err("PAC buffer cannot be empty");
        }
        Ok(Self {
            raw_pac: raw_pac.to_vec(),
        })
    }

    /// Number of bytes in the PAC payload.
    #[inline]
    pub fn len(&self) -> usize {
        self.raw_pac.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.raw_pac.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sapphire_request_validation() {
        let req = SapphireTicketRequest::new(
            "lowpriv",
            "Administrator",
            "CORP.LOCAL",
            "S-1-5-21-1234567890-1234567890-1234567890",
        );
        assert!(req.validate().is_ok());

        let bad_sid = SapphireTicketRequest::new(
            "lowpriv",
            "Administrator",
            "CORP.LOCAL",
            "invalid-sid",
        );
        assert!(bad_sid.validate().is_err());
    }

    #[test]
    fn test_pac_transplant() {
        let fake_pac = vec![0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let transplant = PacTransplant::from_bytes(&fake_pac).unwrap();
        assert_eq!(transplant.len(), 8);
    }
}
