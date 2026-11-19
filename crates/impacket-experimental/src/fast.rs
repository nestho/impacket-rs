//! RFC 6113 Kerberos Flexible Authentication Secure Tunneling (FAST) Armoring Helpers.
//!
//! Provides high-level abstractions to bootstrap an outer armor tunnel from a machine account
//! credential (`COMPUTER$`) and tunnel arbitrary user `AS-REQ` requests through enforced Domain Controllers.

/// Credentials for the machine account used to build the outer FAST armor tunnel.
#[derive(Debug, Clone)]
pub struct ArmorMachineCredential {
    /// NetBIOS or sAMAccountName of the machine (e.g. `WORKSTATION01$`).
    pub machine_name: String,
    /// Realm / Domain FQDN.
    pub realm: String,
    /// Machine account secret (NTLM hash or AES-128/256 key).
    pub key: Vec<u8>,
}

impl ArmorMachineCredential {
    pub fn new(machine_name: impl Into<String>, realm: impl Into<String>, key: Vec<u8>) -> Self {
        Self {
            machine_name: machine_name.into(),
            realm: realm.into(),
            key,
        }
    }

    /// Verifies machine credential parameters.
    pub fn is_valid(&self) -> bool {
        !self.machine_name.is_empty() && !self.realm.is_empty() && !self.key.is_empty()
    }
}

/// Status of FAST armor negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastArmoringStatus {
    NotEnforced,
    Enforced,
    ArmoredSuccessfully,
    Failed(i32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_armor_credential_validity() {
        let cred = ArmorMachineCredential::new(
            "DC01$",
            "CORP.LOCAL",
            vec![0x01, 0x02, 0x03, 0x04],
        );
        assert!(cred.is_valid());

        let invalid = ArmorMachineCredential::new(
            "",
            "CORP.LOCAL",
            vec![],
        );
        assert!(!invalid.is_valid());
    }
}
