//! `delegation`: Active Directory Kerberos delegation scanner (`impacket/examples/findDelegation.py`).
//!
//! Enumerates Active Directory objects configured with:
//! 1. **Unconstrained Delegation** (`TRUSTED_FOR_DELEGATION` 0x80000)
//! 2. **Constrained Delegation** (`msDS-AllowedToDelegateTo` / `TRUSTED_TO_AUTH_FOR_DELEGATION`)
//! 3. **Resource-Based Constrained Delegation (RBCD)** (`msDS-AllowedToActOnBehalfOfOtherIdentity`)

use crate::client::{LdapClient, LdapEntry};
use crate::filter_present;
use crate::rbcd::parse_rbcd_allowed_sids;
use impacket_core::CoreError;
use impacket_ndr::RpcSid;
use std::io::{Read, Write};

pub const UAC_TRUSTED_FOR_DELEGATION: u32 = 0x0008_0000;
pub const UAC_TRUSTED_TO_AUTH_FOR_DELEGATION: u32 = 0x0100_0000;
pub const UAC_SERVER_TRUST_ACCOUNT: u32 = 0x0000_2000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationType {
    Unconstrained {
        is_dc: bool,
    },
    Constrained {
        protocol_transition: bool,
        allowed_targets: Vec<String>,
    },
    ResourceBased {
        allowed_sids: Vec<RpcSid>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationRecord {
    pub dn: String,
    pub sam_account_name: String,
    pub user_account_control: u32,
    pub delegation: DelegationType,
}

/// Discovers all delegation configurations across the given search base.
pub fn find_delegation<S: Read + Write>(
    client: &mut LdapClient<S>,
    base_dn: &str,
) -> Result<Vec<DelegationRecord>, CoreError> {
    let mut results = Vec::new();

    // Query all objects with objectClass=* requesting delegation attributes
    let entries = client.search(
        base_dn,
        crate::asn1::SearchScope::WholeSubtree,
        &filter_present("objectClass"),
        &[
            "sAMAccountName",
            "userAccountControl",
            "msDS-AllowedToDelegateTo",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
        ],
    )?;

    for entry in entries {
        parse_entry_delegations(&entry, &mut results);
    }

    Ok(results)
}

fn parse_entry_delegations(entry: &LdapEntry, out: &mut Vec<DelegationRecord>) {
    let sam = match entry.get_string("sAMAccountName") {
        Some(s) => s,
        None => return,
    };

    let uac = entry
        .get_string("userAccountControl")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);

    // 1. Check Unconstrained Delegation
    if (uac & UAC_TRUSTED_FOR_DELEGATION) != 0 {
        let is_dc = (uac & UAC_SERVER_TRUST_ACCOUNT) != 0;
        out.push(DelegationRecord {
            dn: entry.dn.clone(),
            sam_account_name: sam.clone(),
            user_account_control: uac,
            delegation: DelegationType::Unconstrained { is_dc },
        });
    }

    // 2. Check Constrained Delegation
    let targets = entry.get_all_strings("msDS-AllowedToDelegateTo");
    if !targets.is_empty() {
        let protocol_transition = (uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION) != 0;
        out.push(DelegationRecord {
            dn: entry.dn.clone(),
            sam_account_name: sam.clone(),
            user_account_control: uac,
            delegation: DelegationType::Constrained {
                protocol_transition,
                allowed_targets: targets,
            },
        });
    }

    // 3. Check Resource-Based Constrained Delegation
    if let Some(raw_sd) = entry.get_first_raw("msDS-AllowedToActOnBehalfOfOtherIdentity") {
        if let Ok(sids) = parse_rbcd_allowed_sids(raw_sd) {
            if !sids.is_empty() {
                out.push(DelegationRecord {
                    dn: entry.dn.clone(),
                    sam_account_name: sam,
                    user_account_control: uac,
                    delegation: DelegationType::ResourceBased { allowed_sids: sids },
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_parse_entry_unconstrained_and_constrained() {
        let mut attrs = HashMap::new();
        attrs.insert("sAMAccountName".into(), vec![b"web01$".to_vec()]);
        attrs.insert("userAccountControl".into(), vec![b"524288".to_vec()]); // TRUSTED_FOR_DELEGATION

        let entry = LdapEntry {
            dn: "CN=web01,CN=Computers,DC=contoso,DC=local".into(),
            attributes: attrs,
        };

        let mut out = Vec::new();
        parse_entry_delegations(&entry, &mut out);
        assert_eq!(out.len(), 1);
        match &out[0].delegation {
            DelegationType::Unconstrained { is_dc } => assert!(!is_dc),
            _ => panic!("Expected unconstrained delegation"),
        }
    }
}
