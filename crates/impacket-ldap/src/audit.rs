//! `audit`: Active Directory domain security posture and misconfiguration auditor.
//!
//! Inspects Active Directory objects via LDAP to identify actionable security weaknesses:
//! - **Kerberoasting**: User accounts with `servicePrincipalName` set (excluding machine accounts and krbtgt).
//! - **AS-REP Roasting**: Accounts configured with `DONT_REQ_PREAUTH` (0x0040_0000).
//! - **Privileged Accounts**: Accounts with `adminCount = 1` (AdminSDHolder / SDProp targets).
//! - **Weak Account Policies**: Reversible encryption (`ENCRYPTED_TEXT_PWD_ALLOWED`), no password required (`PASSWD_NOTREQD`), password never expires (`DONT_EXPIRE_PASSWORD`).
//! - **Kerberos Delegations**: Unconstrained, Constrained, and Resource-Based Constrained Delegation (RBCD).

use crate::asn1::{filter_present, SearchScope};
use crate::client::LdapClient;
use crate::delegation::{find_delegation, DelegationRecord};
use impacket_core::CoreError;
use std::io::{Read, Write};

pub const UAC_ACCOUNTDISABLE: u32 = 0x0000_0002;
pub const UAC_PASSWD_NOTREQD: u32 = 0x0000_0020;
pub const UAC_ENCRYPTED_TEXT_PWD_ALLOWED: u32 = 0x0000_0080;
pub const UAC_DONT_EXPIRE_PASSWORD: u32 = 0x0001_0000;
pub const UAC_DONT_REQ_PREAUTH: u32 = 0x0040_0000;
pub const UAC_PASSWORD_EXPIRED: u32 = 0x0080_0000;

/// User account vulnerable to Kerberoasting (holds an SPN and can be requested offline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberoastableAccount {
    pub sam_account_name: String,
    pub dn: String,
    pub spns: Vec<String>,
    pub pwd_last_set: String,
    pub is_admin: bool,
}

/// User account vulnerable to AS-REP Roasting (Kerberos pre-authentication disabled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsrepRoastableAccount {
    pub sam_account_name: String,
    pub dn: String,
    pub user_account_control: u32,
    pub is_admin: bool,
}

/// Privileged account protected by AdminSDHolder (`adminCount = 1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminCountAccount {
    pub sam_account_name: String,
    pub dn: String,
    pub admin_count: u32,
}

/// Account exhibiting weak or risky password/account flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeakAccountPolicyFinding {
    pub sam_account_name: String,
    pub dn: String,
    pub flags: Vec<&'static str>,
}

/// Consolidated Active Directory domain security assessment report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainSecurityReport {
    pub base_dn: String,
    pub kerberoastable_accounts: Vec<KerberoastableAccount>,
    pub asrep_roastable_accounts: Vec<AsrepRoastableAccount>,
    pub admin_count_accounts: Vec<AdminCountAccount>,
    pub weak_policy_accounts: Vec<WeakAccountPolicyFinding>,
    pub delegations: Vec<DelegationRecord>,
    pub total_users_audited: usize,
}

impl DomainSecurityReport {
    /// Total count of high-risk security findings across the domain.
    pub fn high_risk_finding_count(&self) -> usize {
        self.kerberoastable_accounts.len()
            + self.asrep_roastable_accounts.len()
            + self.delegations.len()
            + self
                .weak_policy_accounts
                .iter()
                .filter(|a| a.flags.contains(&"ENCRYPTED_TEXT_PWD_ALLOWED") || a.flags.contains(&"PASSWD_NOTREQD"))
                .count()
    }
}

/// Performs a comprehensive agentless Active Directory domain audit over LDAP.
pub fn audit_domain_security<S: Read + Write>(
    client: &mut LdapClient<S>,
    base_dn: &str,
) -> Result<DomainSecurityReport, CoreError> {
    // 1. Discover all Kerberos delegation paths
    let delegations = find_delegation(client, base_dn).unwrap_or_default();

    // 2. Query user/computer objects across the domain
    let entries = client.search(
        base_dn,
        SearchScope::WholeSubtree,
        &filter_present("sAMAccountName"),
        &[
            "sAMAccountName",
            "distinguishedName",
            "userAccountControl",
            "servicePrincipalName",
            "adminCount",
            "pwdLastSet",
            "objectClass",
        ],
    )?;

    let mut kerberoastable = Vec::new();
    let mut asrep_roastable = Vec::new();
    let mut admin_counts = Vec::new();
    let mut weak_accounts = Vec::new();
    let mut total_users = 0;

    for entry in &entries {
        let sam = match entry.get_string("sAMAccountName") {
            Some(s) => s,
            None => continue,
        };

        let object_classes = entry.get_all_strings("objectClass");
        let is_computer = object_classes
            .iter()
            .any(|c| c.eq_ignore_ascii_case("computer"))
            || sam.ends_with('$');

        // Only inspect security principals (skip pure container/schema objects)
        if !object_classes
            .iter()
            .any(|c| c.eq_ignore_ascii_case("user") || c.eq_ignore_ascii_case("person") || c.eq_ignore_ascii_case("computer"))
        {
            continue;
        }

        if !is_computer {
            total_users += 1;
        }

        let uac = entry
            .get_string("userAccountControl")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let admin_count = entry
            .get_string("adminCount")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let is_admin = admin_count == 1;

        // Skip disabled accounts for active exploitation assessment
        let is_disabled = (uac & UAC_ACCOUNTDISABLE) != 0;

        // 1. Kerberoastable check
        let spns = entry.get_all_strings("servicePrincipalName");
        if !is_computer
            && !sam.eq_ignore_ascii_case("krbtgt")
            && !spns.is_empty()
            && !is_disabled
        {
            kerberoastable.push(KerberoastableAccount {
                sam_account_name: sam.clone(),
                dn: entry.dn.clone(),
                spns,
                pwd_last_set: entry.get_string("pwdLastSet").unwrap_or_else(|| "0".into()),
                is_admin,
            });
        }

        // 2. AS-REP Roastable check (DONT_REQ_PREAUTH)
        if (uac & UAC_DONT_REQ_PREAUTH) != 0 && !is_disabled && !sam.eq_ignore_ascii_case("krbtgt") {
            asrep_roastable.push(AsrepRoastableAccount {
                sam_account_name: sam.clone(),
                dn: entry.dn.clone(),
                user_account_control: uac,
                is_admin,
            });
        }

        // 3. AdminCount check
        if is_admin && !is_computer {
            admin_counts.push(AdminCountAccount {
                sam_account_name: sam.clone(),
                dn: entry.dn.clone(),
                admin_count,
            });
        }

        // 4. Weak account flags
        let mut flags = Vec::new();
        if (uac & UAC_ENCRYPTED_TEXT_PWD_ALLOWED) != 0 {
            flags.push("ENCRYPTED_TEXT_PWD_ALLOWED");
        }
        if (uac & UAC_PASSWD_NOTREQD) != 0 {
            flags.push("PASSWD_NOTREQD");
        }
        if (uac & UAC_DONT_EXPIRE_PASSWORD) != 0 {
            flags.push("DONT_EXPIRE_PASSWORD");
        }

        if !flags.is_empty() && !is_computer {
            weak_accounts.push(WeakAccountPolicyFinding {
                sam_account_name: sam,
                dn: entry.dn.clone(),
                flags,
            });
        }
    }

    Ok(DomainSecurityReport {
        base_dn: base_dn.to_string(),
        kerberoastable_accounts: kerberoastable,
        asrep_roastable_accounts: asrep_roastable,
        admin_count_accounts: admin_counts,
        weak_policy_accounts: weak_accounts,
        delegations,
        total_users_audited: total_users,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_security_report_high_risk_count() {
        let rep = DomainSecurityReport {
            base_dn: "DC=corp,DC=local".into(),
            kerberoastable_accounts: vec![KerberoastableAccount {
                sam_account_name: "sqlsvc".into(),
                dn: "CN=sqlsvc,DC=corp,DC=local".into(),
                spns: vec!["MSSQLSvc/db01.corp.local".into()],
                pwd_last_set: "133000000000000000".into(),
                is_admin: false,
            }],
            asrep_roastable_accounts: vec![AsrepRoastableAccount {
                sam_account_name: "legacyuser".into(),
                dn: "CN=legacyuser,DC=corp,DC=local".into(),
                user_account_control: 0x0041_0000,
                is_admin: false,
            }],
            admin_count_accounts: vec![],
            weak_policy_accounts: vec![WeakAccountPolicyFinding {
                sam_account_name: "badpwd".into(),
                dn: "CN=badpwd,DC=corp,DC=local".into(),
                flags: vec!["PASSWD_NOTREQD"],
            }],
            delegations: vec![],
            total_users_audited: 10,
        };

        assert_eq!(rep.high_risk_finding_count(), 3);
    }
}
