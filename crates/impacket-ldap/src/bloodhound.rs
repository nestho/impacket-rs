//! `bloodhound`: BloodHound Community Edition (v5+) Active Directory collector & ingestor codec.
//!
//! Generates BloodHound v5 compliant JSON files (`users.json`, `computers.json`, `groups.json`, `domains.json`)
//! and standalone `.zip` ingestion bundles for import into BloodHound CE / SharpHound compatible graph databases.

use crate::client::{LdapClient, LdapEntry};
use crate::filter_equality;
use crate::rbcd::parse_rbcd_allowed_sids;
use crate::security_descriptor::{access_mask, SecurityDescriptor};
use impacket_core::CoreError;
use impacket_ndr::RpcSid;
use std::io::{Read, Write};

/// BloodHound Access Control Entry (`ACE`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloodHoundAce {
    pub principal_sid: String,
    pub principal_type: String,
    pub right_name: String,
    pub is_inherited: bool,
}

impl BloodHoundAce {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"PrincipalSID\":\"{}\",\"PrincipalType\":\"{}\",\"RightName\":\"{}\",\"IsInherited\":{}}}",
            escape_json(&self.principal_sid),
            escape_json(&self.principal_type),
            escape_json(&self.right_name),
            if self.is_inherited { "true" } else { "false" }
        )
    }
}

/// BloodHound User object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloodHoundUser {
    pub object_identifier: String,
    pub primary_group_sid: Option<String>,
    pub allowed_to_delegate: Vec<String>,
    pub spn_targets: Vec<String>,
    pub has_sid_history: Vec<String>,
    pub aces: Vec<BloodHoundAce>,
    // Properties
    pub domain: String,
    pub name: String,
    pub distinguished_name: String,
    pub domainsid: String,
    pub sam_account_name: String,
    pub enabled: bool,
    pub high_value: bool,
    pub admin_count: bool,
    pub dont_req_preauth: bool,
    pub password_not_reqd: bool,
    pub unconstrained_delegation: bool,
    pub sensitive: bool,
    pub pwd_never_expires: bool,
    pub has_spn: bool,
    pub service_principal_names: Vec<String>,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub last_logon: u64,
    pub pwd_last_set: u64,
}

impl BloodHoundUser {
    pub fn to_json(&self) -> String {
        let spns_json = format_json_string_array(&self.service_principal_names);
        let del_json = format_json_string_array(&self.allowed_to_delegate);
        let spn_targets_json = format_json_string_array(&self.spn_targets);
        let sid_hist_json = format_json_string_array(&self.has_sid_history);
        let aces_json = format_json_ace_array(&self.aces);

        let p_group_json = match &self.primary_group_sid {
            Some(s) => format!("\"{}\"", escape_json(s)),
            None => "null".to_string(),
        };

        let email_json = match &self.email {
            Some(e) => format!("\"{}\"", escape_json(e)),
            None => "null".to_string(),
        };

        let display_json = match &self.display_name {
            Some(d) => format!("\"{}\"", escape_json(d)),
            None => "null".to_string(),
        };

        format!(
            "{{\"ObjectIdentifier\":\"{}\",\"PrimaryGroupSID\":{},\"AllowedToDelegate\":{},\"SPNTargets\":{},\"HasSIDHistory\":{},\"Aces\":{},\"Properties\":{{\"domain\":\"{}\",\"name\":\"{}\",\"distinguishedname\":\"{}\",\"domainsid\":\"{}\",\"samaccountname\":\"{}\",\"enabled\":{},\"highvalue\":{},\"admincount\":{},\"dontreqpreauth\":{},\"passwordnotreqd\":{},\"unconstraineddelegation\":{},\"sensitive\":{},\"pwdneverexpires\":{},\"hasspn\":{},\"serviceprincipalnames\":{},\"email\":{},\"displayname\":{},\"lastlogon\":{},\"pwdlastset\":{}}}}}",
            escape_json(&self.object_identifier),
            p_group_json,
            del_json,
            spn_targets_json,
            sid_hist_json,
            aces_json,
            escape_json(&self.domain),
            escape_json(&self.name),
            escape_json(&self.distinguished_name),
            escape_json(&self.domainsid),
            escape_json(&self.sam_account_name),
            self.enabled,
            self.high_value,
            self.admin_count,
            self.dont_req_preauth,
            self.password_not_reqd,
            self.unconstrained_delegation,
            self.sensitive,
            self.pwd_never_expires,
            self.has_spn,
            spns_json,
            email_json,
            display_json,
            self.last_logon,
            self.pwd_last_set
        )
    }
}

/// BloodHound Computer object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloodHoundComputer {
    pub object_identifier: String,
    pub primary_group_sid: Option<String>,
    pub allowed_to_delegate: Vec<String>,
    pub allowed_to_act: Vec<String>,
    pub has_sid_history: Vec<String>,
    pub aces: Vec<BloodHoundAce>,
    // Properties
    pub domain: String,
    pub name: String,
    pub distinguished_name: String,
    pub domainsid: String,
    pub sam_account_name: String,
    pub enabled: bool,
    pub high_value: bool,
    pub unconstrained_delegation: bool,
    pub trusted_to_auth: bool,
    pub operating_system: Option<String>,
    pub last_logon: u64,
    pub pwd_last_set: u64,
}

impl BloodHoundComputer {
    pub fn to_json(&self) -> String {
        let del_json = format_json_string_array(&self.allowed_to_delegate);
        let act_json = format_json_string_array(&self.allowed_to_act);
        let sid_hist_json = format_json_string_array(&self.has_sid_history);
        let aces_json = format_json_ace_array(&self.aces);

        let p_group_json = match &self.primary_group_sid {
            Some(s) => format!("\"{}\"", escape_json(s)),
            None => "null".to_string(),
        };

        let os_json = match &self.operating_system {
            Some(os) => format!("\"{}\"", escape_json(os)),
            None => "null".to_string(),
        };

        format!(
            "{{\"ObjectIdentifier\":\"{}\",\"PrimaryGroupSID\":{},\"AllowedToDelegate\":{},\"AllowedToAct\":{},\"HasSIDHistory\":{},\"Sessions\":{{\"Collected\":false,\"FailureReason\":null,\"Results\":[]}},\"PrivilegedSessions\":{{\"Collected\":false,\"FailureReason\":null,\"Results\":[]}},\"RegistrySessions\":{{\"Collected\":false,\"FailureReason\":null,\"Results\":[]}},\"Aces\":{},\"Properties\":{{\"domain\":\"{}\",\"name\":\"{}\",\"distinguishedname\":\"{}\",\"domainsid\":\"{}\",\"samaccountname\":\"{}\",\"enabled\":{},\"highvalue\":{},\"unconstraineddelegation\":{},\"trustedtoauth\":{},\"operatingsystem\":{},\"lastlogon\":{},\"pwdlastset\":{}}}}}",
            escape_json(&self.object_identifier),
            p_group_json,
            del_json,
            act_json,
            sid_hist_json,
            aces_json,
            escape_json(&self.domain),
            escape_json(&self.name),
            escape_json(&self.distinguished_name),
            escape_json(&self.domainsid),
            escape_json(&self.sam_account_name),
            self.enabled,
            self.high_value,
            self.unconstrained_delegation,
            self.trusted_to_auth,
            os_json,
            self.last_logon,
            self.pwd_last_set
        )
    }
}

/// BloodHound Group Member entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloodHoundGroupMember {
    pub object_identifier: String,
    pub object_type: String,
}

impl BloodHoundGroupMember {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"ObjectIdentifier\":\"{}\",\"ObjectType\":\"{}\"}}",
            escape_json(&self.object_identifier),
            escape_json(&self.object_type)
        )
    }
}

/// BloodHound Group object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloodHoundGroup {
    pub object_identifier: String,
    pub members: Vec<BloodHoundGroupMember>,
    pub aces: Vec<BloodHoundAce>,
    // Properties
    pub domain: String,
    pub name: String,
    pub distinguished_name: String,
    pub domainsid: String,
    pub sam_account_name: String,
    pub high_value: bool,
    pub admin_count: bool,
}

impl BloodHoundGroup {
    pub fn to_json(&self) -> String {
        let members_json = format!(
            "[{}]",
            self.members
                .iter()
                .map(BloodHoundGroupMember::to_json)
                .collect::<Vec<_>>()
                .join(",")
        );
        let aces_json = format_json_ace_array(&self.aces);

        format!(
            "{{\"ObjectIdentifier\":\"{}\",\"Members\":{},\"Aces\":{},\"Properties\":{{\"domain\":\"{}\",\"name\":\"{}\",\"distinguishedname\":\"{}\",\"domainsid\":\"{}\",\"samaccountname\":\"{}\",\"highvalue\":{},\"admincount\":{}}}}}",
            escape_json(&self.object_identifier),
            members_json,
            aces_json,
            escape_json(&self.domain),
            escape_json(&self.name),
            escape_json(&self.distinguished_name),
            escape_json(&self.domainsid),
            escape_json(&self.sam_account_name),
            self.high_value,
            self.admin_count
        )
    }
}

/// BloodHound Domain Trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloodHoundTrust {
    pub target_domain_name: String,
    pub target_domain_sid: String,
    pub is_transitive: bool,
    pub trust_direction: String,
    pub trust_type: String,
    pub sid_filtering_enabled: bool,
}

impl BloodHoundTrust {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"TargetDomainName\":\"{}\",\"TargetDomainSid\":\"{}\",\"IsTransitive\":{},\"TrustDirection\":\"{}\",\"TrustType\":\"{}\",\"SidFilteringEnabled\":{}}}",
            escape_json(&self.target_domain_name),
            escape_json(&self.target_domain_sid),
            self.is_transitive,
            escape_json(&self.trust_direction),
            escape_json(&self.trust_type),
            self.sid_filtering_enabled
        )
    }
}

/// BloodHound Domain object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BloodHoundDomain {
    pub object_identifier: String,
    pub trusts: Vec<BloodHoundTrust>,
    pub aces: Vec<BloodHoundAce>,
    // Properties
    pub domain: String,
    pub name: String,
    pub distinguished_name: String,
    pub domainsid: String,
    pub high_value: bool,
    pub function_level: String,
}

impl BloodHoundDomain {
    pub fn to_json(&self) -> String {
        let trusts_json = format!(
            "[{}]",
            self.trusts
                .iter()
                .map(BloodHoundTrust::to_json)
                .collect::<Vec<_>>()
                .join(",")
        );
        let aces_json = format_json_ace_array(&self.aces);

        format!(
            "{{\"ObjectIdentifier\":\"{}\",\"Trusts\":{},\"Aces\":{},\"ChildObjects\":[],\"Properties\":{{\"domain\":\"{}\",\"name\":\"{}\",\"distinguishedname\":\"{}\",\"domainsid\":\"{}\",\"highvalue\":{},\"functionallevel\":\"{}\"}}}}",
            escape_json(&self.object_identifier),
            trusts_json,
            aces_json,
            escape_json(&self.domain),
            escape_json(&self.name),
            escape_json(&self.distinguished_name),
            escape_json(&self.domainsid),
            self.high_value,
            escape_json(&self.function_level)
        )
    }
}

/// High-level collection bundle holding all extracted Active Directory graph nodes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BloodHoundDump {
    pub users: Vec<BloodHoundUser>,
    pub computers: Vec<BloodHoundComputer>,
    pub groups: Vec<BloodHoundGroup>,
    pub domains: Vec<BloodHoundDomain>,
}

impl BloodHoundDump {
    pub fn new() -> Self {
        Self::default()
    }

    /// Formats the users collection as BloodHound v5 `users.json`.
    pub fn to_users_json(&self) -> String {
        format_collection_json("users", &self.users.iter().map(BloodHoundUser::to_json).collect::<Vec<_>>())
    }

    /// Formats the computers collection as BloodHound v5 `computers.json`.
    pub fn to_computers_json(&self) -> String {
        format_collection_json("computers", &self.computers.iter().map(BloodHoundComputer::to_json).collect::<Vec<_>>())
    }

    /// Formats the groups collection as BloodHound v5 `groups.json`.
    pub fn to_groups_json(&self) -> String {
        format_collection_json("groups", &self.groups.iter().map(BloodHoundGroup::to_json).collect::<Vec<_>>())
    }

    /// Formats the domains collection as BloodHound v5 `domains.json`.
    pub fn to_domains_json(&self) -> String {
        format_collection_json("domains", &self.domains.iter().map(BloodHoundDomain::to_json).collect::<Vec<_>>())
    }

    /// Bundles all collections into a standard uncompressed PKZIP archive (`.zip`).
    pub fn to_zip_bytes(&self) -> Vec<u8> {
        let files = [
            ("users.json", self.to_users_json().into_bytes()),
            ("computers.json", self.to_computers_json().into_bytes()),
            ("groups.json", self.to_groups_json().into_bytes()),
            ("domains.json", self.to_domains_json().into_bytes()),
        ];
        create_zip_archive(&files)
    }

    /// Writes all four JSON files to the given directory path.
    pub fn write_to_directory(&self, dir: &std::path::Path) -> Result<(), CoreError> {
        std::fs::create_dir_all(dir)
            .map_err(|e| CoreError::IoError(format!("Failed creating output directory: {}", e)))?;
        std::fs::write(dir.join("users.json"), self.to_users_json())
            .map_err(|e| CoreError::IoError(format!("Failed writing users.json: {}", e)))?;
        std::fs::write(dir.join("computers.json"), self.to_computers_json())
            .map_err(|e| CoreError::IoError(format!("Failed writing computers.json: {}", e)))?;
        std::fs::write(dir.join("groups.json"), self.to_groups_json())
            .map_err(|e| CoreError::IoError(format!("Failed writing groups.json: {}", e)))?;
        std::fs::write(dir.join("domains.json"), self.to_domains_json())
            .map_err(|e| CoreError::IoError(format!("Failed writing domains.json: {}", e)))?;
        Ok(())
    }

    /// Writes the bundled ZIP file to disk.
    pub fn write_to_zip_file(&self, path: &std::path::Path) -> Result<(), CoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CoreError::IoError(format!("Failed creating parent directory: {}", e)))?;
        }
        let zip_bytes = self.to_zip_bytes();
        std::fs::write(path, zip_bytes)
            .map_err(|e| CoreError::IoError(format!("Failed writing BloodHound ZIP file: {}", e)))
    }
}

/// Collects all BloodHound Active Directory data from an authenticated LDAP client session.
pub fn collect_bloodhound_data<S: Read + Write>(
    client: &mut LdapClient<S>,
    domain: &str,
    base_dn: Option<&str>,
) -> Result<BloodHoundDump, CoreError> {
    let resolved_base = match base_dn {
        Some(b) => b.to_string(),
        None => domain_to_base_dn(domain),
    };

    let users = collect_users(client, &resolved_base, domain)?;
    let computers = collect_computers(client, &resolved_base, domain)?;
    let groups = collect_groups(client, &resolved_base, domain)?;
    let domains = collect_domains(client, &resolved_base, domain)?;

    Ok(BloodHoundDump {
        users,
        computers,
        groups,
        domains,
    })
}

pub fn collect_users<S: Read + Write>(
    client: &mut LdapClient<S>,
    base_dn: &str,
    domain: &str,
) -> Result<Vec<BloodHoundUser>, CoreError> {
    let filter = crate::asn1::filter_and(&[
        crate::asn1::filter_equality("objectClass", "user"),
        crate::asn1::filter_not(&crate::asn1::filter_equality("objectClass", "computer")),
    ]);

    let attributes = [
        "objectSid",
        "sAMAccountName",
        "distinguishedName",
        "userAccountControl",
        "servicePrincipalName",
        "msDS-AllowedToDelegateTo",
        "sIDHistory",
        "primaryGroupID",
        "mail",
        "displayName",
        "lastLogon",
        "pwdLastSet",
        "adminCount",
        "nTSecurityDescriptor",
    ];

    let entries = client.search(base_dn, crate::asn1::SearchScope::WholeSubtree, &filter, &attributes)?;
    let mut users = Vec::with_capacity(entries.len());

    for entry in entries {
        if let Some(user) = parse_ldap_user(&entry, domain) {
            users.push(user);
        }
    }
    Ok(users)
}

pub fn collect_computers<S: Read + Write>(
    client: &mut LdapClient<S>,
    base_dn: &str,
    domain: &str,
) -> Result<Vec<BloodHoundComputer>, CoreError> {
    let filter = filter_equality("objectClass", "computer");

    let attributes = [
        "objectSid",
        "sAMAccountName",
        "distinguishedName",
        "userAccountControl",
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "sIDHistory",
        "primaryGroupID",
        "operatingSystem",
        "lastLogon",
        "pwdLastSet",
        "nTSecurityDescriptor",
    ];

    let entries = client.search(base_dn, crate::asn1::SearchScope::WholeSubtree, &filter, &attributes)?;
    let mut computers = Vec::with_capacity(entries.len());

    for entry in entries {
        if let Some(comp) = parse_ldap_computer(&entry, domain) {
            computers.push(comp);
        }
    }
    Ok(computers)
}

pub fn collect_groups<S: Read + Write>(
    client: &mut LdapClient<S>,
    base_dn: &str,
    domain: &str,
) -> Result<Vec<BloodHoundGroup>, CoreError> {
    let filter = filter_equality("objectClass", "group");

    let attributes = [
        "objectSid",
        "sAMAccountName",
        "distinguishedName",
        "member",
        "adminCount",
        "nTSecurityDescriptor",
    ];

    let entries = client.search(base_dn, crate::asn1::SearchScope::WholeSubtree, &filter, &attributes)?;
    let mut groups = Vec::with_capacity(entries.len());

    for entry in entries {
        if let Some(grp) = parse_ldap_group(&entry, domain) {
            groups.push(grp);
        }
    }
    Ok(groups)
}

pub fn collect_domains<S: Read + Write>(
    client: &mut LdapClient<S>,
    base_dn: &str,
    domain: &str,
) -> Result<Vec<BloodHoundDomain>, CoreError> {
    let filter = filter_equality("objectClass", "domainDNS");

    let attributes = [
        "objectSid",
        "distinguishedName",
        "msDS-Behavior-Version",
        "nTSecurityDescriptor",
    ];

    let entries = client.search(base_dn, crate::asn1::SearchScope::BaseObject, &filter, &attributes)?;
    let mut domains = Vec::with_capacity(entries.len());

    for entry in entries {
        if let Some(dom) = parse_ldap_domain(&entry, domain) {
            domains.push(dom);
        }
    }
    Ok(domains)
}

// ---------------------------------------------------------------------------
// LDAP Entry Parser Helpers
// ---------------------------------------------------------------------------

pub fn parse_ldap_user(entry: &LdapEntry, domain: &str) -> Option<BloodHoundUser> {
    let raw_sid = entry.get_first_raw("objectSid")?;
    let rpc_sid = RpcSid::from_le_bytes(raw_sid).ok()?;
    let object_identifier = rpc_sid.to_string();
    let domainsid = get_domain_sid(&rpc_sid);

    let sam = entry.get_string("sAMAccountName").unwrap_or_default();
    let dn = entry.get_string("distinguishedName").unwrap_or_else(|| entry.dn.clone());
    let uac = entry.get_string("userAccountControl").and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);

    let domain_upper = domain.to_uppercase();
    let name = format!("{}@{}", sam.to_uppercase(), domain_upper);

    let spns = entry.get_all_strings("servicePrincipalName");
    let has_spn = !spns.is_empty();

    let allowed_to_delegate = entry.get_all_strings("msDS-AllowedToDelegateTo");
    let has_sid_history = parse_sid_history(entry);

    let primary_group_id = entry.get_string("primaryGroupID").and_then(|s| s.parse::<u32>().ok());
    let primary_group_sid = primary_group_id.map(|rid| format!("{}-{}", domainsid, rid));

    let email = entry.get_string("mail");
    let display_name = entry.get_string("displayName");
    let last_logon = entry.get_string("lastLogon").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let pwd_last_set = entry.get_string("pwdLastSet").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let admin_count = entry.get_string("adminCount").map(|s| s == "1").unwrap_or(false);

    let enabled = (uac & 0x0002) == 0; // ACCOUNTDISABLE = 0x0002
    let dont_req_preauth = (uac & 0x0040_0000) != 0; // DONT_REQ_PREAUTH = 0x00400000
    let password_not_reqd = (uac & 0x0020) != 0; // PASSWD_NOTREQD = 0x0020
    let unconstrained_delegation = (uac & 0x0008_0000) != 0; // TRUSTED_FOR_DELEGATION = 0x00080000
    let sensitive = (uac & 0x0010_0000) != 0; // NOT_DELEGATED = 0x00100000
    let pwd_never_expires = (uac & 0x0001_0000) != 0; // DONT_EXPIRE_PASSWORD = 0x00010000

    let high_value = admin_count || is_high_value_rid(&rpc_sid);
    let aces = parse_entry_aces(entry);

    Some(BloodHoundUser {
        object_identifier,
        primary_group_sid,
        allowed_to_delegate,
        spn_targets: Vec::new(),
        has_sid_history,
        aces,
        domain: domain_upper,
        name,
        distinguished_name: dn,
        domainsid,
        sam_account_name: sam,
        enabled,
        high_value,
        admin_count,
        dont_req_preauth,
        password_not_reqd,
        unconstrained_delegation,
        sensitive,
        pwd_never_expires,
        has_spn,
        service_principal_names: spns,
        email,
        display_name,
        last_logon,
        pwd_last_set,
    })
}

pub fn parse_ldap_computer(entry: &LdapEntry, domain: &str) -> Option<BloodHoundComputer> {
    let raw_sid = entry.get_first_raw("objectSid")?;
    let rpc_sid = RpcSid::from_le_bytes(raw_sid).ok()?;
    let object_identifier = rpc_sid.to_string();
    let domainsid = get_domain_sid(&rpc_sid);

    let sam = entry.get_string("sAMAccountName").unwrap_or_default();
    let dn = entry.get_string("distinguishedName").unwrap_or_else(|| entry.dn.clone());
    let uac = entry.get_string("userAccountControl").and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);

    let domain_upper = domain.to_uppercase();
    let host_prefix = sam.trim_end_matches('$');
    let name = format!("{}.{}", host_prefix.to_uppercase(), domain_upper);

    let allowed_to_delegate = entry.get_all_strings("msDS-AllowedToDelegateTo");
    let allowed_to_act = parse_rbcd_act_sids(entry);
    let has_sid_history = parse_sid_history(entry);

    let primary_group_id = entry.get_string("primaryGroupID").and_then(|s| s.parse::<u32>().ok());
    let primary_group_sid = primary_group_id.map(|rid| format!("{}-{}", domainsid, rid));

    let os = entry.get_string("operatingSystem");
    let last_logon = entry.get_string("lastLogon").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let pwd_last_set = entry.get_string("pwdLastSet").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);

    let enabled = (uac & 0x0002) == 0;
    let unconstrained_delegation = (uac & 0x0008_0000) != 0;
    let trusted_to_auth = (uac & 0x0100_0000) != 0; // TRUSTED_TO_AUTH_FOR_DELEGATION
    let is_dc = (uac & 0x0000_2000) != 0; // SERVER_TRUST_ACCOUNT

    let high_value = is_dc || is_high_value_rid(&rpc_sid);
    let aces = parse_entry_aces(entry);

    Some(BloodHoundComputer {
        object_identifier,
        primary_group_sid,
        allowed_to_delegate,
        allowed_to_act,
        has_sid_history,
        aces,
        domain: domain_upper,
        name,
        distinguished_name: dn,
        domainsid,
        sam_account_name: sam,
        enabled,
        high_value,
        unconstrained_delegation,
        trusted_to_auth,
        operating_system: os,
        last_logon,
        pwd_last_set,
    })
}

pub fn parse_ldap_group(entry: &LdapEntry, domain: &str) -> Option<BloodHoundGroup> {
    let raw_sid = entry.get_first_raw("objectSid")?;
    let rpc_sid = RpcSid::from_le_bytes(raw_sid).ok()?;
    let object_identifier = rpc_sid.to_string();
    let domainsid = get_domain_sid(&rpc_sid);

    let sam = entry.get_string("sAMAccountName").unwrap_or_default();
    let dn = entry.get_string("distinguishedName").unwrap_or_else(|| entry.dn.clone());
    let admin_count = entry.get_string("adminCount").map(|s| s == "1").unwrap_or(false);

    let domain_upper = domain.to_uppercase();
    let name = format!("{}@{}", sam.to_uppercase(), domain_upper);

    let high_value = admin_count || is_high_value_rid(&rpc_sid);
    let aces = parse_entry_aces(entry);

    let raw_members = entry.get_all_strings("member");
    let members = raw_members
        .into_iter()
        .map(|dn_member| BloodHoundGroupMember {
            object_identifier: dn_member,
            object_type: "Unknown".to_string(),
        })
        .collect();

    Some(BloodHoundGroup {
        object_identifier,
        members,
        aces,
        domain: domain_upper,
        name,
        distinguished_name: dn,
        domainsid,
        sam_account_name: sam,
        high_value,
        admin_count,
    })
}

pub fn parse_ldap_domain(entry: &LdapEntry, domain: &str) -> Option<BloodHoundDomain> {
    let raw_sid = entry.get_first_raw("objectSid")?;
    let rpc_sid = RpcSid::from_le_bytes(raw_sid).ok()?;
    let object_identifier = rpc_sid.to_string();
    let domainsid = object_identifier.clone();

    let dn = entry.get_string("distinguishedName").unwrap_or_else(|| entry.dn.clone());
    let domain_upper = domain.to_uppercase();

    let func_level = match entry.get_string("msDS-Behavior-Version").as_deref() {
        Some("7") => "Windows Server 2016",
        Some("6") => "Windows Server 2012 R2",
        Some("5") => "Windows Server 2012",
        Some("4") => "Windows Server 2008 R2",
        Some("3") => "Windows Server 2008",
        Some("2") => "Windows Server 2003",
        _ => "Unknown",
    }
    .to_string();

    let aces = parse_entry_aces(entry);

    Some(BloodHoundDomain {
        object_identifier,
        trusts: Vec::new(),
        aces,
        domain: domain_upper.clone(),
        name: domain_upper,
        distinguished_name: dn,
        domainsid,
        high_value: true,
        function_level: func_level,
    })
}

// ---------------------------------------------------------------------------
// Security Descriptor & ACE Extraction
// ---------------------------------------------------------------------------

fn parse_entry_aces(entry: &LdapEntry) -> Vec<BloodHoundAce> {
    let mut out = Vec::new();
    let raw_sd = match entry.get_first_raw("nTSecurityDescriptor") {
        Some(b) => b,
        None => return out,
    };

    let sd = match SecurityDescriptor::parse(raw_sd) {
        Ok(s) => s,
        Err(_) => return out,
    };

    // Owner ACE
    if let Some(ref owner) = sd.owner_sid {
        out.push(BloodHoundAce {
            principal_sid: owner.to_string(),
            principal_type: "Unknown".to_string(),
            right_name: "Owns".to_string(),
            is_inherited: false,
        });
    }

    // DACL ACEs
    if let Some(ref dacl) = sd.dacl {
        for ace in &dacl.aces {
            let trustee = ace.sid.to_string();
            let is_inherited = (ace.ace_flags & 0x10) != 0;

            if (ace.mask & access_mask::GENERIC_ALL) != 0 || ace.mask == 0x000F_01FF {
                out.push(BloodHoundAce {
                    principal_sid: trustee.clone(),
                    principal_type: "Unknown".to_string(),
                    right_name: "GenericAll".to_string(),
                    is_inherited,
                });
            } else {
                if (ace.mask & access_mask::WRITE_DAC) != 0 {
                    out.push(BloodHoundAce {
                        principal_sid: trustee.clone(),
                        principal_type: "Unknown".to_string(),
                        right_name: "WriteDacl".to_string(),
                        is_inherited,
                    });
                }
                if (ace.mask & access_mask::WRITE_OWNER) != 0 {
                    out.push(BloodHoundAce {
                        principal_sid: trustee.clone(),
                        principal_type: "Unknown".to_string(),
                        right_name: "WriteOwner".to_string(),
                        is_inherited,
                    });
                }
                if (ace.mask & access_mask::GENERIC_WRITE) != 0 {
                    out.push(BloodHoundAce {
                        principal_sid: trustee.clone(),
                        principal_type: "Unknown".to_string(),
                        right_name: "GenericWrite".to_string(),
                        is_inherited,
                    });
                }
                if (ace.mask & access_mask::ADS_RIGHT_DS_CONTROL_ACCESS) != 0 {
                    out.push(BloodHoundAce {
                        principal_sid: trustee.clone(),
                        principal_type: "Unknown".to_string(),
                        right_name: "AllExtendedRights".to_string(),
                        is_inherited,
                    });
                }
            }
        }
    }

    out
}

fn parse_rbcd_act_sids(entry: &LdapEntry) -> Vec<String> {
    match entry.get_first_raw("msDS-AllowedToActOnBehalfOfOtherIdentity") {
        Some(raw) => parse_rbcd_allowed_sids(raw)
            .unwrap_or_default()
            .into_iter()
            .map(|sid| sid.to_string())
            .collect(),
        None => Vec::new(),
    }
}

fn parse_sid_history(entry: &LdapEntry) -> Vec<String> {
    match entry.get_raw("sIDHistory") {
        Some(vals) => vals
            .iter()
            .filter_map(|b| RpcSid::from_le_bytes(b).ok().map(|s| s.to_string()))
            .collect(),
        None => Vec::new(),
    }
}

fn get_domain_sid(sid: &RpcSid) -> String {
    if sid.sub_authorities.len() >= 4 {
        let auth_be = sid.identifier_authority;
        let mut full_auth = [0u8; 8];
        full_auth[2..8].copy_from_slice(&auth_be);
        let auth_val = u64::from_be_bytes(full_auth);
        format!(
            "S-{}-{}-{}-{}-{}",
            sid.revision,
            auth_val,
            sid.sub_authorities[0],
            sid.sub_authorities[1],
            sid.sub_authorities[2]
        )
    } else {
        sid.to_string()
    }
}

fn is_high_value_rid(sid: &RpcSid) -> bool {
    matches!(
        sid.sub_authorities.last(),
        Some(&500) | Some(&502) | Some(&512) | Some(&516) | Some(&519) | Some(&520)
    )
}

fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("DC={}", part))
        .collect::<Vec<_>>()
        .join(",")
}

// ---------------------------------------------------------------------------
// JSON Formatting Helpers
// ---------------------------------------------------------------------------

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn format_json_string_array(items: &[String]) -> String {
    if items.is_empty() {
        return "[]".to_string();
    }
    let parts: Vec<String> = items.iter().map(|s| format!("\"{}\"", escape_json(s))).collect();
    format!("[{}]", parts.join(","))
}

fn format_json_ace_array(aces: &[BloodHoundAce]) -> String {
    if aces.is_empty() {
        return "[]".to_string();
    }
    let parts: Vec<String> = aces.iter().map(BloodHoundAce::to_json).collect();
    format!("[{}]", parts.join(","))
}

fn format_collection_json(collection_type: &str, items_json: &[String]) -> String {
    format!(
        "{{\"data\":[{}],\"meta\":{{\"methods\":0,\"type\":\"{}\",\"count\":{},\"version\":5}}}}",
        items_json.join(","),
        collection_type,
        items_json.len()
    )
}

// ---------------------------------------------------------------------------
// Pure-Rust ZIP File Generator (Store mode, uncompressed)
// ---------------------------------------------------------------------------

fn create_zip_archive(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut local_entries = Vec::new();
    let mut central_dir = Vec::new();
    let mut offset = 0u32;

    for (name, content) in files {
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len() as u16;
        let data_len = content.len() as u32;
        let crc = compute_crc32(content);

        // Local Header
        let mut local_hdr = Vec::with_capacity(30 + name_bytes.len() + content.len());
        local_hdr.extend_from_slice(&0x0403_4B50u32.to_le_bytes()); // PK\x03\x04
        local_hdr.extend_from_slice(&20u16.to_le_bytes()); // Version needed (2.0)
        local_hdr.extend_from_slice(&0u16.to_le_bytes()); // General flags
        local_hdr.extend_from_slice(&0u16.to_le_bytes()); // Compression method (0 = Store)
        local_hdr.extend_from_slice(&0u16.to_le_bytes()); // Last mod time
        local_hdr.extend_from_slice(&0u16.to_le_bytes()); // Last mod date
        local_hdr.extend_from_slice(&crc.to_le_bytes());
        local_hdr.extend_from_slice(&data_len.to_le_bytes()); // Compressed size
        local_hdr.extend_from_slice(&data_len.to_le_bytes()); // Uncompressed size
        local_hdr.extend_from_slice(&name_len.to_le_bytes());
        local_hdr.extend_from_slice(&0u16.to_le_bytes()); // Extra field length
        local_hdr.extend_from_slice(name_bytes);
        local_hdr.extend_from_slice(content);

        let local_entry_len = local_hdr.len() as u32;
        local_entries.push(local_hdr);

        // Central Directory Entry
        central_dir.extend_from_slice(&0x0201_4B50u32.to_le_bytes()); // PK\x01\x02
        central_dir.extend_from_slice(&20u16.to_le_bytes()); // Version made by
        central_dir.extend_from_slice(&20u16.to_le_bytes()); // Version needed
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // General flags
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // Compression method
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // Last mod time
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // Last mod date
        central_dir.extend_from_slice(&crc.to_le_bytes());
        central_dir.extend_from_slice(&data_len.to_le_bytes());
        central_dir.extend_from_slice(&data_len.to_le_bytes());
        central_dir.extend_from_slice(&name_len.to_le_bytes());
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // Extra field length
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // Comment length
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // Disk number start
        central_dir.extend_from_slice(&0u16.to_le_bytes()); // Internal file attributes
        central_dir.extend_from_slice(&0u32.to_le_bytes()); // External file attributes
        central_dir.extend_from_slice(&offset.to_le_bytes()); // Relative offset of local header
        central_dir.extend_from_slice(name_bytes);

        offset += local_entry_len;
    }

    let central_dir_offset = offset;
    let central_dir_size = central_dir.len() as u32;
    let total_entries = files.len() as u16;

    // End of Central Directory Record (EOCD)
    let mut eocd = Vec::with_capacity(22);
    eocd.extend_from_slice(&0x0605_4B50u32.to_le_bytes()); // PK\x05\x06
    eocd.extend_from_slice(&0u16.to_le_bytes()); // Disk number
    eocd.extend_from_slice(&0u16.to_le_bytes()); // Start disk
    eocd.extend_from_slice(&total_entries.to_le_bytes());
    eocd.extend_from_slice(&total_entries.to_le_bytes());
    eocd.extend_from_slice(&central_dir_size.to_le_bytes());
    eocd.extend_from_slice(&central_dir_offset.to_le_bytes());
    eocd.extend_from_slice(&0u16.to_le_bytes()); // Comment length

    let mut out = Vec::with_capacity((central_dir_offset + central_dir_size + 22) as usize);
    for entry in local_entries {
        out.extend_from_slice(&entry);
    }
    out.extend_from_slice(&central_dir);
    out.extend_from_slice(&eocd);
    out
}

fn compute_crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// Unit & Integration Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloodhound_user_json_schema() {
        let user = BloodHoundUser {
            object_identifier: "S-1-5-21-123456789-1001".to_string(),
            primary_group_sid: Some("S-1-5-21-123456789-513".to_string()),
            allowed_to_delegate: vec!["cifs/fileserver.corp.local".to_string()],
            spn_targets: Vec::new(),
            has_sid_history: vec!["S-1-5-21-987654321-1001".to_string()],
            aces: vec![BloodHoundAce {
                principal_sid: "S-1-5-21-123456789-512".to_string(),
                principal_type: "Group".to_string(),
                right_name: "GenericAll".to_string(),
                is_inherited: false,
            }],
            domain: "CORP.LOCAL".to_string(),
            name: "ALICE@CORP.LOCAL".to_string(),
            distinguished_name: "CN=Alice,CN=Users,DC=corp,DC=local".to_string(),
            domainsid: "S-1-5-21-123456789".to_string(),
            sam_account_name: "alice".to_string(),
            enabled: true,
            high_value: false,
            admin_count: false,
            dont_req_preauth: false,
            password_not_reqd: false,
            unconstrained_delegation: false,
            sensitive: false,
            pwd_never_expires: true,
            has_spn: true,
            service_principal_names: vec!["HTTP/app.corp.local".to_string()],
            email: Some("alice@corp.local".to_string()),
            display_name: Some("Alice Smith".to_string()),
            last_logon: 1730000000,
            pwd_last_set: 1729000000,
        };

        let json = user.to_json();
        assert!(json.contains("\"ObjectIdentifier\":\"S-1-5-21-123456789-1001\""));
        assert!(json.contains("\"PrimaryGroupSID\":\"S-1-5-21-123456789-513\""));
        assert!(json.contains("\"name\":\"ALICE@CORP.LOCAL\""));
        assert!(json.contains("\"serviceprincipalnames\":[\"HTTP/app.corp.local\"]"));
        assert!(json.contains("\"RightName\":\"GenericAll\""));
    }

    #[test]
    fn test_bloodhound_dump_collection_and_zip_archive() {
        let user = BloodHoundUser {
            object_identifier: "S-1-5-21-123456789-1001".to_string(),
            primary_group_sid: Some("S-1-5-21-123456789-513".to_string()),
            allowed_to_delegate: Vec::new(),
            spn_targets: Vec::new(),
            has_sid_history: Vec::new(),
            aces: Vec::new(),
            domain: "CORP.LOCAL".to_string(),
            name: "BOB@CORP.LOCAL".to_string(),
            distinguished_name: "CN=Bob,CN=Users,DC=corp,DC=local".to_string(),
            domainsid: "S-1-5-21-123456789".to_string(),
            sam_account_name: "bob".to_string(),
            enabled: true,
            high_value: false,
            admin_count: false,
            dont_req_preauth: false,
            password_not_reqd: false,
            unconstrained_delegation: false,
            sensitive: false,
            pwd_never_expires: false,
            has_spn: false,
            service_principal_names: Vec::new(),
            email: None,
            display_name: None,
            last_logon: 0,
            pwd_last_set: 0,
        };

        let dump = BloodHoundDump {
            users: vec![user],
            computers: Vec::new(),
            groups: Vec::new(),
            domains: Vec::new(),
        };

        let users_json = dump.to_users_json();
        assert!(users_json.contains("\"type\":\"users\""));
        assert!(users_json.contains("\"version\":5"));
        assert!(users_json.contains("\"count\":1"));

        let zip_bytes = dump.to_zip_bytes();
        assert!(zip_bytes.starts_with(b"PK\x03\x04"));
        assert!(zip_bytes.len() > 100);
    }

    #[test]
    fn test_crc32_standard_vector() {
        // Known vector: CRC32("123456789") = 0xCBF43926
        assert_eq!(compute_crc32(b"123456789"), 0xCBF43926);
    }
}
