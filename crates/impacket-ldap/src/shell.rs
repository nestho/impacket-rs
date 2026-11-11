//! Interactive Active Directory LDAP Shell & Administration Engine (`ldap_shell.py`).
//!
//! Provides an interactive and scriptable REPL environment for navigating Active Directory,
//! resolving nested group memberships (via `1.2.840.113556.1.4.1941`), managing user/computer
//! accounts, toggling UAC flags (such as `DONT_REQ_PREAUTH`), resetting passwords, and inspecting
//! LAPS credentials.

use crate::asn1::{AttributeModification, LdapAttribute, ModifyOperation, SearchScope};
use crate::client::LdapClient;
use impacket_core::CoreError;
use impacket_ndr::RpcSid;
use std::io::{BufRead, Write};

/// LDAP Matching Rule in Chain (`LDAP_MATCHING_RULE_IN_CHAIN` per Microsoft AD extension).
pub const LDAP_MATCHING_RULE_IN_CHAIN: &str = "1.2.840.113556.1.4.1941";

/// UserAccountControl bit flags.
pub const UAC_ACCOUNTDISABLE: u32 = 0x0002;
pub const UAC_DONT_REQ_PREAUTH: u32 = 0x0040_0000;
pub const UAC_NORMAL_ACCOUNT: u32 = 0x0200;
pub const UAC_WORKSTATION_TRUST_ACCOUNT: u32 = 0x1000;

/// Interactive LDAP Administration Session.
pub struct LdapShellSession<S: std::io::Read + std::io::Write> {
    pub client: LdapClient<S>,
    pub base_dn: String,
    pub domain_name: String,
    pub bound_user: String,
}

impl<S: std::io::Read + std::io::Write> LdapShellSession<S> {
    /// Creates a new LDAP shell session.
    pub fn new(
        client: LdapClient<S>,
        base_dn: impl Into<String>,
        domain_name: impl Into<String>,
        bound_user: impl Into<String>,
    ) -> Self {
        Self {
            client,
            base_dn: base_dn.into(),
            domain_name: domain_name.into(),
            bound_user: bound_user.into(),
        }
    }

    /// Initializes session by querying RootDSE if `base_dn` is empty.
    pub fn init(&mut self) -> Result<(), CoreError> {
        if self.base_dn.is_empty() {
            let res = self.client.search(
                "",
                SearchScope::BaseObject,
                b"(objectClass=*)",
                &["defaultNamingContext", "dnsHostName"],
            )?;
            if let Some(entry) = res.first() {
                if let Some(dn) = entry.get_string("defaultNamingContext") {
                    self.base_dn = dn;
                }
                if let Some(dns) = entry.get_string("dnsHostName") {
                    if self.domain_name.is_empty() {
                        self.domain_name = dns;
                    }
                }
            }
        }
        Ok(())
    }

    /// Resolves an account name (`sAMAccountName`) to its full Distinguished Name (DN).
    pub fn resolve_account_dn(&mut self, sam_name: &str) -> Result<String, CoreError> {
        let filter = format!("(sAMAccountName={})", sam_name);
        let res = self.client.search(
            &self.base_dn,
            SearchScope::WholeSubtree,
            filter.as_bytes(),
            &["distinguishedName"],
        )?;
        let entry = res
            .first()
            .ok_or_else(|| CoreError::ProtocolError(format!("Account '{}' not found", sam_name)))?;
        Ok(entry.dn.clone())
    }

    /// Resolves a computer name (adding trailing `$` if missing) to its full DN.
    pub fn resolve_computer_dn(&mut self, computer_name: &str) -> Result<String, CoreError> {
        let sam = if computer_name.ends_with('$') {
            computer_name.to_string()
        } else {
            format!("{}$", computer_name)
        };
        self.resolve_account_dn(&sam)
    }

    /// Dispatches a single command line and returns formatted output.
    pub fn dispatch_command(&mut self, line: &str) -> Result<String, CoreError> {
        let args = parse_command_tokens(line);
        if args.is_empty() {
            return Ok(String::new());
        }

        let cmd = args[0].to_lowercase();
        match cmd.as_str() {
            "help" | "?" => Ok(self.cmd_help()),
            "whoami" => Ok(self.cmd_whoami()),
            "search" => {
                if args.len() < 2 {
                    return Err(CoreError::ProtocolError(
                        "Usage: search <filter> [attr1 attr2 ...]".into(),
                    ));
                }
                let filter = &args[1];
                let attrs: Vec<&str> = if args.len() > 2 {
                    args[2..].iter().map(|s| s.as_str()).collect()
                } else {
                    vec!["distinguishedName", "sAMAccountName", "objectClass"]
                };
                self.cmd_search(filter, &attrs)
            }
            "get_user_groups" => {
                if args.len() < 2 {
                    return Err(CoreError::ProtocolError("Usage: get_user_groups <username>".into()));
                }
                self.cmd_get_user_groups(&args[1])
            }
            "get_group_users" => {
                if args.len() < 2 {
                    return Err(CoreError::ProtocolError("Usage: get_group_users <groupname>".into()));
                }
                self.cmd_get_group_users(&args[1])
            }
            "get_laps_password" => {
                if args.len() < 2 {
                    return Err(CoreError::ProtocolError(
                        "Usage: get_laps_password <computername>".into(),
                    ));
                }
                self.cmd_get_laps_password(&args[1])
            }
            "add_user" => {
                if args.len() < 3 {
                    return Err(CoreError::ProtocolError(
                        "Usage: add_user <username> <password> [container_dn]".into(),
                    ));
                }
                let container = args.get(3).map(|s| s.as_str());
                self.cmd_add_user(&args[1], &args[2], container)
            }
            "add_computer" => {
                if args.len() < 2 {
                    return Err(CoreError::ProtocolError(
                        "Usage: add_computer <computername> [password] [container_dn]".into(),
                    ));
                }
                let pwd = args.get(2).map(|s| s.as_str());
                let container = args.get(3).map(|s| s.as_str());
                self.cmd_add_computer(&args[1], pwd, container)
            }
            "add_user_to_group" => {
                if args.len() < 3 {
                    return Err(CoreError::ProtocolError(
                        "Usage: add_user_to_group <username> <groupname>".into(),
                    ));
                }
                self.cmd_add_user_to_group(&args[1], &args[2])
            }
            "remove_user_from_group" => {
                if args.len() < 3 {
                    return Err(CoreError::ProtocolError(
                        "Usage: remove_user_from_group <username> <groupname>".into(),
                    ));
                }
                self.cmd_remove_user_from_group(&args[1], &args[2])
            }
            "change_password" => {
                if args.len() < 3 {
                    return Err(CoreError::ProtocolError(
                        "Usage: change_password <username> <new_password>".into(),
                    ));
                }
                self.cmd_change_password(&args[1], &args[2])
            }
            "enable_account" => {
                if args.len() < 2 {
                    return Err(CoreError::ProtocolError("Usage: enable_account <username>".into()));
                }
                self.cmd_toggle_account_disable(&args[1], false)
            }
            "disable_account" => {
                if args.len() < 2 {
                    return Err(CoreError::ProtocolError("Usage: disable_account <username>".into()));
                }
                self.cmd_toggle_account_disable(&args[1], true)
            }
            "set_dontreqpreauth" => {
                if args.len() < 2 {
                    return Err(CoreError::ProtocolError(
                        "Usage: set_dontreqpreauth <username> [true|false]".into(),
                    ));
                }
                let enable = args.get(2).map(|s| s.as_str() != "false").unwrap_or(true);
                self.cmd_set_dontreqpreauth(&args[1], enable)
            }
            "set_rbcd" => {
                if args.len() < 3 {
                    return Err(CoreError::ProtocolError(
                        "Usage: set_rbcd <target_computer> <grantee_computer>".into(),
                    ));
                }
                self.cmd_set_rbcd(&args[1], &args[2])
            }
            "clear_rbcd" => {
                if args.len() < 2 {
                    return Err(CoreError::ProtocolError("Usage: clear_rbcd <target_computer>".into()));
                }
                self.cmd_clear_rbcd(&args[1])
            }
            "dump" => self.cmd_dump(),
            _ => Err(CoreError::ProtocolError(format!(
                "Unknown command '{}'. Type 'help' for available commands.",
                cmd
            ))),
        }
    }

    fn cmd_help(&self) -> String {
        let mut out = String::new();
        out.push_str("Available LDAP Shell Commands:\n");
        out.push_str("  whoami                                     - Display current user context and base DN\n");
        out.push_str("  search <filter> [attr1 attr2 ...]          - Execute LDAP search query with paged results\n");
        out.push_str("  get_user_groups <username>                 - Recursively enumerate group memberships for user\n");
        out.push_str("  get_group_users <groupname>                - Recursively enumerate member users of a group\n");
        out.push_str("  get_laps_password <computername>           - Retrieve LAPS administrator password\n");
        out.push_str("  add_user <username> <password> [container] - Create new Active Directory user account\n");
        out.push_str("  add_computer <name> [password] [container] - Create new Active Directory computer account\n");
        out.push_str("  add_user_to_group <username> <groupname>   - Add user to an existing group\n");
        out.push_str("  remove_user_from_group <user> <group>      - Remove user from a group\n");
        out.push_str("  change_password <username> <new_password>  - Reset user password via unicodePwd modification\n");
        out.push_str("  enable_account <username>                  - Enable user account (clear ACCOUNTDISABLE)\n");
        out.push_str("  disable_account <username>                 - Disable user account (set ACCOUNTDISABLE)\n");
        out.push_str("  set_dontreqpreauth <username> [true|false] - Toggle DONT_REQ_PREAUTH flag in UAC\n");
        out.push_str("  set_rbcd <target_computer> <grantee>       - Configure Resource-Based Constrained Delegation\n");
        out.push_str("  clear_rbcd <target_computer>               - Remove RBCD delegation settings\n");
        out.push_str("  dump                                       - Display Active Directory naming contexts and summary\n");
        out.push_str("  help, ?                                    - Show this help summary\n");
        out.push_str("  exit, quit                                 - Terminate LDAP shell session\n");
        out
    }

    fn cmd_whoami(&self) -> String {
        format!(
            "Bound User: {}\nDomain:     {}\nBase DN:    {}\n",
            if self.bound_user.is_empty() { "Anonymous / SASL" } else { &self.bound_user },
            if self.domain_name.is_empty() { "Unknown" } else { &self.domain_name },
            if self.base_dn.is_empty() { "Not initialized" } else { &self.base_dn }
        )
    }

    fn cmd_search(&mut self, filter: &str, attrs: &[&str]) -> Result<String, CoreError> {
        let entries = self.client.search_paged(&self.base_dn, SearchScope::WholeSubtree, filter.as_bytes(), attrs, 100)?;
        if entries.is_empty() {
            return Ok(format!("No entries found matching filter '{}'.\n", filter));
        }

        let mut out = format!("[+] Found {} matching entries:\n\n", entries.len());
        for (i, entry) in entries.iter().enumerate() {
            out.push_str(&format!("{}. DN: {}\n", i + 1, entry.dn));
            for (attr_name, vals) in &entry.attributes {
                let formatted_vals: Vec<String> = vals
                    .iter()
                    .map(|v| String::from_utf8_lossy(v).to_string())
                    .collect();
                out.push_str(&format!("   {}: {}\n", attr_name, formatted_vals.join(", ")));
            }
            out.push('\n');
        }
        Ok(out)
    }

    fn cmd_get_user_groups(&mut self, username: &str) -> Result<String, CoreError> {
        let user_dn = self.resolve_account_dn(username)?;
        let filter = format!("(member:{}={})", LDAP_MATCHING_RULE_IN_CHAIN, user_dn);
        let groups = self.client.search_paged(
            &self.base_dn,
            SearchScope::WholeSubtree,
            filter.as_bytes(),
            &["sAMAccountName", "distinguishedName", "adminCount"],
            100,
        )?;

        let mut out = format!("[+] Group memberships for '{}' ({}):\n", username, user_dn);
        if groups.is_empty() {
            out.push_str("   (No group memberships found)\n");
            return Ok(out);
        }

        for g in groups {
            let sam = g.get_string("sAMAccountName").unwrap_or_else(|| "Unknown".into());
            let is_admin = g.get_string("adminCount").map(|c| c == "1").unwrap_or(false);
            let admin_tag = if is_admin { " [ADMIN]" } else { "" };
            out.push_str(&format!("   * {}{} ({})\n", sam, admin_tag, g.dn));
        }
        Ok(out)
    }

    fn cmd_get_group_users(&mut self, groupname: &str) -> Result<String, CoreError> {
        let group_dn = self.resolve_account_dn(groupname)?;
        let filter = format!("(memberOf:{}={})", LDAP_MATCHING_RULE_IN_CHAIN, group_dn);
        let members = self.client.search_paged(
            &self.base_dn,
            SearchScope::WholeSubtree,
            filter.as_bytes(),
            &["sAMAccountName", "distinguishedName", "userAccountControl"],
            100,
        )?;

        let mut out = format!("[+] Members of group '{}' ({}):\n", groupname, group_dn);
        if members.is_empty() {
            out.push_str("   (No members found)\n");
            return Ok(out);
        }

        for m in members {
            let sam = m.get_string("sAMAccountName").unwrap_or_else(|| "Unknown".into());
            let uac = m
                .get_string("userAccountControl")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            let disabled = if (uac & UAC_ACCOUNTDISABLE) != 0 { " [DISABLED]" } else { "" };
            out.push_str(&format!("   * {}{} ({})\n", sam, disabled, m.dn));
        }
        Ok(out)
    }

    fn cmd_get_laps_password(&mut self, computer_name: &str) -> Result<String, CoreError> {
        let sam = if computer_name.ends_with('$') {
            computer_name.to_string()
        } else {
            format!("{}$", computer_name)
        };
        let filter = format!("(|(sAMAccountName={})(cn={}))", sam, computer_name.trim_end_matches('$'));
        let res = self.client.search(
            &self.base_dn,
            SearchScope::WholeSubtree,
            filter.as_bytes(),
            &[
                "sAMAccountName",
                "ms-Mcs-AdmPwd",
                "ms-Mcs-AdmPwdExpirationTime",
                "msLAPS-Password",
                "msLAPS-PasswordExpirationTime",
            ],
        )?;

        let entry = res
            .first()
            .ok_or_else(|| CoreError::ProtocolError(format!("Computer '{}' not found", computer_name)))?;

        let mut out = format!("[+] LAPS Password Information for '{}' ({}):\n", computer_name, entry.dn);

        // Legacy LAPS attribute: ms-Mcs-AdmPwd
        if let Some(pwd) = entry.get_string("ms-Mcs-AdmPwd") {
            out.push_str(&format!("   Legacy LAPS Password:   {}\n", pwd));
            if let Some(exp) = entry.get_string("ms-Mcs-AdmPwdExpirationTime") {
                out.push_str(&format!("   Expiration Timestamp:   {}\n", exp));
            }
            return Ok(out);
        }

        // Modern Windows LAPS: msLAPS-Password
        if let Some(pwd) = entry.get_string("msLAPS-Password") {
            out.push_str(&format!("   Windows LAPS Password:  {}\n", pwd));
            if let Some(exp) = entry.get_string("msLAPS-PasswordExpirationTime") {
                out.push_str(&format!("   Expiration Timestamp:   {}\n", exp));
            }
            return Ok(out);
        }

        out.push_str("   [-] No LAPS password attributes present or readable on computer object.\n");
        Ok(out)
    }

    fn cmd_add_user(&mut self, username: &str, password: &str, container_dn: Option<&str>) -> Result<String, CoreError> {
        let container = container_dn
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("CN=Users,{}", self.base_dn));
        let user_dn = format!("CN={},{}", username, container);

        let upn = if !self.domain_name.is_empty() {
            format!("{}@{}", username, self.domain_name)
        } else {
            username.to_string()
        };

        // Format unicodePwd: UTF-16LE password wrapped in quotation marks
        let quoted_pwd = format!("\"{}\"", password);
        let pwd_utf16: Vec<u8> = quoted_pwd.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        let attributes = vec![
            LdapAttribute {
                type_name: "objectClass".to_string(),
                values: vec![
                    b"top".to_vec(),
                    b"person".to_vec(),
                    b"organizationalPerson".to_vec(),
                    b"user".to_vec(),
                ],
            },
            LdapAttribute {
                type_name: "sAMAccountName".to_string(),
                values: vec![username.as_bytes().to_vec()],
            },
            LdapAttribute {
                type_name: "userPrincipalName".to_string(),
                values: vec![upn.as_bytes().to_vec()],
            },
            LdapAttribute {
                type_name: "unicodePwd".to_string(),
                values: vec![pwd_utf16],
            },
            LdapAttribute {
                type_name: "userAccountControl".to_string(),
                values: vec![UAC_NORMAL_ACCOUNT.to_string().into_bytes()],
            },
        ];

        self.client.add(&user_dn, attributes)?;
        Ok(format!("[+] Successfully created Active Directory user '{}' at '{}'.\n", username, user_dn))
    }

    fn cmd_add_computer(&mut self, computer_name: &str, password: Option<&str>, container_dn: Option<&str>) -> Result<String, CoreError> {
        let sam_name = if computer_name.ends_with('$') {
            computer_name.to_string()
        } else {
            format!("{}$", computer_name)
        };
        let cn = computer_name.trim_end_matches('$');
        let container = container_dn
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("CN=Computers,{}", self.base_dn));
        let computer_dn = format!("CN={},{}", cn, container);

        let host_spn = format!("HOST/{}", cn);
        let host_fqdn_spn = if !self.domain_name.is_empty() {
            format!("HOST/{}.{}", cn, self.domain_name)
        } else {
            host_spn.clone()
        };

        let mut attributes = vec![
            LdapAttribute {
                type_name: "objectClass".to_string(),
                values: vec![
                    b"top".to_vec(),
                    b"person".to_vec(),
                    b"organizationalPerson".to_vec(),
                    b"user".to_vec(),
                    b"computer".to_vec(),
                ],
            },
            LdapAttribute {
                type_name: "sAMAccountName".to_string(),
                values: vec![sam_name.into_bytes()],
            },
            LdapAttribute {
                type_name: "userAccountControl".to_string(),
                values: vec![UAC_WORKSTATION_TRUST_ACCOUNT.to_string().into_bytes()],
            },
            LdapAttribute {
                type_name: "servicePrincipalName".to_string(),
                values: vec![host_spn.into_bytes(), host_fqdn_spn.into_bytes()],
            },
        ];

        if let Some(pwd) = password {
            let quoted_pwd = format!("\"{}\"", pwd);
            let pwd_utf16: Vec<u8> = quoted_pwd.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
            attributes.push(LdapAttribute {
                type_name: "unicodePwd".to_string(),
                values: vec![pwd_utf16],
            });
        }

        self.client.add(&computer_dn, attributes)?;
        Ok(format!("[+] Successfully created Active Directory computer '{}' at '{}'.\n", cn, computer_dn))
    }

    fn cmd_add_user_to_group(&mut self, username: &str, groupname: &str) -> Result<String, CoreError> {
        let user_dn = self.resolve_account_dn(username)?;
        let group_dn = self.resolve_account_dn(groupname)?;

        let mod_op = AttributeModification {
            operation: ModifyOperation::Add,
            attribute: LdapAttribute {
                type_name: "member".to_string(),
                values: vec![user_dn.into_bytes()],
            },
        };

        self.client.modify(&group_dn, vec![mod_op])?;
        Ok(format!("[+] Added user '{}' to group '{}'.\n", username, groupname))
    }

    fn cmd_remove_user_from_group(&mut self, username: &str, groupname: &str) -> Result<String, CoreError> {
        let user_dn = self.resolve_account_dn(username)?;
        let group_dn = self.resolve_account_dn(groupname)?;

        let mod_op = AttributeModification {
            operation: ModifyOperation::Delete,
            attribute: LdapAttribute {
                type_name: "member".to_string(),
                values: vec![user_dn.into_bytes()],
            },
        };

        self.client.modify(&group_dn, vec![mod_op])?;
        Ok(format!("[+] Removed user '{}' from group '{}'.\n", username, groupname))
    }

    fn cmd_change_password(&mut self, username: &str, new_password: &str) -> Result<String, CoreError> {
        let user_dn = self.resolve_account_dn(username)?;
        let quoted_pwd = format!("\"{}\"", new_password);
        let pwd_utf16: Vec<u8> = quoted_pwd.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

        let mod_op = AttributeModification {
            operation: ModifyOperation::Replace,
            attribute: LdapAttribute {
                type_name: "unicodePwd".to_string(),
                values: vec![pwd_utf16],
            },
        };

        self.client.modify(&user_dn, vec![mod_op])?;
        Ok(format!("[+] Successfully updated password for user '{}'.\n", username))
    }

    fn cmd_toggle_account_disable(&mut self, username: &str, disable: bool) -> Result<String, CoreError> {
        let user_dn = self.resolve_account_dn(username)?;
        let res = self.client.search(
            &user_dn,
            SearchScope::BaseObject,
            b"(objectClass=*)",
            &["userAccountControl"],
        )?;
        let entry = res
            .first()
            .ok_or_else(|| CoreError::ProtocolError(format!("Account '{}' not found", username)))?;

        let mut uac = entry
            .get_string("userAccountControl")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(UAC_NORMAL_ACCOUNT);

        if disable {
            uac |= UAC_ACCOUNTDISABLE;
        } else {
            uac &= !UAC_ACCOUNTDISABLE;
        }

        let mod_op = AttributeModification {
            operation: ModifyOperation::Replace,
            attribute: LdapAttribute {
                type_name: "userAccountControl".to_string(),
                values: vec![uac.to_string().into_bytes()],
            },
        };

        self.client.modify(&user_dn, vec![mod_op])?;
        let status = if disable { "disabled" } else { "enabled" };
        Ok(format!("[+] Successfully {} account '{}' (UAC: {:#x}).\n", status, username, uac))
    }

    fn cmd_set_dontreqpreauth(&mut self, username: &str, enable: bool) -> Result<String, CoreError> {
        let user_dn = self.resolve_account_dn(username)?;
        let res = self.client.search(
            &user_dn,
            SearchScope::BaseObject,
            b"(objectClass=*)",
            &["userAccountControl"],
        )?;
        let entry = res
            .first()
            .ok_or_else(|| CoreError::ProtocolError(format!("Account '{}' not found", username)))?;

        let mut uac = entry
            .get_string("userAccountControl")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(UAC_NORMAL_ACCOUNT);

        if enable {
            uac |= UAC_DONT_REQ_PREAUTH;
        } else {
            uac &= !UAC_DONT_REQ_PREAUTH;
        }

        let mod_op = AttributeModification {
            operation: ModifyOperation::Replace,
            attribute: LdapAttribute {
                type_name: "userAccountControl".to_string(),
                values: vec![uac.to_string().into_bytes()],
            },
        };

        self.client.modify(&user_dn, vec![mod_op])?;
        let status = if enable { "enabled" } else { "disabled" };
        Ok(format!("[+] DONT_REQ_PREAUTH {} for '{}' (UAC: {:#x}).\n", status, username, uac))
    }

    fn cmd_set_rbcd(&mut self, target_computer: &str, grantee_computer: &str) -> Result<String, CoreError> {
        let target_dn = self.resolve_computer_dn(target_computer)?;
        let grantee_dn = self.resolve_computer_dn(grantee_computer)?;

        let res = self.client.search(
            &grantee_dn,
            SearchScope::BaseObject,
            b"(objectClass=*)",
            &["objectSid"],
        )?;
        let grantee_entry = res.first().ok_or_else(|| {
            CoreError::ProtocolError(format!("Could not read objectSid for grantee '{}'", grantee_computer))
        })?;
        let sid_bytes = grantee_entry
            .get_first_raw("objectSid")
            .ok_or_else(|| CoreError::ProtocolError("grantee computer missing objectSid".into()))?;

        let sid = RpcSid::from_le_bytes(sid_bytes)?;
        crate::rbcd::write_rbcd(&mut self.client, &target_dn, &sid)?;
        Ok(format!(
            "[+] Successfully configured RBCD: '{}' can act on behalf of other identity to '{}'.\n",
            grantee_computer, target_computer
        ))
    }

    fn cmd_clear_rbcd(&mut self, target_computer: &str) -> Result<String, CoreError> {
        let target_dn = self.resolve_computer_dn(target_computer)?;
        crate::rbcd::flush_rbcd(&mut self.client, &target_dn)?;
        Ok(format!("[+] Cleared RBCD delegation settings on '{}'.\n", target_computer))
    }

    fn cmd_dump(&mut self) -> Result<String, CoreError> {
        let root = self.client.search(
            "",
            SearchScope::BaseObject,
            b"(objectClass=*)",
            &[
                "defaultNamingContext",
                "configurationNamingContext",
                "schemaNamingContext",
                "dnsHostName",
                "domainFunctionality",
                "forestFunctionality",
            ],
        )?;

        let mut out = String::from("[+] Active Directory RootDSE Summary:\n");
        if let Some(entry) = root.first() {
            if let Some(v) = entry.get_string("defaultNamingContext") {
                out.push_str(&format!("   Default Naming Context:       {}\n", v));
            }
            if let Some(v) = entry.get_string("configurationNamingContext") {
                out.push_str(&format!("   Configuration Naming Context: {}\n", v));
            }
            if let Some(v) = entry.get_string("schemaNamingContext") {
                out.push_str(&format!("   Schema Naming Context:        {}\n", v));
            }
            if let Some(v) = entry.get_string("dnsHostName") {
                out.push_str(&format!("   DC DNS Host Name:             {}\n", v));
            }
            if let Some(v) = entry.get_string("domainFunctionality") {
                out.push_str(&format!("   Domain Functional Level:      {}\n", v));
            }
            if let Some(v) = entry.get_string("forestFunctionality") {
                out.push_str(&format!("   Forest Functional Level:      {}\n", v));
            }
        }

        // Count users and computers
        let users = self.client.search_paged(
            &self.base_dn,
            SearchScope::WholeSubtree,
            b"(&(objectClass=user)(!(objectClass=computer)))",
            &["distinguishedName"],
            100,
        )?;
        let computers = self.client.search_paged(
            &self.base_dn,
            SearchScope::WholeSubtree,
            b"(objectClass=computer)",
            &["distinguishedName"],
            100,
        )?;

        out.push_str(&format!("\n[+] Total Active Directory Objects:\n"));
        out.push_str(&format!("   Users:     {}\n", users.len()));
        out.push_str(&format!("   Computers: {}\n", computers.len()));
        Ok(out)
    }

    /// Runs an interactive REPL reading commands from a buffered reader and printing to a writer.
    pub fn run_repl<R: BufRead, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), CoreError> {
        let _ = writer.write_all(b"Type 'help' for commands, 'exit' to quit.\n");
        let _ = writer.flush();

        let mut line = String::new();
        loop {
            let prompt = format!("ldap ({})> ", if self.domain_name.is_empty() { "ad" } else { &self.domain_name });
            let _ = writer.write_all(prompt.as_bytes());
            let _ = writer.flush();

            line.clear();
            let bytes_read = reader
                .read_line(&mut line)
                .map_err(|e| CoreError::IoError(format!("Read line failed: {}", e)))?;
            if bytes_read == 0 {
                break; // EOF
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.eq_ignore_ascii_case("exit") || trimmed.eq_ignore_ascii_case("quit") {
                let _ = writer.write_all(b"[*] Terminating LDAP session.\n");
                let _ = writer.flush();
                break;
            }

            match self.dispatch_command(trimmed) {
                Ok(resp) => {
                    let _ = writer.write_all(resp.as_bytes());
                    let _ = writer.flush();
                }
                Err(e) => {
                    let _ = writer.write_all(format!("[-] Error: {}\n", e).as_bytes());
                    let _ = writer.flush();
                }
            }
        }
        Ok(())
    }
}

/// Splits command line into whitespace-delimited tokens respecting quoted strings (`"..."` or `'...'`).
pub fn parse_command_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quote: Option<char> = None;

    for ch in line.chars() {
        match in_quote {
            Some(q) => {
                if ch == q {
                    in_quote = None;
                } else {
                    cur.push(ch);
                }
            }
            None => {
                if ch == '"' || ch == '\'' {
                    in_quote = Some(ch);
                } else if ch.is_whitespace() {
                    if !cur.is_empty() {
                        tokens.push(cur.clone());
                        cur.clear();
                    }
                } else {
                    cur.push(ch);
                }
            }
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_command_tokens_quotes() {
        let line = r#"search "(&(objectClass=user)(adminCount=1))" sAMAccountName distinguishedName"#;
        let tokens = parse_command_tokens(line);
        assert_eq!(tokens.len(), 4);
        assert_eq!(tokens[0], "search");
        assert_eq!(tokens[1], "(&(objectClass=user)(adminCount=1))");
        assert_eq!(tokens[2], "sAMAccountName");
        assert_eq!(tokens[3], "distinguishedName");

        let line2 = "add_user alice 'P@ssw0rd 123' 'CN=Users,DC=corp,DC=local'";
        let tokens2 = parse_command_tokens(line2);
        assert_eq!(tokens2.len(), 4);
        assert_eq!(tokens2[1], "alice");
        assert_eq!(tokens2[2], "P@ssw0rd 123");
        assert_eq!(tokens2[3], "CN=Users,DC=corp,DC=local");
    }

    #[test]
    fn test_help_and_whoami_output() {
        use std::io::Cursor;
        let dummy_stream = Cursor::new(Vec::new());
        let client = LdapClient::new(dummy_stream);
        let session = LdapShellSession::new(client, "DC=corp,DC=local", "corp.local", "Administrator");

        let help_text = session.cmd_help();
        assert!(help_text.contains("whoami"));
        assert!(help_text.contains("get_user_groups"));
        assert!(help_text.contains("add_user"));

        let who = session.cmd_whoami();
        assert!(who.contains("Administrator"));
        assert!(who.contains("corp.local"));
        assert!(who.contains("DC=corp,DC=local"));
    }
}
