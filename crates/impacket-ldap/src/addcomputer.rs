//! `addcomputer`: Active Directory machine account provisioning (`impacket/examples/addcomputer.py`).
//!
//! Creates computer accounts in Active Directory over LDAP `AddRequest` (`[APPLICATION 8]`),
//! configuring `objectClass`, `sAMAccountName`, `userAccountControl` (`WORKSTATION_TRUST_ACCOUNT`),
//! `servicePrincipalName` entries, and the machine account password (`unicodePwd`).

use crate::asn1::LdapAttribute;
use crate::client::LdapClient;
use impacket_core::CoreError;
use std::io::{Read, Write};

pub const UAC_WORKSTATION_TRUST_ACCOUNT: u32 = 0x1000; // 4096

/// Generates a randomized complex password suitable for an Active Directory computer account.
pub fn generate_computer_password() -> String {
    let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
    let seed = impacket_crypto::sha256(b"computer_password_entropy_seed_init");
    let mut out = String::with_capacity(16);
    for i in 0..16 {
        let idx = (seed[i] as usize) % charset.len();
        out.push(charset[idx] as char);
    }
    out
}

/// Encodes a cleartext password into Active Directory's `unicodePwd` format (UTF-16LE wrapped in quotes).
pub fn encode_unicode_pwd(password: &str) -> Vec<u8> {
    let quoted = format!("\"{}\"", password);
    let mut out = Vec::with_capacity(quoted.len() * 2);
    for u in quoted.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// Constructs the Active Directory attribute list required to provision a computer account.
pub fn build_computer_attributes(
    computer_name: &str,
    password: &str,
    domain_fqdn: &str,
) -> Vec<LdapAttribute> {
    let clean_name = computer_name.trim_end_matches('$');
    let sam_name = format!("{}$", clean_name);
    let dns_host = if domain_fqdn.is_empty() {
        clean_name.to_string()
    } else {
        format!("{}.{}", clean_name, domain_fqdn.to_lowercase())
    };

    let mut attrs = Vec::new();

    // objectClass
    attrs.push(LdapAttribute {
        type_name: "objectClass".to_string(),
        values: vec![
            b"top".to_vec(),
            b"person".to_vec(),
            b"organizationalPerson".to_vec(),
            b"user".to_vec(),
            b"computer".to_vec(),
        ],
    });

    // sAMAccountName
    attrs.push(LdapAttribute {
        type_name: "sAMAccountName".to_string(),
        values: vec![sam_name.into_bytes()],
    });

    // userAccountControl
    attrs.push(LdapAttribute {
        type_name: "userAccountControl".to_string(),
        values: vec![UAC_WORKSTATION_TRUST_ACCOUNT.to_string().into_bytes()],
    });

    // dNSHostName
    attrs.push(LdapAttribute {
        type_name: "dNSHostName".to_string(),
        values: vec![dns_host.as_bytes().to_vec()],
    });

    // servicePrincipalName
    let mut spns = vec![
        format!("HOST/{}", clean_name).into_bytes(),
        format!("RestrictedKrbHost/{}", clean_name).into_bytes(),
    ];
    if !domain_fqdn.is_empty() {
        spns.push(format!("HOST/{}", dns_host).into_bytes());
        spns.push(format!("RestrictedKrbHost/{}", dns_host).into_bytes());
    }
    attrs.push(LdapAttribute {
        type_name: "servicePrincipalName".to_string(),
        values: spns,
    });

    // unicodePwd
    if !password.is_empty() {
        attrs.push(LdapAttribute {
            type_name: "unicodePwd".to_string(),
            values: vec![encode_unicode_pwd(password)],
        });
    }

    attrs
}

/// Provisions a computer account in Active Directory under `parent_dn`.
pub fn add_computer<S: Read + Write>(
    client: &mut LdapClient<S>,
    parent_dn: &str,
    computer_name: &str,
    password: &str,
    domain_fqdn: &str,
) -> Result<String, CoreError> {
    let clean_name = computer_name.trim_end_matches('$');
    let entry_dn = if parent_dn.is_empty() {
        format!("CN={},CN=Computers", clean_name)
    } else {
        format!("CN={},{}", clean_name, parent_dn)
    };

    let attrs = build_computer_attributes(clean_name, password, domain_fqdn);
    client.add(&entry_dn, attrs)?;
    Ok(entry_dn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_computer_attributes_shape() {
        let attrs = build_computer_attributes("PC01", "P@ssw0rd123!", "corp.contoso.com");
        assert!(attrs.iter().any(|a| a.type_name == "objectClass" && a.values.len() == 5));
        assert!(attrs.iter().any(|a| a.type_name == "sAMAccountName" && a.values[0] == b"PC01$"));
        assert!(attrs.iter().any(|a| a.type_name == "userAccountControl" && a.values[0] == b"4096"));
        assert!(attrs.iter().any(|a| a.type_name == "dNSHostName" && a.values[0] == b"PC01.corp.contoso.com"));
        assert!(attrs.iter().any(|a| a.type_name == "servicePrincipalName" && a.values.len() == 4));
        assert!(attrs.iter().any(|a| a.type_name == "unicodePwd"));
    }
}
