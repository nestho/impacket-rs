//! `dacledit`: Active Directory Discretionary Access Control List (DACL) editor (`impacket/examples/dacledit.py`).
//!
//! Inspects and modifies the `nTSecurityDescriptor` attribute on Active Directory objects,
//! granting or revoking privileges such as `GenericAll`, `WriteDacl`, `WriteOwner`, or `ResetPassword`.

use crate::asn1::{AttributeModification, LdapAttribute, ModifyOperation};
use crate::client::LdapClient;
use crate::filter_present;
use crate::security_descriptor::{
    access_mask, ace_flags, ace_type, control_flags, Ace, Acl, SecurityDescriptor,
};
use impacket_core::CoreError;
use impacket_ndr::RpcSid;
use std::io::{Read, Write};

pub const NT_SECURITY_DESCRIPTOR_ATTR: &str = "nTSecurityDescriptor";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaclRight {
    GenericAll,
    WriteDacl,
    WriteOwner,
    ResetPassword,
}

impl DaclRight {
    pub fn access_mask(&self) -> u32 {
        match self {
            Self::GenericAll => access_mask::GENERIC_ALL,
            Self::WriteDacl => access_mask::WRITE_DAC,
            Self::WriteOwner => access_mask::WRITE_OWNER,
            Self::ResetPassword => access_mask::ADS_RIGHT_DS_CONTROL_ACCESS, // User-Force-Change-Password
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "genericall" | "full" => Some(Self::GenericAll),
            "writedacl" => Some(Self::WriteDacl),
            "writeowner" => Some(Self::WriteOwner),
            "resetpassword" | "password" => Some(Self::ResetPassword),
            _ => None,
        }
    }
}

/// Reads and parses the `nTSecurityDescriptor` of `target_dn`.
pub fn read_dacl<S: Read + Write>(
    client: &mut LdapClient<S>,
    target_dn: &str,
) -> Result<SecurityDescriptor, CoreError> {
    let entries = client.search(
        target_dn,
        crate::asn1::SearchScope::BaseObject,
        &filter_present("objectClass"),
        &[NT_SECURITY_DESCRIPTOR_ATTR],
    )?;

    if entries.is_empty() {
        return Err(CoreError::ProtocolError(format!(
            "Target object '{}' not found",
            target_dn
        )));
    }

    let raw_sd = entries[0]
        .get_first_raw(NT_SECURITY_DESCRIPTOR_ATTR)
        .ok_or_else(|| {
            CoreError::ProtocolError(format!(
                "Object '{}' does not have a readable nTSecurityDescriptor attribute",
                target_dn
            ))
        })?;

    SecurityDescriptor::parse(raw_sd)
}

/// Writes a modified `SecurityDescriptor` back to `target_dn`'s `nTSecurityDescriptor`.
pub fn write_dacl<S: Read + Write>(
    client: &mut LdapClient<S>,
    target_dn: &str,
    sd: &SecurityDescriptor,
) -> Result<(), CoreError> {
    let sd_bytes = sd.to_bytes();
    let mod_attr = AttributeModification {
        operation: ModifyOperation::Replace,
        attribute: LdapAttribute {
            type_name: NT_SECURITY_DESCRIPTOR_ATTR.to_string(),
            values: vec![sd_bytes],
        },
    };
    client.modify(target_dn, vec![mod_attr])
}

/// Grants `right` to `trustee_sid` on `target_dn`.
pub fn grant_right<S: Read + Write>(
    client: &mut LdapClient<S>,
    target_dn: &str,
    trustee_sid: &RpcSid,
    right: DaclRight,
) -> Result<(), CoreError> {
    let mut sd = read_dacl(client, target_dn)?;

    let new_ace = Ace {
        ace_type: ace_type::ACCESS_ALLOWED_ACE_TYPE,
        ace_flags: ace_flags::OBJECT_INHERIT_ACE | ace_flags::CONTAINER_INHERIT_ACE,
        mask: right.access_mask(),
        sid: trustee_sid.clone(),
        object_flags: None,
        object_type: None,
        inherited_object_type: None,
    };

    let mut aces = match sd.dacl {
        Some(d) => d.aces,
        None => Vec::new(),
    };

    // Prepend or append the new ACE
    aces.insert(0, new_ace);
    sd.dacl = Some(Acl::new(aces));
    sd.control |= control_flags::SE_DACL_PRESENT;

    write_dacl(client, target_dn, &sd)
}

/// Revokes all ACEs matching `trustee_sid` from `target_dn`'s DACL.
pub fn revoke_rights<S: Read + Write>(
    client: &mut LdapClient<S>,
    target_dn: &str,
    trustee_sid: &RpcSid,
) -> Result<usize, CoreError> {
    let mut sd = read_dacl(client, target_dn)?;
    let mut removed = 0;

    if let Some(mut dacl) = sd.dacl.take() {
        let initial_len = dacl.aces.len();
        dacl.aces.retain(|ace| {
            if ace.sid == *trustee_sid {
                false
            } else {
                true
            }
        });
        removed = initial_len - dacl.aces.len();
        sd.dacl = Some(dacl);
    }

    if removed > 0 {
        write_dacl(client, target_dn, &sd)?;
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dacl_right_access_masks() {
        assert_eq!(DaclRight::GenericAll.access_mask(), 0x1000_0000);
        assert_eq!(DaclRight::WriteDacl.access_mask(), 0x0004_0000);
        assert_eq!(DaclRight::WriteOwner.access_mask(), 0x0008_0000);
    }
}
