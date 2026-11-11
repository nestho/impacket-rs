//! `rbcd`: Resource-Based Constrained Delegation configuration (`impacket/examples/rbcd.py`).
//!
//! Manages the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on Active Directory computer
//! and user accounts via LDAP BER `ModifyRequest`.

use crate::asn1::{AttributeModification, LdapAttribute, ModifyOperation};
use crate::client::LdapClient;
use crate::security_descriptor::{
    access_mask, ace_type, control_flags, Ace, Acl, SecurityDescriptor,
};
use impacket_core::CoreError;
use impacket_ndr::RpcSid;
use std::io::{Read, Write};

pub const RBCD_ATTR_NAME: &str = "msDS-AllowedToActOnBehalfOfOtherIdentity";

/// Constructs a self-relative Security Descriptor with a DACL granting `GENERIC_ALL`
/// to `grantee_sid` for RBCD.
pub fn build_rbcd_security_descriptor(grantee_sid: &RpcSid) -> SecurityDescriptor {
    let ace = Ace {
        ace_type: ace_type::ACCESS_ALLOWED_ACE_TYPE,
        ace_flags: 0x00,
        mask: access_mask::GENERIC_ALL,
        sid: grantee_sid.clone(),
        object_flags: None,
        object_type: None,
        inherited_object_type: None,
    };
    let dacl = Acl::new(vec![ace]);
    let mut sd = SecurityDescriptor::new(None, None, Some(dacl), None);
    sd.control = control_flags::SE_DACL_PRESENT | control_flags::SE_SELF_RELATIVE;
    sd
}

/// Parses raw `msDS-AllowedToActOnBehalfOfOtherIdentity` bytes and returns allowed trustee SIDs.
pub fn parse_rbcd_allowed_sids(raw_sd: &[u8]) -> Result<Vec<RpcSid>, CoreError> {
    let sd = SecurityDescriptor::parse(raw_sd)?;
    let mut sids = Vec::new();
    if let Some(dacl) = sd.dacl {
        for ace in dacl.aces {
            if ace.ace_type == ace_type::ACCESS_ALLOWED_ACE_TYPE {
                sids.push(ace.sid);
            }
        }
    }
    Ok(sids)
}

/// Reads the allowed RBCD trustee SIDs from the target object DN.
pub fn read_rbcd<S: Read + Write>(
    client: &mut LdapClient<S>,
    target_dn: &str,
) -> Result<Vec<RpcSid>, CoreError> {
    let entries = client.search(
        target_dn,
        crate::asn1::SearchScope::BaseObject,
        &crate::filter_present("objectClass"),
        &[RBCD_ATTR_NAME],
    )?;

    if entries.is_empty() {
        return Err(CoreError::ProtocolError(format!(
            "Target object not found: {}",
            target_dn
        )));
    }

    if let Some(raw_sd) = entries[0].get_first_raw(RBCD_ATTR_NAME) {
        parse_rbcd_allowed_sids(raw_sd)
    } else {
        Ok(Vec::new())
    }
}

/// Configures RBCD on `target_dn` allowing `grantee_sid` to impersonate users to it.
pub fn write_rbcd<S: Read + Write>(
    client: &mut LdapClient<S>,
    target_dn: &str,
    grantee_sid: &RpcSid,
) -> Result<(), CoreError> {
    let sd = build_rbcd_security_descriptor(grantee_sid);
    let sd_bytes = sd.to_bytes();

    let mod_attr = AttributeModification {
        operation: ModifyOperation::Replace,
        attribute: LdapAttribute {
            type_name: RBCD_ATTR_NAME.to_string(),
            values: vec![sd_bytes],
        },
    };

    client.modify(target_dn, vec![mod_attr])
}

/// Clears the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on `target_dn`.
pub fn flush_rbcd<S: Read + Write>(
    client: &mut LdapClient<S>,
    target_dn: &str,
) -> Result<(), CoreError> {
    let mod_attr = AttributeModification {
        operation: ModifyOperation::Delete,
        attribute: LdapAttribute {
            type_name: RBCD_ATTR_NAME.to_string(),
            values: Vec::new(),
        },
    };

    client.modify(target_dn, vec![mod_attr])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rbcd_security_descriptor_roundtrip() {
        let grantee_sid = RpcSid::parse("S-1-5-21-12345678-12345678-12345678-1105").unwrap();
        let sd = build_rbcd_security_descriptor(&grantee_sid);
        let bytes = sd.to_bytes();

        let parsed_sids = parse_rbcd_allowed_sids(&bytes).unwrap();
        assert_eq!(parsed_sids.len(), 1);
        assert_eq!(parsed_sids[0], grantee_sid);
    }
}
