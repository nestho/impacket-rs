//! `security_descriptor`: Windows NT Security Descriptor (`SR_SECURITY_DESCRIPTOR`, `ACL`, `ACE`)
//! parser and serializer following `[MS-DTYP]` Section 2.4.6 and `impacket/ldap/ldaptypes.py`.

use impacket_core::CoreError;
use impacket_ndr::{RpcSid, RpcUuid};

pub mod control_flags {
    pub const SE_OWNER_DEFAULTED: u16 = 0x0001;
    pub const SE_GROUP_DEFAULTED: u16 = 0x0002;
    pub const SE_DACL_PRESENT: u16 = 0x0004;
    pub const SE_DACL_DEFAULTED: u16 = 0x0008;
    pub const SE_SACL_PRESENT: u16 = 0x0010;
    pub const SE_SACL_DEFAULTED: u16 = 0x0020;
    pub const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
    pub const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
    pub const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
    pub const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
    pub const SE_DACL_PROTECTED: u16 = 0x1000;
    pub const SE_SACL_PROTECTED: u16 = 0x2000;
    pub const SE_SELF_RELATIVE: u16 = 0x8000;
}

pub mod ace_type {
    pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
    pub const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
    pub const SYSTEM_AUDIT_ACE_TYPE: u8 = 0x02;
    pub const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
    pub const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x06;
    pub const SYSTEM_AUDIT_OBJECT_ACE_TYPE: u8 = 0x07;
}

pub mod ace_flags {
    pub const OBJECT_INHERIT_ACE: u8 = 0x01;
    pub const CONTAINER_INHERIT_ACE: u8 = 0x02;
    pub const NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
    pub const INHERIT_ONLY_ACE: u8 = 0x08;
    pub const INHERITED_ACE: u8 = 0x10;
    pub const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;
    pub const FAILED_ACCESS_ACE_FLAG: u8 = 0x80;
}

pub mod access_mask {
    pub const DELETE: u32 = 0x0001_0000;
    pub const READ_CONTROL: u32 = 0x0002_0000;
    pub const WRITE_DAC: u32 = 0x0004_0000;
    pub const WRITE_OWNER: u32 = 0x0008_0000;
    pub const SYNCHRONIZE: u32 = 0x0010_0000;

    pub const STANDARD_RIGHTS_REQUIRED: u32 = 0x000F_0000;
    pub const STANDARD_RIGHTS_ALL: u32 = 0x001F_0000;

    pub const GENERIC_READ: u32 = 0x8000_0000;
    pub const GENERIC_WRITE: u32 = 0x4000_0000;
    pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
    pub const GENERIC_ALL: u32 = 0x1000_0000;

    // Active Directory Access Rights ([MS-ADTS] 5.1.3.2)
    pub const ADS_RIGHT_DS_CREATE_CHILD: u32 = 0x0000_0001;
    pub const ADS_RIGHT_DS_DELETE_CHILD: u32 = 0x0000_0002;
    pub const ADS_RIGHT_ACTRL_DS_LIST: u32 = 0x0000_0004;
    pub const ADS_RIGHT_DS_SELF: u32 = 0x0000_0008;
    pub const ADS_RIGHT_DS_READ_PROP: u32 = 0x0000_0010;
    pub const ADS_RIGHT_DS_WRITE_PROP: u32 = 0x0000_0020;
    pub const ADS_RIGHT_DS_DELETE_TREE: u32 = 0x0000_0040;
    pub const ADS_RIGHT_DS_LIST_OBJECT: u32 = 0x0000_0080;
    pub const ADS_RIGHT_DS_CONTROL_ACCESS: u32 = 0x0000_0100;
}

/// Decodes a raw binary SID (`[MS-DTYP]` 2.4.2), returning the SID and the number of consumed bytes.
pub fn read_raw_sid(data: &[u8]) -> Result<(RpcSid, usize), CoreError> {
    if data.len() < 8 {
        return Err(CoreError::BufferUnderflow {
            needed: 8,
            available: data.len(),
        });
    }
    let revision = data[0];
    let sub_auth_count = data[1] as usize;
    let mut identifier_authority = [0u8; 6];
    identifier_authority.copy_from_slice(&data[2..8]);

    let total_len = 8 + sub_auth_count * 4;
    if data.len() < total_len {
        return Err(CoreError::BufferUnderflow {
            needed: total_len,
            available: data.len(),
        });
    }

    let mut sub_authorities = Vec::with_capacity(sub_auth_count);
    for i in 0..sub_auth_count {
        let off = 8 + i * 4;
        let sub = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        sub_authorities.push(sub);
    }

    Ok((
        RpcSid {
            revision,
            identifier_authority,
            sub_authorities,
        },
        total_len,
    ))
}

/// Encodes an `RpcSid` into raw binary SID bytes.
pub fn write_raw_sid(sid: &RpcSid, out: &mut Vec<u8>) {
    out.push(sid.revision);
    out.push(sid.sub_authorities.len() as u8);
    out.extend_from_slice(&sid.identifier_authority);
    for &sub in &sid.sub_authorities {
        out.extend_from_slice(&sub.to_le_bytes());
    }
}

/// Access Control Entry (`ACE`, `[MS-DTYP]` 2.4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    pub ace_type: u8,
    pub ace_flags: u8,
    pub mask: u32,
    pub sid: RpcSid,
    pub object_flags: Option<u32>,
    pub object_type: Option<RpcUuid>,
    pub inherited_object_type: Option<RpcUuid>,
}

impl Ace {
    pub fn is_object_ace(&self) -> bool {
        matches!(
            self.ace_type,
            ace_type::ACCESS_ALLOWED_OBJECT_ACE_TYPE
                | ace_type::ACCESS_DENIED_OBJECT_ACE_TYPE
                | ace_type::SYSTEM_AUDIT_OBJECT_ACE_TYPE
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.mask.to_le_bytes());

        if self.is_object_ace() {
            let flags = self.object_flags.unwrap_or(0);
            body.extend_from_slice(&flags.to_le_bytes());
            if (flags & 1) != 0 {
                if let Some(ref uuid) = self.object_type {
                    body.extend_from_slice(&uuid.to_le_bytes());
                } else {
                    body.extend_from_slice(&[0u8; 16]);
                }
            }
            if (flags & 2) != 0 {
                if let Some(ref uuid) = self.inherited_object_type {
                    body.extend_from_slice(&uuid.to_le_bytes());
                } else {
                    body.extend_from_slice(&[0u8; 16]);
                }
            }
        }

        write_raw_sid(&self.sid, &mut body);

        let total_size = (4 + body.len()) as u16;
        let mut out = Vec::with_capacity(total_size as usize);
        out.push(self.ace_type);
        out.push(self.ace_flags);
        out.extend_from_slice(&total_size.to_le_bytes());
        out.extend_from_slice(&body);
        out
    }

    pub fn parse(data: &[u8]) -> Result<(Self, usize), CoreError> {
        if data.len() < 8 {
            return Err(CoreError::BufferUnderflow {
                needed: 8,
                available: data.len(),
            });
        }
        let ace_type = data[0];
        let ace_flags = data[1];
        let ace_size = u16::from_le_bytes([data[2], data[3]]) as usize;
        if ace_size < 8 || data.len() < ace_size {
            return Err(CoreError::BufferUnderflow {
                needed: ace_size,
                available: data.len(),
            });
        }

        let mask = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let mut pos = 8;

        let is_object = matches!(
            ace_type,
            ace_type::ACCESS_ALLOWED_OBJECT_ACE_TYPE
                | ace_type::ACCESS_DENIED_OBJECT_ACE_TYPE
                | ace_type::SYSTEM_AUDIT_OBJECT_ACE_TYPE
        );

        let mut object_flags = None;
        let mut object_type = None;
        let mut inherited_object_type = None;

        if is_object {
            if pos + 4 > ace_size {
                return Err(CoreError::BufferUnderflow {
                    needed: pos + 4,
                    available: ace_size,
                });
            }
            let flags = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            pos += 4;
            object_flags = Some(flags);

            if (flags & 1) != 0 {
                if pos + 16 > ace_size {
                    return Err(CoreError::BufferUnderflow {
                        needed: pos + 16,
                        available: ace_size,
                    });
                }
                object_type = Some(RpcUuid::from_le_bytes(
                    data[pos..pos + 16].try_into().unwrap(),
                ));
                pos += 16;
            }
            if (flags & 2) != 0 {
                if pos + 16 > ace_size {
                    return Err(CoreError::BufferUnderflow {
                        needed: pos + 16,
                        available: ace_size,
                    });
                }
                inherited_object_type = Some(RpcUuid::from_le_bytes(
                    data[pos..pos + 16].try_into().unwrap(),
                ));
                pos += 16;
            }
        }

        let (sid, _) = read_raw_sid(&data[pos..ace_size])?;

        Ok((
            Self {
                ace_type,
                ace_flags,
                mask,
                sid,
                object_flags,
                object_type,
                inherited_object_type,
            },
            ace_size,
        ))
    }
}

/// Access Control List (`ACL`, `[MS-DTYP]` 2.4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acl {
    pub revision: u8,
    pub sbz1: u8,
    pub sbz2: u16,
    pub aces: Vec<Ace>,
}

impl Acl {
    pub fn new(aces: Vec<Ace>) -> Self {
        Self {
            revision: 2,
            sbz1: 0,
            sbz2: 0,
            aces,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ace_bytes = Vec::new();
        for ace in &self.aces {
            ace_bytes.extend_from_slice(&ace.to_bytes());
        }

        let total_size = (8 + ace_bytes.len()) as u16;
        let mut out = Vec::with_capacity(total_size as usize);
        out.push(self.revision);
        out.push(self.sbz1);
        out.extend_from_slice(&total_size.to_le_bytes());
        out.extend_from_slice(&(self.aces.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.sbz2.to_le_bytes());
        out.extend_from_slice(&ace_bytes);
        out
    }

    pub fn parse(data: &[u8]) -> Result<(Self, usize), CoreError> {
        if data.len() < 8 {
            return Err(CoreError::BufferUnderflow {
                needed: 8,
                available: data.len(),
            });
        }
        let revision = data[0];
        let sbz1 = data[1];
        let acl_size = u16::from_le_bytes([data[2], data[3]]) as usize;
        let ace_count = u16::from_le_bytes([data[4], data[5]]) as usize;
        let sbz2 = u16::from_le_bytes([data[6], data[7]]);

        if acl_size < 8 || data.len() < acl_size {
            return Err(CoreError::BufferUnderflow {
                needed: acl_size,
                available: data.len(),
            });
        }

        let mut aces = Vec::with_capacity(ace_count);
        let mut pos = 8;
        for _ in 0..ace_count {
            if pos >= acl_size {
                break;
            }
            let (ace, consumed) = Ace::parse(&data[pos..acl_size])?;
            aces.push(ace);
            pos += consumed;
        }

        Ok((
            Self {
                revision,
                sbz1,
                sbz2,
                aces,
            },
            acl_size,
        ))
    }
}

/// Self-Relative Security Descriptor (`[MS-DTYP]` Section 2.4.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityDescriptor {
    pub revision: u8,
    pub sbz1: u8,
    pub control: u16,
    pub owner_sid: Option<RpcSid>,
    pub group_sid: Option<RpcSid>,
    pub sacl: Option<Acl>,
    pub dacl: Option<Acl>,
}

impl SecurityDescriptor {
    pub fn new(
        owner_sid: Option<RpcSid>,
        group_sid: Option<RpcSid>,
        dacl: Option<Acl>,
        sacl: Option<Acl>,
    ) -> Self {
        let mut control = control_flags::SE_SELF_RELATIVE;
        if dacl.is_some() {
            control |= control_flags::SE_DACL_PRESENT;
        }
        if sacl.is_some() {
            control |= control_flags::SE_SACL_PRESENT;
        }
        Self {
            revision: 1,
            sbz1: 0,
            control,
            owner_sid,
            group_sid,
            sacl,
            dacl,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        let header_len = 20u32;

        let mut offset_owner = 0u32;
        if let Some(ref sid) = self.owner_sid {
            offset_owner = header_len + payload.len() as u32;
            write_raw_sid(sid, &mut payload);
        }

        let mut offset_group = 0u32;
        if let Some(ref sid) = self.group_sid {
            offset_group = header_len + payload.len() as u32;
            write_raw_sid(sid, &mut payload);
        }

        let mut offset_sacl = 0u32;
        if let Some(ref acl) = self.sacl {
            offset_sacl = header_len + payload.len() as u32;
            payload.extend_from_slice(&acl.to_bytes());
        }

        let mut offset_dacl = 0u32;
        if let Some(ref acl) = self.dacl {
            offset_dacl = header_len + payload.len() as u32;
            payload.extend_from_slice(&acl.to_bytes());
        }

        let mut out = Vec::with_capacity((header_len as usize) + payload.len());
        out.push(self.revision);
        out.push(self.sbz1);
        out.extend_from_slice(&self.control.to_le_bytes());
        out.extend_from_slice(&offset_owner.to_le_bytes());
        out.extend_from_slice(&offset_group.to_le_bytes());
        out.extend_from_slice(&offset_sacl.to_le_bytes());
        out.extend_from_slice(&offset_dacl.to_le_bytes());
        out.extend_from_slice(&payload);
        out
    }

    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 20 {
            return Err(CoreError::BufferUnderflow {
                needed: 20,
                available: data.len(),
            });
        }
        let revision = data[0];
        let sbz1 = data[1];
        let control = u16::from_le_bytes([data[2], data[3]]);
        let offset_owner = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let offset_group = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let offset_sacl = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let offset_dacl = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;

        let owner_sid = if offset_owner != 0 && offset_owner < data.len() {
            let (sid, _) = read_raw_sid(&data[offset_owner..])?;
            Some(sid)
        } else {
            None
        };

        let group_sid = if offset_group != 0 && offset_group < data.len() {
            let (sid, _) = read_raw_sid(&data[offset_group..])?;
            Some(sid)
        } else {
            None
        };

        let sacl = if offset_sacl != 0 && offset_sacl < data.len() {
            let (acl, _) = Acl::parse(&data[offset_sacl..])?;
            Some(acl)
        } else {
            None
        };

        let dacl = if offset_dacl != 0 && offset_dacl < data.len() {
            let (acl, _) = Acl::parse(&data[offset_dacl..])?;
            Some(acl)
        } else {
            None
        };

        Ok(Self {
            revision,
            sbz1,
            control,
            owner_sid,
            group_sid,
            sacl,
            dacl,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_descriptor_roundtrip() {
        let owner = RpcSid::parse("S-1-5-21-1234-5678-9012-500").unwrap();
        let group = RpcSid::parse("S-1-5-21-1234-5678-9012-513").unwrap();
        let user_sid = RpcSid::parse("S-1-5-21-1234-5678-9012-1105").unwrap();

        let ace1 = Ace {
            ace_type: ace_type::ACCESS_ALLOWED_ACE_TYPE,
            ace_flags: ace_flags::OBJECT_INHERIT_ACE | ace_flags::CONTAINER_INHERIT_ACE,
            mask: access_mask::GENERIC_ALL,
            sid: user_sid.clone(),
            object_flags: None,
            object_type: None,
            inherited_object_type: None,
        };

        let dacl = Acl::new(vec![ace1]);
        let sd = SecurityDescriptor::new(Some(owner.clone()), Some(group.clone()), Some(dacl), None);

        let bytes = sd.to_bytes();
        let parsed = SecurityDescriptor::parse(&bytes).unwrap();

        assert_eq!(parsed.revision, 1);
        assert_eq!(parsed.owner_sid.as_ref(), Some(&owner));
        assert_eq!(parsed.group_sid.as_ref(), Some(&group));
        assert!(parsed.dacl.is_some());

        let dacl_parsed = parsed.dacl.unwrap();
        assert_eq!(dacl_parsed.aces.len(), 1);
        assert_eq!(dacl_parsed.aces[0].ace_type, ace_type::ACCESS_ALLOWED_ACE_TYPE);
        assert_eq!(dacl_parsed.aces[0].mask, access_mask::GENERIC_ALL);
        assert_eq!(dacl_parsed.aces[0].sid, user_sid);
    }
}
