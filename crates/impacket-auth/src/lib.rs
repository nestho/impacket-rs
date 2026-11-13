//! `impacket-auth`: Cross-Era NTLMSSP & SPNEGO Authentication Engine (`impacket/ntlm.py` & `impacket/spnego.py`).
//!
//! Supports the complete spectrum of Active Directory environments:
//! - **Legacy Era (Windows NT 4.0 / 2000 / 2003 / XP)**: LMv1, NTLMv1 (DES-56 `DESL`), and NTLMv1 with Extended Session Security (ESS)
//! - **Standard Era (Windows 2008 R2 -> 2022)**: NTLMv2 (`NTOWFv2` HMAC-MD5) with `AV_PAIR` target info parsing (`DumpNTLMInfo`)
//! - **Modern Hardened Era (Windows Server 2022 / 2025)**: NTLMv2 with EPA Channel Binding (`MsvAvChannelBindings`), Target SPN (`MsvAvTargetName`), and `MsvAvFlags` MIC enforcement
//! - **SPNEGO (`1.3.6.1.5.5.2`)**: ASN.1 DER `NegTokenInit` and `NegTokenResp` token wrapping

pub mod cbt;
pub mod session_security;
pub mod spnego;

pub use cbt::{
    compute_channel_bindings_hash_from_cert, compute_channel_bindings_hash_from_sha256,
    inject_channel_bindings, MSV_AV_FLAG_CHANNEL_BINDING_PRESENT,
};
pub use session_security::NtlmSessionSecurity;

use impacket_core::{
    decode_utf16le, encode_utf16le, AdCompatProfile, CoreError, FileTime, NtlmHashes,
};
use impacket_crypto::{compute_lm_hash, des_long_response, hmac_md5, md4, md5};

/// NTLMSSP Negotiate flags (`impacket/ntlm.py`).
pub mod ntlm_flags {
    pub const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
    pub const NTLMSSP_NEGOTIATE_OEM: u32 = 0x0000_0002;
    pub const NTLMSSP_REQUEST_TARGET: u32 = 0x0000_0004;
    pub const NTLMSSP_NEGOTIATE_SIGN: u32 = 0x0000_0010;
    pub const NTLMSSP_NEGOTIATE_SEAL: u32 = 0x0000_0020;
    pub const NTLMSSP_NEGOTIATE_LM_KEY: u32 = 0x0000_0080;
    pub const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x0000_0200;
    pub const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
    pub const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
    pub const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
    pub const NTLMSSP_NEGOTIATE_VERSION: u32 = 0x0200_0000;
    pub const NTLMSSP_NEGOTIATE_128: u32 = 0x2000_0000;
    pub const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
    pub const NTLMSSP_NEGOTIATE_56: u32 = 0x8000_0000;

    pub const DEFAULT_CLIENT_FLAGS: u32 = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_SIGN
        | NTLMSSP_NEGOTIATE_SEAL
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_VERSION
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_KEY_EXCH
        | NTLMSSP_NEGOTIATE_56;
}

/// Computes both LM and NT hashes from a cleartext password.
/// If `include_lm` is true (e.g., `AdCompatProfile::LegacyWin2000`), computes the real DES LM hash;
/// otherwise sets `lm` to `aad3b435b51404eeaad3b435b51404ee`.
pub fn compute_ntlm_hashes_with_compat(password: &str, include_lm: bool) -> NtlmHashes {
    let utf16 = encode_utf16le(password);
    let nt = md4(&utf16);
    let lm = if include_lm {
        compute_lm_hash(password)
    } else {
        impacket_core::EMPTY_LM_HASH
    };
    NtlmHashes {
        lm,
        nt,
        has_lm: include_lm,
    }
}

/// Computes the Windows NT hash (`MD4(UTF-16LE(password))`) with an empty LM hash.
pub fn compute_ntlm_hashes(password: &str) -> NtlmHashes {
    compute_ntlm_hashes_with_compat(password, false)
}

/// NTLMSSP Type 1 (`NTLM_AUTH_NEGOTIATE`) message replacing `getNTLMSSPType1` in `impacket/ntlm.py`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmNegotiateMessage {
    pub flags: u32,
    pub os_major: u8,
    pub os_minor: u8,
    pub os_build: u16,
}

impl Default for NtlmNegotiateMessage {
    fn default() -> Self {
        Self::for_profile(AdCompatProfile::UniversalAuto)
    }
}

impl NtlmNegotiateMessage {
    pub fn for_profile(profile: AdCompatProfile) -> Self {
        match profile {
            AdCompatProfile::LegacyWin2000 => Self {
                flags: ntlm_flags::NTLMSSP_NEGOTIATE_UNICODE
                    | ntlm_flags::NTLMSSP_NEGOTIATE_OEM
                    | ntlm_flags::NTLMSSP_REQUEST_TARGET
                    | ntlm_flags::NTLMSSP_NEGOTIATE_NTLM
                    | ntlm_flags::NTLMSSP_NEGOTIATE_LM_KEY
                    | ntlm_flags::NTLMSSP_NEGOTIATE_ALWAYS_SIGN,
                os_major: 5,
                os_minor: 0,
                os_build: 2195, // Windows 2000
            },
            AdCompatProfile::UniversalAuto => Self {
                flags: ntlm_flags::DEFAULT_CLIENT_FLAGS,
                os_major: 10,
                os_minor: 0,
                os_build: 19041,
            },
            AdCompatProfile::ModernHardened2025 => Self {
                flags: ntlm_flags::DEFAULT_CLIENT_FLAGS | ntlm_flags::NTLMSSP_NEGOTIATE_TARGET_INFO,
                os_major: 10,
                os_minor: 0,
                os_build: 26100, // Windows Server 2025
            },
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(b"NTLMSSP\x00");
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&40u32.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&40u32.to_le_bytes());
        buf.push(self.os_major);
        buf.push(self.os_minor);
        buf.extend_from_slice(&self.os_build.to_le_bytes());
        buf.extend_from_slice(&[0, 0, 0, 15]);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 32 || &data[0..8] != b"NTLMSSP\x00" {
            return Err(CoreError::ProtocolError("Invalid NTLMSSP signature".into()));
        }
        let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        if msg_type != 1 {
            return Err(CoreError::ProtocolError(format!(
                "Expected NTLMSSP Type 1, got {}",
                msg_type
            )));
        }
        let flags = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let (os_major, os_minor, os_build) = if data.len() >= 40 {
            (
                data[32],
                data[33],
                u16::from_le_bytes([data[34], data[35]]),
            )
        } else {
            (0, 0, 0)
        };
        Ok(Self {
            flags,
            os_major,
            os_minor,
            os_build,
        })
    }
}

/// NTLMSSP `AV_PAIR` Attribute IDs (`AV_PAIRS` in `impacket/ntlm.py`).
pub mod av_ids {
    pub const MSV_AV_EOL: u16 = 0x0000;
    pub const MSV_AV_NB_COMPUTER_NAME: u16 = 0x0001;
    pub const MSV_AV_NB_DOMAIN_NAME: u16 = 0x0002;
    pub const MSV_AV_DNS_COMPUTER_NAME: u16 = 0x0003;
    pub const MSV_AV_DNS_DOMAIN_NAME: u16 = 0x0004;
    pub const MSV_AV_DNS_TREE_NAME: u16 = 0x0005;
    pub const MSV_AV_FLAGS: u16 = 0x0006;
    pub const MSV_AV_TIMESTAMP: u16 = 0x0007;
    pub const MSV_AV_SINGLE_HOST: u16 = 0x0008;
    pub const MSV_AV_TARGET_NAME: u16 = 0x0009;
    pub const MSV_AV_CHANNEL_BINDINGS: u16 = 0x000A;
}

/// Structured representation of a server's NTLMSSP `AV_PAIR` TargetInfo block (powers `DumpNTLMInfo.py`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NtlmTargetInfo {
    pub nb_computer_name: Option<String>,
    pub nb_domain_name: Option<String>,
    pub dns_computer_name: Option<String>,
    pub dns_domain_name: Option<String>,
    pub dns_tree_name: Option<String>,
    pub flags: Option<u32>,
    pub timestamp: Option<FileTime>,
    pub target_name: Option<String>,
    pub channel_bindings: Option<[u8; 16]>,
    pub raw_pairs: Vec<(u16, Vec<u8>)>,
}

impl NtlmTargetInfo {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        let mut info = Self::default();
        let mut pos = 0;
        while pos + 4 <= data.len() {
            let av_id = u16::from_le_bytes([data[pos], data[pos + 1]]);
            let av_len = u16::from_le_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            if pos + av_len > data.len() {
                return Err(CoreError::BufferUnderflow {
                    needed: pos + av_len,
                    available: data.len(),
                });
            }
            let val = &data[pos..pos + av_len];
            pos += av_len;

            if av_id == av_ids::MSV_AV_EOL {
                break;
            }
            info.raw_pairs.push((av_id, val.to_vec()));
            match av_id {
                av_ids::MSV_AV_NB_COMPUTER_NAME => {
                    info.nb_computer_name = Some(decode_utf16le(val)?);
                }
                av_ids::MSV_AV_NB_DOMAIN_NAME => {
                    info.nb_domain_name = Some(decode_utf16le(val)?);
                }
                av_ids::MSV_AV_DNS_COMPUTER_NAME => {
                    info.dns_computer_name = Some(decode_utf16le(val)?);
                }
                av_ids::MSV_AV_DNS_DOMAIN_NAME => {
                    info.dns_domain_name = Some(decode_utf16le(val)?);
                }
                av_ids::MSV_AV_DNS_TREE_NAME => {
                    info.dns_tree_name = Some(decode_utf16le(val)?);
                }
                av_ids::MSV_AV_FLAGS if val.len() == 4 => {
                    info.flags = Some(u32::from_le_bytes([val[0], val[1], val[2], val[3]]));
                }
                av_ids::MSV_AV_TIMESTAMP if val.len() == 8 => {
                    info.timestamp = Some(FileTime::from_le_bytes(val.try_into().unwrap()));
                }
                av_ids::MSV_AV_TARGET_NAME => {
                    info.target_name = Some(decode_utf16le(val)?);
                }
                av_ids::MSV_AV_CHANNEL_BINDINGS if val.len() == 16 => {
                    info.channel_bindings = Some(val.try_into().unwrap());
                }
                _ => {}
            }
        }
        Ok(info)
    }

    /// Injects `MsvAvChannelBindings` (EPA) calculated from a TLS server certificate
    /// and marks `MSV_AV_FLAG_CHANNEL_BINDING_PRESENT` in `MsvAvFlags` for hardened Active Directory.
    pub fn with_channel_bindings(mut self, cert_der: &[u8]) -> Self {
        let hash = cbt::compute_channel_bindings_hash_from_cert(cert_der);
        cbt::inject_channel_bindings(&mut self, hash);
        self
    }

    /// Serializes `AV_PAIR` list back to wire format, injecting or updating `MsvAvFlags`,
    /// `MsvAvTargetName` (SPN), and `MsvAvChannelBindings` (EPA) for hardened Windows Server 2022/2025.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        fn push_utf16(out: &mut Vec<u8>, id: u16, s: &str) {
            let b = encode_utf16le(s);
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&(b.len() as u16).to_le_bytes());
            out.extend_from_slice(&b);
        }

        if let Some(ref s) = self.nb_domain_name {
            push_utf16(&mut out, av_ids::MSV_AV_NB_DOMAIN_NAME, s);
        }
        if let Some(ref s) = self.nb_computer_name {
            push_utf16(&mut out, av_ids::MSV_AV_NB_COMPUTER_NAME, s);
        }
        if let Some(ref s) = self.dns_domain_name {
            push_utf16(&mut out, av_ids::MSV_AV_DNS_DOMAIN_NAME, s);
        }
        if let Some(ref s) = self.dns_computer_name {
            push_utf16(&mut out, av_ids::MSV_AV_DNS_COMPUTER_NAME, s);
        }
        if let Some(ref s) = self.dns_tree_name {
            push_utf16(&mut out, av_ids::MSV_AV_DNS_TREE_NAME, s);
        }
        if let Some(flags) = self.flags {
            out.extend_from_slice(&av_ids::MSV_AV_FLAGS.to_le_bytes());
            out.extend_from_slice(&4u16.to_le_bytes());
            out.extend_from_slice(&flags.to_le_bytes());
        }
        if let Some(ts) = self.timestamp {
            out.extend_from_slice(&av_ids::MSV_AV_TIMESTAMP.to_le_bytes());
            out.extend_from_slice(&8u16.to_le_bytes());
            out.extend_from_slice(&ts.to_le_bytes());
        }
        if let Some(ref s) = self.target_name {
            push_utf16(&mut out, av_ids::MSV_AV_TARGET_NAME, s);
        }
        if let Some(cb) = self.channel_bindings {
            out.extend_from_slice(&av_ids::MSV_AV_CHANNEL_BINDINGS.to_le_bytes());
            out.extend_from_slice(&16u16.to_le_bytes());
            out.extend_from_slice(&cb);
        }
        // MsvAvEOL (0x0000, len 0)
        out.extend_from_slice(&[0, 0, 0, 0]);
        out
    }
}

/// NTLMSSP Type 2 (`NTLM_AUTH_CHALLENGE`) message parser & builder (`DumpNTLMInfo.py` & `ntlm.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmChallengeMessage {
    pub target_name: String,
    pub flags: u32,
    pub server_challenge: [u8; 8],
    pub os_major: u8,
    pub os_minor: u8,
    pub os_build: u16,
    pub ntlm_revision: u8,
    pub target_info: NtlmTargetInfo,
}

impl NtlmChallengeMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let target_bytes = encode_utf16le(&self.target_name);
        let ti_bytes = self.target_info.to_bytes();

        let target_offset = 56u32;
        let ti_offset = target_offset + (target_bytes.len() as u32);

        let mut buf = Vec::with_capacity(56 + target_bytes.len() + ti_bytes.len());
        buf.extend_from_slice(b"NTLMSSP\x00");
        buf.extend_from_slice(&2u32.to_le_bytes()); // Type 2 (Challenge)
        buf.extend_from_slice(&(target_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(target_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&target_offset.to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf.extend_from_slice(&self.server_challenge);
        buf.extend_from_slice(&[0u8; 8]); // Reserved
        buf.extend_from_slice(&(ti_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(ti_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(&ti_offset.to_le_bytes());
        buf.push(self.os_major);
        buf.push(self.os_minor);
        buf.extend_from_slice(&self.os_build.to_le_bytes());
        buf.extend_from_slice(&[0, 0, 0, self.ntlm_revision]);
        buf.extend_from_slice(&target_bytes);
        buf.extend_from_slice(&ti_bytes);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 32 || &data[0..8] != b"NTLMSSP\x00" {
            return Err(CoreError::ProtocolError("Invalid NTLMSSP Type 2 signature".into()));
        }
        let msg_type = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        if msg_type != 2 {
            return Err(CoreError::ProtocolError(format!(
                "Expected NTLMSSP Type 2, got {}",
                msg_type
            )));
        }
        let t_len = u16::from_le_bytes([data[12], data[13]]) as usize;
        let t_off = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
        let flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let server_challenge: [u8; 8] = data[24..32].try_into().unwrap();

        let target_name = if t_len > 0 && t_off + t_len <= data.len() {
            decode_utf16le(&data[t_off..t_off + t_len])?
        } else {
            String::new()
        };

        let mut target_info = NtlmTargetInfo::default();
        if data.len() >= 48 && (flags & ntlm_flags::NTLMSSP_NEGOTIATE_TARGET_INFO) != 0 {
            let ti_len = u16::from_le_bytes([data[40], data[41]]) as usize;
            let ti_off = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;
            if ti_len > 0 && ti_off + ti_len <= data.len() {
                target_info = NtlmTargetInfo::parse(&data[ti_off..ti_off + ti_len])?;
            }
        }

        let (os_major, os_minor, os_build, ntlm_revision) = if data.len() >= 56 {
            (
                data[48],
                data[49],
                u16::from_le_bytes([data[50], data[51]]),
                data[55],
            )
        } else {
            (0, 0, 0, 0)
        };

        Ok(Self {
            target_name,
            flags,
            server_challenge,
            os_major,
            os_minor,
            os_build,
            ntlm_revision,
            target_info,
        })
    }

    /// Maps Windows OS Major/Minor/Build numbers to human-readable Windows Server / Client editions
    /// (just like `DumpNTLMInfo.py`).
    pub fn guessed_os_version(&self) -> String {
        match (self.os_major, self.os_minor, self.os_build) {
            (5, 0, _) => format!("Windows 2000 (Build {})", self.os_build),
            (5, 1, _) => format!("Windows XP (Build {})", self.os_build),
            (5, 2, _) => format!("Windows Server 2003 (Build {})", self.os_build),
            (6, 0, _) => format!("Windows Server 2008 / Vista (Build {})", self.os_build),
            (6, 1, _) => format!("Windows Server 2008 R2 / 7 (Build {})", self.os_build),
            (6, 2, _) => format!("Windows Server 2012 / 8 (Build {})", self.os_build),
            (6, 3, _) => format!("Windows Server 2012 R2 / 8.1 (Build {})", self.os_build),
            (10, 0, 14393) => "Windows Server 2016 (Build 14393)".into(),
            (10, 0, 17763) => "Windows Server 2019 (Build 17763)".into(),
            (10, 0, 20348) => "Windows Server 2022 (Build 20348)".into(),
            (10, 0, 26100..) => format!("Windows Server 2025 (Build {})", self.os_build),
            (10, 0, b) => format!("Windows 10/11 / Server (Build {})", b),
            (maj, min, b) => format!("Windows {}.{} (Build {})", maj, min, b),
        }
    }
}

/// Computes NTLMv1, NTLMv1-ESS, or NTLMv2 Challenge Responses and the 16-byte `SessionBaseKey`
/// across all Active Directory compatibility modes (`computeResponse` in `impacket/ntlm.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmComputedResponses {
    pub lm_challenge_response: Vec<u8>,
    pub nt_challenge_response: Vec<u8>,
    pub session_base_key: [u8; 16],
}

/// Computes NTLMv1 or NTLMv1 with Extended Session Security (ESS) for Legacy Windows 2000/2003.
pub fn compute_ntlmv1_response(
    hashes: &NtlmHashes,
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    extended_session_security: bool,
) -> NtlmComputedResponses {
    let session_base_key = md4(&hashes.nt);
    if extended_session_security {
        let mut lm_resp = vec![0u8; 24];
        lm_resp[0..8].copy_from_slice(client_challenge);
        let mut concat = [0u8; 16];
        concat[0..8].copy_from_slice(server_challenge);
        concat[8..16].copy_from_slice(client_challenge);
        let session_hash = md5(&concat);
        let chall8: [u8; 8] = session_hash[0..8].try_into().unwrap();
        let nt_resp = des_long_response(&hashes.nt, &chall8).to_vec();
        NtlmComputedResponses {
            lm_challenge_response: lm_resp,
            nt_challenge_response: nt_resp,
            session_base_key,
        }
    } else {
        let lm_resp = des_long_response(&hashes.lm, server_challenge).to_vec();
        let nt_resp = des_long_response(&hashes.nt, server_challenge).to_vec();
        NtlmComputedResponses {
            lm_challenge_response: lm_resp,
            nt_challenge_response: nt_resp,
            session_base_key,
        }
    }
}

/// Computes `NTOWFv2` (`HMAC-MD5(NT_Hash, UTF-16LE(UPPER(User) + Domain))`) and the NTLMv2
/// response blob + `SessionBaseKey` (`computeResponseNTLMv2` in `impacket/ntlm.py`).
pub fn compute_ntlmv2_response(
    username: &str,
    domain: &str,
    hashes: &NtlmHashes,
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    timestamp: FileTime,
    target_info_bytes: &[u8],
) -> NtlmComputedResponses {
    let user_dom = format!("{}{}", username.to_uppercase(), domain);
    let response_key_nt = hmac_md5(&hashes.nt, &encode_utf16le(&user_dom));

    // NTLMv2_CLIENT_CHALLENGE (temp blob):
    // RespType(1) + HiRespType(1) + Reserved1(2) + Reserved2(4) + TimeStamp(8) + ChallengeFromClient(8) + Reserved3(4) + AvPairs + Reserved4(4)
    let mut temp = Vec::with_capacity(28 + target_info_bytes.len() + 4);
    temp.push(1); // RespType = 1
    temp.push(1); // HiRespType = 1
    temp.extend_from_slice(&[0u8; 6]);
    temp.extend_from_slice(&timestamp.to_le_bytes());
    temp.extend_from_slice(client_challenge);
    temp.extend_from_slice(&[0u8; 4]);
    temp.extend_from_slice(target_info_bytes);
    temp.extend_from_slice(&[0u8; 4]);

    let mut nt_proof_input = Vec::with_capacity(8 + temp.len());
    nt_proof_input.extend_from_slice(server_challenge);
    nt_proof_input.extend_from_slice(&temp);
    let nt_proof_str = hmac_md5(&response_key_nt, &nt_proof_input);

    let mut nt_challenge_response = Vec::with_capacity(16 + temp.len());
    nt_challenge_response.extend_from_slice(&nt_proof_str);
    nt_challenge_response.extend_from_slice(&temp);

    let session_base_key = hmac_md5(&response_key_nt, &nt_proof_str);

    // When MsvAvTimestamp is present, Windows sets LMv2 response to 24 zero bytes
    let lm_challenge_response = vec![0u8; 24];

    NtlmComputedResponses {
        lm_challenge_response,
        nt_challenge_response,
        session_base_key,
    }
}

/// NTLMSSP Type 3 (`NTLM_AUTH_AUTHENTICATE`) message builder (`getNTLMSSPType3` in `impacket/ntlm.py`).
///
/// Serializes the `AUTHENTICATE_MESSAGE` with six security buffers (LM/NT responses, domain, user,
/// workstation, encrypted session key) plus the version block. The optional 16-byte MIC is not emitted
/// (payloads begin at offset 72); callers targeting MIC-enforcing servers must extend this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmAuthenticateMessage {
    pub domain: String,
    pub username: String,
    pub workstation: String,
    pub lm_challenge_response: Vec<u8>,
    pub nt_challenge_response: Vec<u8>,
    pub encrypted_session_key: Vec<u8>,
    pub flags: u32,
    pub os_major: u8,
    pub os_minor: u8,
    pub os_build: u16,
}

impl NtlmAuthenticateMessage {
    /// Fixed-header size with a version block and no MIC.
    const PAYLOAD_BASE: u32 = 72;

    pub fn to_bytes(&self) -> Vec<u8> {
        let domain = encode_utf16le(&self.domain);
        let user = encode_utf16le(&self.username);
        let workstation = encode_utf16le(&self.workstation);

        // Payload order: LM, NT, Domain, User, Workstation, SessionKey.
        let mut payload = Vec::new();
        let mut base = Self::PAYLOAD_BASE;
        let mut sec_bufs = Vec::with_capacity(6);
        for field in [
            &self.lm_challenge_response,
            &self.nt_challenge_response,
            &domain,
            &user,
            &workstation,
            &self.encrypted_session_key,
        ] {
            let len = field.len() as u16;
            sec_bufs.push((len, base));
            payload.extend_from_slice(field);
            base += len as u32;
        }

        let mut buf = Vec::with_capacity(Self::PAYLOAD_BASE as usize + payload.len());
        buf.extend_from_slice(b"NTLMSSP\x00");
        buf.extend_from_slice(&3u32.to_le_bytes()); // MessageType = 3
        for (len, offset) in &sec_bufs {
            buf.extend_from_slice(&len.to_le_bytes()); // Len
            buf.extend_from_slice(&len.to_le_bytes()); // MaxLen
            buf.extend_from_slice(&offset.to_le_bytes()); // BufferOffset
        }
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf.push(self.os_major);
        buf.push(self.os_minor);
        buf.extend_from_slice(&self.os_build.to_le_bytes());
        buf.extend_from_slice(&[0, 0, 0, 15]); // Reserved + NTLMRevisionCurrent
        debug_assert_eq!(buf.len(), Self::PAYLOAD_BASE as usize);
        buf.extend_from_slice(&payload);
        buf
    }

    /// Parses an NTLMSSP Type 3 (`AUTHENTICATE_MESSAGE`) buffer.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 64 || &data[0..8] != b"NTLMSSP\x00" {
            return Err(CoreError::ProtocolError(
                "Invalid NTLMSSP Authenticate signature".into(),
            ));
        }
        let msg_type = u32::from_le_bytes(data[8..12].try_into().unwrap());
        if msg_type != 3 {
            return Err(CoreError::ProtocolError(format!(
                "Expected NTLMSSP Type 3 message, got type {}",
                msg_type
            )));
        }

        let read_buf_desc = |offset: usize| -> Result<(usize, usize), CoreError> {
            if offset + 8 > data.len() {
                return Err(CoreError::BufferUnderflow {
                    needed: offset + 8,
                    available: data.len(),
                });
            }
            let len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
            let buf_offset =
                u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;
            Ok((len, buf_offset))
        };

        let (lm_len, lm_offset) = read_buf_desc(12)?;
        let (nt_len, nt_offset) = read_buf_desc(20)?;
        let (dom_len, dom_offset) = read_buf_desc(28)?;
        let (user_len, user_offset) = read_buf_desc(36)?;
        let (ws_len, ws_offset) = read_buf_desc(44)?;
        let (skey_len, skey_offset) = read_buf_desc(52)?;

        let flags = u32::from_le_bytes(data[60..64].try_into().unwrap());

        let (os_major, os_minor, os_build) = if data.len() >= 72 {
            let major = data[64];
            let minor = data[65];
            let build = u16::from_le_bytes(data[66..68].try_into().unwrap());
            (major, minor, build)
        } else {
            (6, 1, 7601)
        };

        let extract_slice = |offset: usize, len: usize| -> Result<&[u8], CoreError> {
            if len == 0 {
                return Ok(&[]);
            }
            if offset + len > data.len() {
                return Err(CoreError::BufferUnderflow {
                    needed: offset + len,
                    available: data.len(),
                });
            }
            Ok(&data[offset..offset + len])
        };

        let is_unicode = (flags & 0x0000_0001) != 0;

        let decode_str = |slice: &[u8]| -> String {
            if slice.is_empty() {
                String::new()
            } else if is_unicode && slice.len() >= 2 {
                impacket_core::decode_utf16le(slice).unwrap_or_else(|_| String::from_utf8_lossy(slice).to_string())
            } else {
                String::from_utf8_lossy(slice).to_string()
            }
        };

        let lm_challenge_response = extract_slice(lm_offset, lm_len)?.to_vec();
        let nt_challenge_response = extract_slice(nt_offset, nt_len)?.to_vec();
        let domain = decode_str(extract_slice(dom_offset, dom_len)?);
        let username = decode_str(extract_slice(user_offset, user_len)?);
        let workstation = decode_str(extract_slice(ws_offset, ws_len)?);
        let encrypted_session_key = extract_slice(skey_offset, skey_len)?.to_vec();

        Ok(Self {
            domain,
            username,
            workstation,
            lm_challenge_response,
            nt_challenge_response,
            encrypted_session_key,
            flags,
            os_major,
            os_minor,
            os_build,
        })
    }

    /// Formats the credentials as a NetNTLMv2 hash string for Hashcat (mode 5600) / John the Ripper.
    ///
    /// Format: `username::domain:server_challenge:nt_proof_str:client_challenge_blob`
    pub fn to_netntlmv2_format(&self, server_challenge: &[u8; 8]) -> Option<String> {
        if self.nt_challenge_response.len() < 24 {
            return None;
        }
        let nt_proof = &self.nt_challenge_response[..16];
        let client_blob = &self.nt_challenge_response[16..];
        Some(format!(
            "{}::{}:{}:{}:{}",
            self.username,
            self.domain,
            impacket_core::encode_hex(server_challenge),
            impacket_core::encode_hex(nt_proof),
            impacket_core::encode_hex(client_blob),
        ))
    }
}

/// MIT Kerberos Credential Cache (`.ccache` format v4, `0x0504`) header parser (`impacket/krb5/ccache.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcacheHeader {
    pub version: u16,
    pub default_realm: String,
    pub default_components: Vec<String>,
}

impl CcacheHeader {
    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 12 {
            return Err(CoreError::BufferUnderflow {
                needed: 12,
                available: data.len(),
            });
        }
        let version = u16::from_be_bytes([data[0], data[1]]);
        if version != 0x0504 && version != 0x0503 {
            return Err(CoreError::ProtocolError(format!(
                "Unsupported ccache file version: 0x{:04x}",
                version
            )));
        }
        let mut pos = 2;
        if version == 0x0504 {
            let hdr_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2 + hdr_len;
        }
        if pos + 8 > data.len() {
            return Err(CoreError::BufferUnderflow {
                needed: pos + 8,
                available: data.len(),
            });
        }
        let num_components =
            u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
                as usize;
        pos += 8;

        let read_counted_str = |pos: &mut usize| -> Result<String, CoreError> {
            if *pos + 4 > data.len() {
                return Err(CoreError::BufferUnderflow {
                    needed: *pos + 4,
                    available: data.len(),
                });
            }
            let len = u32::from_be_bytes([
                data[*pos],
                data[*pos + 1],
                data[*pos + 2],
                data[*pos + 3],
            ]) as usize;
            *pos += 4;
            if *pos + len > data.len() {
                return Err(CoreError::BufferUnderflow {
                    needed: *pos + len,
                    available: data.len(),
                });
            }
            let s = String::from_utf8_lossy(&data[*pos..*pos + len]).into_owned();
            *pos += len;
            Ok(s)
        };

        let default_realm = read_counted_str(&mut pos)?;
        let mut default_components = Vec::with_capacity(num_components.min(16));
        for _ in 0..num_components {
            default_components.push(read_counted_str(&mut pos)?);
        }

        Ok(Self {
            version,
            default_realm,
            default_components,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use impacket_core::encode_hex;

    #[test]
    fn test_ntlm_challenge_type2_and_av_pairs_roundtrip() {
        let mut ti = NtlmTargetInfo::default();
        ti.nb_domain_name = Some("CONTOSO".into());
        ti.nb_computer_name = Some("DC01".into());
        ti.dns_domain_name = Some("contoso.local".into());
        ti.dns_computer_name = Some("dc01.contoso.local".into());
        ti.dns_tree_name = Some("contoso.local".into());
        ti.timestamp = Some(FileTime::from_unix_secs(1_730_000_000));

        let chall = NtlmChallengeMessage {
            target_name: "CONTOSO".into(),
            flags: ntlm_flags::DEFAULT_CLIENT_FLAGS | ntlm_flags::NTLMSSP_NEGOTIATE_TARGET_INFO,
            server_challenge: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            os_major: 10,
            os_minor: 0,
            os_build: 20348,
            ntlm_revision: 15,
            target_info: ti,
        };

        let wire = chall.to_bytes();
        let parsed = NtlmChallengeMessage::from_bytes(&wire).unwrap();
        assert_eq!(parsed.target_name, "CONTOSO");
        assert_eq!(
            parsed.target_info.dns_computer_name.as_deref(),
            Some("dc01.contoso.local")
        );
        assert_eq!(parsed.guessed_os_version(), "Windows Server 2022 (Build 20348)");
    }

    #[test]
    fn test_ntlm_type3_authenticate_layout() {
        let msg = NtlmAuthenticateMessage {
            domain: "CORP".into(),
            username: "svc_backup".into(),
            workstation: "ATTACKER".into(),
            lm_challenge_response: vec![0u8; 24],
            nt_challenge_response: vec![0xABu8; 48],
            encrypted_session_key: Vec::new(),
            flags: ntlm_flags::DEFAULT_CLIENT_FLAGS,
            os_major: 10,
            os_minor: 0,
            os_build: 19041,
        };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..8], b"NTLMSSP\x00");
        assert_eq!(u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]), 3);
        // NT response SecBuf is the 2nd buffer (offset 12 + 8). Len 48, offset 72+24=96.
        assert_eq!(u16::from_le_bytes([bytes[20], bytes[21]]), 48);
        assert_eq!(u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]), 96);
        // NT response bytes land at offset 96.
        assert_eq!(&bytes[96..96 + 48], &[0xABu8; 48][..]);

        let parsed = NtlmAuthenticateMessage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.username, "svc_backup");
        assert_eq!(parsed.domain, "CORP");
        assert_eq!(parsed.workstation, "ATTACKER");
        assert_eq!(parsed.nt_challenge_response, vec![0xABu8; 48]);

        let server_chall = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let hashcat_str = parsed.to_netntlmv2_format(&server_chall).unwrap();
        assert!(hashcat_str.starts_with("svc_backup::CORP:1122334455667788:"));
    }

    #[test]
    fn test_ntlmv1_and_ntlmv2_computation() {
        let hashes = compute_ntlm_hashes_with_compat("Password", true);
        assert_eq!(encode_hex(&hashes.nt), "a4f49c406510bdcab6824ee7c30fd852");
        assert_eq!(encode_hex(&hashes.lm), "e52cac67419a9a224a3b108f3fa6cb6d");

        let server_chall = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let client_chall = [0xaa; 8];
        let v1 = compute_ntlmv1_response(&hashes, &server_chall, &client_chall, false);
        assert_eq!(v1.nt_challenge_response.len(), 24);

        let v2 = compute_ntlmv2_response(
            "User",
            "Domain",
            &hashes,
            &server_chall,
            &client_chall,
            FileTime::from_raw(0),
            &[0, 0, 0, 0],
        );
        assert!(v2.nt_challenge_response.len() > 32);
    }
}
