//! `spnego`: Simple and Protected GSS-API Negotiation Mechanism (SPNEGO, RFC 4178).
//!
//! Provides ASN.1 DER framing for `NegTokenInit` and `NegTokenResp`, supporting
//! NTLMSSP (`1.3.6.1.4.1.311.2.2.10`), Kerberos (`1.2.840.113554.1.2.2`), MS-Kerberos
//! (`1.2.840.48018.1.2.2`), and NEGOEX (`1.3.6.1.4.1.311.2.2.30`).

use impacket_core::der;
use impacket_core::CoreError;

pub mod oid {
    /// SPNEGO: `1.3.6.1.5.5.2`
    pub const SPNEGO: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];
    /// NTLMSSP: `1.3.6.1.4.1.311.2.2.10`
    pub const NTLMSSP: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A];
    /// MS KRB5: `1.2.840.48018.1.2.2`
    pub const MS_KRB5: &[u8] = &[0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02];
    /// Standard KRB5: `1.2.840.113554.1.2.2`
    pub const KRB5: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02];
    /// NEGOEX: `1.3.6.1.4.1.311.2.2.30`
    pub const NEGOEX: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1E];
}

/// Recognized GSS-API Mechanism Types.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MechType {
    Spnego,
    Ntlmssp,
    MsKrb5,
    Krb5,
    Negoex,
}

impl MechType {
    pub fn from_oid_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes == oid::NTLMSSP {
            Some(Self::Ntlmssp)
        } else if bytes == oid::SPNEGO {
            Some(Self::Spnego)
        } else if bytes == oid::MS_KRB5 {
            Some(Self::MsKrb5)
        } else if bytes == oid::KRB5 {
            Some(Self::Krb5)
        } else if bytes == oid::NEGOEX {
            Some(Self::Negoex)
        } else {
            None
        }
    }

    pub fn to_oid_bytes(self) -> &'static [u8] {
        match self {
            Self::Spnego => oid::SPNEGO,
            Self::Ntlmssp => oid::NTLMSSP,
            Self::MsKrb5 => oid::MS_KRB5,
            Self::Krb5 => oid::KRB5,
            Self::Negoex => oid::NEGOEX,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Spnego => "SPNEGO",
            Self::Ntlmssp => "NTLMSSP",
            Self::MsKrb5 => "MS-KRB5",
            Self::Krb5 => "KRB5",
            Self::Negoex => "NEGOEX",
        }
    }
}

/// Negotiation state in `NegTokenResp`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NegState {
    AcceptCompleted = 0,
    AcceptIncomplete = 1,
    Reject = 2,
    RequestMic = 3,
}

impl NegState {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::AcceptCompleted),
            1 => Some(Self::AcceptIncomplete),
            2 => Some(Self::Reject),
            3 => Some(Self::RequestMic),
            _ => None,
        }
    }
}

/// SPNEGO `NegTokenInit` (RFC 4178 §4.2.1) optionally wrapped in a GSS-API InitialContextToken (RFC 2743).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegTokenInit {
    pub mech_types: Vec<MechType>,
    pub req_flags: Option<u32>,
    pub mech_token: Option<Vec<u8>>,
    pub mech_list_mic: Option<Vec<u8>>,
}

impl NegTokenInit {
    pub fn new(mech_types: Vec<MechType>, mech_token: Option<Vec<u8>>) -> Self {
        Self {
            mech_types,
            req_flags: None,
            mech_token,
            mech_list_mic: None,
        }
    }

    /// Convenience builder for NTLMSSP negotiation.
    pub fn for_ntlmssp(ntlm_token: &[u8]) -> Self {
        Self::new(vec![MechType::Ntlmssp], Some(ntlm_token.to_vec()))
    }

    /// Serializes this token into a GSS-API InitialContextToken (Application 0 `0x60`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut fields = Vec::new();

        // [0] mechTypes Sequence
        let mechs_der: Vec<Vec<u8>> = self
            .mech_types
            .iter()
            .map(|m| der::encode_oid(m.to_oid_bytes()))
            .collect();
        let mechs_seq = der::encode_sequence(&mechs_der);
        fields.push(der::encode_context_explicit(0, &mechs_seq));

        // [1] reqFlags (optional)
        if let Some(flags) = self.req_flags {
            fields.push(der::encode_context_explicit(1, &der::encode_bit_string_u32(flags)));
        }

        // [2] mechToken (optional)
        if let Some(ref tok) = self.mech_token {
            fields.push(der::encode_context_explicit(2, &der::encode_octet_string(tok)));
        }

        // [3] mechListMIC (optional)
        if let Some(ref mic) = self.mech_list_mic {
            fields.push(der::encode_context_explicit(3, &der::encode_octet_string(mic)));
        }

        let inner_seq = der::encode_sequence(&fields);
        let neg_token_init = der::encode_context_explicit(0, &inner_seq);

        // GSS-API wrapper: Application 0 [ 0x06 OID(SPNEGO) || [0] negTokenInit ]
        let mut gss_body = Vec::new();
        gss_body.extend_from_slice(&der::encode_oid(oid::SPNEGO));
        gss_body.extend_from_slice(&neg_token_init);
        der::encode_application(0, &gss_body)
    }

    /// Parses a `NegTokenInit` from either a GSS-API wrapped buffer (tag `0x60`)
    /// or a bare `negTokenInit` context tag (`0xA0`).
    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        let (tag, body, _) = der::decode_tlv(data)?;
        let token_data = if tag == 0x60 {
            let (oid_tag, oid_val, rest) = der::decode_tlv(body)?;
            if oid_tag != 0x06 || oid_val != oid::SPNEGO {
                return Err(CoreError::ProtocolError("Invalid SPNEGO GSS-API OID".into()));
            }
            let (ctx_tag, ctx_body, _) = der::decode_tlv(rest)?;
            if ctx_tag != 0xA0 {
                return Err(CoreError::ProtocolError(format!(
                    "Expected negTokenInit (0xA0), got 0x{:02X}",
                    ctx_tag
                )));
            }
            ctx_body
        } else if tag == 0xA0 {
            body
        } else {
            return Err(CoreError::ProtocolError(format!(
                "Expected GSS-API (0x60) or negTokenInit (0xA0), got 0x{:02X}",
                tag
            )));
        };

        let (seq_tag, seq_body, _) = der::decode_tlv(token_data)?;
        if seq_tag != 0x30 {
            return Err(CoreError::ProtocolError("Expected Sequence in negTokenInit".into()));
        }

        let mut mech_types = Vec::new();
        let mut req_flags = None;
        let mut mech_token = None;
        let mut mech_list_mic = None;

        let mut cur = seq_body;
        while !cur.is_empty() {
            let (f_tag, f_val, rest) = der::decode_tlv(cur)?;
            cur = rest;
            match f_tag {
                0xA0 => {
                    let (s_tag, s_body, _) = der::decode_tlv(f_val)?;
                    if s_tag == 0x30 {
                        let mut m_cur = s_body;
                        while !m_cur.is_empty() {
                            let (oid_val, m_rest) = der::decode_oid(m_cur)?;
                            m_cur = m_rest;
                            if let Some(m) = MechType::from_oid_bytes(oid_val) {
                                mech_types.push(m);
                            }
                        }
                    }
                }
                0xA1 => {
                    let (b_tag, b_val, _) = der::decode_tlv(f_val)?;
                    if b_tag == 0x03 && b_val.len() >= 5 {
                        req_flags = Some(u32::from_be_bytes([b_val[1], b_val[2], b_val[3], b_val[4]]));
                    }
                }
                0xA2 => {
                    let (o_tag, o_val, _) = der::decode_tlv(f_val)?;
                    if o_tag == 0x04 {
                        mech_token = Some(o_val.to_vec());
                    }
                }
                0xA3 => {
                    let (o_tag, o_val, _) = der::decode_tlv(f_val)?;
                    if o_tag == 0x04 {
                        mech_list_mic = Some(o_val.to_vec());
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            mech_types,
            req_flags,
            mech_token,
            mech_list_mic,
        })
    }
}

/// SPNEGO `NegTokenResp` (RFC 4178 §4.2.2). Tag `0xA1`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NegTokenResp {
    pub neg_state: Option<NegState>,
    pub supported_mech: Option<MechType>,
    pub response_token: Option<Vec<u8>>,
    pub mech_list_mic: Option<Vec<u8>>,
}

impl NegTokenResp {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut fields = Vec::new();

        if let Some(state) = self.neg_state {
            let state_der = der::encode_tlv(0x0A, &[state as u8]);
            fields.push(der::encode_context_explicit(0, &state_der));
        }

        if let Some(mech) = self.supported_mech {
            let mech_der = der::encode_oid(mech.to_oid_bytes());
            fields.push(der::encode_context_explicit(1, &mech_der));
        }

        if let Some(ref tok) = self.response_token {
            fields.push(der::encode_context_explicit(2, &der::encode_octet_string(tok)));
        }

        if let Some(ref mic) = self.mech_list_mic {
            fields.push(der::encode_context_explicit(3, &der::encode_octet_string(mic)));
        }

        let seq = der::encode_sequence(&fields);
        der::encode_context_explicit(1, &seq)
    }

    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        let (tag, body, _) = der::decode_tlv(data)?;
        if tag != 0xA1 {
            return Err(CoreError::ProtocolError(format!(
                "Expected negTokenResp (0xA1), got 0x{:02X}",
                tag
            )));
        }

        let (seq_tag, seq_body, _) = der::decode_tlv(body)?;
        if seq_tag != 0x30 {
            return Err(CoreError::ProtocolError("Expected Sequence in negTokenResp".into()));
        }

        let mut neg_state = None;
        let mut supported_mech = None;
        let mut response_token = None;
        let mut mech_list_mic = None;

        let mut cur = seq_body;
        while !cur.is_empty() {
            let (f_tag, f_val, rest) = der::decode_tlv(cur)?;
            cur = rest;
            match f_tag {
                0xA0 => {
                    let (e_tag, e_val, _) = der::decode_tlv(f_val)?;
                    if (e_tag == 0x0A || e_tag == 0x02) && !e_val.is_empty() {
                        neg_state = NegState::from_u8(e_val[0]);
                    }
                }
                0xA1 => {
                    if let Ok((oid_val, _)) = der::decode_oid(f_val) {
                        supported_mech = MechType::from_oid_bytes(oid_val);
                    }
                }
                0xA2 => {
                    let (o_tag, o_val, _) = der::decode_tlv(f_val)?;
                    if o_tag == 0x04 {
                        response_token = Some(o_val.to_vec());
                    }
                }
                0xA3 => {
                    let (o_tag, o_val, _) = der::decode_tlv(f_val)?;
                    if o_tag == 0x04 {
                        mech_list_mic = Some(o_val.to_vec());
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            neg_state,
            supported_mech,
            response_token,
            mech_list_mic,
        })
    }
}

/// Extracts the underlying security token (e.g. NTLMSSP or Kerberos) from an authentication blob.
/// Handles GSS-API / SPNEGO `NegTokenInit`, `NegTokenResp`, and bare tokens.
pub fn extract_embedded_auth_token(blob: &[u8]) -> Result<Vec<u8>, CoreError> {
    if blob.is_empty() {
        return Err(CoreError::BufferUnderflow { needed: 1, available: 0 });
    }
    match blob[0] {
        0x60 | 0xA0 => {
            if let Ok(init) = NegTokenInit::parse(blob) {
                if let Some(tok) = init.mech_token {
                    return Ok(tok);
                }
            }
        }
        0xA1 => {
            if let Ok(resp) = NegTokenResp::parse(blob) {
                if let Some(tok) = resp.response_token {
                    return Ok(tok);
                }
            }
        }
        _ => {}
    }

    if let Some(pos) = blob.windows(8).position(|w| w == b"NTLMSSP\x00") {
        return Ok(blob[pos..].to_vec());
    }

    Ok(blob.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spnego_neg_token_init_roundtrip() {
        let fake_ntlm = b"NTLMSSP\x00\x01\x00\x00\x00";
        let init = NegTokenInit::new(
            vec![MechType::Ntlmssp, MechType::MsKrb5],
            Some(fake_ntlm.to_vec()),
        );
        let bytes = init.to_bytes();
        assert_eq!(bytes[0], 0x60); // GSS-API Application 0

        let parsed = NegTokenInit::parse(&bytes).unwrap();
        assert_eq!(parsed.mech_types, vec![MechType::Ntlmssp, MechType::MsKrb5]);
        assert_eq!(parsed.mech_token.as_deref(), Some(&fake_ntlm[..]));

        let extracted = extract_embedded_auth_token(&bytes).unwrap();
        assert_eq!(extracted, fake_ntlm);
    }

    #[test]
    fn test_spnego_neg_token_resp_roundtrip() {
        let fake_challenge = b"NTLMSSP\x00\x02\x00\x00\x00";
        let mut resp = NegTokenResp::new();
        resp.neg_state = Some(NegState::AcceptIncomplete);
        resp.supported_mech = Some(MechType::Ntlmssp);
        resp.response_token = Some(fake_challenge.to_vec());

        let bytes = resp.to_bytes();
        assert_eq!(bytes[0], 0xA1); // Context 1

        let parsed = NegTokenResp::parse(&bytes).unwrap();
        assert_eq!(parsed.neg_state, Some(NegState::AcceptIncomplete));
        assert_eq!(parsed.supported_mech, Some(MechType::Ntlmssp));
        assert_eq!(parsed.response_token.as_deref(), Some(&fake_challenge[..]));

        let extracted = extract_embedded_auth_token(&bytes).unwrap();
        assert_eq!(extracted, fake_challenge);
    }
}
