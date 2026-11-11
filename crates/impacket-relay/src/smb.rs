//! `smb`: SMB protocol adapter for NTLM authentication relaying (`impacket/examples/ntlmrelayx/servers/smbrelayserver.py`).

use impacket_auth::spnego::{
    extract_embedded_auth_token, MechType, NegState, NegTokenInit, NegTokenResp,
};
use impacket_core::CoreError;

/// Extracts the raw NTLMSSP token from an SMB2 Session Setup security buffer,
/// unwrapping SPNEGO `NegTokenInit` or `NegTokenResp` if present.
pub fn extract_ntlm_from_smb2_security_buffer(sec_buffer: &[u8]) -> Result<Vec<u8>, CoreError> {
    if sec_buffer.starts_with(b"NTLMSSP\x00") {
        return Ok(sec_buffer.to_vec());
    }

    // Try extracting from SPNEGO wrapper
    match extract_embedded_auth_token(sec_buffer) {
        Ok(token) if token.starts_with(b"NTLMSSP\x00") => Ok(token),
        _ => Err(CoreError::ProtocolError(
            "Security buffer does not contain an NTLMSSP token".into(),
        )),
    }
}

/// Wraps an NTLMSSP Type 2 challenge in an ASN.1 SPNEGO `NegTokenResp` buffer for SMB2 Session Setup.
pub fn wrap_ntlm_challenge_in_spnego(challenge_ntlm: &[u8]) -> Result<Vec<u8>, CoreError> {
    let resp = NegTokenResp {
        neg_state: Some(NegState::AcceptIncomplete),
        supported_mech: Some(MechType::Ntlmssp),
        response_token: Some(challenge_ntlm.to_vec()),
        mech_list_mic: None,
    };
    Ok(resp.to_bytes())
}

/// Wraps an NTLMSSP Type 1 negotiate message in an ASN.1 SPNEGO `NegTokenInit` buffer for SMB2 Session Setup.
pub fn wrap_ntlm_negotiate_in_spnego(negotiate_ntlm: &[u8]) -> Result<Vec<u8>, CoreError> {
    let init = NegTokenInit::for_ntlmssp(negotiate_ntlm);
    Ok(init.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smb_security_buffer_spnego_wrapping_and_extraction() {
        let ntlm_token = b"NTLMSSP\x00\x01\x00\x00\x00";

        // Raw
        let extracted_raw = extract_ntlm_from_smb2_security_buffer(ntlm_token).unwrap();
        assert_eq!(extracted_raw, ntlm_token);

        // SPNEGO Init wrapped
        let spnego_init = wrap_ntlm_negotiate_in_spnego(ntlm_token).unwrap();
        let extracted_init = extract_ntlm_from_smb2_security_buffer(&spnego_init).unwrap();
        assert_eq!(extracted_init, ntlm_token);

        // SPNEGO Resp wrapped
        let spnego_resp = wrap_ntlm_challenge_in_spnego(ntlm_token).unwrap();
        let extracted_resp = extract_ntlm_from_smb2_security_buffer(&spnego_resp).unwrap();
        assert_eq!(extracted_resp, ntlm_token);
    }
}
