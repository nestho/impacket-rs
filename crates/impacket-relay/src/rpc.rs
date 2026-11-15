//! `rpc`: DCE/RPC protocol adapter for NTLM authentication relaying (`impacket/examples/ntlmrelayx/servers/rpcrelayserver.py`).
//!
//! Provides codecs for extracting and injecting NTLMSSP authentication tokens
//! into DCE/RPC `Bind` (PDU 11), `BindAck` (PDU 12), and `Auth3` (PDU 16) PDUs.

use impacket_core::CoreError;
use impacket_dcerpc::{pdu_type, rpc_auth_type, SecTrailer};
use impacket_ndr::{NdrDeserialize, NdrReader, NdrSerialize, NdrWriter};

/// Extracts the NTLMSSP authentication blob from a DCE/RPC PDU with an attached `SecTrailer`.
pub fn extract_ntlm_from_rpc_pdu(pdu: &[u8]) -> Result<Vec<u8>, CoreError> {
    if pdu.len() < 16 {
        return Err(CoreError::ProtocolError("DCE/RPC PDU too short".into()));
    }
    let auth_len = u16::from_le_bytes(pdu[10..12].try_into().unwrap()) as usize;
    if auth_len == 0 {
        return Err(CoreError::ProtocolError(
            "DCE/RPC PDU does not contain authentication data".into(),
        ));
    }
    let frag_len = u16::from_le_bytes(pdu[8..10].try_into().unwrap()) as usize;
    if pdu.len() < frag_len || frag_len < 8 + auth_len {
        return Err(CoreError::ProtocolError("Invalid DCE/RPC PDU length bounds".into()));
    }

    // SecTrailer is 8 bytes immediately preceding the auth_len payload at the end of the fragment
    let trailer_start = frag_len - auth_len - 8;
    let mut r = NdrReader::new(&pdu[trailer_start..trailer_start + 8]);
    let trailer = SecTrailer::ndr_deserialize(&mut r)?;
    if trailer.auth_type != rpc_auth_type::RPC_C_AUTHN_WINNT {
        return Err(CoreError::ProtocolError(format!(
            "Unsupported DCE/RPC auth type: {} (expected NTLMSSP 10)",
            trailer.auth_type
        )));
    }

    let auth_val = &pdu[trailer_start + 8..frag_len - (trailer.auth_pad_length as usize)];
    if auth_val.len() < 8 || &auth_val[..8] != b"NTLMSSP\x00" {
        return Err(CoreError::ProtocolError("Invalid NTLMSSP magic in RPC PDU".into()));
    }

    Ok(auth_val.to_vec())
}

/// Appends a `SecTrailer` and NTLMSSP token to a DCE/RPC PDU, updating header lengths.
pub fn append_ntlm_sec_trailer_to_pdu(
    mut base_pdu: Vec<u8>,
    token: &[u8],
    auth_level: u8,
    context_id: u32,
) -> Vec<u8> {
    // 4-byte align the body before appending SecTrailer
    let pad_len = (4 - (base_pdu.len() % 4)) % 4;
    base_pdu.resize(base_pdu.len() + pad_len, 0);

    let auth_len = token.len() as u16;
    let trailer = SecTrailer {
        auth_type: rpc_auth_type::RPC_C_AUTHN_WINNT,
        auth_level,
        auth_pad_length: pad_len as u8,
        auth_reserved: 0,
        auth_context_id: context_id,
    };

    let mut w = NdrWriter::with_capacity(8);
    trailer.ndr_serialize(&mut w);
    base_pdu.extend_from_slice(&w.into_bytes());
    base_pdu.extend_from_slice(token);

    // Update frag_len (offset 8..10) and auth_len (offset 10..12)
    let total_len = base_pdu.len() as u16;
    base_pdu[8..10].copy_from_slice(&total_len.to_le_bytes());
    base_pdu[10..12].copy_from_slice(&auth_len.to_le_bytes());

    base_pdu
}

/// Builds a minimal DCE/RPC `BindAck` PDU encapsulating an NTLMSSP Type 2 challenge.
pub fn wrap_ntlm_in_rpc_bind_ack(
    call_id: u32,
    assoc_group_id: u32,
    token: &[u8],
    auth_level: u8,
    context_id: u32,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(72 + token.len());
    // DCE/RPC Header (16 bytes)
    header.push(5); // Major version
    header.push(0); // Minor version
    header.push(pdu_type::RPC_BIND_ACK); // PDU type 12
    header.push(0x03); // Flags: PFC_FIRST_FRAG | PFC_LAST_FRAG
    header.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // Data representation: Little-endian ASCII
    header.extend_from_slice(&0u16.to_le_bytes()); // Frag len (placeholder)
    header.extend_from_slice(&0u16.to_le_bytes()); // Auth len (placeholder)
    header.extend_from_slice(&call_id.to_le_bytes()); // Call ID

    // BindAck specific header:
    header.extend_from_slice(&4096u16.to_le_bytes()); // Max xmit frag
    header.extend_from_slice(&4096u16.to_le_bytes()); // Max recv frag
    header.extend_from_slice(&assoc_group_id.to_le_bytes()); // Assoc group ID

    // Secondary address length + string (e.g. "\pipe\epmapper\0")
    let sec_addr = b"\\pipe\\epmapper\x00";
    header.extend_from_slice(&(sec_addr.len() as u16).to_le_bytes());
    header.extend_from_slice(sec_addr);
    // 4-byte alignment
    let pad = (4 - (header.len() % 4)) % 4;
    header.resize(header.len() + pad, 0);

    // Result list: 1 result (presentation context ack)
    header.push(1); // num_results
    header.push(0); // reserved
    header.extend_from_slice(&0u16.to_le_bytes()); // reserved2
    header.extend_from_slice(&0u16.to_le_bytes()); // result: acceptance (0)
    header.extend_from_slice(&0u16.to_le_bytes()); // reason: none (0)
    // Transfer syntax: NDR 32-bit (8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0)
    header.extend_from_slice(&[
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48,
        0x60,
    ]);
    header.extend_from_slice(&2u32.to_le_bytes()); // syntax version 2

    append_ntlm_sec_trailer_to_pdu(header, token, auth_level, context_id)
}

/// Builds a DCE/RPC `Auth3` (PDU 16) encapsulating an NTLMSSP Type 3 authenticate token.
pub fn wrap_ntlm_in_rpc_auth3(
    call_id: u32,
    token: &[u8],
    auth_level: u8,
    context_id: u32,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(32 + token.len());
    header.push(5); // Major version
    header.push(0); // Minor version
    header.push(16); // PDU type 16: RPC_AUTH3
    header.push(0x03); // Flags
    header.extend_from_slice(&[0x10, 0x00, 0x00, 0x00]); // Data representation
    header.extend_from_slice(&0u16.to_le_bytes()); // Frag len (placeholder)
    header.extend_from_slice(&0u16.to_le_bytes()); // Auth len (placeholder)
    header.extend_from_slice(&call_id.to_le_bytes()); // Call ID
    header.extend_from_slice(&4096u32.to_le_bytes()); // Max xmit frag padding

    append_ntlm_sec_trailer_to_pdu(header, token, auth_level, context_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_sec_trailer_append_and_extract() {
        let ntlm_token = b"NTLMSSP\x00\x01\x00\x00\x00\x07\x82\x08\x00";
        let base_pdu = vec![
            5, 0, 11, 3, // Bind PDU
            0x10, 0, 0, 0,
            0, 0, // frag len
            0, 0, // auth len
            1, 0, 0, 0, // call id
            0x10, 0x00, // max xmit
            0x10, 0x00, // max recv
            0, 0, 0, 0, // assoc group
            1, 0, 0, 0, // num contexts
        ];

        let wrapped = append_ntlm_sec_trailer_to_pdu(base_pdu, ntlm_token, 6, 1);
        let extracted = extract_ntlm_from_rpc_pdu(&wrapped).unwrap();
        assert_eq!(&extracted[..], &ntlm_token[..]);
    }

    #[test]
    fn test_wrap_ntlm_in_rpc_bind_ack_roundtrip() {
        let challenge = b"NTLMSSP\x00\x02\x00\x00\x00\x00\x00\x00\x00";
        let ack = wrap_ntlm_in_rpc_bind_ack(1, 0x1234, challenge, 6, 0);
        assert_eq!(ack[2], pdu_type::RPC_BIND_ACK);

        let extracted = extract_ntlm_from_rpc_pdu(&ack).unwrap();
        assert_eq!(&extracted[..], &challenge[..]);
    }

    #[test]
    fn test_wrap_ntlm_in_rpc_auth3_roundtrip() {
        let auth = b"NTLMSSP\x00\x03\x00\x00\x00\x00\x00\x00\x00";
        let auth3 = wrap_ntlm_in_rpc_auth3(1, auth, 6, 0);
        assert_eq!(auth3[2], 16);

        let extracted = extract_ntlm_from_rpc_pdu(&auth3).unwrap();
        assert_eq!(&extracted[..], &auth[..]);
    }
}
