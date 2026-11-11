//! `[MS-SMBD]`: SMB2 Remote Direct Memory Access (RDMA) Transport Protocol.
//!
//! Provides protocol packet codecs, negotiation handshakes, buffer descriptors,
//! framing abstraction, and multi-fragment payload assembly for RDMA/iWARP/RoCE
//! high-throughput SMB3 connections.

use impacket_core::CoreError;
use std::io::{Read, Write};

/// Standard IANA port for SMB Direct over RDMA (iWARP / RoCE).
pub const SMBD_DEFAULT_PORT: u16 = 5445;

/// SMBD Protocol Version 1.00 (0x0100).
pub const SMBD_VERSION_1_0: u16 = 0x0100;

/// SMBD Data Transfer Flags (`[MS-SMBD] 2.2.2.1`).
pub const SMBD_FLAG_NONE: u16 = 0x0000;
pub const SMBD_FLAG_RESPONSE_REQUESTED: u16 = 0x0001;

/// Default SMBD buffer and credit configuration.
pub const SMBD_DEFAULT_CREDITS: u16 = 255;
pub const SMBD_DEFAULT_SEND_SIZE: u32 = 8192;
pub const SMBD_DEFAULT_RECEIVE_SIZE: u32 = 8192;
pub const SMBD_DEFAULT_MAX_FRAGMENTED_SIZE: u32 = 1024 * 1024; // 1 MB

// ============================================================================
// Protocol Packets: Negotiate Request & Response
// ============================================================================

/// `[MS-SMBD] 2.2.1.1` SMBD Negotiate Request Packet (16 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbdNegotiateReq {
    pub credits_requested: u16,
    pub receive_credit_max: u16,
    pub preferred_send_size: u32,
    pub max_receive_size: u32,
    pub max_fragmented_size: u32,
}

impl SmbdNegotiateReq {
    pub fn new(
        credits_requested: u16,
        receive_credit_max: u16,
        preferred_send_size: u32,
        max_receive_size: u32,
        max_fragmented_size: u32,
    ) -> Self {
        Self {
            credits_requested,
            receive_credit_max,
            preferred_send_size,
            max_receive_size,
            max_fragmented_size,
        }
    }

    pub fn default_client() -> Self {
        Self::new(
            SMBD_DEFAULT_CREDITS,
            SMBD_DEFAULT_CREDITS,
            SMBD_DEFAULT_SEND_SIZE,
            SMBD_DEFAULT_RECEIVE_SIZE,
            SMBD_DEFAULT_MAX_FRAGMENTED_SIZE,
        )
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..2].copy_from_slice(&self.credits_requested.to_le_bytes());
        out[2..4].copy_from_slice(&self.receive_credit_max.to_le_bytes());
        out[4..8].copy_from_slice(&self.preferred_send_size.to_le_bytes());
        out[8..12].copy_from_slice(&self.max_receive_size.to_le_bytes());
        out[12..16].copy_from_slice(&self.max_fragmented_size.to_le_bytes());
        out
    }

    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 16 {
            return Err(CoreError::ProtocolError(format!(
                "SMBD Negotiate Request truncated: expected 16 bytes, got {}",
                data.len()
            )));
        }
        Ok(Self {
            credits_requested: u16::from_le_bytes([data[0], data[1]]),
            receive_credit_max: u16::from_le_bytes([data[2], data[3]]),
            preferred_send_size: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            max_receive_size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            max_fragmented_size: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        })
    }
}

/// `[MS-SMBD] 2.2.1.2` SMBD Negotiate Response Packet (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbdNegotiateResp {
    pub min_version: u16,
    pub max_version: u16,
    pub negotiated_version: u16,
    pub reserved: u16,
    pub credits_requested: u16,
    pub credits_granted: u16,
    pub status: u32,
    pub max_readwrite_size: u32,
    pub preferred_send_size: u32,
    pub max_receive_size: u32,
    pub max_fragmented_size: u32,
}

impl SmbdNegotiateResp {
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..2].copy_from_slice(&self.min_version.to_le_bytes());
        out[2..4].copy_from_slice(&self.max_version.to_le_bytes());
        out[4..6].copy_from_slice(&self.negotiated_version.to_le_bytes());
        out[6..8].copy_from_slice(&self.reserved.to_le_bytes());
        out[8..10].copy_from_slice(&self.credits_requested.to_le_bytes());
        out[10..12].copy_from_slice(&self.credits_granted.to_le_bytes());
        out[12..16].copy_from_slice(&self.status.to_le_bytes());
        out[16..20].copy_from_slice(&self.max_readwrite_size.to_le_bytes());
        out[20..24].copy_from_slice(&self.preferred_send_size.to_le_bytes());
        out[24..28].copy_from_slice(&self.max_receive_size.to_le_bytes());
        out[28..32].copy_from_slice(&self.max_fragmented_size.to_le_bytes());
        out
    }

    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 32 {
            return Err(CoreError::ProtocolError(format!(
                "SMBD Negotiate Response truncated: expected 32 bytes, got {}",
                data.len()
            )));
        }
        Ok(Self {
            min_version: u16::from_le_bytes([data[0], data[1]]),
            max_version: u16::from_le_bytes([data[2], data[3]]),
            negotiated_version: u16::from_le_bytes([data[4], data[5]]),
            reserved: u16::from_le_bytes([data[6], data[7]]),
            credits_requested: u16::from_le_bytes([data[8], data[9]]),
            credits_granted: u16::from_le_bytes([data[10], data[11]]),
            status: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            max_readwrite_size: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            preferred_send_size: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            max_receive_size: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            max_fragmented_size: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
        })
    }
}

// ============================================================================
// Data Transfer & RDMA Descriptors
// ============================================================================

/// `[MS-SMBD] 2.2.2.1` SMBD Data Transfer Message Header (20 bytes + 4 bytes padding = 24 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbdDataTransfer {
    pub credits_requested: u16,
    pub credits_granted: u16,
    pub flags: u16,
    pub reserved: u16,
    pub remaining_data_length: u32,
    pub data_offset: u32,
    pub data_length: u32,
    pub payload: Vec<u8>,
}

impl SmbdDataTransfer {
    /// Creates a new SMBD Data Transfer message encapsulating an SMB2 packet.
    pub fn new(
        credits_requested: u16,
        credits_granted: u16,
        flags: u16,
        remaining_data_length: u32,
        payload: Vec<u8>,
    ) -> Self {
        let data_offset = 24u32; // Standard 24-byte header (20 bytes fields + 4 bytes padding)
        let data_length = payload.len() as u32;
        Self {
            credits_requested,
            credits_granted,
            flags,
            reserved: 0,
            remaining_data_length,
            data_offset,
            data_length,
            payload,
        }
    }

    /// Serializes header + padding + payload to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24 + self.payload.len());
        out.extend_from_slice(&self.credits_requested.to_le_bytes());
        out.extend_from_slice(&self.credits_granted.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.reserved.to_le_bytes());
        out.extend_from_slice(&self.remaining_data_length.to_le_bytes());
        out.extend_from_slice(&self.data_offset.to_le_bytes());
        out.extend_from_slice(&self.data_length.to_le_bytes());
        // 4 bytes padding to reach 24-byte offset
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parses an incoming SMBD Data Transfer packet.
    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 20 {
            return Err(CoreError::ProtocolError(format!(
                "SMBD Data Transfer truncated: expected >= 20 bytes, got {}",
                data.len()
            )));
        }
        let credits_requested = u16::from_le_bytes([data[0], data[1]]);
        let credits_granted = u16::from_le_bytes([data[2], data[3]]);
        let flags = u16::from_le_bytes([data[4], data[5]]);
        let reserved = u16::from_le_bytes([data[6], data[7]]);
        let remaining_data_length = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let data_length = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);

        let start = data_offset as usize;
        let end = start + data_length as usize;

        if data.len() < end {
            return Err(CoreError::ProtocolError(format!(
                "SMBD payload out of bounds: offset={}, length={}, packet_len={}",
                data_offset,
                data_length,
                data.len()
            )));
        }

        let payload = data[start..end].to_vec();
        Ok(Self {
            credits_requested,
            credits_granted,
            flags,
            reserved,
            remaining_data_length,
            data_offset,
            data_length,
            payload,
        })
    }
}

/// `[MS-SMBD] 2.2.3.1` SMBD Buffer Descriptor V1 (16 bytes).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SmbdBufferDescriptorV1 {
    pub offset: u64,
    pub token: u32,
    pub length: u32,
}

impl SmbdBufferDescriptorV1 {
    pub fn new(offset: u64, token: u32, length: u32) -> Self {
        Self { offset, token, length }
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&self.offset.to_le_bytes());
        out[8..12].copy_from_slice(&self.token.to_le_bytes());
        out[12..16].copy_from_slice(&self.length.to_le_bytes());
        out
    }

    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 16 {
            return Err(CoreError::ProtocolError(format!(
                "SMBD Buffer Descriptor V1 truncated: expected 16 bytes, got {}",
                data.len()
            )));
        }
        let offset = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let token = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let length = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        Ok(Self { offset, token, length })
    }
}

// ============================================================================
// Multi-Fragment Message Reassembler & Framer
// ============================================================================

/// Reassembles multi-fragment SMBD Data Transfer messages into full SMB2 packets.
#[derive(Debug, Default)]
pub struct SmbdMessageReassembler {
    buffer: Vec<u8>,
    expected_remaining: u32,
}

impl SmbdMessageReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds a new SMBD Data Transfer packet into the reassembler.
    /// Returns `Some(complete_smb2_payload)` when all fragments have been received.
    pub fn process_packet(&mut self, pkt: SmbdDataTransfer) -> Option<Vec<u8>> {
        self.buffer.extend_from_slice(&pkt.payload);
        self.expected_remaining = pkt.remaining_data_length;

        if self.expected_remaining == 0 {
            let full_payload = std::mem::take(&mut self.buffer);
            Some(full_payload)
        } else {
            None
        }
    }

    /// Resets the internal assembly buffer.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.expected_remaining = 0;
    }
}

/// Drives SMBD negotiation and packet exchange over a stream.
pub struct SmbdTransport<S: Read + Write> {
    stream: S,
    pub negotiated: Option<SmbdNegotiateResp>,
    pub available_credits: u16,
    reassembler: SmbdMessageReassembler,
}

impl<S: Read + Write> SmbdTransport<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            negotiated: None,
            available_credits: 1,
            reassembler: SmbdMessageReassembler::new(),
        }
    }

    /// Performs the SMBD client negotiation handshake.
    pub fn negotiate(&mut self, req: &SmbdNegotiateReq) -> Result<SmbdNegotiateResp, CoreError> {
        let req_bytes = req.to_bytes();
        self.stream
            .write_all(&req_bytes)
            .map_err(|e| CoreError::IoError(format!("Failed sending SMBD Negotiate Request: {}", e)))?;
        self.stream
            .flush()
            .map_err(|e| CoreError::IoError(format!("Failed flushing stream: {}", e)))?;

        let mut resp_buf = [0u8; 32];
        self.stream
            .read_exact(&mut resp_buf)
            .map_err(|e| CoreError::IoError(format!("Failed reading SMBD Negotiate Response: {}", e)))?;

        let resp = SmbdNegotiateResp::parse(&resp_buf)?;
        if resp.status != 0 {
            return Err(CoreError::ProtocolError(format!(
                "SMBD Negotiate failed with status 0x{:08X}",
                resp.status
            )));
        }

        self.available_credits = resp.credits_granted;
        self.negotiated = Some(resp.clone());
        Ok(resp)
    }

    /// Sends an SMB2 message over SMBD, segmenting into fragments if needed.
    pub fn send_smb2_message(&mut self, message: &[u8]) -> Result<(), CoreError> {
        let max_send = self
            .negotiated
            .as_ref()
            .map(|n| n.preferred_send_size as usize)
            .unwrap_or(SMBD_DEFAULT_SEND_SIZE as usize);

        let mut offset = 0;
        let total_len = message.len();

        while offset < total_len {
            let chunk_len = std::cmp::min(max_send, total_len - offset);
            let chunk = &message[offset..offset + chunk_len];
            let remaining = (total_len - (offset + chunk_len)) as u32;

            let pkt = SmbdDataTransfer::new(
                SMBD_DEFAULT_CREDITS,
                1,
                if remaining > 0 { SMBD_FLAG_NONE } else { SMBD_FLAG_RESPONSE_REQUESTED },
                remaining,
                chunk.to_vec(),
            );

            self.stream
                .write_all(&pkt.to_bytes())
                .map_err(|e| CoreError::IoError(format!("Failed sending SMBD Data Transfer frame: {}", e)))?;

            offset += chunk_len;
        }

        self.stream
            .flush()
            .map_err(|e| CoreError::IoError(format!("Failed flushing SMBD stream: {}", e)))?;
        Ok(())
    }

    /// Reads an incoming SMBD frame and returns the reassembled SMB2 message if complete.
    pub fn read_smb2_message(&mut self) -> Result<Vec<u8>, CoreError> {
        loop {
            let mut header_buf = [0u8; 20];
            self.stream
                .read_exact(&mut header_buf)
                .map_err(|e| CoreError::IoError(format!("Failed reading SMBD frame header: {}", e)))?;

            let data_offset = u32::from_le_bytes([header_buf[12], header_buf[13], header_buf[14], header_buf[15]]) as usize;
            let data_length = u32::from_le_bytes([header_buf[16], header_buf[17], header_buf[18], header_buf[19]]) as usize;

            let padding_len = if data_offset > 20 { data_offset - 20 } else { 0 };
            if padding_len > 0 {
                let mut pad_buf = vec![0u8; padding_len];
                self.stream
                    .read_exact(&mut pad_buf)
                    .map_err(|e| CoreError::IoError(format!("Failed reading SMBD padding: {}", e)))?;
            }

            let mut payload_buf = vec![0u8; data_length];
            self.stream
                .read_exact(&mut payload_buf)
                .map_err(|e| CoreError::IoError(format!("Failed reading SMBD payload: {}", e)))?;

            let mut full_packet = Vec::with_capacity(20 + padding_len + data_length);
            full_packet.extend_from_slice(&header_buf);
            full_packet.extend_from_slice(&vec![0u8; padding_len]);
            full_packet.extend_from_slice(&payload_buf);

            let pkt = SmbdDataTransfer::parse(&full_packet)?;
            if let Some(msg) = self.reassembler.process_packet(pkt) {
                return Ok(msg);
            }
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smbd_negotiate_req_and_resp_roundtrip() {
        let req = SmbdNegotiateReq::new(128, 256, 8192, 16384, 1048576);
        let req_bytes = req.to_bytes();
        let parsed_req = SmbdNegotiateReq::parse(&req_bytes).expect("Parse request failed");
        assert_eq!(parsed_req, req);

        let resp = SmbdNegotiateResp {
            min_version: SMBD_VERSION_1_0,
            max_version: SMBD_VERSION_1_0,
            negotiated_version: SMBD_VERSION_1_0,
            reserved: 0,
            credits_requested: 128,
            credits_granted: 128,
            status: 0,
            max_readwrite_size: 1048576,
            preferred_send_size: 8192,
            max_receive_size: 16384,
            max_fragmented_size: 1048576,
        };
        let resp_bytes = resp.to_bytes();
        let parsed_resp = SmbdNegotiateResp::parse(&resp_bytes).expect("Parse response failed");
        assert_eq!(parsed_resp, resp);
    }

    #[test]
    fn test_smbd_data_transfer_serialization_and_padding() {
        let payload = b"SMB2_MOCK_PAYLOAD_FOR_DIRECT".to_vec();
        let pkt = SmbdDataTransfer::new(10, 5, SMBD_FLAG_RESPONSE_REQUESTED, 0, payload.clone());
        let bytes = pkt.to_bytes();

        assert_eq!(bytes.len(), 24 + payload.len());
        let parsed = SmbdDataTransfer::parse(&bytes).expect("Parse data transfer failed");
        assert_eq!(parsed.credits_requested, 10);
        assert_eq!(parsed.credits_granted, 5);
        assert_eq!(parsed.flags, SMBD_FLAG_RESPONSE_REQUESTED);
        assert_eq!(parsed.remaining_data_length, 0);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_smbd_buffer_descriptor_v1_roundtrip() {
        let desc = SmbdBufferDescriptorV1::new(0x1000_2000_3000, 0xABCDEF01, 65536);
        let bytes = desc.to_bytes();
        let parsed = SmbdBufferDescriptorV1::parse(&bytes).expect("Parse buffer descriptor failed");
        assert_eq!(parsed, desc);
    }

    #[test]
    fn test_smbd_multi_fragment_reassembly() {
        let mut reassembler = SmbdMessageReassembler::new();

        let frag1 = SmbdDataTransfer::new(10, 5, SMBD_FLAG_NONE, 10, b"Part1_".to_vec());
        let frag2 = SmbdDataTransfer::new(10, 5, SMBD_FLAG_RESPONSE_REQUESTED, 0, b"Part2".to_vec());

        assert!(reassembler.process_packet(frag1).is_none());
        let full = reassembler.process_packet(frag2).expect("Reassembly should complete");
        assert_eq!(full, b"Part1_Part2");
    }
}
