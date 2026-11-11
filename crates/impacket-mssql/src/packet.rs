//! `packet`: Tabular Data Stream (`[MS-TDS]`) packet framing and stream I/O.

use impacket_core::CoreError;
use std::io::{Read, Write};

pub const TDS_HEADER_LEN: usize = 8;
pub const DEFAULT_PACKET_SIZE: usize = 4096;

pub mod packet_type {
    pub const SQL_BATCH: u8 = 1;
    pub const PRE_TDS7_LOGIN: u8 = 2;
    pub const RPC: u8 = 3;
    pub const TABULAR_RESULT: u8 = 4;
    pub const ATTENTION: u8 = 6;
    pub const BULK_LOAD: u8 = 7;
    pub const FEDAUTH_TOKEN: u8 = 8;
    pub const TRANSACTION_MANAGER: u8 = 14;
    pub const TDS7_LOGIN: u8 = 16;
    pub const SSPI_MESSAGE: u8 = 17;
    pub const PRE_LOGIN: u8 = 18;
}

pub mod packet_status {
    pub const NORMAL: u8 = 0x00;
    pub const EOM: u8 = 0x01; // End of message
    pub const IGNORE: u8 = 0x02;
    pub const RESET_CONNECTION: u8 = 0x08;
    pub const RESET_CONNECTION_SKIP_TRAN: u8 = 0x10;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TdsHeader {
    pub ptype: u8,
    pub status: u8,
    pub length: u16, // Big-Endian total length including header
    pub spid: u16,   // Big-Endian Server Process ID
    pub packet_id: u8,
    pub window: u8,
}

impl TdsHeader {
    pub fn new(ptype: u8, status: u8, total_len: u16, packet_id: u8) -> Self {
        Self {
            ptype,
            status,
            length: total_len,
            spid: 0,
            packet_id,
            window: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0] = self.ptype;
        b[1] = self.status;
        b[2..4].copy_from_slice(&self.length.to_be_bytes());
        b[4..6].copy_from_slice(&self.spid.to_be_bytes());
        b[6] = self.packet_id;
        b[7] = self.window;
        b
    }

    pub fn from_bytes(b: &[u8; 8]) -> Self {
        Self {
            ptype: b[0],
            status: b[1],
            length: u16::from_be_bytes([b[2], b[3]]),
            spid: u16::from_be_bytes([b[4], b[5]]),
            packet_id: b[6],
            window: b[7],
        }
    }
}

/// Reads a single TDS packet from the stream: `(header, payload)`.
pub fn read_tds_packet<R: Read>(r: &mut R) -> Result<(TdsHeader, Vec<u8>), CoreError> {
    let mut hdr_bytes = [0u8; 8];
    r.read_exact(&mut hdr_bytes)
        .map_err(|e| CoreError::ProtocolError(format!("Failed reading TDS header: {}", e)))?;
    let hdr = TdsHeader::from_bytes(&hdr_bytes);
    if hdr.length < 8 {
        return Err(CoreError::ProtocolError(format!(
            "Invalid TDS packet length < 8 ({})",
            hdr.length
        )));
    }
    let payload_len = (hdr.length as usize) - 8;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        r.read_exact(&mut payload)
            .map_err(|e| CoreError::ProtocolError(format!("Failed reading TDS payload: {}", e)))?;
    }
    Ok((hdr, payload))
}

/// Reads all consecutive TDS packets until `status & STATUS_EOM` is set, reassembling the payload.
pub fn read_full_tds_message<R: Read>(r: &mut R) -> Result<(u8, Vec<u8>), CoreError> {
    let mut full_payload = Vec::new();

    loop {
        let (hdr, chunk) = read_tds_packet(r)?;
        full_payload.extend_from_slice(&chunk);
        if (hdr.status & packet_status::EOM) != 0 {
            return Ok((hdr.ptype, full_payload));
        }
    }
}

/// Writes a TDS message, splitting into packets of at most `max_packet_size` if necessary.
pub fn write_tds_message<W: Write>(
    w: &mut W,
    ptype: u8,
    payload: &[u8],
    max_packet_size: usize,
) -> Result<(), CoreError> {
    let max_payload = max_packet_size.saturating_sub(8).max(128);
    let chunks: Vec<&[u8]> = if payload.is_empty() {
        vec![&[][..]]
    } else {
        payload.chunks(max_payload).collect()
    };

    for (i, chunk) in chunks.iter().enumerate() {
        let is_last = i + 1 == chunks.len();
        let status = if is_last {
            packet_status::EOM
        } else {
            packet_status::NORMAL
        };
        let total_len = (8 + chunk.len()) as u16;
        let hdr = TdsHeader::new(ptype, status, total_len, (i + 1) as u8);
        w.write_all(&hdr.to_bytes())
            .map_err(|e| CoreError::ProtocolError(format!("Failed writing TDS header: {}", e)))?;
        if !chunk.is_empty() {
            w.write_all(chunk)
                .map_err(|e| CoreError::ProtocolError(format!("Failed writing TDS chunk: {}", e)))?;
        }
    }
    w.flush()
        .map_err(|e| CoreError::ProtocolError(format!("Failed flushing TDS message: {}", e)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_tds_header_roundtrip() {
        let hdr = TdsHeader::new(packet_type::SQL_BATCH, packet_status::EOM, 50, 1);
        let bytes = hdr.to_bytes();
        let parsed = TdsHeader::from_bytes(&bytes);
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn test_tds_message_fragmentation_and_reassembly() {
        let mut stream = Vec::new();
        let big_payload = vec![0x42u8; 1000];

        // Write with small 256-byte packet size
        write_tds_message(&mut stream, packet_type::SQL_BATCH, &big_payload, 256).unwrap();

        let mut cursor = Cursor::new(stream);
        let (ptype, reassembled) = read_full_tds_message(&mut cursor).unwrap();
        assert_eq!(ptype, packet_type::SQL_BATCH);
        assert_eq!(reassembled, big_payload);
    }
}
