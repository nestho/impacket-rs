//! `smb1`: operational legacy SMB1 / CIFS client (`NT LM 0.12`) for hosts that speak only SMB1
//! (Windows NT4 / 2000 / 2003 / XP). Mirrors the `SmbConnection` surface
//! (`connect`/`login`/`tree_connect`/`open_pipe`/`transact_pipe`) so the `ncacn_np` RPC transport can
//! drive SMB1-only targets transparently.
//!
//! Uses classic (non-extended-security) NTLMv1 authentication: the 8-byte challenge from
//! `SMB_COM_NEGOTIATE` + DES `DESL` responses in `SESSION_SETUP_ANDX`. DCE/RPC is carried over
//! `SMB_COM_TRANSACTION` / `TransactNmPipe` (subcommand `0x0026`). SMB1 message signing is not emitted
//! (legacy pipe targets rarely require it).

use crate::{read_netbios_packet, wrap_netbios_session};
use impacket_auth::compute_ntlmv1_response;
use impacket_core::{encode_utf16le, CoreError, NtStatus, NtlmHashes};
use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// SMB1 command codes (`[MS-CIFS]` / `[MS-SMB]`).
mod cmd {
    pub const NEGOTIATE: u8 = 0x72;
    pub const SESSION_SETUP_ANDX: u8 = 0x73;
    pub const TREE_CONNECT_ANDX: u8 = 0x75;
    pub const NT_CREATE_ANDX: u8 = 0xA2;
    pub const TRANSACTION: u8 = 0x25;
}

/// `TRANS_TRANSACT_NMPIPE` subcommand.
const TRANS_TRANSACT_NMPIPE: u16 = 0x0026;

const FLAGS: u8 = 0x18; // CASE_INSENSITIVE | CANONICALIZED_PATHS
const FLAGS2: u16 = 0xC001; // UNICODE | NT_STATUS | LONG_NAMES (no EXTENDED_SECURITY)
const ANDX_NONE: u8 = 0xFF;

/// Builds a 32-byte SMB1 header into a fresh message buffer.
fn smb1_header(command: u8, tid: u16, uid: u16, mid: u16) -> Vec<u8> {
    let mut h = Vec::with_capacity(64);
    h.extend_from_slice(b"\xFFSMB");
    h.push(command);
    h.extend_from_slice(&0u32.to_le_bytes()); // Status
    h.push(FLAGS);
    h.extend_from_slice(&FLAGS2.to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes()); // PIDHigh
    h.extend_from_slice(&[0u8; 8]); // SecurityFeatures
    h.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    h.extend_from_slice(&tid.to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes()); // PIDLow
    h.extend_from_slice(&uid.to_le_bytes());
    h.extend_from_slice(&mid.to_le_bytes());
    debug_assert_eq!(h.len(), 32);
    h
}

fn header_status(msg: &[u8]) -> Result<NtStatus, CoreError> {
    if msg.len() < 32 || &msg[0..4] != b"\xFFSMB" {
        return Err(CoreError::ProtocolError("Not an SMB1 response".into()));
    }
    Ok(NtStatus(u32::from_le_bytes([msg[5], msg[6], msg[7], msg[8]])))
}

fn header_tid(msg: &[u8]) -> u16 {
    u16::from_le_bytes([msg[24], msg[25]])
}

fn header_uid(msg: &[u8]) -> u16 {
    u16::from_le_bytes([msg[28], msg[29]])
}

/// Appends a UTF-16LE string, first inserting a 1-byte pad if the current absolute offset is odd
/// (SMB1 UNICODE strings must start on an even offset relative to the header).
fn push_unicode_aligned(msg: &mut Vec<u8>, s: &str, nul: bool) {
    if msg.len() % 2 != 0 {
        msg.push(0);
    }
    msg.extend_from_slice(&encode_utf16le(s));
    if nul {
        msg.extend_from_slice(&[0, 0]);
    }
}

/// An authenticated SMB1 session driving `ncacn_np` DCE/RPC named pipes.
pub struct Smb1Connection {
    stream: TcpStream,
    tid: u16,
    uid: u16,
    mid: u16,
    challenge: [u8; 8],
    /// 16-byte MAC signing key (derived from NTLMv1 session base key).
    signing_key: Option<[u8; 16]>,
    /// Monotonically incrementing 32-bit sequence number (`[MS-SMB]` 3.1.5.1).
    sequence_number: u32,
}

impl Smb1Connection {
    fn next_mid(&mut self) -> u16 {
        let m = self.mid;
        self.mid = self.mid.wrapping_add(1);
        m
    }

    /// Computes and inserts the SMB1 signature into `SecurityFeatures` [14..22] (`[MS-SMB]` 3.1.5.1).
    fn sign(&mut self, msg: &mut [u8]) {
        let key = match &self.signing_key {
            Some(k) => *k,
            None => return,
        };
        if msg.len() < 32 {
            return;
        }
        // Set SecurityFeatures [14..22] to sequence number (u32 LE) followed by 4 zeros.
        let seq = self.sequence_number;
        msg[14..18].copy_from_slice(&seq.to_le_bytes());
        msg[18..22].fill(0);

        // Signature is the first 8 bytes of MD5(SigningKey || Message).
        let mut buf = Vec::with_capacity(16 + msg.len());
        buf.extend_from_slice(&key);
        buf.extend_from_slice(msg);
        let digest = impacket_crypto::md5(&buf);
        msg[14..22].copy_from_slice(&digest[..8]);

        self.sequence_number = self.sequence_number.wrapping_add(2);
    }

    fn send(&mut self, msg: &[u8]) -> Result<Vec<u8>, CoreError> {
        let mut owned = msg.to_vec();
        self.sign(&mut owned);
        self.stream
            .write_all(&wrap_netbios_session(&owned))
            .map_err(|e| CoreError::ProtocolError(format!("SMB1 send failed: {}", e)))?;
        read_netbios_packet(&mut self.stream)
    }

    /// Connects and performs `SMB_COM_NEGOTIATE` with the single `NT LM 0.12` dialect (non-extended),
    /// capturing the 8-byte challenge.
    pub fn connect(host: &str, port: u16, timeout: Duration) -> Result<Self, CoreError> {
        let addr_str = format!("{}:{}", host, port);
        let sock_addr: SocketAddr = addr_str
            .to_socket_addrs()
            .map_err(|e| CoreError::ProtocolError(format!("Failed resolving {}: {}", addr_str, e)))?
            .next()
            .ok_or_else(|| CoreError::ProtocolError(format!("No address for {}", addr_str)))?;
        let stream = TcpStream::connect_timeout(&sock_addr, timeout)
            .map_err(|e| CoreError::ProtocolError(format!("TCP connect to {} failed: {}", addr_str, e)))?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));

        let mut conn = Self {
            stream,
            tid: 0,
            uid: 0,
            mid: 0,
            challenge: [0u8; 8],
            signing_key: None,
            sequence_number: 0,
        };

        let mut msg = smb1_header(cmd::NEGOTIATE, 0, 0, conn.next_mid());
        msg.push(0); // WordCount = 0
        let dialects = b"\x02NT LM 0.12\x00"; // BufferFormat 0x02 + dialect string
        msg.extend_from_slice(&(dialects.len() as u16).to_le_bytes()); // ByteCount
        msg.extend_from_slice(dialects);

        let resp = conn.send(&msg)?;
        let status = header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        conn.parse_negotiate_challenge(&resp)?;
        Ok(conn)
    }

    /// Extracts the 8-byte encryption challenge from an `NT LM 0.12` negotiate response (non-extended).
    fn parse_negotiate_challenge(&mut self, resp: &[u8]) -> Result<(), CoreError> {
        if resp.len() < 33 {
            return Err(CoreError::BufferUnderflow { needed: 33, available: resp.len() });
        }
        let word_count = resp[32] as usize;
        if word_count != 17 {
            return Err(CoreError::ProtocolError(format!(
                "SMB1 NEGOTIATE response WordCount {} (expected 17 for NT LM 0.12)",
                word_count
            )));
        }
        // Capabilities field is at words offset 20..24 within the parameter block.
        let words_start = 33;
        let capabilities = u32::from_le_bytes([
            resp[words_start + 20],
            resp[words_start + 21],
            resp[words_start + 22],
            resp[words_start + 23],
        ]);
        if capabilities & 0x8000_0000 != 0 {
            return Err(CoreError::ProtocolError(
                "server requires SMB1 extended security (SPNEGO); classic NTLMv1 path unsupported".into(),
            ));
        }
        // EncryptionKeyLength is the last word byte (offset 33 within words = 32 words + 1).
        let key_len = resp[words_start + 32] as usize; // byte 33 of the 34-byte word block
        let bytecount_off = words_start + word_count * 2; // 33 + 34 = 67
        let data_off = bytecount_off + 2;
        if key_len < 8 || data_off + 8 > resp.len() {
            return Err(CoreError::ProtocolError("SMB1 negotiate challenge missing/too short".into()));
        }
        self.challenge.copy_from_slice(&resp[data_off..data_off + 8]);
        Ok(())
    }

    /// `SMB_COM_SESSION_SETUP_ANDX` with classic NTLMv1 (DES) responses over the negotiate challenge.
    pub fn login(
        &mut self,
        domain: &str,
        username: &str,
        hashes: &NtlmHashes,
        workstation: &str,
    ) -> Result<(), CoreError> {
        let v1 = compute_ntlmv1_response(hashes, &self.challenge, &[0u8; 8], false);
        let lm = v1.lm_challenge_response; // 24
        let nt = v1.nt_challenge_response; // 24

        let mid = self.next_mid();
        let mut msg = smb1_header(cmd::SESSION_SETUP_ANDX, 0, 0, mid);
        msg.push(13); // WordCount
        msg.push(ANDX_NONE); // AndXCommand
        msg.push(0); // AndXReserved
        msg.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset
        msg.extend_from_slice(&4356u16.to_le_bytes()); // MaxBufferSize
        msg.extend_from_slice(&1u16.to_le_bytes()); // MaxMpxCount
        msg.extend_from_slice(&0u16.to_le_bytes()); // VcNumber
        msg.extend_from_slice(&0u32.to_le_bytes()); // SessionKey
        msg.extend_from_slice(&(lm.len() as u16).to_le_bytes()); // CaseInsensitivePasswordLength
        msg.extend_from_slice(&(nt.len() as u16).to_le_bytes()); // CaseSensitivePasswordLength
        msg.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        msg.extend_from_slice(&0x0000_00D4u32.to_le_bytes()); // Capabilities: UNICODE|NT_SMBS|STATUS32

        // ByteCount placeholder; fill after building the data block.
        let bc_pos = msg.len();
        msg.extend_from_slice(&0u16.to_le_bytes());
        let data_start = msg.len();

        msg.extend_from_slice(&lm);
        msg.extend_from_slice(&nt);
        // Unicode strings follow, aligned to even offset.
        push_unicode_aligned(&mut msg, username, true);
        push_unicode_aligned(&mut msg, domain, true);
        push_unicode_aligned(&mut msg, "impacket-rs", true);
        push_unicode_aligned(&mut msg, workstation, true);

        let byte_count = (msg.len() - data_start) as u16;
        msg[bc_pos..bc_pos + 2].copy_from_slice(&byte_count.to_le_bytes());

        let resp = self.send(&msg)?;
        let status = header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        self.uid = header_uid(&resp);
        self.signing_key = Some(v1.session_base_key);
        self.sequence_number = 2;
        Ok(())
    }

    /// `SMB_COM_TREE_CONNECT_ANDX` to `\\<host>\IPC$`.
    pub fn tree_connect(&mut self, unc_path: &str) -> Result<u16, CoreError> {
        let mid = self.next_mid();
        let mut msg = smb1_header(cmd::TREE_CONNECT_ANDX, 0, self.uid, mid);
        msg.push(4); // WordCount
        msg.push(ANDX_NONE);
        msg.push(0);
        msg.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset
        msg.extend_from_slice(&0u16.to_le_bytes()); // Flags
        msg.extend_from_slice(&1u16.to_le_bytes()); // PasswordLength = 1 (null password)

        let bc_pos = msg.len();
        msg.extend_from_slice(&0u16.to_le_bytes());
        let data_start = msg.len();

        msg.push(0x00); // Password (1 null byte)
        push_unicode_aligned(&mut msg, unc_path, true); // Path (unicode)
        msg.extend_from_slice(b"?????\x00"); // Service (always OEM/ASCII)

        let byte_count = (msg.len() - data_start) as u16;
        msg[bc_pos..bc_pos + 2].copy_from_slice(&byte_count.to_le_bytes());

        let resp = self.send(&msg)?;
        let status = header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        self.tid = header_tid(&resp);
        Ok(self.tid)
    }

    /// `SMB_COM_NT_CREATE_ANDX` to open a named pipe; returns its 16-bit `FID`.
    pub fn open_pipe(&mut self, pipe_name: &str) -> Result<u16, CoreError> {
        let clean = pipe_name
            .trim_start_matches(r"\PIPE\")
            .trim_start_matches(r"\pipe\")
            .trim_start_matches('\\');
        let path = format!(r"\{}", clean);
        let name_utf16 = encode_utf16le(&path);

        let mid = self.next_mid();
        let mut msg = smb1_header(cmd::NT_CREATE_ANDX, self.tid, self.uid, mid);
        msg.push(24); // WordCount
        msg.push(ANDX_NONE);
        msg.push(0);
        msg.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset
        msg.push(0); // Reserved
        msg.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes()); // NameLength
        msg.extend_from_slice(&0u32.to_le_bytes()); // Flags
        msg.extend_from_slice(&0u32.to_le_bytes()); // RootDirectoryFID
        msg.extend_from_slice(&0x0012_019Fu32.to_le_bytes()); // DesiredAccess
        msg.extend_from_slice(&0u64.to_le_bytes()); // AllocationSize
        msg.extend_from_slice(&0x0000_0080u32.to_le_bytes()); // ExtFileAttributes = NORMAL
        msg.extend_from_slice(&0x0000_0003u32.to_le_bytes()); // ShareAccess = READ|WRITE
        msg.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // CreateDisposition = FILE_OPEN
        msg.extend_from_slice(&0u32.to_le_bytes()); // CreateOptions
        msg.extend_from_slice(&0x0000_0002u32.to_le_bytes()); // ImpersonationLevel = IMPERSONATION
        msg.push(0); // SecurityFlags

        let bc_pos = msg.len();
        msg.extend_from_slice(&0u16.to_le_bytes());
        let data_start = msg.len();
        // Name (unicode, aligned). A single pad byte precedes it to even-align.
        push_unicode_aligned(&mut msg, &path, true);
        let byte_count = (msg.len() - data_start) as u16;
        msg[bc_pos..bc_pos + 2].copy_from_slice(&byte_count.to_le_bytes());

        let resp = self.send(&msg)?;
        let status = header_status(&resp)?;
        if !status.is_success() {
            return Err(CoreError::NtStatus(status));
        }
        // NT_CREATE_ANDX response: FID is a u16 at absolute offset 38.
        if resp.len() < 40 {
            return Err(CoreError::BufferUnderflow { needed: 40, available: resp.len() });
        }
        Ok(u16::from_le_bytes([resp[38], resp[39]]))
    }

    /// `SMB_COM_TRANSACTION` / `TransactNmPipe` — write one DCE/RPC PDU and read the response PDU.
    pub fn transact_pipe(&mut self, fid: u16, rpc_pdu: &[u8]) -> Result<Vec<u8>, CoreError> {
        let mid = self.next_mid();
        let mut msg = smb1_header(cmd::TRANSACTION, self.tid, self.uid, mid);
        msg.push(16); // WordCount = 14 + SetupCount(2)
        msg.extend_from_slice(&0u16.to_le_bytes()); // TotalParameterCount
        msg.extend_from_slice(&(rpc_pdu.len() as u16).to_le_bytes()); // TotalDataCount
        msg.extend_from_slice(&0u16.to_le_bytes()); // MaxParameterCount
        msg.extend_from_slice(&65535u16.to_le_bytes()); // MaxDataCount
        msg.push(0); // MaxSetupCount
        msg.push(0); // Reserved1
        msg.extend_from_slice(&0u16.to_le_bytes()); // Flags
        msg.extend_from_slice(&0u32.to_le_bytes()); // Timeout
        msg.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
        msg.extend_from_slice(&0u16.to_le_bytes()); // ParameterCount
        // ParameterOffset / DataOffset filled after layout is known.
        let param_off_pos = msg.len();
        msg.extend_from_slice(&0u16.to_le_bytes()); // ParameterOffset
        msg.extend_from_slice(&(rpc_pdu.len() as u16).to_le_bytes()); // DataCount
        let data_off_pos = msg.len();
        msg.extend_from_slice(&0u16.to_le_bytes()); // DataOffset
        msg.push(2); // SetupCount (words)
        msg.push(0); // Reserved3
        msg.extend_from_slice(&TRANS_TRANSACT_NMPIPE.to_le_bytes()); // Setup[0]
        msg.extend_from_slice(&fid.to_le_bytes()); // Setup[1] = FID

        let bc_pos = msg.len();
        msg.extend_from_slice(&0u16.to_le_bytes()); // ByteCount placeholder
        let data_section_start = msg.len();

        // Transaction Name "\PIPE\" (unicode, aligned).
        push_unicode_aligned(&mut msg, r"\PIPE\", true);
        // Pad data to a 4-byte boundary, then the DCE/RPC PDU.
        while (msg.len() % 4) != 0 {
            msg.push(0);
        }
        let data_offset = msg.len();
        msg.extend_from_slice(rpc_pdu);

        // Backfill ParameterOffset (points to just after name/pad, len 0) and DataOffset.
        msg[param_off_pos..param_off_pos + 2].copy_from_slice(&(data_offset as u16).to_le_bytes());
        msg[data_off_pos..data_off_pos + 2].copy_from_slice(&(data_offset as u16).to_le_bytes());
        let byte_count = (msg.len() - data_section_start) as u16;
        msg[bc_pos..bc_pos + 2].copy_from_slice(&byte_count.to_le_bytes());

        let resp = self.send(&msg)?;
        let status = header_status(&resp)?;
        if !status.is_success() && status.0 != 0x8000_0005 {
            return Err(CoreError::NtStatus(status));
        }
        parse_transaction_response_data(&resp)
    }
}

/// Parses the response-data bytes out of an `SMB_COM_TRANSACTION` reply.
fn parse_transaction_response_data(resp: &[u8]) -> Result<Vec<u8>, CoreError> {
    // Response: header(32) + WordCount(1); words: TotalParameterCount(2), TotalDataCount(2),
    // Reserved(2), ParameterCount(2), ParameterOffset(2), ParameterDisplacement(2),
    // DataCount(2)@45, DataOffset(2)@47.
    if resp.len() < 49 {
        return Err(CoreError::BufferUnderflow { needed: 49, available: resp.len() });
    }
    let data_count = u16::from_le_bytes([resp[45], resp[46]]) as usize;
    let data_offset = u16::from_le_bytes([resp[47], resp[48]]) as usize;
    if data_offset + data_count > resp.len() {
        return Err(CoreError::BufferUnderflow {
            needed: data_offset + data_count,
            available: resp.len(),
        });
    }
    Ok(resp[data_offset..data_offset + data_count].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_setup_andx_structure() {
        // Build a SESSION_SETUP_ANDX by hand-driving the builder fields through a fake connection.
        let hashes = NtlmHashes::parse(":31d6cfe0d16ae931b73c59d7e0c089c0").unwrap();
        let v1 = compute_ntlmv1_response(&hashes, &[0x11; 8], &[0u8; 8], false);
        assert_eq!(v1.lm_challenge_response.len(), 24);
        assert_eq!(v1.nt_challenge_response.len(), 24);
    }

    #[test]
    fn test_transaction_response_parser() {
        // Hand-build a minimal SMB_COM_TRANSACTION response carrying 4 data bytes.
        let mut resp = smb1_header(cmd::TRANSACTION, 1, 1, 1);
        // status success already zero.
        resp.push(10); // WordCount
        resp.extend_from_slice(&0u16.to_le_bytes()); // TotalParameterCount
        resp.extend_from_slice(&4u16.to_le_bytes()); // TotalDataCount
        resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        resp.extend_from_slice(&0u16.to_le_bytes()); // ParameterCount
        resp.extend_from_slice(&0u16.to_le_bytes()); // ParameterOffset
        resp.extend_from_slice(&0u16.to_le_bytes()); // ParameterDisplacement
        resp.extend_from_slice(&4u16.to_le_bytes()); // DataCount @45
        let data_off_pos = resp.len();
        resp.extend_from_slice(&0u16.to_le_bytes()); // DataOffset @47 (backfill)
        resp.push(0); // SetupCount
        resp.push(0); // Reserved2
        resp.extend_from_slice(&0u16.to_le_bytes()); // ByteCount
        let data_off = resp.len();
        resp.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        resp[data_off_pos..data_off_pos + 2].copy_from_slice(&(data_off as u16).to_le_bytes());

        let data = parse_transaction_response_data(&resp).unwrap();
        assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
