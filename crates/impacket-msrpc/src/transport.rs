//! `transport`: live `ncacn_np` DCE/RPC transport over an authenticated SMB named pipe
//! (`impacket/dcerpc/v5/transport.py:SMBTransport`).
//!
//! Selects the SMB dialect family by compatibility profile: `AdCompatProfile::LegacyWin2000` drives the
//! legacy SMB1/CIFS stack (`Smb1Connection`) for SMB1-only hosts (NT4/2000/XP/2003); every other profile
//! uses the signed SMB 2.0.2–3.1.1 stack (`SmbConnection`). Both expose the same
//! connect/login/tree/pipe/transact surface, so the high-level `[MS-*]` clients transact unchanged.

use impacket_auth::compute_ntlm_hashes_with_compat;
use impacket_core::{AdCompatProfile, CoreError};
use impacket_dcerpc::{pdu_type, RpcBindPdu, RpcTransport};
use impacket_ndr::RpcUuid;
use impacket_smb::{Smb1Connection, SmbConnection, SmbCredential};
use std::time::Duration;

enum Pipe {
    /// SMB 2.0.2–3.1.1: 16-byte `FileId`.
    V2(SmbConnection, [u8; 16]),
    /// SMB1/CIFS: 16-bit `FID`.
    V1(Smb1Connection, u16),
}

/// A bound DCE/RPC-over-SMB-named-pipe transport (`ncacn_np`), SMB1 or SMB2/3.
pub struct SmbPipeTransport {
    pipe: Pipe,
    call_id: u32,
}

impl SmbPipeTransport {
    /// Connects to `host`, authenticates, opens `IPC$`, opens `\<pipe>`, and binds `interface`.
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        host: &str,
        domain: &str,
        username: &str,
        credential: &SmbCredential,
        pipe: &str,
        interface: RpcUuid,
        version_major: u16,
        version_minor: u16,
        profile: AdCompatProfile,
        timeout: Duration,
    ) -> Result<Self, CoreError> {
        let clean = pipe
            .trim_start_matches(r"\PIPE\")
            .trim_start_matches(r"\pipe\")
            .trim_start_matches('\\');
        let bind = RpcBindPdu::new(0, interface, version_major, version_minor).to_bytes();

        let inner = if profile == AdCompatProfile::LegacyWin2000 {
            let mut conn = Smb1Connection::connect(host, 445, timeout)?;
            // Legacy NTLMv1 needs the real LM hash; derive it when only a password was supplied.
            let hashes = match credential {
                SmbCredential::NtlmHashes(h) => h.clone(),
                SmbCredential::Password(p) => compute_ntlm_hashes_with_compat(p, true),
            };
            conn.login(domain, username, &hashes, "impacket-rs")?;
            conn.tree_connect(&format!(r"\\{}\IPC$", host))?;
            let fid = conn.open_pipe(clean)?;
            let ack = conn.transact_pipe(fid, &bind)?;
            check_bind_ack(&ack, clean)?;
            Pipe::V1(conn, fid)
        } else {
            let mut conn = SmbConnection::connect(host, 445, profile, timeout)?;
            conn.login(domain, username, credential, "impacket-rs")?;
            conn.tree_connect(&format!(r"\\{}\IPC$", host))?;
            let file_id = conn.open_pipe(clean)?;
            let ack = conn.transact_pipe(file_id, &bind)?;
            check_bind_ack(&ack, clean)?;
            Pipe::V2(conn, file_id)
        };

        Ok(Self {
            pipe: inner,
            call_id: 1,
        })
    }

    /// Returns the negotiated session key of the underlying transport.
    pub fn session_key(&self) -> &[u8; 16] {
        static ZERO: [u8; 16] = [0u8; 16];
        match &self.pipe {
            Pipe::V2(conn, _) => conn.session_key(),
            Pipe::V1(_, _) => &ZERO,
        }
    }
}

fn check_bind_ack(ack: &[u8], pipe: &str) -> Result<(), CoreError> {
    if ack.len() < 3 || ack[2] != pdu_type::RPC_BIND_ACK {
        return Err(CoreError::ProtocolError(format!(
            "DCE/RPC Bind to pipe '{}' rejected (ptype {})",
            pipe,
            ack.get(2).copied().unwrap_or(0)
        )));
    }
    let res = impacket_dcerpc::parse_bind_ack(ack)?;
    if !res.accepted {
        return Err(CoreError::ProtocolError(format!(
            "DCE/RPC Bind to pipe '{}' context rejected (reason {})",
            pipe,
            res.reject_reason
        )));
    }
    Ok(())
}

impl RpcTransport for SmbPipeTransport {
    fn transceive(&mut self, request_pdu: &[u8]) -> Result<Vec<u8>, CoreError> {
        self.call_id += 1;
        match &mut self.pipe {
            Pipe::V2(conn, file_id) => conn.transact_pipe(*file_id, request_pdu),
            Pipe::V1(conn, fid) => conn.transact_pipe(*fid, request_pdu),
        }
    }
}
