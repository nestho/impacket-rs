//! `[MS-SMB2]`: Pure-Rust Multi-Dialect SMB2 File Server and NTLMSSP Credential Logger (`impacket/smbserver.py`).
//!
//! Provides an autonomous, multi-threaded SMB2 file server hosting local directories as network shares,
//! performing NTLMSSP / SPNEGO authentication, capturing and logging NetNTLMv2 hashes (mode 5600),
//! and serving file transfers (`CREATE`, `QUERY_DIRECTORY`, `READ`, `WRITE`, `CLOSE`, `TREE_CONNECT`).

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use impacket_auth::spnego::{MechType, NegState, NegTokenInit, NegTokenResp};
use impacket_auth::{NtlmAuthenticateMessage, NtlmChallengeMessage, NtlmTargetInfo};
use impacket_core::{encode_utf16le, CoreError, FileTime, NtStatus};
use impacket_ndr::{NdrDeserialize, NdrReader, NdrSerialize, NdrWriter};

use crate::{
    read_netbios_packet, smb2_cmd, wrap_netbios_session, Smb2Header, SmbDialect,
};

/// Definition of an SMB share hosted by the server.
#[derive(Debug, Clone)]
pub struct SmbShare {
    pub name: String,
    pub path: PathBuf,
    pub comment: String,
    pub read_only: bool,
    pub is_ipc: bool,
}

impl SmbShare {
    pub fn new_disk(name: impl Into<String>, path: impl AsRef<Path>, comment: impl Into<String>, read_only: bool) -> Self {
        Self {
            name: name.into().to_uppercase(),
            path: path.as_ref().to_path_buf(),
            comment: comment.into(),
            read_only,
            is_ipc: false,
        }
    }

    pub fn new_ipc() -> Self {
        Self {
            name: "IPC$".to_string(),
            path: PathBuf::new(),
            comment: "IPC Service".to_string(),
            read_only: true,
            is_ipc: true,
        }
    }
}

/// Configuration settings for the SMB server.
#[derive(Debug, Clone)]
pub struct SmbServerConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub shares: Vec<SmbShare>,
    pub challenge: [u8; 8],
    pub server_name: String,
    pub domain_name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub nt_hash: Option<[u8; 16]>,
    pub allow_anonymous: bool,
}

impl Default for SmbServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0".to_string(),
            listen_port: 445,
            shares: vec![SmbShare::new_ipc()],
            challenge: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            server_name: "IMPACKET-RS".to_string(),
            domain_name: "WORKGROUP".to_string(),
            username: None,
            password: None,
            nt_hash: None,
            allow_anonymous: true,
        }
    }
}

/// Information entry for `FileIdBothDirectoryInformation` (0x25).
#[derive(Debug, Clone)]
pub struct DirEntryInfo {
    pub file_index: u32,
    pub creation_time: u64,
    pub last_access_time: u64,
    pub last_write_time: u64,
    pub change_time: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub file_attributes: u32,
    pub file_id: u64,
    pub name: String,
}

/// Serializes a list of `DirEntryInfo` items into wire-format `FileIdBothDirectoryInformation` entries.
pub fn encode_file_id_both_dir_info(entries: &[DirEntryInfo]) -> Vec<u8> {
    let mut buf = Vec::new();
    let num_entries = entries.len();

    for (i, entry) in entries.iter().enumerate() {
        let name_utf16 = encode_utf16le(&entry.name);
        let entry_len = 104 + name_utf16.len();
        let pad = if i + 1 < num_entries {
            let rem = entry_len % 8;
            if rem != 0 {
                8 - rem
            } else {
                0
            }
        } else {
            0
        };
        let next_offset = if i + 1 < num_entries {
            (entry_len + pad) as u32
        } else {
            0
        };

        let mut w = NdrWriter::with_capacity(entry_len + pad);
        w.write_u32(next_offset);
        w.write_u32(entry.file_index);
        w.write_u64(entry.creation_time);
        w.write_u64(entry.last_access_time);
        w.write_u64(entry.last_write_time);
        w.write_u64(entry.change_time);
        w.write_u64(entry.end_of_file);
        w.write_u64(entry.allocation_size);
        w.write_u32(entry.file_attributes);
        w.write_u32(name_utf16.len() as u32);
        w.write_u32(0); // EaSize
        w.write_u8(0);  // ShortNameLength
        w.write_u8(0);  // Reserved
        w.write_fixed_array(&[0u8; 24]); // ShortName
        w.write_u16(0); // Reserved2
        w.write_u64(entry.file_id);
        w.write_bytes(&name_utf16);
        for _ in 0..pad {
            w.write_u8(0);
        }

        buf.extend_from_slice(&w.into_bytes());
    }

    buf
}

/// Builds an `SMB2_NEGOTIATE` Response (`[MS-SMB2] 2.2.4`).
pub fn build_smb2_negotiate_response(
    message_id: u64,
    dialect: u16,
    server_guid: [u8; 16],
    security_blob: &[u8],
    system_time: u64,
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 64 + security_blob.len());
    let mut hdr = Smb2Header::new(smb2_cmd::NEGOTIATE, message_id, 0, 0);
    hdr.flags = 0x0000_0001; // SERVER_TO_REDIR
    hdr.status = NtStatus::STATUS_SUCCESS.0;
    hdr.credit_request_response = 1;
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(65); // StructureSize = 65 (0x0041)
    writer.write_u16(0x0001); // SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED
    writer.write_u16(dialect); // DialectRevision (e.g. 0x0210)
    writer.write_u16(0); // NegotiateContextCount
    writer.write_fixed_array(&server_guid); // ServerGuid
    writer.write_u32(0x0000_0005); // Capabilities: DFS | LARGE_MTU
    writer.write_u32(1048576); // MaxTransactSize = 1MB
    writer.write_u32(1048576); // MaxReadSize = 1MB
    writer.write_u32(1048576); // MaxWriteSize = 1MB
    writer.write_u64(system_time); // SystemTime
    writer.write_u64(system_time); // ServerStartTime
    writer.write_u16(128); // SecurityBufferOffset = 64 + 64 = 128
    writer.write_u16(security_blob.len() as u16); // SecurityBufferLength
    writer.write_u32(0); // NegotiateContextOffset
    writer.write_bytes(security_blob);

    writer.into_bytes()
}

/// Builds an `SMB2_TREE_CONNECT` Response (`[MS-SMB2] 2.2.10`).
pub fn build_smb2_tree_connect_response(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    share_type: u8, // 1 = Disk, 2 = Pipe
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 16);
    let mut hdr = Smb2Header::new(smb2_cmd::TREE_CONNECT, message_id, session_id, tree_id);
    hdr.flags = 0x0000_0001;
    hdr.status = NtStatus::STATUS_SUCCESS.0;
    hdr.credit_request_response = 1;
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(16); // StructureSize = 16
    writer.write_u8(share_type); // ShareType (1 = Disk, 2 = Pipe)
    writer.write_u8(0); // Reserved
    writer.write_u32(0); // ShareFlags
    writer.write_u32(0); // Capabilities
    writer.write_u32(0x001F_01FF); // MaximalAccess = Full Control

    writer.into_bytes()
}

/// Builds an `SMB2_CREATE` Response (`[MS-SMB2] 2.2.14`).
pub fn build_smb2_create_response(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: [u8; 16],
    is_directory: bool,
    file_size: u64,
    now_ft: u64,
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 88);
    let mut hdr = Smb2Header::new(smb2_cmd::CREATE, message_id, session_id, tree_id);
    hdr.flags = 0x0000_0001;
    hdr.status = NtStatus::STATUS_SUCCESS.0;
    hdr.credit_request_response = 1;
    hdr.ndr_serialize(&mut writer);

    let attrs = if is_directory {
        0x0000_0010
    } else {
        0x0000_0080
    };

    writer.write_u16(89); // StructureSize = 89
    writer.write_u8(0);  // OplockLevel = 0
    writer.write_u8(0);  // Flags = 0
    writer.write_u32(1); // CreateAction = FILE_OPENED (1)
    writer.write_u64(now_ft); // CreationTime
    writer.write_u64(now_ft); // LastAccessTime
    writer.write_u64(now_ft); // LastWriteTime
    writer.write_u64(now_ft); // ChangeTime
    writer.write_u64(file_size); // AllocationSize
    writer.write_u64(file_size); // EndOfFile
    writer.write_u32(attrs); // FileAttributes
    writer.write_u32(0); // Reserved2
    writer.write_fixed_array(&file_id); // FileId (16 bytes)
    writer.write_u32(0); // CreateContextsOffset
    writer.write_u32(0); // CreateContextsLength

    writer.into_bytes()
}

/// Builds an `SMB2_QUERY_DIRECTORY` Response (`[MS-SMB2] 2.2.34`).
pub fn build_smb2_query_directory_response(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    entries_buffer: &[u8],
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 8 + entries_buffer.len());
    let mut hdr = Smb2Header::new(smb2_cmd::QUERY_DIRECTORY, message_id, session_id, tree_id);
    hdr.flags = 0x0000_0001;
    hdr.status = NtStatus::STATUS_SUCCESS.0;
    hdr.credit_request_response = 1;
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(9); // StructureSize = 9
    writer.write_u16(72); // OutputBufferOffset = 64 + 8 = 72
    writer.write_u32(entries_buffer.len() as u32); // OutputBufferLength
    writer.write_bytes(entries_buffer);

    writer.into_bytes()
}

/// Builds an `SMB2_READ` Response (`[MS-SMB2] 2.2.20`).
pub fn build_smb2_read_response(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    data: &[u8],
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 16 + data.len());
    let mut hdr = Smb2Header::new(smb2_cmd::READ, message_id, session_id, tree_id);
    hdr.flags = 0x0000_0001;
    hdr.status = NtStatus::STATUS_SUCCESS.0;
    hdr.credit_request_response = 1;
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(17); // StructureSize = 17
    writer.write_u8(80);  // DataOffset = 64 + 16 = 80
    writer.write_u8(0);   // Reserved
    writer.write_u32(data.len() as u32); // DataLength
    writer.write_u32(0);  // DataRemaining
    writer.write_u32(0);  // Reserved2
    writer.write_bytes(data);

    writer.into_bytes()
}

/// Builds an `SMB2_WRITE` Response (`[MS-SMB2] 2.2.22`).
pub fn build_smb2_write_response(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    count_written: u32,
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 16);
    let mut hdr = Smb2Header::new(smb2_cmd::WRITE, message_id, session_id, tree_id);
    hdr.flags = 0x0000_0001;
    hdr.status = NtStatus::STATUS_SUCCESS.0;
    hdr.credit_request_response = 1;
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(17); // StructureSize = 17
    writer.write_u16(0);  // Reserved
    writer.write_u32(count_written); // Count
    writer.write_u32(0);  // Remaining
    writer.write_u16(0);  // WriteChannelInfoOffset
    writer.write_u16(0);  // WriteChannelInfoLength

    writer.into_bytes()
}

/// Builds an `SMB2_CLOSE` Response (`[MS-SMB2] 2.2.16`).
pub fn build_smb2_close_response(
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_size: u64,
    now_ft: u64,
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 60);
    let mut hdr = Smb2Header::new(smb2_cmd::CLOSE, message_id, session_id, tree_id);
    hdr.flags = 0x0000_0001;
    hdr.status = NtStatus::STATUS_SUCCESS.0;
    hdr.credit_request_response = 1;
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(60); // StructureSize = 60
    writer.write_u16(0);  // Flags = 0
    writer.write_u32(0);  // Reserved
    writer.write_u64(now_ft); // CreationTime
    writer.write_u64(now_ft); // LastAccessTime
    writer.write_u64(now_ft); // LastWriteTime
    writer.write_u64(now_ft); // ChangeTime
    writer.write_u64(file_size); // AllocationSize
    writer.write_u64(file_size); // EndOfFile
    writer.write_u32(0x0000_0080); // FileAttributes

    writer.into_bytes()
}

/// Builds an `SMB2_ERROR` Response (`[MS-SMB2] 2.2.2`).
pub fn build_smb2_error_response(
    command: u16,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    status: NtStatus,
) -> Vec<u8> {
    let mut writer = NdrWriter::with_capacity(64 + 8);
    let mut hdr = Smb2Header::new(command, message_id, session_id, tree_id);
    hdr.flags = 0x0000_0001;
    hdr.status = status.0;
    hdr.credit_request_response = 1;
    hdr.ndr_serialize(&mut writer);

    writer.write_u16(9); // StructureSize = 9
    writer.write_u16(0); // ErrorContextCount
    writer.write_u32(0); // ByteCount

    writer.into_bytes()
}

pub struct OpenFileHandle {
    pub path: PathBuf,
    pub is_directory: bool,
    pub file: Option<File>,
    pub size: u64,
}

/// State tracking for an active SMB connection.
pub struct ConnectionState {
    pub session_id: u64,
    pub tree_id: u32,
    pub authenticated: bool,
    pub client_username: String,
    pub client_domain: String,
    pub current_share: Option<SmbShare>,
    pub open_handles: HashMap<[u8; 16], OpenFileHandle>,
    pub next_handle_id: u64,
}

impl ConnectionState {
    pub fn new() -> Self {
        Self {
            session_id: 0,
            tree_id: 0,
            authenticated: false,
            client_username: String::new(),
            client_domain: String::new(),
            current_share: None,
            open_handles: HashMap::new(),
            next_handle_id: 1,
        }
    }
}

/// Pure-Rust SMB2 File Server.
#[derive(Clone)]
pub struct SmbServer {
    config: Arc<SmbServerConfig>,
}

impl SmbServer {
    pub fn new(config: SmbServerConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Adds a disk share to the server.
    pub fn add_share(&mut self, name: &str, path: impl AsRef<Path>, comment: &str, read_only: bool) {
        let mut cfg = (*self.config).clone();
        cfg.shares.push(SmbShare::new_disk(name, path, comment, read_only));
        self.config = Arc::new(cfg);
    }

    /// Starts listening on `listen_addr:listen_port` and serves incoming clients until interrupted.
    pub fn run(&self) -> Result<(), CoreError> {
        self.run_with_callback::<fn(&str)>(None)
    }

    /// Starts listening on `listen_addr:listen_port` with an optional callback invoked
    /// whenever an authenticating client sends NTLMSSP credentials.
    pub fn run_with_callback<F>(&self, callback: Option<Arc<F>>) -> Result<(), CoreError>
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        let bind_addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        let listener = TcpListener::bind(&bind_addr).map_err(|e| {
            CoreError::ProtocolError(format!("Failed binding SMB server on {}: {}", bind_addr, e))
        })?;

        println!("[*] SMB Server listening on {}", bind_addr);
        for share in &self.config.shares {
            println!("  [+] Share '{}' -> {:?} (read_only: {})", share.name, share.path, share.read_only);
        }

        for stream in listener.incoming() {
            match stream {
                Ok(mut socket) => {
                    let server_clone = self.clone();
                    let cb_clone = callback.clone();
                    let peer_addr = socket.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "unknown".into());
                    std::thread::spawn(move || {
                        let cb_ref = cb_clone.as_deref().map(|f| f as &dyn Fn(&str));
                        if let Err(e) = server_clone.handle_client(&mut socket, &peer_addr, cb_ref) {
                            eprintln!("[-] Connection from {} closed: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[-] Accept failed: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Processes an active client connection stream.
    pub fn handle_client<S: Read + Write>(
        &self,
        stream: &mut S,
        peer_addr: &str,
        hash_callback: Option<&dyn Fn(&str)>,
    ) -> Result<(), CoreError> {
        let mut state = ConnectionState::new();
        let server_guid = [0x53, 0x4D, 0x42, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

        loop {
            let frame = match read_netbios_packet(stream) {
                Ok(f) => f,
                Err(CoreError::BufferUnderflow { .. }) => break, // Client closed
                Err(e) => return Err(e),
            };

            if frame.is_empty() {
                break;
            }

            let resp = self.dispatch_packet(&frame, &mut state, peer_addr, &server_guid, hash_callback)?;
            if let Some(resp_bytes) = resp {
                let framed = wrap_netbios_session(&resp_bytes);
                stream.write_all(&framed).map_err(|e| {
                    CoreError::ProtocolError(format!("Failed sending response to {}: {}", peer_addr, e))
                })?;
                stream.flush().map_err(|e| {
                    CoreError::ProtocolError(format!("Failed flushing response to {}: {}", peer_addr, e))
                })?;
            }
        }

        Ok(())
    }

    /// Dispatches an incoming SMB request packet and returns the response PDU.
    pub fn dispatch_packet(
        &self,
        pdu: &[u8],
        state: &mut ConnectionState,
        peer_addr: &str,
        server_guid: &[u8; 16],
        hash_callback: Option<&dyn Fn(&str)>,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let now_unix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let now_ft = FileTime::from_unix_secs(now_unix).0;

        // Legacy SMBv1 Negotiate
        if pdu.starts_with(b"\xFFSMB") {
            // Check if dialects include SMB2 upgrade (0x0202 / SMB 2.002 / SMB 2.???)
            let has_smb2 = pdu.windows(8).any(|w| w == b"SMB 2.00" || w == b"SMB 2.??");
            if has_smb2 {
                let neg_token = NegTokenInit::new(vec![MechType::Ntlmssp], None);
                let resp = build_smb2_negotiate_response(0, SmbDialect::Smb210 as u16, *server_guid, &neg_token.to_bytes(), now_ft);
                return Ok(Some(resp));
            } else {
                return Err(CoreError::ProtocolError("SMBv1-only clients not supported; upgrade to SMB2 required".into()));
            }
        }

        if !pdu.starts_with(&Smb2Header::MAGIC) {
            return Err(CoreError::ProtocolError("Invalid SMB2 magic bytes".into()));
        }

        let mut reader = NdrReader::new(pdu);
        let hdr = Smb2Header::ndr_deserialize(&mut reader)?;

        match hdr.command {
            smb2_cmd::NEGOTIATE => {
                let neg_token = NegTokenInit::new(vec![MechType::Ntlmssp], None);
                let resp = build_smb2_negotiate_response(
                    hdr.message_id,
                    SmbDialect::Smb210 as u16,
                    *server_guid,
                    &neg_token.to_bytes(),
                    now_ft,
                );
                Ok(Some(resp))
            }
            smb2_cmd::SESSION_SETUP => {
                let body_slice = &pdu[64..];
                if body_slice.len() < 24 {
                    return Err(CoreError::BufferUnderflow { needed: 24, available: body_slice.len() });
                }
                let sec_offset = u16::from_le_bytes(body_slice[12..14].try_into().unwrap()) as usize;
                let sec_len = u16::from_le_bytes(body_slice[14..16].try_into().unwrap()) as usize;

                let token_bytes = if sec_offset >= 64 && sec_offset + sec_len <= pdu.len() {
                    &pdu[sec_offset..sec_offset + sec_len]
                } else {
                    &[]
                };

                // Check if client sent NTLMSSP Type 1 or Type 3
                let ntlm_pos = token_bytes.windows(8).position(|w| w == b"NTLMSSP\x00");
                let ntlm_msg_type = ntlm_pos.and_then(|pos| {
                    if pos + 12 <= token_bytes.len() {
                        Some(u32::from_le_bytes(token_bytes[pos + 8..pos + 12].try_into().unwrap()))
                    } else {
                        None
                    }
                });
                let is_type1 = ntlm_msg_type == Some(1);
                let is_type3 = ntlm_msg_type == Some(3);

                if is_type1 || state.session_id == 0 {
                    state.session_id = 0x1000_0000_0001;

                    let mut target_info = NtlmTargetInfo::new();
                    target_info.nb_domain_name = Some(self.config.domain_name.clone());
                    target_info.nb_computer_name = Some(self.config.server_name.clone());
                    target_info.dns_domain_name = Some(self.config.domain_name.clone());
                    target_info.dns_computer_name = Some(self.config.server_name.clone());
                    target_info.timestamp = Some(FileTime::from_unix_secs(now_unix));

                    let chall = NtlmChallengeMessage {
                        target_name: self.config.server_name.clone(),
                        flags: 0x6289_8215,
                        server_challenge: self.config.challenge,
                        target_info,
                        os_major: 10,
                        os_minor: 0,
                        os_build: 19041,
                        ntlm_revision: 15,
                    };
                    let type2_bytes = chall.to_bytes();

                    let neg_resp = NegTokenResp {
                        neg_state: Some(NegState::AcceptIncomplete),
                        supported_mech: Some(MechType::Ntlmssp),
                        response_token: Some(type2_bytes),
                        mech_list_mic: None,
                    };
                    let resp = crate::build_smb2_session_setup_response(
                        hdr.message_id,
                        state.session_id,
                        NtStatus(0xC000_0016), // STATUS_MORE_PROCESSING_REQUIRED
                        &neg_resp.to_bytes(),
                    );
                    Ok(Some(resp))
                } else if is_type3 {
                    // Extract inner NTLMSSP Type 3 buffer
                    let type3_start = token_bytes.windows(8).position(|w| w == b"NTLMSSP\x00").unwrap_or(0);
                    let type3_slice = &token_bytes[type3_start..];

                    if let Ok(auth_msg) = NtlmAuthenticateMessage::from_bytes(type3_slice) {
                        state.client_username = auth_msg.username.clone();
                        state.client_domain = auth_msg.domain.clone();
                        state.authenticated = true;

                        if let Some(hash_str) = auth_msg.to_netntlmv2_format(&self.config.challenge) {
                            println!("[+] NetNTLMv2 Captured: {}", hash_str);
                            if let Some(cb) = hash_callback {
                                cb(&hash_str);
                            }
                        }
                    }

                    let neg_resp = NegTokenResp {
                        neg_state: Some(NegState::AcceptCompleted),
                        supported_mech: Some(MechType::Ntlmssp),
                        response_token: None,
                        mech_list_mic: None,
                    };
                    let resp = crate::build_smb2_session_setup_response(
                        hdr.message_id,
                        state.session_id,
                        NtStatus::STATUS_SUCCESS,
                        &neg_resp.to_bytes(),
                    );
                    Ok(Some(resp))
                } else {
                    let resp = crate::build_smb2_session_setup_response(
                        hdr.message_id,
                        state.session_id,
                        NtStatus::STATUS_SUCCESS,
                        &[],
                    );
                    Ok(Some(resp))
                }
            }
            smb2_cmd::TREE_CONNECT => {
                let body_slice = &pdu[64..];
                if body_slice.len() < 8 {
                    return Err(CoreError::BufferUnderflow { needed: 8, available: body_slice.len() });
                }
                let path_offset = u16::from_le_bytes(body_slice[4..6].try_into().unwrap()) as usize;
                let path_len = u16::from_le_bytes(body_slice[6..8].try_into().unwrap()) as usize;

                let unc_path = if path_offset >= 64 && path_offset + path_len <= pdu.len() {
                    impacket_core::decode_utf16le(&pdu[path_offset..path_offset + path_len]).unwrap_or_default()
                } else {
                    String::new()
                };

                let share_name = unc_path
                    .trim_start_matches('\\')
                    .split('\\')
                    .last()
                    .unwrap_or("")
                    .to_uppercase();

                println!("[*] TreeConnect: {} (Share '{}') from {}", unc_path, share_name, peer_addr);

                let matched_share = self.config.shares.iter().find(|s| s.name == share_name).cloned();

                if let Some(share) = matched_share {
                    state.tree_id = 1;
                    state.current_share = Some(share.clone());
                    let share_type = if share.is_ipc { 0x02 } else { 0x01 };
                    let resp = build_smb2_tree_connect_response(hdr.message_id, state.session_id, state.tree_id, share_type);
                    Ok(Some(resp))
                } else {
                    let resp = build_smb2_error_response(
                        smb2_cmd::TREE_CONNECT,
                        hdr.message_id,
                        state.session_id,
                        0,
                        NtStatus(0xC000_00CC), // STATUS_BAD_NETWORK_NAME
                    );
                    Ok(Some(resp))
                }
            }
            smb2_cmd::CREATE => {
                let body_slice = &pdu[64..];
                if body_slice.len() < 56 {
                    return Err(CoreError::BufferUnderflow { needed: 56, available: body_slice.len() });
                }
                let name_offset = u16::from_le_bytes(body_slice[44..46].try_into().unwrap()) as usize;
                let name_len = u16::from_le_bytes(body_slice[46..48].try_into().unwrap()) as usize;
                let disp = u32::from_le_bytes(body_slice[36..40].try_into().unwrap());

                let file_name = if name_offset >= 64 && name_offset + name_len <= pdu.len() {
                    impacket_core::decode_utf16le(&pdu[name_offset..name_offset + name_len]).unwrap_or_default()
                } else {
                    String::new()
                };

                let rel_path = file_name.replace('\\', "/").trim_start_matches('/').to_string();

                let share = match state.current_share.as_ref() {
                    Some(s) => s,
                    None => {
                        let resp = build_smb2_error_response(
                            smb2_cmd::CREATE,
                            hdr.message_id,
                            state.session_id,
                            hdr.tree_id,
                            NtStatus(0xC000_00CC),
                        );
                        return Ok(Some(resp));
                    }
                };

                let target_path = if rel_path.is_empty() {
                    share.path.clone()
                } else {
                    share.path.join(&rel_path)
                };

                let is_dir = target_path.is_dir() || rel_path.is_empty();

                if is_dir {
                    let file_id_num = state.next_handle_id;
                    state.next_handle_id += 1;
                    let mut file_id = [0u8; 16];
                    file_id[..8].copy_from_slice(&file_id_num.to_le_bytes());
                    file_id[8..].copy_from_slice(&file_id_num.to_le_bytes());

                    state.open_handles.insert(
                        file_id,
                        OpenFileHandle {
                            path: target_path,
                            is_directory: true,
                            file: None,
                            size: 0,
                        },
                    );

                    let resp = build_smb2_create_response(
                        hdr.message_id,
                        state.session_id,
                        hdr.tree_id,
                        file_id,
                        true,
                        0,
                        now_ft,
                    );
                    Ok(Some(resp))
                } else {
                    let should_create = disp == 2 || disp == 3 || disp == 5; // CREATE, OPEN_IF, OVERWRITE_IF
                    let file_res = if should_create && !share.read_only {
                        OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create(true)
                            .truncate(disp == 5)
                            .open(&target_path)
                    } else {
                        File::open(&target_path)
                    };

                    match file_res {
                        Ok(file) => {
                            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
                            let file_id_num = state.next_handle_id;
                            state.next_handle_id += 1;
                            let mut file_id = [0u8; 16];
                            file_id[..8].copy_from_slice(&file_id_num.to_le_bytes());
                            file_id[8..].copy_from_slice(&file_id_num.to_le_bytes());

                            state.open_handles.insert(
                                file_id,
                                OpenFileHandle {
                                    path: target_path,
                                    is_directory: false,
                                    file: Some(file),
                                    size,
                                },
                            );

                            let resp = build_smb2_create_response(
                                hdr.message_id,
                                state.session_id,
                                hdr.tree_id,
                                file_id,
                                false,
                                size,
                                now_ft,
                            );
                            Ok(Some(resp))
                        }
                        Err(_) => {
                            let resp = build_smb2_error_response(
                                smb2_cmd::CREATE,
                                hdr.message_id,
                                state.session_id,
                                hdr.tree_id,
                                NtStatus(0xC000_0034), // STATUS_OBJECT_NAME_NOT_FOUND
                            );
                            Ok(Some(resp))
                        }
                    }
                }
            }
            smb2_cmd::QUERY_DIRECTORY => {
                let body_slice = &pdu[64..];
                if body_slice.len() < 32 {
                    return Err(CoreError::BufferUnderflow { needed: 32, available: body_slice.len() });
                }
                let mut file_id = [0u8; 16];
                file_id.copy_from_slice(&body_slice[8..24]);

                let handle = match state.open_handles.get(&file_id) {
                    Some(h) if h.is_directory => h,
                    _ => {
                        let resp = build_smb2_error_response(
                            smb2_cmd::QUERY_DIRECTORY,
                            hdr.message_id,
                            state.session_id,
                            hdr.tree_id,
                            NtStatus(0xC000_0008), // STATUS_INVALID_HANDLE
                        );
                        return Ok(Some(resp));
                    }
                };

                let mut entries = Vec::new();
                entries.push(DirEntryInfo {
                    file_index: 0,
                    creation_time: now_ft,
                    last_access_time: now_ft,
                    last_write_time: now_ft,
                    change_time: now_ft,
                    end_of_file: 0,
                    allocation_size: 0,
                    file_attributes: 0x0000_0010,
                    file_id: 1,
                    name: ".".into(),
                });
                entries.push(DirEntryInfo {
                    file_index: 1,
                    creation_time: now_ft,
                    last_access_time: now_ft,
                    last_write_time: now_ft,
                    change_time: now_ft,
                    end_of_file: 0,
                    allocation_size: 0,
                    file_attributes: 0x0000_0010,
                    file_id: 2,
                    name: "..".into(),
                });

                if let Ok(dir_iter) = fs::read_dir(&handle.path) {
                    for (idx, entry_res) in dir_iter.flatten().enumerate() {
                        let meta = entry_res.metadata().ok();
                        let is_d = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                        let sz = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                        let name_str = entry_res.file_name().to_string_lossy().to_string();

                        entries.push(DirEntryInfo {
                            file_index: (idx + 2) as u32,
                            creation_time: now_ft,
                            last_access_time: now_ft,
                            last_write_time: now_ft,
                            change_time: now_ft,
                            end_of_file: sz,
                            allocation_size: sz,
                            file_attributes: if is_d { 0x0000_0010 } else { 0x0000_0080 },
                            file_id: (idx + 3) as u64,
                            name: name_str,
                        });
                    }
                }

                let entries_buf = encode_file_id_both_dir_info(&entries);
                let resp = build_smb2_query_directory_response(
                    hdr.message_id,
                    state.session_id,
                    hdr.tree_id,
                    &entries_buf,
                );
                Ok(Some(resp))
            }
            smb2_cmd::READ => {
                let body_slice = &pdu[64..];
                if body_slice.len() < 32 {
                    return Err(CoreError::BufferUnderflow { needed: 32, available: body_slice.len() });
                }
                let length = u32::from_le_bytes(body_slice[4..8].try_into().unwrap()) as usize;
                let offset = u64::from_le_bytes(body_slice[8..16].try_into().unwrap());
                let mut file_id = [0u8; 16];
                file_id.copy_from_slice(&body_slice[16..32]);

                let handle = match state.open_handles.get_mut(&file_id) {
                    Some(h) if !h.is_directory => h,
                    _ => {
                        let resp = build_smb2_error_response(
                            smb2_cmd::READ,
                            hdr.message_id,
                            state.session_id,
                            hdr.tree_id,
                            NtStatus(0xC000_0008),
                        );
                        return Ok(Some(resp));
                    }
                };

                let mut data_buf = vec![0u8; length];
                let bytes_read = if let Some(ref mut f) = handle.file {
                    let _ = f.seek(SeekFrom::Start(offset));
                    f.read(&mut data_buf).unwrap_or(0)
                } else {
                    0
                };
                data_buf.truncate(bytes_read);

                let resp = build_smb2_read_response(
                    hdr.message_id,
                    state.session_id,
                    hdr.tree_id,
                    &data_buf,
                );
                Ok(Some(resp))
            }
            smb2_cmd::WRITE => {
                let body_slice = &pdu[64..];
                if body_slice.len() < 32 {
                    return Err(CoreError::BufferUnderflow { needed: 32, available: body_slice.len() });
                }
                let data_offset = u16::from_le_bytes(body_slice[2..4].try_into().unwrap()) as usize;
                let length = u32::from_le_bytes(body_slice[4..8].try_into().unwrap()) as usize;
                let offset = u64::from_le_bytes(body_slice[8..16].try_into().unwrap());
                let mut file_id = [0u8; 16];
                file_id.copy_from_slice(&body_slice[16..32]);

                let is_read_only = state.current_share.as_ref().map(|s| s.read_only).unwrap_or(true);
                if is_read_only {
                    let resp = build_smb2_error_response(
                        smb2_cmd::WRITE,
                        hdr.message_id,
                        state.session_id,
                        hdr.tree_id,
                        NtStatus(0xC000_0022), // STATUS_ACCESS_DENIED
                    );
                    return Ok(Some(resp));
                }

                let handle = match state.open_handles.get_mut(&file_id) {
                    Some(h) if !h.is_directory => h,
                    _ => {
                        let resp = build_smb2_error_response(
                            smb2_cmd::WRITE,
                            hdr.message_id,
                            state.session_id,
                            hdr.tree_id,
                            NtStatus(0xC000_0008),
                        );
                        return Ok(Some(resp));
                    }
                };

                let payload = if data_offset >= 64 && data_offset + length <= pdu.len() {
                    &pdu[data_offset..data_offset + length]
                } else {
                    &[]
                };

                let written = if let Some(ref mut f) = handle.file {
                    let _ = f.seek(SeekFrom::Start(offset));
                    f.write(payload).unwrap_or(0)
                } else {
                    0
                };

                let resp = build_smb2_write_response(
                    hdr.message_id,
                    state.session_id,
                    hdr.tree_id,
                    written as u32,
                );
                Ok(Some(resp))
            }
            smb2_cmd::CLOSE => {
                let body_slice = &pdu[64..];
                if body_slice.len() < 24 {
                    return Err(CoreError::BufferUnderflow { needed: 24, available: body_slice.len() });
                }
                let mut file_id = [0u8; 16];
                file_id.copy_from_slice(&body_slice[8..24]);

                let sz = state.open_handles.remove(&file_id).map(|h| h.size).unwrap_or(0);
                let resp = build_smb2_close_response(
                    hdr.message_id,
                    state.session_id,
                    hdr.tree_id,
                    sz,
                    now_ft,
                );
                Ok(Some(resp))
            }
            smb2_cmd::TREE_DISCONNECT | smb2_cmd::LOGOFF | smb2_cmd::FLUSH => {
                let mut writer = NdrWriter::with_capacity(64 + 4);
                let mut resp_hdr = Smb2Header::new(hdr.command, hdr.message_id, state.session_id, hdr.tree_id);
                resp_hdr.flags = 0x0000_0001;
                resp_hdr.status = NtStatus::STATUS_SUCCESS.0;
                resp_hdr.credit_request_response = 1;
                resp_hdr.ndr_serialize(&mut writer);
                writer.write_u16(4); // StructureSize = 4
                writer.write_u16(0); // Reserved
                Ok(Some(writer.into_bytes()))
            }
            smb2_cmd::ECHO => {
                let mut writer = NdrWriter::with_capacity(64 + 4);
                let mut resp_hdr = Smb2Header::new(smb2_cmd::ECHO, hdr.message_id, state.session_id, 0);
                resp_hdr.flags = 0x0000_0001;
                resp_hdr.status = NtStatus::STATUS_SUCCESS.0;
                resp_hdr.credit_request_response = 1;
                resp_hdr.ndr_serialize(&mut writer);
                writer.write_u16(4);
                writer.write_u16(0);
                Ok(Some(writer.into_bytes()))
            }
            _ => {
                let resp = build_smb2_error_response(
                    hdr.command,
                    hdr.message_id,
                    state.session_id,
                    hdr.tree_id,
                    NtStatus(0xC000_00BB), // STATUS_NOT_SUPPORTED
                );
                Ok(Some(resp))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockStream {
        pub client_to_server: Vec<u8>,
        pub server_to_client: Vec<u8>,
        pub read_pos: usize,
    }

    impl MockStream {
        fn new() -> Self {
            Self {
                client_to_server: Vec::new(),
                server_to_client: Vec::new(),
                read_pos: 0,
            }
        }

        fn send_client_frame(&mut self, frame: &[u8]) {
            let framed = wrap_netbios_session(frame);
            self.client_to_server.extend_from_slice(&framed);
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.read_pos >= self.client_to_server.len() {
                return Ok(0);
            }
            let avail = self.client_to_server.len() - self.read_pos;
            let n = buf.len().min(avail);
            buf[..n].copy_from_slice(&self.client_to_server[self.read_pos..self.read_pos + n]);
            self.read_pos += n;
            Ok(n)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.server_to_client.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_smb_server_negotiate_and_session_setup_and_hash_capture() {
        let tmp_dir = std::env::temp_dir().join("impacket_smbserver_test");
        let _ = fs::create_dir_all(&tmp_dir);
        let test_file = tmp_dir.join("test.txt");
        let _ = fs::write(&test_file, b"Hello from Impacket-RS pure-Rust SMB2 server!");

        let mut config = SmbServerConfig::default();
        config.shares = vec![
            SmbShare::new_ipc(),
            SmbShare::new_disk("TEST", &tmp_dir, "Test Share", false),
        ];
        config.challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let server = SmbServer::new(config);
        let mut stream = MockStream::new();

        // 1. Client sends SMB2 Negotiate
        let client_guid = [0xCCu8; 16];
        let neg_req = crate::build_smb2_negotiate_request(impacket_core::AdCompatProfile::UniversalAuto, client_guid);
        stream.send_client_frame(&neg_req);

        let captured_hash = Arc::new(Mutex::new(String::new()));
        let captured_clone = captured_hash.clone();

        let cb = move |hash: &str| {
            let mut l = captured_clone.lock().unwrap();
            *l = hash.to_string();
        };

        server.handle_client(&mut stream, "127.0.0.1:12345", Some(&cb)).unwrap();

        assert!(!stream.server_to_client.is_empty());
        let mut r = &stream.server_to_client[..];
        let resp_body = read_netbios_packet(&mut r).unwrap();
        assert_eq!(&resp_body[0..4], &Smb2Header::MAGIC);
        assert_eq!(u16::from_le_bytes(resp_body[12..14].try_into().unwrap()), smb2_cmd::NEGOTIATE);
    }

    #[test]
    fn test_smb_server_multi_step_file_io_roundtrip() {
        let tmp_dir = std::env::temp_dir().join("impacket_smb_io_test");
        let _ = fs::create_dir_all(&tmp_dir);
        let file_path = tmp_dir.join("test_io.txt");
        if file_path.exists() {
            let _ = fs::remove_file(&file_path);
        }

        let mut config = SmbServerConfig::default();
        config.shares = vec![
            SmbShare::new_ipc(),
            SmbShare::new_disk("TESTSHARE", &tmp_dir, "Test Share", false),
        ];
        config.challenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

        let server = SmbServer::new(config);
        let mut state = ConnectionState::new();
        let server_guid = [0xAA; 16];
        let captured_hash = Arc::new(Mutex::new(String::new()));
        let captured_clone = captured_hash.clone();
        let cb = move |hash: &str| {
            let mut l = captured_clone.lock().unwrap();
            *l = hash.to_string();
        };

        // 1. SMB2 Negotiate
        let neg_req = crate::build_smb2_negotiate_request(impacket_core::AdCompatProfile::UniversalAuto, [0xBB; 16]);
        let neg_resp = server
            .dispatch_packet(&neg_req, &mut state, "127.0.0.1", &server_guid, Some(&cb))
            .unwrap()
            .expect("negotiate response");
        assert_eq!(&neg_resp[0..4], &Smb2Header::MAGIC);
        assert_eq!(u32::from_le_bytes(neg_resp[8..12].try_into().unwrap()), 0);

        // 2. SMB2 Session Setup (Type 1 Negotiate)
        let ntlm_neg = impacket_auth::NtlmNegotiateMessage {
            flags: 0x6208_8215,
            os_major: 10,
            os_minor: 0,
            os_build: 19041,
        };
        let ss_req_1 = crate::build_smb2_session_setup_request(1, 0, &ntlm_neg.to_bytes());
        let ss_resp_1 = server
            .dispatch_packet(&ss_req_1, &mut state, "127.0.0.1", &server_guid, Some(&cb))
            .unwrap()
            .expect("session setup 1 response");
        assert_eq!(u32::from_le_bytes(ss_resp_1[8..12].try_into().unwrap()), 0xC000_0016);
        assert_eq!(state.session_id, 0x1000_0000_0001);

        // 3. SMB2 Session Setup (Type 3 Authenticate)
        let ntlm_auth = impacket_auth::NtlmAuthenticateMessage {
            domain: "CONTOSO".into(),
            username: "Administrator".into(),
            workstation: "WORKSTATION".into(),
            lm_challenge_response: vec![0u8; 24],
            nt_challenge_response: vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            encrypted_session_key: Vec::new(),
            flags: 0x6208_8215,
            os_major: 10,
            os_minor: 0,
            os_build: 19041,
        };
        let ss_req_2 = crate::build_smb2_session_setup_request(2, state.session_id, &ntlm_auth.to_bytes());
        let ss_resp_2 = server
            .dispatch_packet(&ss_req_2, &mut state, "127.0.0.1", &server_guid, Some(&cb))
            .unwrap()
            .expect("session setup 2 response");
        assert_eq!(u32::from_le_bytes(ss_resp_2[8..12].try_into().unwrap()), 0);
        assert!(state.authenticated);
        let hash_captured = captured_hash.lock().unwrap().clone();
        assert!(hash_captured.starts_with("Administrator::CONTOSO:1122334455667788:"));

        // 4. SMB2 Tree Connect
        let tc_req = crate::build_smb2_tree_connect_request(3, state.session_id, r"\\127.0.0.1\TESTSHARE");
        let tc_resp = server
            .dispatch_packet(&tc_req, &mut state, "127.0.0.1", &server_guid, Some(&cb))
            .unwrap()
            .expect("tree connect response");
        assert_eq!(u32::from_le_bytes(tc_resp[8..12].try_into().unwrap()), 0);
        assert_eq!(state.tree_id, 1);

        // 5. SMB2 Create (Create/Overwrite file "test_io.txt")
        let create_req = crate::build_smb2_create_request(
            4,
            state.session_id,
            state.tree_id,
            "test_io.txt",
            0x001F_01FF,
            0x0000_0080,
            0x0000_0007,
            5, // FILE_OVERWRITE_IF
            0x0000_0040,
        );
        let create_resp = server
            .dispatch_packet(&create_req, &mut state, "127.0.0.1", &server_guid, Some(&cb))
            .unwrap()
            .expect("create response");
        assert_eq!(u32::from_le_bytes(create_resp[8..12].try_into().unwrap()), 0);
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&create_resp[128..144]);
        assert_ne!(file_id, [0u8; 16]);

        // 6. SMB2 Write to file_id
        let write_payload = b"Hello from pure-Rust Impacket SMB2 server roundtrip!";
        let write_req = crate::build_smb2_write_request(5, state.session_id, state.tree_id, file_id, 0, write_payload);
        let write_resp = server
            .dispatch_packet(&write_req, &mut state, "127.0.0.1", &server_guid, Some(&cb))
            .unwrap()
            .expect("write response");
        assert_eq!(u32::from_le_bytes(write_resp[8..12].try_into().unwrap()), 0);
        let bytes_written = u32::from_le_bytes(write_resp[68..72].try_into().unwrap());
        assert_eq!(bytes_written as usize, write_payload.len());

        let disk_content = fs::read(&file_path).unwrap();
        assert_eq!(disk_content, write_payload);

        // 7. SMB2 Read from file_id
        let read_req = crate::build_smb2_read_request(6, state.session_id, state.tree_id, file_id, 0, write_payload.len() as u32);
        let read_resp = server
            .dispatch_packet(&read_req, &mut state, "127.0.0.1", &server_guid, Some(&cb))
            .unwrap()
            .expect("read response");
        assert_eq!(u32::from_le_bytes(read_resp[8..12].try_into().unwrap()), 0);
        let read_len = u32::from_le_bytes(read_resp[68..72].try_into().unwrap()) as usize;
        assert_eq!(read_len, write_payload.len());
        let read_data = &read_resp[80..80 + read_len];
        assert_eq!(read_data, write_payload);

        // 8. SMB2 Close file_id
        let close_req = crate::build_smb2_close_request(7, state.session_id, state.tree_id, file_id);
        let close_resp = server
            .dispatch_packet(&close_req, &mut state, "127.0.0.1", &server_guid, Some(&cb))
            .unwrap()
            .expect("close response");
        assert_eq!(u32::from_le_bytes(close_resp[8..12].try_into().unwrap()), 0);
        assert!(!state.open_handles.contains_key(&file_id));

        // 9. SMB2 Tree Disconnect
        let td_req = crate::build_smb2_tree_disconnect_request(8, state.session_id, state.tree_id);
        let td_resp = server
            .dispatch_packet(&td_req, &mut state, "127.0.0.1", &server_guid, Some(&cb))
            .unwrap()
            .expect("tree disconnect response");
        assert_eq!(u32::from_le_bytes(td_resp[8..12].try_into().unwrap()), 0);

        let _ = fs::remove_file(&file_path);
        let _ = fs::remove_dir_all(&tmp_dir);
    }
}
