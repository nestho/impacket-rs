//! `client`: Microsoft SQL Server Tabular Data Stream (`[MS-TDS]`) client engine.
//!
//! Provides SQL authentication and Windows Integrated Authentication (NTLM/SSPI),
//! SQL batch query execution, and administrative automation (`xp_cmdshell`).

use impacket_auth::{
    compute_ntlm_hashes_with_compat, compute_ntlmv2_response, ntlm_flags,
    NtlmAuthenticateMessage, NtlmChallengeMessage, NtlmNegotiateMessage,
};
use impacket_core::{encode_utf16le, AdCompatProfile, CoreError, FileTime, NtlmHashes};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::login::{build_login7_payload, Login7Params};
use crate::packet::{packet_type, read_full_tds_message, write_tds_message, DEFAULT_PACKET_SIZE};
use crate::prelogin::{build_prelogin_request, encrypt_mode, parse_prelogin_response, PreloginResponse};
use crate::tokens::{parse_tds_tokens, ColumnMetadata, MssqlError, MssqlRow, TdsToken};

/// Result of executing a SQL batch query.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryResult {
    pub columns: Vec<ColumnMetadata>,
    pub rows: Vec<MssqlRow>,
    pub messages: Vec<String>,
    pub errors: Vec<MssqlError>,
    pub rows_affected: u64,
}

/// TDS 7.2+ `ALL_HEADERS` descriptor (22 bytes) for standalone SQL batches without outer transaction.
const TDS72_ALL_HEADERS: [u8; 22] = [
    0x16, 0x00, 0x00, 0x00, // TotalLength = 22
    0x12, 0x00, 0x00, 0x00, // HeaderLength = 18
    0x02, 0x00,             // HeaderType = 2 (Transaction Descriptor)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // TransactionID = 0
    0x01, 0x00, 0x00, 0x00, // OutstandingRequestCount = 1
];

/// Microsoft SQL Server TDS client.
pub struct MssqlClient<S = TcpStream> {
    stream: S,
    packet_size: usize,
    pub server_name: String,
    pub database: String,
    pub server_version: Option<String>,
}

impl MssqlClient<TcpStream> {
    /// Connects to Microsoft SQL Server at `addr` (e.g. `"192.168.1.100:1433"` or `"192.168.1.100"`).
    pub fn connect(addr: &str) -> Result<Self, CoreError> {
        let full_addr = if addr.contains(':') {
            addr.to_string()
        } else {
            format!("{}:1433", addr)
        };
        let stream = TcpStream::connect(&full_addr).map_err(|e| {
            CoreError::IoError(format!("Failed connecting to MSSQL at {}: {}", full_addr, e))
        })?;
        stream.set_read_timeout(Some(Duration::from_secs(15))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(15))).ok();

        let host = full_addr.split(':').next().unwrap_or("MSSQL").to_string();
        Self::connect_with_stream(stream, &host)
    }
}

impl<S: Read + Write> MssqlClient<S> {
    /// Creates a client using an existing stream (e.g. TCP stream or test stream) and executes PRELOGIN.
    pub fn connect_with_stream(mut stream: S, host: &str) -> Result<Self, CoreError> {
        let _prelogin = Self::do_prelogin(&mut stream)?;
        Ok(Self {
            stream,
            packet_size: DEFAULT_PACKET_SIZE,
            server_name: host.to_string(),
            database: "master".to_string(),
            server_version: None,
        })
    }

    /// Performs the initial TDS `PRELOGIN` handshake.
    fn do_prelogin(stream: &mut S) -> Result<PreloginResponse, CoreError> {
        let req = build_prelogin_request(encrypt_mode::ENCRYPT_NOT_SUP);
        write_tds_message(stream, packet_type::PRE_LOGIN, &req, DEFAULT_PACKET_SIZE)?;

        let (_ptype, resp_bytes) = read_full_tds_message(stream)?;
        parse_prelogin_response(&resp_bytes)
    }

    /// Authenticates using standard SQL Server Authentication.
    pub fn login_sql(&mut self, user: &str, password: &str, database: &str) -> Result<(), CoreError> {
        let target_db = if database.is_empty() { "master" } else { database };
        let params = Login7Params {
            host_name: "WORKSTATION",
            user_name: user,
            password,
            app_name: "impacket-rs",
            server_name: &self.server_name,
            database: target_db,
            sspi_negotiate_bytes: None,
            desired_packet_size: self.packet_size as u32,
        };

        let payload = build_login7_payload(&params);
        write_tds_message(&mut self.stream, packet_type::TDS7_LOGIN, &payload, self.packet_size)?;

        let (_ptype, resp_bytes) = read_full_tds_message(&mut self.stream)?;
        let tokens = parse_tds_tokens(&resp_bytes)?;

        self.process_login_tokens(&tokens, target_db)
    }

    /// Authenticates using Windows Integrated Authentication (SSPI / NTLMv2).
    pub fn login_windows(
        &mut self,
        domain: &str,
        user: &str,
        password: &str,
        hashes: Option<&NtlmHashes>,
        database: &str,
    ) -> Result<(), CoreError> {
        let target_db = if database.is_empty() { "master" } else { database };

        // 1. Build NTLMSSP Type 1 Negotiate message
        let negotiate = NtlmNegotiateMessage::for_profile(AdCompatProfile::UniversalAuto);
        let type1_bytes = negotiate.to_bytes();

        let params = Login7Params {
            host_name: "WORKSTATION",
            user_name: user,
            password: "",
            app_name: "impacket-rs",
            server_name: &self.server_name,
            database: target_db,
            sspi_negotiate_bytes: Some(&type1_bytes),
            desired_packet_size: self.packet_size as u32,
        };

        let payload = build_login7_payload(&params);
        write_tds_message(&mut self.stream, packet_type::TDS7_LOGIN, &payload, self.packet_size)?;

        // 2. Read NTLMSSP Type 2 Challenge from server SSPI token
        let (_ptype, resp_bytes) = read_full_tds_message(&mut self.stream)?;
        let tokens = parse_tds_tokens(&resp_bytes)?;

        let mut challenge_bytes: Option<Vec<u8>> = None;
        for token in &tokens {
            if let TdsToken::Sspi(bytes) = token {
                challenge_bytes = Some(bytes.clone());
                break;
            } else if let TdsToken::Error(err) = token {
                return Err(CoreError::ProtocolError(format!(
                    "MSSQL login error {}: {}",
                    err.number, err.message
                )));
            }
        }

        let challenge_raw = challenge_bytes.ok_or_else(|| {
            CoreError::ProtocolError("Server did not return SSPI challenge token".into())
        })?;

        let challenge = NtlmChallengeMessage::from_bytes(&challenge_raw)?;

        // 3. Compute NTLMv2 response
        let user_hashes = match hashes {
            Some(h) => h.clone(),
            None => compute_ntlm_hashes_with_compat(password, false),
        };

        let client_challenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let timestamp = challenge
            .target_info
            .timestamp
            .unwrap_or_else(|| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                FileTime::from_unix_secs(now)
            });

        let ti_bytes = challenge.target_info.to_bytes();
        let computed = compute_ntlmv2_response(
            user,
            domain,
            &user_hashes,
            &challenge.server_challenge,
            &client_challenge,
            timestamp,
            &ti_bytes,
        );

        let auth_msg = NtlmAuthenticateMessage {
            domain: domain.to_string(),
            username: user.to_string(),
            workstation: "WORKSTATION".to_string(),
            lm_challenge_response: computed.lm_challenge_response,
            nt_challenge_response: computed.nt_challenge_response,
            encrypted_session_key: Vec::new(),
            flags: challenge.flags & !ntlm_flags::NTLMSSP_NEGOTIATE_KEY_EXCH,
            os_major: 10,
            os_minor: 0,
            os_build: 19041,
        };

        let type3_bytes = auth_msg.to_bytes();

        // 4. Send SSPI token in TDS SSPI_MESSAGE packet (17)
        write_tds_message(
            &mut self.stream,
            packet_type::SSPI_MESSAGE,
            &type3_bytes,
            self.packet_size,
        )?;

        // 5. Read authentication confirmation
        let (_ptype3, resp_bytes3) = read_full_tds_message(&mut self.stream)?;
        let tokens3 = parse_tds_tokens(&resp_bytes3)?;

        self.process_login_tokens(&tokens3, target_db)
    }

    fn process_login_tokens(&mut self, tokens: &[TdsToken], target_db: &str) -> Result<(), CoreError> {
        let mut login_ack = false;
        let mut err_msg = None;

        for token in tokens {
            match token {
                TdsToken::LoginAck(ack) => {
                    login_ack = true;
                    self.server_version = Some(format!(
                        "{} (Major {}, Minor {})",
                        ack.prog_name, ack.major, ack.minor
                    ));
                }
                TdsToken::EnvChange { env_type, new_val, .. } => {
                    if *env_type == 1 {
                        // Database context changed
                        self.database = new_val.clone();
                    }
                }
                TdsToken::Error(err) => {
                    err_msg = Some(format!("Error {}: {}", err.number, err.message));
                }
                _ => {}
            }
        }

        if login_ack {
            if self.database.is_empty() {
                self.database = target_db.to_string();
            }
            Ok(())
        } else if let Some(msg) = err_msg {
            Err(CoreError::ProtocolError(msg))
        } else {
            Err(CoreError::ProtocolError(
                "MSSQL login failed: no LOGINACK received".into(),
            ))
        }
    }

    /// Executes a SQL batch query and returns columns, rows, info messages, and affected row count.
    pub fn query(&mut self, sql: &str) -> Result<QueryResult, CoreError> {
        let mut payload = Vec::with_capacity(22 + sql.len() * 2);
        payload.extend_from_slice(&TDS72_ALL_HEADERS);
        payload.extend_from_slice(&encode_utf16le(sql));

        write_tds_message(&mut self.stream, packet_type::SQL_BATCH, &payload, self.packet_size)?;

        let (_ptype, resp_bytes) = read_full_tds_message(&mut self.stream)?;
        let tokens = parse_tds_tokens(&resp_bytes)?;

        let mut res = QueryResult::default();
        for token in tokens {
            match token {
                TdsToken::ColMetadata(cols) => {
                    res.columns = cols;
                }
                TdsToken::Row(row) => {
                    res.rows.push(row);
                }
                TdsToken::Info(msg) => {
                    res.messages.push(msg);
                }
                TdsToken::Error(err) => {
                    res.errors.push(err);
                }
                TdsToken::Done { row_count, .. } => {
                    res.rows_affected = row_count;
                }
                _ => {}
            }
        }

        if !res.errors.is_empty() && res.rows.is_empty() {
            let first = &res.errors[0];
            return Err(CoreError::ProtocolError(format!(
                "SQL Server Error {}: {}",
                first.number, first.message
            )));
        }

        Ok(res)
    }

    /// Executes a SQL statement that produces no rows, returning rows affected.
    pub fn execute(&mut self, sql: &str) -> Result<u64, CoreError> {
        let res = self.query(sql)?;
        Ok(res.rows_affected)
    }

    /// Switches the active database catalog using `USE [database]`.
    pub fn use_database(&mut self, db: &str) -> Result<(), CoreError> {
        let sql = format!("USE [{}]", db.replace(']', "]]"));
        self.execute(&sql)?;
        self.database = db.to_string();
        Ok(())
    }

    /// Enables `xp_cmdshell` by configuring `show advanced options` and `xp_cmdshell`.
    pub fn enable_xp_cmdshell(&mut self) -> Result<(), CoreError> {
        let sql = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
        self.query(sql)?;
        Ok(())
    }

    /// Disables `xp_cmdshell` by configuring `xp_cmdshell` and `show advanced options` to 0.
    pub fn disable_xp_cmdshell(&mut self) -> Result<(), CoreError> {
        let sql = "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE; EXEC sp_configure 'show advanced options', 0; RECONFIGURE;";
        self.query(sql)?;
        Ok(())
    }

    /// Executes an operating system command via `xp_cmdshell` and captures output lines.
    pub fn xp_cmdshell(&mut self, cmd: &str) -> Result<Vec<String>, CoreError> {
        let escaped = cmd.replace('\'', "''");
        let sql = format!("EXEC master..xp_cmdshell '{}'", escaped);
        let res = self.query(&sql)?;

        let mut lines = Vec::new();
        for row in res.rows {
            if let Some(Some(val)) = row.values.into_iter().next() {
                lines.push(val);
            }
        }

        // Also append any PRINT/INFO messages returned
        for msg in res.messages {
            lines.push(msg);
        }

        Ok(lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{packet_status, TdsHeader};
    use crate::prelogin::prelogin_token;
    use crate::tokens::token_id;

    /// Mock in-memory duplex stream for deterministic TDS unit testing.
    struct MockStream {
        read_data: Vec<u8>,
        read_pos: usize,
        written: Vec<u8>,
    }

    impl MockStream {
        fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_data,
                read_pos: 0,
                written: Vec::new(),
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.read_pos >= self.read_data.len() {
                return Ok(0);
            }
            let avail = &self.read_data[self.read_pos..];
            let to_copy = avail.len().min(buf.len());
            buf[..to_copy].copy_from_slice(&avail[..to_copy]);
            self.read_pos += to_copy;
            Ok(to_copy)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn frame_tds_packet(ptype: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = (8 + payload.len()) as u16;
        let hdr = TdsHeader::new(ptype, packet_status::EOM, total_len, 1);
        let mut out = hdr.to_bytes().to_vec();
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn test_prelogin_handshake() {
        // Build mock PRELOGIN response: VERSION (6 bytes) + ENCRYPTION (1 byte = NOT_SUP) + TERMINATOR
        let mut prelogin_resp_payload = Vec::new();
        // offset table: 2 options * 5 bytes + 1 terminator = 11 bytes base
        // Option 0: VERSION (offset 11, len 6)
        prelogin_resp_payload.push(prelogin_token::VERSION);
        prelogin_resp_payload.extend_from_slice(&11u16.to_be_bytes());
        prelogin_resp_payload.extend_from_slice(&6u16.to_be_bytes());
        // Option 1: ENCRYPTION (offset 17, len 1)
        prelogin_resp_payload.push(prelogin_token::ENCRYPTION);
        prelogin_resp_payload.extend_from_slice(&17u16.to_be_bytes());
        prelogin_resp_payload.extend_from_slice(&1u16.to_be_bytes());
        // Terminator
        prelogin_resp_payload.push(prelogin_token::TERMINATOR);
        // Option data
        prelogin_resp_payload.extend_from_slice(&[15, 0, 0x07, 0xD0, 0, 0]); // v15.0.2000.0
        prelogin_resp_payload.push(encrypt_mode::ENCRYPT_NOT_SUP);

        let packet = frame_tds_packet(packet_type::TABULAR_RESULT, &prelogin_resp_payload);
        let stream = MockStream::new(packet);

        let client = MssqlClient::connect_with_stream(stream, "10.0.0.1").unwrap();
        assert_eq!(client.server_name, "10.0.0.1");
        assert_eq!(client.database, "master");
    }

    #[test]
    fn test_query_execution() {
        // Mock query response:
        // 1. COLMETADATA: 1 col "version" (NVARCHAR)
        // 2. ROW: "Microsoft SQL Server 2022"
        // 3. DONE: row_count 1
        let mut resp_tokens = Vec::new();

        // COLMETADATA: token 0x81, count 1
        resp_tokens.push(token_id::COLMETADATA);
        resp_tokens.extend_from_slice(&1u16.to_le_bytes()); // 1 column
        resp_tokens.extend_from_slice(&0u32.to_le_bytes()); // user type
        resp_tokens.extend_from_slice(&0u16.to_le_bytes()); // flags
        resp_tokens.push(0xE7); // type: NVARCHAR
        resp_tokens.extend_from_slice(&500u16.to_le_bytes()); // max len
        resp_tokens.extend_from_slice(&[0u8; 5]); // collation
        let col_name = impacket_core::encode_utf16le("version");
        resp_tokens.push((col_name.len() / 2) as u8);
        resp_tokens.extend_from_slice(&col_name);

        // ROW: token 0xD1
        resp_tokens.push(token_id::ROW);
        let cell = impacket_core::encode_utf16le("Microsoft SQL Server 2022");
        resp_tokens.extend_from_slice(&(cell.len() as u16).to_le_bytes());
        resp_tokens.extend_from_slice(&cell);

        // DONE: token 0xFD
        resp_tokens.push(token_id::DONE);
        resp_tokens.extend_from_slice(&0x0010u16.to_le_bytes());
        resp_tokens.extend_from_slice(&0u16.to_le_bytes());
        resp_tokens.extend_from_slice(&1u64.to_le_bytes());

        let packet = frame_tds_packet(packet_type::TABULAR_RESULT, &resp_tokens);
        let mut client = MssqlClient {
            stream: MockStream::new(packet),
            packet_size: DEFAULT_PACKET_SIZE,
            server_name: "test-sql".to_string(),
            database: "master".to_string(),
            server_version: None,
        };

        let result = client.query("SELECT @@VERSION").unwrap();
        assert_eq!(result.columns.len(), 1);
        assert_eq!(result.columns[0].name, "version");
        assert_eq!(result.rows.len(), 1);
        assert_eq!(
            result.rows[0].values[0].as_deref(),
            Some("Microsoft SQL Server 2022")
        );
        assert_eq!(result.rows_affected, 1);
    }
}
