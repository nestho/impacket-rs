//! `tokens`: Tabular Data Stream (`[MS-TDS]`) token parsing (metadata, rows, errors, envchange, SSPI).

use impacket_core::{decode_utf16le, CoreError};

pub mod token_id {
    pub const COLMETADATA: u8 = 0x81;
    pub const ERROR: u8 = 0xAA;
    pub const INFO: u8 = 0xAB;
    pub const LOGINACK: u8 = 0xAD;
    pub const ROW: u8 = 0xD1;
    pub const NBC_ROW: u8 = 0xD2;
    pub const ENVCHANGE: u8 = 0xE3;
    pub const SSPI: u8 = 0xED;
    pub const DONE: u8 = 0xFD;
    pub const DONEPROC: u8 = 0xFE;
    pub const DONEINPROC: u8 = 0xFF;
}

pub mod data_type {
    pub const NULL: u8 = 0x1F;
    pub const INT1: u8 = 0x30;
    pub const BIT: u8 = 0x32;
    pub const INT2: u8 = 0x34;
    pub const INT4: u8 = 0x38;
    pub const DATETIME4: u8 = 0x3A;
    pub const REAL: u8 = 0x3B;
    pub const MONEY: u8 = 0x3C;
    pub const DATETIME: u8 = 0x3D;
    pub const FLOAT8: u8 = 0x3E;
    pub const MONEY4: u8 = 0x7A;
    pub const INT8: u8 = 0x7F;
    pub const BIGVARBINARY: u8 = 0xA5;
    pub const BIGVARCHAR: u8 = 0xA7;
    pub const BIGBINARY: u8 = 0xAD;
    pub const BIGCHAR: u8 = 0xAF;
    pub const NVARCHAR: u8 = 0xE7;
    pub const NCHAR: u8 = 0xEF;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnMetadata {
    pub name: String,
    pub type_id: u8,
    pub user_type: u32,
    pub flags: u16,
    pub max_length: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MssqlRow {
    pub values: Vec<Option<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MssqlError {
    pub number: u32,
    pub state: u8,
    pub severity: u8,
    pub message: String,
    pub server_name: String,
    pub proc_name: String,
    pub line_number: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginAck {
    pub interface: u8,
    pub tds_version: u32,
    pub prog_name: String,
    pub major: u8,
    pub minor: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TdsToken {
    Sspi(Vec<u8>),
    LoginAck(LoginAck),
    EnvChange { env_type: u8, new_val: String, old_val: String },
    ColMetadata(Vec<ColumnMetadata>),
    Row(MssqlRow),
    Info(String),
    Error(MssqlError),
    Done { status: u16, row_count: u64 },
}

/// Parses a token stream into high-level TDS tokens.
pub fn parse_tds_tokens(mut data: &[u8]) -> Result<Vec<TdsToken>, CoreError> {
    let mut tokens = Vec::new();
    let mut current_cols: Vec<ColumnMetadata> = Vec::new();

    while !data.is_empty() {
        let token_type = data[0];
        data = &data[1..];

        match token_type {
            token_id::SSPI => {
                if data.len() < 2 {
                    return Err(CoreError::ProtocolError("Truncated SSPI token".into()));
                }
                let len = u16::from_le_bytes([data[0], data[1]]) as usize;
                data = &data[2..];
                if data.len() < len {
                    return Err(CoreError::ProtocolError("Truncated SSPI token data".into()));
                }
                let sspi_bytes = data[..len].to_vec();
                data = &data[len..];
                tokens.push(TdsToken::Sspi(sspi_bytes));
            }
            token_id::LOGINACK => {
                if data.len() < 2 {
                    return Err(CoreError::ProtocolError("Truncated LOGINACK token".into()));
                }
                let len = u16::from_le_bytes([data[0], data[1]]) as usize;
                data = &data[2..];
                if data.len() < len || len < 9 {
                    return Err(CoreError::ProtocolError("Invalid LOGINACK payload".into()));
                }
                let iface = data[0];
                let tds_ver = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                let prog_len = data[5] as usize;
                let prog_bytes = &data[6..6 + prog_len * 2];
                let prog_name = decode_utf16le(prog_bytes).unwrap_or_default();
                let ver_offset = 6 + prog_len * 2;
                let major = if ver_offset < len { data[ver_offset] } else { 0 };
                let minor = if ver_offset + 1 < len { data[ver_offset + 1] } else { 0 };

                data = &data[len..];
                tokens.push(TdsToken::LoginAck(LoginAck {
                    interface: iface,
                    tds_version: tds_ver,
                    prog_name,
                    major,
                    minor,
                }));
            }
            token_id::ENVCHANGE => {
                if data.len() < 2 {
                    return Err(CoreError::ProtocolError("Truncated ENVCHANGE token".into()));
                }
                let len = u16::from_le_bytes([data[0], data[1]]) as usize;
                data = &data[2..];
                if data.len() < len {
                    return Err(CoreError::ProtocolError("Invalid ENVCHANGE length".into()));
                }
                let env_type = data[0];
                let mut p = 1;
                let new_len = if p < len { data[p] as usize } else { 0 };
                p += 1;
                let new_val = if p + new_len * 2 <= len {
                    decode_utf16le(&data[p..p + new_len * 2]).unwrap_or_default()
                } else {
                    String::new()
                };
                p += new_len * 2;
                let old_len = if p < len { data[p] as usize } else { 0 };
                p += 1;
                let old_val = if p + old_len * 2 <= len {
                    decode_utf16le(&data[p..p + old_len * 2]).unwrap_or_default()
                } else {
                    String::new()
                };

                data = &data[len..];
                tokens.push(TdsToken::EnvChange {
                    env_type,
                    new_val,
                    old_val,
                });
            }
            token_id::INFO | token_id::ERROR => {
                if data.len() < 2 {
                    return Err(CoreError::ProtocolError("Truncated INFO/ERROR token".into()));
                }
                let len = u16::from_le_bytes([data[0], data[1]]) as usize;
                data = &data[2..];
                if data.len() < len || len < 8 {
                    return Err(CoreError::ProtocolError("Invalid INFO/ERROR length".into()));
                }
                let num = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                let state = data[4];
                let severity = data[5];
                let msg_len = u16::from_le_bytes([data[6], data[7]]) as usize;
                let mut p = 8;
                let msg = if p + msg_len * 2 <= len {
                    decode_utf16le(&data[p..p + msg_len * 2]).unwrap_or_default()
                } else {
                    String::new()
                };
                p += msg_len * 2;
                let srv_len = if p < len { data[p] as usize } else { 0 };
                p += 1;
                let srv_name = if p + srv_len * 2 <= len {
                    decode_utf16le(&data[p..p + srv_len * 2]).unwrap_or_default()
                } else {
                    String::new()
                };
                p += srv_len * 2;
                let proc_len = if p < len { data[p] as usize } else { 0 };
                p += 1;
                let proc_name = if p + proc_len * 2 <= len {
                    decode_utf16le(&data[p..p + proc_len * 2]).unwrap_or_default()
                } else {
                    String::new()
                };
                p += proc_len * 2;
                let line = if p + 4 <= len {
                    u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]])
                } else {
                    0
                };

                data = &data[len..];
                let err = MssqlError {
                    number: num,
                    state,
                    severity,
                    message: msg.clone(),
                    server_name: srv_name,
                    proc_name,
                    line_number: line,
                };
                if token_type == token_id::INFO {
                    tokens.push(TdsToken::Info(msg));
                } else {
                    tokens.push(TdsToken::Error(err));
                }
            }
            token_id::COLMETADATA => {
                if data.len() < 2 {
                    return Err(CoreError::ProtocolError("Truncated COLMETADATA token".into()));
                }
                let col_count = u16::from_le_bytes([data[0], data[1]]) as usize;
                data = &data[2..];
                let mut cols = Vec::with_capacity(col_count);

                for _ in 0..col_count {
                    if data.len() < 7 {
                        return Err(CoreError::ProtocolError("Truncated column metadata".into()));
                    }
                    let user_type = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let flags = u16::from_le_bytes([data[4], data[5]]);
                    let type_id = data[6];
                    data = &data[7..];

                    let mut max_len = 0u32;
                    match type_id {
                        data_type::INT1 | data_type::BIT => max_len = 1,
                        data_type::INT2 => max_len = 2,
                        data_type::INT4 => max_len = 4,
                        data_type::INT8 | data_type::DATETIME | data_type::FLOAT8 => max_len = 8,
                        data_type::NVARCHAR
                        | data_type::NCHAR
                        | data_type::BIGVARCHAR
                        | data_type::BIGCHAR
                        | data_type::BIGVARBINARY
                        | data_type::BIGBINARY => {
                            if data.len() < 2 {
                                return Err(CoreError::ProtocolError("Truncated var-type length".into()));
                            }
                            max_len = u16::from_le_bytes([data[0], data[1]]) as u32;
                            data = &data[2..];
                            // Text types carry 5-byte collation
                            if type_id == data_type::NVARCHAR
                                || type_id == data_type::NCHAR
                                || type_id == data_type::BIGVARCHAR
                                || type_id == data_type::BIGCHAR
                            {
                                if data.len() < 5 {
                                    return Err(CoreError::ProtocolError("Truncated collation".into()));
                                }
                                data = &data[5..];
                            }
                        }
                        _ => {}
                    }

                    if data.is_empty() {
                        return Err(CoreError::ProtocolError("Missing column name length".into()));
                    }
                    let name_len = data[0] as usize;
                    data = &data[1..];
                    if data.len() < name_len * 2 {
                        return Err(CoreError::ProtocolError("Truncated column name".into()));
                    }
                    let name = decode_utf16le(&data[..name_len * 2]).unwrap_or_default();
                    data = &data[name_len * 2..];

                    cols.push(ColumnMetadata {
                        name,
                        type_id,
                        user_type,
                        flags,
                        max_length: max_len,
                    });
                }

                current_cols = cols.clone();
                tokens.push(TdsToken::ColMetadata(cols));
            }
            token_id::ROW => {
                let mut values = Vec::with_capacity(current_cols.len());
                for col in &current_cols {
                    match col.type_id {
                        data_type::INT1 => {
                            if data.is_empty() {
                                return Err(CoreError::ProtocolError("Truncated INT1 row cell".into()));
                            }
                            values.push(Some(data[0].to_string()));
                            data = &data[1..];
                        }
                        data_type::INT2 => {
                            if data.is_empty() {
                                return Err(CoreError::ProtocolError("Truncated INT2 row cell".into()));
                            }
                            let len = data[0] as usize;
                            data = &data[1..];
                            if len == 0 {
                                values.push(None);
                            } else if len >= 2 && data.len() >= 2 {
                                let v = i16::from_le_bytes([data[0], data[1]]);
                                values.push(Some(v.to_string()));
                                data = &data[2..];
                            }
                        }
                        data_type::INT4 => {
                            if data.is_empty() {
                                return Err(CoreError::ProtocolError("Truncated INT4 row cell".into()));
                            }
                            let len = data[0] as usize;
                            data = &data[1..];
                            if len == 0 {
                                values.push(None);
                            } else if len >= 4 && data.len() >= 4 {
                                let v = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                                values.push(Some(v.to_string()));
                                data = &data[4..];
                            }
                        }
                        data_type::INT8 => {
                            if data.is_empty() {
                                return Err(CoreError::ProtocolError("Truncated INT8 row cell".into()));
                            }
                            let len = data[0] as usize;
                            data = &data[1..];
                            if len == 0 {
                                values.push(None);
                            } else if len >= 8 && data.len() >= 8 {
                                let v = i64::from_le_bytes([
                                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                                ]);
                                values.push(Some(v.to_string()));
                                data = &data[8..];
                            }
                        }
                        data_type::NVARCHAR | data_type::NCHAR => {
                            if data.len() < 2 {
                                return Err(CoreError::ProtocolError("Truncated NVARCHAR row cell length".into()));
                            }
                            let len = u16::from_le_bytes([data[0], data[1]]);
                            data = &data[2..];
                            if len == 0xFFFF {
                                values.push(None);
                            } else {
                                let byte_len = len as usize;
                                if data.len() < byte_len {
                                    return Err(CoreError::ProtocolError("Truncated NVARCHAR row cell data".into()));
                                }
                                let s = decode_utf16le(&data[..byte_len]).unwrap_or_default();
                                values.push(Some(s));
                                data = &data[byte_len..];
                            }
                        }
                        data_type::BIGVARCHAR | data_type::BIGCHAR => {
                            if data.len() < 2 {
                                return Err(CoreError::ProtocolError("Truncated VARCHAR row cell length".into()));
                            }
                            let len = u16::from_le_bytes([data[0], data[1]]);
                            data = &data[2..];
                            if len == 0xFFFF {
                                values.push(None);
                            } else {
                                let byte_len = len as usize;
                                if data.len() < byte_len {
                                    return Err(CoreError::ProtocolError("Truncated VARCHAR row cell data".into()));
                                }
                                let s = String::from_utf8_lossy(&data[..byte_len]).to_string();
                                values.push(Some(s));
                                data = &data[byte_len..];
                            }
                        }
                        _ => {
                            // Generic variable length fallback
                            if data.len() < 2 {
                                values.push(None);
                            } else {
                                let len = u16::from_le_bytes([data[0], data[1]]);
                                data = &data[2..];
                                if len == 0xFFFF || len == 0 {
                                    values.push(None);
                                } else {
                                    let byte_len = (len as usize).min(data.len());
                                    values.push(Some(impacket_core::encode_hex(&data[..byte_len])));
                                    data = &data[byte_len..];
                                }
                            }
                        }
                    }
                }
                tokens.push(TdsToken::Row(MssqlRow { values }));
            }
            token_id::DONE | token_id::DONEPROC | token_id::DONEINPROC => {
                if data.len() < 12 {
                    // Try 8-byte older format if less than 12
                    if data.len() >= 8 {
                        let st = u16::from_le_bytes([data[0], data[1]]);
                        let rc = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as u64;
                        data = &data[8..];
                        tokens.push(TdsToken::Done {
                            status: st,
                            row_count: rc,
                        });
                        continue;
                    }
                    return Err(CoreError::ProtocolError("Truncated DONE token".into()));
                }
                let st = u16::from_le_bytes([data[0], data[1]]);
                let rc = u64::from_le_bytes([
                    data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
                ]);
                data = &data[12..];
                tokens.push(TdsToken::Done {
                    status: st,
                    row_count: rc,
                });
            }
            _ => {
                // Unknown token, skip rest
                break;
            }
        }
    }

    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_loginack_and_done() {
        let mut raw = Vec::new();
        // 1. LOGINACK: type 0xAD, len 16, iface 1, ver 0x74000004, prog_len 2, "OK", major 15, minor 0
        raw.push(token_id::LOGINACK);
        let prog = impacket_core::encode_utf16le("OK");
        let payload_len = 6 + prog.len() + 2;
        raw.extend_from_slice(&(payload_len as u16).to_le_bytes());
        raw.push(1); // interface
        raw.extend_from_slice(&0x7400_0004u32.to_be_bytes()); // TDS 7.4
        raw.push((prog.len() / 2) as u8);
        raw.extend_from_slice(&prog);
        raw.push(15); // major
        raw.push(0); // minor

        // 2. DONE: type 0xFD, status 0x0010 (DONE_COUNT), cur_cmd 0, count 1
        raw.push(token_id::DONE);
        raw.extend_from_slice(&0x0010u16.to_le_bytes());
        raw.extend_from_slice(&0u16.to_le_bytes());
        raw.extend_from_slice(&1u64.to_le_bytes());

        let tokens = parse_tds_tokens(&raw).unwrap();
        assert_eq!(tokens.len(), 2);
        match &tokens[0] {
            TdsToken::LoginAck(ack) => {
                assert_eq!(ack.prog_name, "OK");
                assert_eq!(ack.major, 15);
            }
            _ => panic!("Expected LoginAck"),
        }
        match &tokens[1] {
            TdsToken::Done { row_count, status } => {
                assert_eq!(*row_count, 1);
                assert_eq!(*status, 0x0010);
            }
            _ => panic!("Expected Done"),
        }
    }
}
