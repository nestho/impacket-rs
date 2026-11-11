//! `prelogin`: `[MS-TDS]` Section 2.2.6.5 PRELOGIN packet encoder and decoder.

use impacket_core::CoreError;

pub mod prelogin_token {
    pub const VERSION: u8 = 0x00;
    pub const ENCRYPTION: u8 = 0x01;
    pub const INSTOPT: u8 = 0x02;
    pub const THREADID: u8 = 0x03;
    pub const MARS: u8 = 0x04;
    pub const FEDAUTHREQUIRED: u8 = 0x05;
    pub const TERMINATOR: u8 = 0xFF;
}

pub mod encrypt_mode {
    pub const ENCRYPT_OFF: u8 = 0x00;
    pub const ENCRYPT_ON: u8 = 0x01;
    pub const ENCRYPT_NOT_SUP: u8 = 0x02;
    pub const ENCRYPT_REQ: u8 = 0x03;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreloginResponse {
    pub version: [u8; 6],
    pub encryption: u8,
    pub mars: u8,
}

/// Builds client `PRELOGIN` payload advertising TDS client capabilities.
pub fn build_prelogin_request(encrypt: u8) -> Vec<u8> {
    // We send: VERSION (6 bytes), ENCRYPTION (1 byte), INSTOPT (1 byte), THREADID (4 bytes), MARS (1 byte), TERMINATOR (0xFF)
    // Header size = 5 options * 5 bytes + 1 terminator = 26 bytes.
    let mut table = Vec::with_capacity(26);
    let mut data = Vec::new();

    let mut add_opt = |token: u8, val: &[u8]| {
        let offset = (26 + data.len()) as u16;
        let len = val.len() as u16;
        table.push(token);
        table.extend_from_slice(&offset.to_be_bytes());
        table.extend_from_slice(&len.to_be_bytes());
        data.extend_from_slice(val);
    };

    // 1. Version: 09.00.1399 (SQL Server 2005+ format)
    add_opt(prelogin_token::VERSION, &[0x09, 0x00, 0x05, 0x77, 0x00, 0x00]);
    // 2. Encryption
    add_opt(prelogin_token::ENCRYPTION, &[encrypt]);
    // 3. InstOpt
    add_opt(prelogin_token::INSTOPT, &[0x00]);
    // 4. ThreadID
    add_opt(prelogin_token::THREADID, &[0x00, 0x00, 0x00, 0x00]);
    // 5. MARS
    add_opt(prelogin_token::MARS, &[0x00]); // MARS disabled

    table.push(prelogin_token::TERMINATOR);

    let mut payload = table;
    payload.extend_from_slice(&data);
    payload
}

/// Parses server `PRELOGIN` response.
pub fn parse_prelogin_response(payload: &[u8]) -> Result<PreloginResponse, CoreError> {
    let mut pos = 0;
    let mut options = Vec::new();

    while pos < payload.len() {
        let token = payload[pos];
        if token == prelogin_token::TERMINATOR {
            break;
        }
        if pos + 5 > payload.len() {
            return Err(CoreError::ProtocolError("Truncated PRELOGIN table".into()));
        }
        let offset = u16::from_be_bytes([payload[pos + 1], payload[pos + 2]]) as usize;
        let len = u16::from_be_bytes([payload[pos + 3], payload[pos + 4]]) as usize;
        pos += 5;
        options.push((token, offset, len));
    }

    let mut version = [0u8; 6];
    let mut encryption = encrypt_mode::ENCRYPT_NOT_SUP;
    let mut mars = 0u8;

    for (token, offset, len) in options {
        if offset + len > payload.len() {
            continue;
        }
        let val = &payload[offset..offset + len];
        match token {
            prelogin_token::VERSION if val.len() >= 6 => {
                version.copy_from_slice(&val[..6]);
            }
            prelogin_token::ENCRYPTION if !val.is_empty() => {
                encryption = val[0];
            }
            prelogin_token::MARS if !val.is_empty() => {
                mars = val[0];
            }
            _ => {}
        }
    }

    Ok(PreloginResponse {
        version,
        encryption,
        mars,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prelogin_build_and_parse_roundtrip() {
        let req = build_prelogin_request(encrypt_mode::ENCRYPT_NOT_SUP);
        assert!(!req.is_empty());
        let parsed = parse_prelogin_response(&req).unwrap();
        assert_eq!(parsed.encryption, encrypt_mode::ENCRYPT_NOT_SUP);
        assert_eq!(parsed.version, [0x09, 0x00, 0x05, 0x77, 0x00, 0x00]);
        assert_eq!(parsed.mars, 0);
    }
}
