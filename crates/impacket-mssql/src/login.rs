//! `login`: `[MS-TDS]` Section 2.2.6.4 LOGIN7 packet encoder supporting Windows Auth (SSPI) & SQL Auth.

use impacket_core::encode_utf16le;

pub const TDS_VERSION_7_4: u32 = 0x7400_0004; // SQL Server 2012 - 2022
pub const TDS_VERSION_7_1: u32 = 0x7100_0001; // SQL Server 2000

/// Obfuscates SQL Server authentication password per `[MS-TDS]` §2.2.6.4.
pub fn obfuscate_sql_password(pwd: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(pwd.len() * 2);
    for b in encode_utf16le(pwd) {
        let high = (b & 0xF0) >> 4;
        let low = (b & 0x0F) << 4;
        out.push((low | high) ^ 0xA5);
    }
    out
}

/// De-obfuscates SQL Server password per `[MS-TDS]` §2.2.6.4.
pub fn deobfuscate_sql_password(obf: &[u8]) -> Result<String, impacket_core::CoreError> {
    let mut out = Vec::with_capacity(obf.len());
    for &b in obf {
        let x = b ^ 0xA5;
        let high = (x & 0xF0) >> 4;
        let low = (x & 0x0F) << 4;
        out.push(low | high);
    }
    impacket_core::decode_utf16le(&out)
}

pub struct Login7Params<'a> {
    pub host_name: &'a str,
    pub user_name: &'a str,
    pub password: &'a str,
    pub app_name: &'a str,
    pub server_name: &'a str,
    pub database: &'a str,
    pub sspi_negotiate_bytes: Option<&'a [u8]>,
    pub desired_packet_size: u32,
}

fn push_field(offsets: &mut Vec<u8>, data: &mut Vec<u8>, base_offset: u16, raw_bytes: &[u8], unit_count: u16) {
    if unit_count == 0 {
        offsets.extend_from_slice(&0u16.to_le_bytes());
        offsets.extend_from_slice(&0u16.to_le_bytes());
    } else {
        let offset = base_offset + data.len() as u16;
        offsets.extend_from_slice(&offset.to_le_bytes());
        offsets.extend_from_slice(&unit_count.to_le_bytes());
        data.extend_from_slice(raw_bytes);
    }
}

fn push_string_field(offsets: &mut Vec<u8>, data: &mut Vec<u8>, base_offset: u16, s: &str) {
    let utf16 = encode_utf16le(s);
    let chars = (utf16.len() / 2) as u16;
    push_field(offsets, data, base_offset, &utf16, chars);
}

fn push_empty_field(offsets: &mut Vec<u8>) {
    offsets.extend_from_slice(&0u16.to_le_bytes());
    offsets.extend_from_slice(&0u16.to_le_bytes());
}

/// Builds a `LOGIN7` payload.
pub fn build_login7_payload(params: &Login7Params<'_>) -> Vec<u8> {
    let mut data = Vec::new();
    let base_offset: u16 = 94; // Fixed header (36) + Offset table (58)
    let mut offsets = Vec::with_capacity(58);

    let is_sspi = params.sspi_negotiate_bytes.is_some();

    // 1. ibHostName, cchHostName
    push_string_field(&mut offsets, &mut data, base_offset, params.host_name);

    // 2. ibUserName, cchUserName
    if is_sspi {
        push_empty_field(&mut offsets);
    } else {
        push_string_field(&mut offsets, &mut data, base_offset, params.user_name);
    }

    // 3. ibPassword, cchPassword
    if is_sspi {
        push_empty_field(&mut offsets);
    } else {
        let chars = params.password.encode_utf16().count() as u16;
        let obf = obfuscate_sql_password(params.password);
        push_field(&mut offsets, &mut data, base_offset, &obf, chars);
    }

    // 4. ibAppName, cchAppName
    push_string_field(&mut offsets, &mut data, base_offset, params.app_name);
    // 5. ibServerName, cchServerName
    push_string_field(&mut offsets, &mut data, base_offset, params.server_name);
    // 6. ibExtension, cchExtension (unused)
    push_empty_field(&mut offsets);
    // 7. ibCltIntName, cchCltIntName
    push_string_field(&mut offsets, &mut data, base_offset, "ODBC");
    // 8. ibLanguage, cchLanguage (unused)
    push_empty_field(&mut offsets);
    // 9. ibDatabase, cchDatabase
    push_string_field(&mut offsets, &mut data, base_offset, params.database);

    // 10. client_mac: 6 bytes
    offsets.extend_from_slice(&[0x00, 0x50, 0x56, 0xC0, 0x00, 0x08]);

    // 11. ibSSPILogin, cchSSPILogin (bytes, not chars)
    if let Some(sspi_bytes) = params.sspi_negotiate_bytes {
        push_field(&mut offsets, &mut data, base_offset, sspi_bytes, sspi_bytes.len() as u16);
    } else {
        push_empty_field(&mut offsets);
    }

    // 12. ibAtchDBFile, cchAtchDBFile
    push_empty_field(&mut offsets);
    // 13. ibChangePassword, cchChangePassword
    push_empty_field(&mut offsets);
    // 14. cbSSPILong (u32)
    offsets.extend_from_slice(&0u32.to_le_bytes());

    let total_len = (36 + offsets.len() + data.len()) as u32;

    let mut payload = Vec::with_capacity(total_len as usize);
    // Fixed header (36 bytes):
    payload.extend_from_slice(&total_len.to_le_bytes()); // Length
    payload.extend_from_slice(&TDS_VERSION_7_4.to_le_bytes()); // TDSVersion
    payload.extend_from_slice(&params.desired_packet_size.to_le_bytes()); // PacketSize
    payload.extend_from_slice(&7u32.to_le_bytes()); // ClientProgVer
    payload.extend_from_slice(&0x1234u32.to_le_bytes()); // ClientPID
    payload.extend_from_slice(&0u32.to_le_bytes()); // ConnectionID

    // option_flags1: fByteOrder(1) | fChar(1) | fFloat(1) = 0xE0
    payload.push(0xE0);
    // option_flags2: 0x80 (fIntegratedSecurity) if SSPI, else 0x00, plus 0x03 (fODBC)
    let flags2 = if is_sspi { 0x80 | 0x03 } else { 0x03 };
    payload.push(flags2);
    // type_flags: 0
    payload.push(0x00);
    // option_flags3: 0
    payload.push(0x00);
    // client_tz: 0
    payload.extend_from_slice(&0i32.to_le_bytes());
    // client_lcid: 0x00000409 (en-US)
    payload.extend_from_slice(&0x0000_0409u32.to_le_bytes());

    // Offset table (58 bytes)
    payload.extend_from_slice(&offsets);
    // Data
    payload.extend_from_slice(&data);

    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_obfuscation_symmetric() {
        let clear = "MySecretPassw0rd!";
        let obf = obfuscate_sql_password(clear);
        assert_eq!(obf.len(), clear.len() * 2);

        let restored = deobfuscate_sql_password(&obf).unwrap();
        assert_eq!(restored, clear);
    }

    #[test]
    fn test_login7_builder_layout() {
        let params = Login7Params {
            host_name: "WORKSTATION1",
            user_name: "sa",
            password: "password123",
            app_name: "impacket-rs",
            server_name: "SQLSRV01",
            database: "master",
            sspi_negotiate_bytes: None,
            desired_packet_size: 4096,
        };
        let payload = build_login7_payload(&params);
        assert!(payload.len() > 94);
        let len = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        assert_eq!(len as usize, payload.len());
        let version = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        assert_eq!(version, TDS_VERSION_7_4);
    }
}
