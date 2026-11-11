//! `rrp`: `[MS-RRP]` Windows Remote Registry Protocol client (`impacket/dcerpc/v5/rrp.py`).
//!
//! Implements remote registry operations over `\PIPE\winreg`:
//! - Root key access: `OpenClassesRoot` (0), `OpenCurrentUser` (1), `OpenLocalMachine` (2), `OpenUsers` (4)
//! - Key operations: `BaseRegOpenKey` (15), `BaseRegCreateKey` (6), `BaseRegDeleteKey` (7), `BaseRegCloseKey` (5)
//! - Value operations: `BaseRegQueryValue` (17), `BaseRegSetValue` (22), `BaseRegDeleteValue` (8)
//! - Enumeration: `BaseRegEnumKey` (9), `BaseRegEnumValue` (10)
//! - Hive export: `BaseRegSaveKey` (20)

use crate::dtypes::{write_string_wchar_pointee, REFERENT_BASE};
use impacket_core::{decode_utf16le, encode_utf16le, CoreError};
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport};
use impacket_ndr::{NdrReader, NdrWriter};

/// A 20-byte registry RPC context handle (`RPC_HKEY`).
pub type RegHandle = [u8; 20];

pub mod opnum {
    pub const OPEN_CLASSES_ROOT: u16 = 0;
    pub const OPEN_CURRENT_USER: u16 = 1;
    pub const OPEN_LOCAL_MACHINE: u16 = 2;
    pub const OPEN_USERS: u16 = 4;
    pub const BASE_REG_CLOSE_KEY: u16 = 5;
    pub const BASE_REG_CREATE_KEY: u16 = 6;
    pub const BASE_REG_DELETE_KEY: u16 = 7;
    pub const BASE_REG_DELETE_VALUE: u16 = 8;
    pub const BASE_REG_ENUM_KEY: u16 = 9;
    pub const BASE_REG_ENUM_VALUE: u16 = 10;
    pub const BASE_REG_OPEN_KEY: u16 = 15;
    pub const BASE_REG_QUERY_INFO_KEY: u16 = 16;
    pub const BASE_REG_QUERY_VALUE: u16 = 17;
    pub const BASE_REG_SAVE_KEY: u16 = 20;
    pub const BASE_REG_SET_VALUE: u16 = 22;
}

pub mod reg_type {
    pub const REG_NONE: u32 = 0;
    pub const REG_SZ: u32 = 1;
    pub const REG_EXPAND_SZ: u32 = 2;
    pub const REG_BINARY: u32 = 3;
    pub const REG_DWORD: u32 = 4;
    pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
    pub const REG_LINK: u32 = 6;
    pub const REG_MULTI_SZ: u32 = 7;
    pub const REG_QWORD: u32 = 11;

    pub fn name(val: u32) -> &'static str {
        match val {
            REG_NONE => "REG_NONE",
            REG_SZ => "REG_SZ",
            REG_EXPAND_SZ => "REG_EXPAND_SZ",
            REG_BINARY => "REG_BINARY",
            REG_DWORD => "REG_DWORD",
            REG_DWORD_BIG_ENDIAN => "REG_DWORD_BIG_ENDIAN",
            REG_LINK => "REG_LINK",
            REG_MULTI_SZ => "REG_MULTI_SZ",
            REG_QWORD => "REG_QWORD",
            _ => "REG_UNKNOWN",
        }
    }

    pub fn parse(s: &str) -> Option<u32> {
        match s.to_ascii_uppercase().as_str() {
            "REG_NONE" => Some(REG_NONE),
            "REG_SZ" => Some(REG_SZ),
            "REG_EXPAND_SZ" => Some(REG_EXPAND_SZ),
            "REG_BINARY" => Some(REG_BINARY),
            "REG_DWORD" => Some(REG_DWORD),
            "REG_DWORD_BIG_ENDIAN" => Some(REG_DWORD_BIG_ENDIAN),
            "REG_LINK" => Some(REG_LINK),
            "REG_MULTI_SZ" => Some(REG_MULTI_SZ),
            "REG_QWORD" => Some(REG_QWORD),
            _ => None,
        }
    }
}

/// Windows Registry predefined root hives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegHive {
    ClassesRoot,
    CurrentUser,
    LocalMachine,
    Users,
}

impl RegHive {
    pub fn name(&self) -> &'static str {
        match self {
            RegHive::ClassesRoot => "HKEY_CLASSES_ROOT",
            RegHive::CurrentUser => "HKEY_CURRENT_USER",
            RegHive::LocalMachine => "HKEY_LOCAL_MACHINE",
            RegHive::Users => "HKEY_USERS",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let upper = s.to_ascii_uppercase();
        match upper.as_str() {
            "HKLM" | "HKEY_LOCAL_MACHINE" => Some(RegHive::LocalMachine),
            "HKU" | "HKEY_USERS" => Some(RegHive::Users),
            "HKCR" | "HKEY_CLASSES_ROOT" => Some(RegHive::ClassesRoot),
            "HKCU" | "HKEY_CURRENT_USER" => Some(RegHive::CurrentUser),
            _ => None,
        }
    }
}

/// Parses a registry key path like `"HKLM\\Software\\Microsoft"` into `(RegHive, subkey)`.
pub fn parse_reg_key_path(full_path: &str) -> Result<(RegHive, String), CoreError> {
    let normalized = full_path.replace('/', "\\");
    let trimmed = normalized.trim_start_matches('\\');
    let (hive_str, subkey) = match trimmed.find('\\') {
        Some(pos) => (&trimmed[..pos], trimmed[pos + 1..].trim_start_matches('\\')),
        None => (trimmed, ""),
    };
    let hive = RegHive::parse(hive_str).ok_or_else(|| {
        CoreError::ProtocolError(format!(
            "Unknown registry hive '{}' (expected HKLM, HKU, HKCR, or HKCU)",
            hive_str
        ))
    })?;
    Ok((hive, subkey.to_string()))
}

/// Encodes text representation of a value into binary bytes according to its registry type.
pub fn encode_reg_data(dw_type: u32, val_str: &str) -> Result<Vec<u8>, CoreError> {
    match dw_type {
        reg_type::REG_SZ | reg_type::REG_EXPAND_SZ => {
            let mut bytes = encode_utf16le(val_str);
            bytes.extend_from_slice(&[0, 0]);
            Ok(bytes)
        }
        reg_type::REG_DWORD => {
            let n = if val_str.starts_with("0x") || val_str.starts_with("0X") {
                u32::from_str_radix(&val_str[2..], 16)
            } else {
                val_str.parse::<u32>()
            }
            .map_err(|e| CoreError::ProtocolError(format!("Invalid DWORD integer '{}': {}", val_str, e)))?;
            Ok(n.to_le_bytes().to_vec())
        }
        reg_type::REG_QWORD => {
            let n = if val_str.starts_with("0x") || val_str.starts_with("0X") {
                u64::from_str_radix(&val_str[2..], 16)
            } else {
                val_str.parse::<u64>()
            }
            .map_err(|e| CoreError::ProtocolError(format!("Invalid QWORD integer '{}': {}", val_str, e)))?;
            Ok(n.to_le_bytes().to_vec())
        }
        reg_type::REG_BINARY => {
            let clean = val_str.replace([' ', ',', ':', '-'], "");
            let bytes = impacket_core::decode_hex(&clean)
                .map_err(|e| CoreError::ProtocolError(format!("Invalid hex binary data: {}", e)))?;
            Ok(bytes)
        }
        reg_type::REG_MULTI_SZ => {
            let mut out = Vec::new();
            for part in val_str.split(r"\0") {
                if !part.is_empty() {
                    out.extend_from_slice(&encode_utf16le(part));
                    out.extend_from_slice(&[0, 0]);
                }
            }
            out.extend_from_slice(&[0, 0]);
            Ok(out)
        }
        _ => Ok(val_str.as_bytes().to_vec()),
    }
}

/// Formats raw registry value bytes into a human-readable display string according to `dw_type`.
pub fn format_reg_data(dw_type: u32, data: &[u8]) -> String {
    match dw_type {
        reg_type::REG_SZ | reg_type::REG_EXPAND_SZ => {
            let stripped = if data.len() >= 2 && data[data.len() - 2..] == [0, 0] {
                &data[..data.len() - 2]
            } else {
                data
            };
            decode_utf16le(stripped).unwrap_or_else(|_| String::from_utf8_lossy(data).to_string())
        }
        reg_type::REG_DWORD if data.len() >= 4 => {
            let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            format!("{:#x} ({})", val, val)
        }
        reg_type::REG_QWORD if data.len() >= 8 => {
            let val = u64::from_le_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            format!("{:#x} ({})", val, val)
        }
        reg_type::REG_BINARY => impacket_core::encode_hex(data),
        reg_type::REG_MULTI_SZ => {
            let mut items = Vec::new();
            let mut cur = Vec::new();
            for chunk in data.chunks_exact(2) {
                if chunk == [0, 0] {
                    if !cur.is_empty() {
                        if let Ok(s) = decode_utf16le(&cur) {
                            items.push(s);
                        }
                        cur.clear();
                    }
                } else {
                    cur.extend_from_slice(chunk);
                }
            }
            items.join(", ")
        }
        _ => impacket_core::encode_hex(data),
    }
}

/// Broad access mask (`MAXIMUM_ALLOWED`).
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
pub const KEY_READ: u32 = 0x0002_0019;
pub const KEY_WRITE: u32 = 0x0002_0006;
pub const KEY_ALL_ACCESS: u32 = 0x000F_003F;

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;

/// Writes an `RRP_UNICODE_STRING` inline header (`Length` excl NUL, `MaximumLength` incl NUL, `Buffer`
/// referent). Caller defers the NUL-terminated buffer with [`write_string_wchar_pointee`].
fn write_rrp_unicode_string_header(w: &mut NdrWriter, s: &str, referent: u32) {
    let chars = (encode_utf16le(s).len() / 2) as u16;
    w.write_u16(chars * 2); // Length (bytes, no NUL)
    w.write_u16((chars + 1) * 2); // MaximumLength (incl NUL)
    w.write_u32(referent);
}

/// Reads a deferred conformant+varying UTF-16LE string from an NDR reader.
fn read_deferred_unicode_string(r: &mut NdrReader<'_>) -> Result<String, CoreError> {
    let max_count = r.read_u32()?;
    let _offset = r.read_u32()?;
    let actual_count = r.read_u32()?;
    if actual_count > max_count || actual_count > 65_536 {
        return Err(CoreError::ProtocolError(format!(
            "Invalid unicode string counts: max={}, actual={}",
            max_count, actual_count
        )));
    }
    let raw = r.read_bytes((actual_count as usize) * 2)?;
    let stripped = if raw.len() >= 2 && raw[raw.len() - 2..] == [0, 0] {
        &raw[..raw.len() - 2]
    } else {
        raw
    };
    let s = decode_utf16le(stripped)?;
    r.align(4)?;
    Ok(s)
}

/// Generic root key open stub (`ServerName = NULL`, `samDesired`).
pub fn build_open_root_stub(sam_desired: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(16);
    w.write_u32(0); // ServerName = NULL
    w.write_u32(sam_desired);
    w.into_bytes()
}

/// `OpenLocalMachine` (2): `ServerName` is `[unique] USHORT*` → NULL.
pub fn build_open_local_machine_stub(sam_desired: u32) -> Vec<u8> {
    build_open_root_stub(sam_desired)
}

/// `BaseRegOpenKey` (15): `hKey`, `lpSubKey` (RRP_UNICODE_STRING), `dwOptions`, `samDesired`.
pub fn build_base_reg_open_key_stub(
    hkey: &RegHandle,
    subkey: &str,
    options: u32,
    sam_desired: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_fixed_array(hkey);
    write_rrp_unicode_string_header(&mut w, subkey, REFERENT_BASE);
    w.write_u32(options);
    w.write_u32(sam_desired);
    // Deferred string buffer (NUL-terminated).
    write_string_wchar_pointee(&mut w, subkey);
    w.into_bytes()
}

/// `BaseRegCreateKey` (6): `hKey`, `lpSubKey`, `lpClass` (NULL), `dwOptions`, `samDesired`, `lpSecurityAttributes` (NULL), `lpdwDisposition`.
pub fn build_base_reg_create_key_stub(
    hkey: &RegHandle,
    subkey: &str,
    options: u32,
    sam_desired: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_fixed_array(hkey);
    write_rrp_unicode_string_header(&mut w, subkey, REFERENT_BASE);
    // lpClass = empty/NULL RRP_UNICODE_STRING
    w.write_u16(0);
    w.write_u16(0);
    w.write_u32(0);
    w.write_u32(options);
    w.write_u32(sam_desired);
    w.write_u32(0); // lpSecurityAttributes = NULL
    w.write_u32(REFERENT_BASE + 4); // lpdwDisposition referent
    w.write_u32(0); // disposition value
    write_string_wchar_pointee(&mut w, subkey);
    w.into_bytes()
}

/// `BaseRegDeleteKey` (7): `hKey`, `lpSubKey`.
pub fn build_base_reg_delete_key_stub(hkey: &RegHandle, subkey: &str) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_fixed_array(hkey);
    write_rrp_unicode_string_header(&mut w, subkey, REFERENT_BASE);
    write_string_wchar_pointee(&mut w, subkey);
    w.into_bytes()
}

/// `BaseRegDeleteValue` (8): `hKey`, `lpValueName`.
pub fn build_base_reg_delete_value_stub(hkey: &RegHandle, value_name: &str) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_fixed_array(hkey);
    write_rrp_unicode_string_header(&mut w, value_name, REFERENT_BASE);
    write_string_wchar_pointee(&mut w, value_name);
    w.into_bytes()
}

/// `BaseRegSetValue` (22): `hKey`, `lpValueName`, `dwType`, `lpData` (conformant byte array), `cbData`.
pub fn build_base_reg_set_value_stub(
    hkey: &RegHandle,
    value_name: &str,
    dw_type: u32,
    data: &[u8],
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64 + data.len());
    w.write_fixed_array(hkey);
    write_rrp_unicode_string_header(&mut w, value_name, REFERENT_BASE);
    w.write_u32(dw_type);
    w.write_u32(data.len() as u32); // conformant array max_count
    w.write_bytes(data);
    w.align(4);
    w.write_u32(data.len() as u32); // cbData
    write_string_wchar_pointee(&mut w, value_name);
    w.into_bytes()
}

/// `BaseRegQueryValue` (17): `hKey`, `lpValueName`, `lpType`, `lpData`, `lpcbData`, `lpcbLen`.
pub fn build_base_reg_query_value_stub(
    hkey: &RegHandle,
    value_name: &str,
    max_buf_len: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(80);
    w.write_fixed_array(hkey);
    write_rrp_unicode_string_header(&mut w, value_name, REFERENT_BASE);
    w.write_u32(REFERENT_BASE + 4); // lpType referent
    w.write_u32(0); // lpType in
    w.write_u32(REFERENT_BASE + 8); // lpData referent
    w.write_u32(max_buf_len); // max_count
    w.write_u32(0); // offset
    w.write_u32(0); // actual_count
    w.write_u32(REFERENT_BASE + 12); // lpcbData referent
    w.write_u32(max_buf_len); // lpcbData in
    w.write_u32(REFERENT_BASE + 16); // lpcbLen referent
    w.write_u32(0); // lpcbLen in
    write_string_wchar_pointee(&mut w, value_name);
    w.into_bytes()
}

/// `BaseRegEnumKey` (9): `hKey`, `dwIndex`, `lpNameIn`, `lpClassIn` (NULL), `lpftLastWriteTime` (NULL).
pub fn build_base_reg_enum_key_stub(hkey: &RegHandle, index: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_fixed_array(hkey);
    w.write_u32(index);
    // lpNameIn: allocated buffer for subkey name (512 bytes / 256 WCHARs)
    w.write_u16(0); // Length = 0
    w.write_u16(512); // MaximumLength = 512
    w.write_u32(REFERENT_BASE); // Buffer referent
    w.write_u32(0); // lpClassIn = NULL
    w.write_u32(0); // lpftLastWriteTime = NULL
    // Deferred conformant array for lpNameIn buffer
    w.write_u32(256); // max_count
    w.write_u32(0); // offset
    w.write_u32(0); // actual_count
    w.into_bytes()
}

/// `BaseRegEnumValue` (10): `hKey`, `dwIndex`, `lpValueNameIn`, `lpType`, `lpData`, `lpcbData`, `lpcbLen`.
pub fn build_base_reg_enum_value_stub(hkey: &RegHandle, index: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(80);
    w.write_fixed_array(hkey);
    w.write_u32(index);
    w.write_u16(0); // Length = 0
    w.write_u16(512); // MaximumLength = 512
    w.write_u32(REFERENT_BASE); // Buffer referent
    w.write_u32(REFERENT_BASE + 4); // lpType referent
    w.write_u32(0); // lpType in
    w.write_u32(REFERENT_BASE + 8); // lpData referent
    w.write_u32(4096); // max_count
    w.write_u32(0); // offset
    w.write_u32(0); // actual_count
    w.write_u32(REFERENT_BASE + 12); // lpcbData referent
    w.write_u32(4096); // lpcbData in
    w.write_u32(REFERENT_BASE + 16); // lpcbLen referent
    w.write_u32(0); // lpcbLen in
    // Deferred conformant array for lpValueNameIn
    w.write_u32(256); // max_count
    w.write_u32(0);
    w.write_u32(0);
    w.into_bytes()
}

/// `BaseRegSaveKey` (20): `hKey`, `lpFile` (RRP_UNICODE_STRING), `pSecurityAttributes` (NULL).
pub fn build_base_reg_save_key_stub(hkey: &RegHandle, filename: &str) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_fixed_array(hkey);
    write_rrp_unicode_string_header(&mut w, filename, REFERENT_BASE);
    w.write_u32(0); // pSecurityAttributes [unique] = NULL
    write_string_wchar_pointee(&mut w, filename); // deferred buffer
    w.into_bytes()
}

/// `BaseRegCloseKey` (5): `[in,out] hKey`.
pub fn build_base_reg_close_key_stub(hkey: &RegHandle) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(20);
    w.write_fixed_array(hkey);
    w.into_bytes()
}

/// Parses `[out] handle(20) + Win32 error` (OpenLocalMachine / BaseRegOpenKey / BaseRegCreateKey).
pub fn parse_handle_response(stub: &[u8]) -> Result<RegHandle, CoreError> {
    let mut r = NdrReader::new(stub);
    let h = r.read_fixed_array::<20>()?;
    // For BaseRegCreateKey, disposition precedes error code
    if stub.len() >= 28 {
        let _ = r.read_u32()?; // lpdwDisposition
    }
    accept_win32(r.read_u32()?)?;
    Ok(h)
}

/// Parses a response that returns only a Win32 error (BaseRegSaveKey, BaseRegSetValue, BaseRegDeleteKey, BaseRegDeleteValue).
pub fn parse_error_response(stub: &[u8]) -> Result<(), CoreError> {
    let mut r = NdrReader::new(stub);
    // BaseRegCloseKey echoes the [out] handle first; the error is the final 4 bytes either way.
    if stub.len() >= 24 {
        let _ = r.read_fixed_array::<20>()?;
    }
    accept_win32(r.read_u32()?)
}

/// Parses `BaseRegQueryValue` response returning `(data_type, data_bytes)`.
pub fn parse_query_value_response(stub: &[u8]) -> Result<(u32, Vec<u8>), CoreError> {
    let mut r = NdrReader::new(stub);
    let type_ref = r.read_u32()?;
    let val_type = if type_ref != 0 { r.read_u32()? } else { 0 };

    let data_ref = r.read_u32()?;
    let data = if data_ref != 0 {
        let max_count = r.read_u32()?;
        let _offset = r.read_u32()?;
        let actual_count = r.read_u32()?;
        if actual_count > max_count || actual_count > 10 * 1024 * 1024 {
            return Err(CoreError::ProtocolError("Invalid registry data count".into()));
        }
        let raw = r.read_bytes(actual_count as usize)?.to_vec();
        r.align(4)?;
        raw
    } else {
        Vec::new()
    };

    let _cb_data_ref = r.read_u32()?;
    let _cb_data = r.read_u32()?;
    let _cb_len_ref = r.read_u32()?;
    let _cb_len = r.read_u32()?;
    let err = r.read_u32()?;
    accept_win32(err)?;

    Ok((val_type, data))
}

/// Parses `BaseRegEnumKey` response returning `Option<String>` (None when `ERROR_NO_MORE_ITEMS`).
pub fn parse_enum_key_response(stub: &[u8]) -> Result<Option<String>, CoreError> {
    let mut r = NdrReader::new(stub);
    let _length = r.read_u16()?;
    let _max_length = r.read_u16()?;
    let buf_ref = r.read_u32()?;

    let _class_ref = r.read_u32()?;
    let _time_ref = r.read_u32()?;

    let key_name = if buf_ref != 0 {
        read_deferred_unicode_string(&mut r)?
    } else {
        String::new()
    };

    let err = r.read_u32()?;
    if err == ERROR_NO_MORE_ITEMS {
        return Ok(None);
    }
    accept_win32(err)?;
    Ok(Some(key_name))
}

/// Parses `BaseRegEnumValue` response returning `Option<(name, type, data)>`.
pub fn parse_enum_value_response(stub: &[u8]) -> Result<Option<(String, u32, Vec<u8>)>, CoreError> {
    let mut r = NdrReader::new(stub);
    let _length = r.read_u16()?;
    let _max_length = r.read_u16()?;
    let name_buf_ref = r.read_u32()?;

    let type_ref = r.read_u32()?;
    let val_type = if type_ref != 0 { r.read_u32()? } else { 0 };

    let data_ref = r.read_u32()?;

    let name = if name_buf_ref != 0 {
        read_deferred_unicode_string(&mut r)?
    } else {
        String::new()
    };

    let data = if data_ref != 0 {
        let max_count = r.read_u32()?;
        let _offset = r.read_u32()?;
        let actual_count = r.read_u32()?;
        if actual_count > max_count || actual_count > 10 * 1024 * 1024 {
            return Err(CoreError::ProtocolError("Invalid registry data count".into()));
        }
        let raw = r.read_bytes(actual_count as usize)?.to_vec();
        r.align(4)?;
        raw
    } else {
        Vec::new()
    };

    let _cb_data_ref = r.read_u32()?;
    let _cb_data = r.read_u32()?;
    let _cb_len_ref = r.read_u32()?;
    let _cb_len = r.read_u32()?;

    let err = r.read_u32()?;
    if err == ERROR_NO_MORE_ITEMS {
        return Ok(None);
    }
    accept_win32(err)?;
    Ok(Some((name, val_type, data)))
}

fn accept_win32(err: u32) -> Result<(), CoreError> {
    if err == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(CoreError::ProtocolError(format!("RRP Win32 error {}", err)))
    }
}

/// `[MS-RRP]` high-level client over a bound [`RpcTransport`] (`\PIPE\winreg`).
pub struct RrpClient<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> RrpClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            call_id: 1,
        }
    }

    fn call(&mut self, opnum: u16, stub: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let call_id = self.call_id;
        self.call_id += 1;
        let pdu = RpcRequestPdu {
            call_id,
            context_id: 0,
            opnum,
            stub_data: stub,
        }
        .to_bytes();
        let resp = self.transport.transceive(&pdu)?;
        extract_response_stub(&resp)
    }

    pub fn open_hive(&mut self, hive: RegHive, sam_desired: u32) -> Result<RegHandle, CoreError> {
        match hive {
            RegHive::ClassesRoot => self.open_classes_root(sam_desired),
            RegHive::CurrentUser => self.open_current_user(sam_desired),
            RegHive::LocalMachine => self.open_local_machine(sam_desired),
            RegHive::Users => self.open_users(sam_desired),
        }
    }

    pub fn open_classes_root(&mut self, sam_desired: u32) -> Result<RegHandle, CoreError> {
        let r = self.call(opnum::OPEN_CLASSES_ROOT, build_open_root_stub(sam_desired))?;
        parse_handle_response(&r)
    }

    pub fn open_current_user(&mut self, sam_desired: u32) -> Result<RegHandle, CoreError> {
        let r = self.call(opnum::OPEN_CURRENT_USER, build_open_root_stub(sam_desired))?;
        parse_handle_response(&r)
    }

    pub fn open_local_machine(&mut self, sam_desired: u32) -> Result<RegHandle, CoreError> {
        let r = self.call(opnum::OPEN_LOCAL_MACHINE, build_open_local_machine_stub(sam_desired))?;
        parse_handle_response(&r)
    }

    pub fn open_users(&mut self, sam_desired: u32) -> Result<RegHandle, CoreError> {
        let r = self.call(opnum::OPEN_USERS, build_open_root_stub(sam_desired))?;
        parse_handle_response(&r)
    }

    pub fn open_key(
        &mut self,
        hkey: &RegHandle,
        subkey: &str,
        sam_desired: u32,
    ) -> Result<RegHandle, CoreError> {
        let r = self.call(
            opnum::BASE_REG_OPEN_KEY,
            build_base_reg_open_key_stub(hkey, subkey, 0, sam_desired),
        )?;
        parse_handle_response(&r)
    }

    pub fn create_key(
        &mut self,
        hkey: &RegHandle,
        subkey: &str,
        sam_desired: u32,
    ) -> Result<RegHandle, CoreError> {
        let r = self.call(
            opnum::BASE_REG_CREATE_KEY,
            build_base_reg_create_key_stub(hkey, subkey, 0, sam_desired),
        )?;
        parse_handle_response(&r)
    }

    pub fn delete_key(&mut self, hkey: &RegHandle, subkey: &str) -> Result<(), CoreError> {
        let r = self.call(
            opnum::BASE_REG_DELETE_KEY,
            build_base_reg_delete_key_stub(hkey, subkey),
        )?;
        parse_error_response(&r)
    }

    pub fn delete_value(&mut self, hkey: &RegHandle, value_name: &str) -> Result<(), CoreError> {
        let r = self.call(
            opnum::BASE_REG_DELETE_VALUE,
            build_base_reg_delete_value_stub(hkey, value_name),
        )?;
        parse_error_response(&r)
    }

    pub fn set_value(
        &mut self,
        hkey: &RegHandle,
        value_name: &str,
        dw_type: u32,
        data: &[u8],
    ) -> Result<(), CoreError> {
        let r = self.call(
            opnum::BASE_REG_SET_VALUE,
            build_base_reg_set_value_stub(hkey, value_name, dw_type, data),
        )?;
        parse_error_response(&r)
    }

    pub fn query_value(
        &mut self,
        hkey: &RegHandle,
        value_name: &str,
    ) -> Result<(u32, Vec<u8>), CoreError> {
        let r = self.call(
            opnum::BASE_REG_QUERY_VALUE,
            build_base_reg_query_value_stub(hkey, value_name, 4096),
        )?;
        parse_query_value_response(&r)
    }

    pub fn enum_key(
        &mut self,
        hkey: &RegHandle,
        index: u32,
    ) -> Result<Option<String>, CoreError> {
        let r = self.call(opnum::BASE_REG_ENUM_KEY, build_base_reg_enum_key_stub(hkey, index))?;
        parse_enum_key_response(&r)
    }

    pub fn enum_value(
        &mut self,
        hkey: &RegHandle,
        index: u32,
    ) -> Result<Option<(String, u32, Vec<u8>)>, CoreError> {
        let r = self.call(
            opnum::BASE_REG_ENUM_VALUE,
            build_base_reg_enum_value_stub(hkey, index),
        )?;
        parse_enum_value_response(&r)
    }

    pub fn save_key(&mut self, hkey: &RegHandle, filename: &str) -> Result<(), CoreError> {
        let r = self.call(
            opnum::BASE_REG_SAVE_KEY,
            build_base_reg_save_key_stub(hkey, filename),
        )?;
        parse_error_response(&r)
    }

    pub fn close_key(&mut self, hkey: &RegHandle) -> Result<(), CoreError> {
        let r = self.call(
            opnum::BASE_REG_CLOSE_KEY,
            build_base_reg_close_key_stub(hkey),
        )?;
        parse_error_response(&r)
    }

    /// Enumerates all values in an opened key.
    pub fn enum_all_values(
        &mut self,
        hkey: &RegHandle,
    ) -> Result<Vec<(String, u32, Vec<u8>)>, CoreError> {
        let mut vals = Vec::new();
        let mut idx = 0u32;
        loop {
            match self.enum_value(hkey, idx)? {
                Some(v) => {
                    vals.push(v);
                    idx += 1;
                }
                None => break,
            }
        }
        Ok(vals)
    }

    /// Enumerates all subkey names in an opened key.
    pub fn enum_all_subkeys(
        &mut self,
        hkey: &RegHandle,
    ) -> Result<Vec<String>, CoreError> {
        let mut keys = Vec::new();
        let mut idx = 0u32;
        loop {
            match self.enum_key(hkey, idx)? {
                Some(k) => {
                    keys.push(k);
                    idx += 1;
                }
                None => break,
            }
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use impacket_dcerpc::{pdu_type, RpcCommonHeader};
    use impacket_ndr::NdrSerialize;
    use std::collections::VecDeque;

    struct MockRrp {
        responses: VecDeque<Vec<u8>>,
    }
    impl MockRrp {
        fn new(stubs: Vec<Vec<u8>>) -> Self {
            let responses = stubs
                .into_iter()
                .map(|stub| {
                    let frag_len = (24 + stub.len()) as u16;
                    let hdr = RpcCommonHeader::new(pdu_type::RPC_RESPONSE, frag_len, 0, 1);
                    let mut w = NdrWriter::with_capacity(frag_len as usize);
                    hdr.ndr_serialize(&mut w);
                    w.write_u32(stub.len() as u32);
                    w.write_u16(0);
                    w.write_u16(0);
                    w.write_bytes(&stub);
                    w.into_bytes()
                })
                .collect();
            Self { responses }
        }
    }
    impl RpcTransport for MockRrp {
        fn transceive(&mut self, _r: &[u8]) -> Result<Vec<u8>, CoreError> {
            self.responses
                .pop_front()
                .ok_or_else(|| CoreError::ProtocolError("no more".into()))
        }
    }

    fn handle_resp(h: [u8; 20]) -> Vec<u8> {
        let mut w = NdrWriter::with_capacity(24);
        w.write_fixed_array(&h);
        w.write_u32(0); // ERROR_SUCCESS
        w.into_bytes()
    }
    fn error_resp() -> Vec<u8> {
        let mut w = NdrWriter::with_capacity(4);
        w.write_u32(0);
        w.into_bytes()
    }

    #[test]
    fn test_rrp_open_save_close_flow() {
        let hklm = [0x11u8; 20];
        let subkey = [0x22u8; 20];
        let mock = MockRrp::new(vec![
            handle_resp(hklm),   // OpenLocalMachine
            handle_resp(subkey), // BaseRegOpenKey
            error_resp(),        // BaseRegSaveKey
            error_resp(),        // BaseRegCloseKey (subkey)
            error_resp(),        // BaseRegCloseKey (hklm)
        ]);
        let mut c = RrpClient::new(mock);
        let hklm_h = c.open_local_machine(MAXIMUM_ALLOWED).unwrap();
        assert_eq!(hklm_h, hklm);
        let sub_h = c.open_key(&hklm_h, "SYSTEM", MAXIMUM_ALLOWED).unwrap();
        assert_eq!(sub_h, subkey);
        c.save_key(&sub_h, r"Temp\x.save").unwrap();
        c.close_key(&sub_h).unwrap();
        c.close_key(&hklm_h).unwrap();
    }

    #[test]
    fn test_open_key_stub_defers_buffer() {
        let stub = build_base_reg_open_key_stub(&[0u8; 20], "SAM", 0, MAXIMUM_ALLOWED);
        // handle(20) + Length(2)=6 + MaxLength(2)=8 + referent(4) + options(4) + sam(4) + buffer.
        assert_eq!(u16::from_le_bytes([stub[20], stub[21]]), 6); // "SAM" = 3 chars * 2
        assert_eq!(u16::from_le_bytes([stub[22], stub[23]]), 8); // incl NUL
    }

    #[test]
    fn test_rrp_crud_operations() {
        let hkey = [0x33u8; 20];
        let new_key = [0x44u8; 20];

        // 1. Create key response
        let mut create_resp = Vec::new();
        create_resp.extend_from_slice(&new_key);
        create_resp.extend_from_slice(&1u32.to_le_bytes()); // REG_CREATED_NEW_KEY
        create_resp.extend_from_slice(&0u32.to_le_bytes()); // ERROR_SUCCESS

        // 2. Query value response: REG_SZ "TestData"
        let mut query_resp = Vec::new();
        query_resp.extend_from_slice(&REFERENT_BASE.to_le_bytes());
        query_resp.extend_from_slice(&reg_type::REG_SZ.to_le_bytes());
        query_resp.extend_from_slice(&(REFERENT_BASE + 4).to_le_bytes());
        let val_bytes = encode_utf16le("TestData\0");
        query_resp.extend_from_slice(&(val_bytes.len() as u32).to_le_bytes()); // max_count
        query_resp.extend_from_slice(&0u32.to_le_bytes()); // offset
        query_resp.extend_from_slice(&(val_bytes.len() as u32).to_le_bytes()); // actual_count
        query_resp.extend_from_slice(&val_bytes);
        while query_resp.len() % 4 != 0 {
            query_resp.push(0);
        }
        query_resp.extend_from_slice(&(REFERENT_BASE + 8).to_le_bytes());
        query_resp.extend_from_slice(&(val_bytes.len() as u32).to_le_bytes());
        query_resp.extend_from_slice(&(REFERENT_BASE + 12).to_le_bytes());
        query_resp.extend_from_slice(&(val_bytes.len() as u32).to_le_bytes());
        query_resp.extend_from_slice(&0u32.to_le_bytes()); // ERROR_SUCCESS

        let mock = MockRrp::new(vec![
            create_resp,  // create_key
            error_resp(), // set_value
            query_resp,   // query_value
            error_resp(), // delete_value
            error_resp(), // delete_key
        ]);

        let mut c = RrpClient::new(mock);
        let created = c.create_key(&hkey, "Software\\ImpacketTest", MAXIMUM_ALLOWED).unwrap();
        assert_eq!(created, new_key);

        c.set_value(&created, "TestVal", reg_type::REG_SZ, &val_bytes).unwrap();
        let (val_type, data) = c.query_value(&created, "TestVal").unwrap();
        assert_eq!(val_type, reg_type::REG_SZ);
        assert_eq!(data, val_bytes);

        c.delete_value(&created, "TestVal").unwrap();
        c.delete_key(&hkey, "Software\\ImpacketTest").unwrap();
    }

    #[test]
    fn test_reg_path_parsing_and_data_codecs() {
        // Path parsing
        let (hive, sub) = parse_reg_key_path(r"HKLM\SYSTEM\CurrentControlSet\Services").unwrap();
        assert_eq!(hive, RegHive::LocalMachine);
        assert_eq!(sub, r"SYSTEM\CurrentControlSet\Services");

        let (hive2, sub2) = parse_reg_key_path("HKEY_CURRENT_USER/Software/Test").unwrap();
        assert_eq!(hive2, RegHive::CurrentUser);
        assert_eq!(sub2, r"Software\Test");

        // Codecs: REG_SZ
        let enc_sz = encode_reg_data(reg_type::REG_SZ, "Hello").unwrap();
        assert_eq!(format_reg_data(reg_type::REG_SZ, &enc_sz), "Hello");

        // Codecs: REG_DWORD
        let enc_dw = encode_reg_data(reg_type::REG_DWORD, "1337").unwrap();
        assert_eq!(enc_dw, 1337u32.to_le_bytes());
        assert_eq!(format_reg_data(reg_type::REG_DWORD, &enc_dw), "0x539 (1337)");

        // Codecs: REG_BINARY
        let enc_bin = encode_reg_data(reg_type::REG_BINARY, "dead beef cafe").unwrap();
        assert_eq!(enc_bin, vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]);
        assert_eq!(format_reg_data(reg_type::REG_BINARY, &enc_bin), "deadbeefcafe");
    }
}
