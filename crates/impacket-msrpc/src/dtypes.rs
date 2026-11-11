//! Shared NDR20 pointer + string marshalling helpers for the real `[MS-SAMR]` / `[MS-LSAT]` / `[MS-SRVS]`
//! wire modules. These implement the pointer-referent + deferral discipline and the two Windows string
//! shapes by hand, since the project avoids a full generic NDR engine.
//!
//! Two string shapes appear on the wire:
//! - `[string] wchar_t*` — a conformant+varying array that **includes** a trailing NUL
//!   (`MaxCount`/`ActualCount` count the NUL). Used for `ServerName`, `SHARE_INFO_1` fields, etc.
//! - `RPC_UNICODE_STRING { Length, MaximumLength, Buffer }` — a counted header whose `Buffer` pointee is a
//!   conformant+varying array with **no** NUL. Used for SAMR names, domain names, etc.

use impacket_core::{decode_utf16le, encode_utf16le, CoreError};
use impacket_ndr::{NdrReader, NdrWriter};

/// Base referent id for top-level `unique` pointers (any non-zero value is valid on the wire;
/// Windows/Impacket emit `0x00020000`).
pub const REFERENT_BASE: u32 = 0x0002_0000;

/// Marshals a `[string] wchar_t*` pointee: NUL-terminated conformant+varying array.
pub fn write_string_wchar_pointee(w: &mut NdrWriter, s: &str) {
    let mut utf16 = encode_utf16le(s);
    utf16.extend_from_slice(&[0, 0]); // NUL terminator
    let count = (utf16.len() / 2) as u32;
    w.write_u32(count); // MaxCount (incl NUL)
    w.write_u32(0); // Offset
    w.write_u32(count); // ActualCount (incl NUL)
    w.write_bytes(&utf16);
    w.align(4);
}

/// Reads a `[string] wchar_t*` pointee (NUL-terminated conformant+varying) and strips the trailing NUL.
pub fn read_string_wchar_pointee(r: &mut NdrReader<'_>) -> Result<String, CoreError> {
    let max_count = r.read_u32()?;
    let _offset = r.read_u32()?;
    let actual_count = r.read_u32()?;
    if actual_count > max_count || actual_count > 65_536 {
        return Err(CoreError::ProtocolError(format!(
            "[string] wchar counts invalid: max={}, actual={}",
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

/// Marshals an `RPC_UNICODE_STRING` inline header `{ Length: u16, MaximumLength: u16, Buffer: referent }`.
/// Returns the referent written (0 when empty). Caller must defer [`write_counted_wchar_pointee`].
pub fn write_rpc_unicode_string_header(w: &mut NdrWriter, s: &str, referent: u32) -> u32 {
    let byte_len = encode_utf16le(s).len() as u16;
    w.write_u16(byte_len); // Length (no NUL)
    w.write_u16(byte_len); // MaximumLength
    if byte_len == 0 {
        w.write_u32(0);
        0
    } else {
        w.write_u32(referent);
        referent
    }
}

/// Marshals an `RPC_UNICODE_STRING` deferred `Buffer` pointee: conformant+varying wchar, no NUL.
pub fn write_counted_wchar_pointee(w: &mut NdrWriter, s: &str) {
    let utf16 = encode_utf16le(s);
    let count = (utf16.len() / 2) as u32;
    w.write_u32(count); // MaxCount
    w.write_u32(0); // Offset
    w.write_u32(count); // ActualCount
    w.write_bytes(&utf16);
    w.align(4);
}

/// Reads an `RPC_UNICODE_STRING` inline header, returning `(byte_length, buffer_referent)`.
pub fn read_rpc_unicode_string_header(r: &mut NdrReader<'_>) -> Result<(u16, u32), CoreError> {
    let length = r.read_u16()?;
    let _max_length = r.read_u16()?;
    let referent = r.read_u32()?;
    Ok((length, referent))
}

/// Reads a deferred `RPC_UNICODE_STRING` `Buffer` pointee (no NUL assumption).
pub fn read_counted_wchar_pointee(r: &mut NdrReader<'_>) -> Result<String, CoreError> {
    let max_count = r.read_u32()?;
    let _offset = r.read_u32()?;
    let actual_count = r.read_u32()?;
    if actual_count > max_count || actual_count > 65_536 {
        return Err(CoreError::ProtocolError(format!(
            "RPC_UNICODE_STRING buffer counts invalid: max={}, actual={}",
            max_count, actual_count
        )));
    }
    let raw = r.read_bytes((actual_count as usize) * 2)?;
    let s = decode_utf16le(raw)?;
    r.align(4)?;
    Ok(s)
}
