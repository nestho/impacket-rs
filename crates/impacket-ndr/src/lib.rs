//! `impacket-ndr`: High-performance, compile-time bounds-checked NDR (Network Data Representation)
//! transfer syntax engine (MS-RPCE, little-endian) replacing `impacket/structure.py` and `impacket/dcerpc/v5/ndr.py`.
//!
//! Features:
//! - Zero-allocation cursor reader (`NdrReader`) and pre-allocated buffer writer (`NdrWriter`)
//! - Automatic 2, 4, and 8-byte NDR stream alignment
//! - Conformant and varying UTF-16LE NDR strings (`NdrUnicodeString` — replacing `'w'` format in `structure.py`)
//! - Windows RPC SID (`RpcSid`), GUID/UUID (`RpcUuid`), and `RpcSyntaxId`
//! - `ndr_struct!` declarative macro for compile-time struct marshaling without runtime string parsing

use impacket_core::{decode_utf16le, encode_utf16le, CoreError};
use std::fmt;

/// Trait for types that can be serialized into an NDR byte stream.
pub trait NdrSerialize {
    fn ndr_serialize(&self, writer: &mut NdrWriter);
}

/// Trait for types that can be deserialized from an NDR byte stream with compile-time bounds checking.
pub trait NdrDeserialize: Sized {
    fn ndr_deserialize(reader: &mut NdrReader<'_>) -> Result<Self, CoreError>;
}

/// High-speed NDR byte writer with automatic alignment padding.
#[derive(Debug, Default, Clone)]
pub struct NdrWriter {
    buf: Vec<u8>,
}

impl NdrWriter {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
        }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Pads buffer with zeros to reach `align`-byte boundary (2, 4, or 8).
    #[inline]
    pub fn align(&mut self, align: usize) {
        debug_assert!(align.is_power_of_two());
        let rem = self.buf.len() & (align - 1);
        if rem != 0 {
            let pad = align - rem;
            self.buf.resize(self.buf.len() + pad, 0);
        }
    }

    #[inline]
    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    #[inline]
    pub fn write_u16(&mut self, v: u16) {
        self.align(2);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn write_u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn write_u64(&mut self, v: u64) {
        self.align(8);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    #[inline]
    pub fn write_fixed_array<const N: usize>(&mut self, arr: &[u8; N]) {
        self.buf.extend_from_slice(arr);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// Zero-copy NDR byte reader with automatic alignment and strict bounds checking.
#[derive(Debug, Clone)]
pub struct NdrReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> NdrReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    #[inline]
    pub fn align(&mut self, align: usize) -> Result<(), CoreError> {
        debug_assert!(align.is_power_of_two());
        let rem = self.pos & (align - 1);
        if rem != 0 {
            let pad = align - rem;
            self.ensure(pad)?;
            self.pos += pad;
        }
        Ok(())
    }

    #[inline]
    fn ensure(&self, count: usize) -> Result<(), CoreError> {
        if self.remaining() < count {
            Err(CoreError::BufferUnderflow {
                needed: count,
                available: self.remaining(),
            })
        } else {
            Ok(())
        }
    }

    #[inline]
    pub fn read_u8(&mut self) -> Result<u8, CoreError> {
        self.ensure(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    #[inline]
    pub fn read_u16(&mut self) -> Result<u16, CoreError> {
        self.align(2)?;
        self.ensure(2)?;
        let bytes = [self.data[self.pos], self.data[self.pos + 1]];
        self.pos += 2;
        Ok(u16::from_le_bytes(bytes))
    }

    #[inline]
    pub fn read_u32(&mut self) -> Result<u32, CoreError> {
        self.align(4)?;
        self.ensure(4)?;
        let bytes = [
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ];
        self.pos += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    #[inline]
    pub fn read_u64(&mut self) -> Result<u64, CoreError> {
        self.align(8)?;
        self.ensure(8)?;
        let bytes: [u8; 8] = self.data[self.pos..self.pos + 8].try_into().unwrap();
        self.pos += 8;
        Ok(u64::from_le_bytes(bytes))
    }

    #[inline]
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], CoreError> {
        self.ensure(len)?;
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    #[inline]
    pub fn read_fixed_array<const N: usize>(&mut self) -> Result<[u8; N], CoreError> {
        let slice = self.read_bytes(N)?;
        Ok(slice.try_into().unwrap())
    }
}

impl NdrSerialize for u8 {
    #[inline]
    fn ndr_serialize(&self, writer: &mut NdrWriter) {
        writer.write_u8(*self);
    }
}
impl NdrDeserialize for u8 {
    #[inline]
    fn ndr_deserialize(reader: &mut NdrReader<'_>) -> Result<Self, CoreError> {
        reader.read_u8()
    }
}

impl NdrSerialize for u16 {
    #[inline]
    fn ndr_serialize(&self, writer: &mut NdrWriter) {
        writer.write_u16(*self);
    }
}
impl NdrDeserialize for u16 {
    #[inline]
    fn ndr_deserialize(reader: &mut NdrReader<'_>) -> Result<Self, CoreError> {
        reader.read_u16()
    }
}

impl NdrSerialize for u32 {
    #[inline]
    fn ndr_serialize(&self, writer: &mut NdrWriter) {
        writer.write_u32(*self);
    }
}
impl NdrDeserialize for u32 {
    #[inline]
    fn ndr_deserialize(reader: &mut NdrReader<'_>) -> Result<Self, CoreError> {
        reader.read_u32()
    }
}

impl NdrSerialize for u64 {
    #[inline]
    fn ndr_serialize(&self, writer: &mut NdrWriter) {
        writer.write_u64(*self);
    }
}
impl NdrDeserialize for u64 {
    #[inline]
    fn ndr_deserialize(reader: &mut NdrReader<'_>) -> Result<Self, CoreError> {
        reader.read_u64()
    }
}

impl<const N: usize> NdrSerialize for [u8; N] {
    #[inline]
    fn ndr_serialize(&self, writer: &mut NdrWriter) {
        writer.write_fixed_array(self);
    }
}
impl<const N: usize> NdrDeserialize for [u8; N] {
    #[inline]
    fn ndr_deserialize(reader: &mut NdrReader<'_>) -> Result<Self, CoreError> {
        reader.read_fixed_array::<N>()
    }
}

/// DCE-RPC/NDR Conformant & Varying Unicode String (`'w'` format specifier in `impacket/structure.py`).
///
/// Wire layout:
/// - `max_count: u32` (number of UTF-16 code units including NUL terminator)
/// - `offset: u32` (always 0)
/// - `actual_count: u32` (number of UTF-16 code units including NUL terminator)
/// - `utf16le_bytes: [u8; actual_count * 2]`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NdrUnicodeString(pub String);

impl NdrUnicodeString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl NdrSerialize for NdrUnicodeString {
    fn ndr_serialize(&self, writer: &mut NdrWriter) {
        let mut utf16_bytes = encode_utf16le(&self.0);
        // Append NUL-NUL UTF-16 terminator
        utf16_bytes.extend_from_slice(&[0x00, 0x00]);
        let char_count = (utf16_bytes.len() / 2) as u32;

        writer.write_u32(char_count); // MaxCount
        writer.write_u32(0); // Offset
        writer.write_u32(char_count); // ActualCount
        writer.write_bytes(&utf16_bytes);
    }
}

impl NdrDeserialize for NdrUnicodeString {
    fn ndr_deserialize(reader: &mut NdrReader<'_>) -> Result<Self, CoreError> {
        let max_count = reader.read_u32()?;
        let _offset = reader.read_u32()?;
        let actual_count = reader.read_u32()?;

        if actual_count > max_count || actual_count > 65536 {
            return Err(CoreError::ProtocolError(format!(
                "Invalid NDR string counts: max={}, actual={}",
                max_count, actual_count
            )));
        }

        let byte_len = (actual_count as usize) * 2;
        let raw = reader.read_bytes(byte_len)?;
        // Strip trailing NUL UTF-16 code unit if present
        let stripped = if raw.len() >= 2 && raw[raw.len() - 2..] == [0, 0] {
            &raw[..raw.len() - 2]
        } else {
            raw
        };
        Ok(Self(decode_utf16le(stripped)?))
    }
}

/// DCE/RPC UUID (`impacket/uuid.py`), stored in mixed-endian MS-RPCE wire format.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RpcUuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl RpcUuid {
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// Parses canonical UUID string `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
    pub fn parse(s: &str) -> Result<Self, CoreError> {
        let parts: Vec<&str> = s.trim().split('-').collect();
        if parts.len() != 5 {
            return Err(CoreError::ProtocolError(format!("Invalid UUID: {}", s)));
        }
        let data1 = u32::from_str_radix(parts[0], 16)
            .map_err(|_| CoreError::ProtocolError("Invalid UUID data1".into()))?;
        let data2 = u16::from_str_radix(parts[1], 16)
            .map_err(|_| CoreError::ProtocolError("Invalid UUID data2".into()))?;
        let data3 = u16::from_str_radix(parts[2], 16)
            .map_err(|_| CoreError::ProtocolError("Invalid UUID data3".into()))?;
        let d4_hi = impacket_core::decode_hex(parts[3])?;
        let d4_lo = impacket_core::decode_hex(parts[4])?;
        if d4_hi.len() != 2 || d4_lo.len() != 6 {
            return Err(CoreError::ProtocolError("Invalid UUID data4 length".into()));
        }
        let mut data4 = [0u8; 8];
        data4[0..2].copy_from_slice(&d4_hi);
        data4[2..8].copy_from_slice(&d4_lo);

        Ok(Self {
            data1,
            data2,
            data3,
            data4,
        })
    }

    /// Converts UUID to 16 little-endian bytes (Windows GUID format: data1 LE, data2 LE, data3 LE, data4 BE).
    pub fn to_le_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&self.data1.to_le_bytes());
        out[4..6].copy_from_slice(&self.data2.to_le_bytes());
        out[6..8].copy_from_slice(&self.data3.to_le_bytes());
        out[8..16].copy_from_slice(&self.data4);
        out
    }

    /// Parses UUID from 16 little-endian bytes (Windows GUID format).
    pub fn from_le_bytes(bytes: [u8; 16]) -> Self {
        let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
        let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(&bytes[8..16]);
        Self {
            data1,
            data2,
            data3,
            data4,
        }
    }
}

impl fmt::Display for RpcUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }
}

impl fmt::Debug for RpcUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RpcUuid({})", self)
    }
}

impl NdrSerialize for RpcUuid {
    #[inline]
    fn ndr_serialize(&self, writer: &mut NdrWriter) {
        writer.write_u32(self.data1);
        writer.write_u16(self.data2);
        writer.write_u16(self.data3);
        writer.write_fixed_array(&self.data4);
    }
}

impl NdrDeserialize for RpcUuid {
    #[inline]
    fn ndr_deserialize(reader: &mut NdrReader<'_>) -> Result<Self, CoreError> {
        Ok(Self {
            data1: reader.read_u32()?,
            data2: reader.read_u16()?,
            data3: reader.read_u16()?,
            data4: reader.read_fixed_array::<8>()?,
        })
    }
}

/// Windows Security Identifier (`RPC_SID` / `SAMPR_SID_INFORMATION`), supporting string conversion
/// (`S-1-5-21-...`) and binary NDR wire serialization.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RpcSid {
    pub revision: u8,
    pub identifier_authority: [u8; 6],
    pub sub_authorities: Vec<u32>,
}

impl RpcSid {
    /// Parses a canonical SID string like `S-1-5-21-3623811015-3361044348-30300820-1013`
    pub fn parse(s: &str) -> Result<Self, CoreError> {
        let parts: Vec<&str> = s.trim().split('-').collect();
        if parts.len() < 3 || !parts[0].eq_ignore_ascii_case("S") {
            return Err(CoreError::ProtocolError(format!("Invalid SID string: {}", s)));
        }
        let revision: u8 = parts[1]
            .parse()
            .map_err(|_| CoreError::ProtocolError("Invalid SID revision".into()))?;
        let auth_val: u64 = parts[2]
            .parse()
            .map_err(|_| CoreError::ProtocolError("Invalid SID authority".into()))?;
        let auth_bytes = auth_val.to_be_bytes();
        let mut identifier_authority = [0u8; 6];
        identifier_authority.copy_from_slice(&auth_bytes[2..8]);

        let mut sub_authorities = Vec::with_capacity(parts.len() - 3);
        for sub in &parts[3..] {
            let val: u32 = sub
                .parse()
                .map_err(|_| CoreError::ProtocolError(format!("Invalid sub-authority: {}", sub)))?;
            sub_authorities.push(val);
        }

        Ok(Self {
            revision,
            identifier_authority,
            sub_authorities,
        })
    }

    /// Parses a raw binary SID (`[MS-DTYP]` 2.4.2).
    pub fn from_le_bytes(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 8 {
            return Err(CoreError::BufferUnderflow {
                needed: 8,
                available: data.len(),
            });
        }
        let revision = data[0];
        let sub_auth_count = data[1] as usize;
        let mut identifier_authority = [0u8; 6];
        identifier_authority.copy_from_slice(&data[2..8]);

        let total_len = 8 + sub_auth_count * 4;
        if data.len() < total_len {
            return Err(CoreError::BufferUnderflow {
                needed: total_len,
                available: data.len(),
            });
        }

        let mut sub_authorities = Vec::with_capacity(sub_auth_count);
        for i in 0..sub_auth_count {
            let off = 8 + i * 4;
            let sub = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            sub_authorities.push(sub);
        }

        Ok(Self {
            revision,
            identifier_authority,
            sub_authorities,
        })
    }

    /// Serializes to raw binary SID (`[MS-DTYP]` 2.4.2).
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.sub_authorities.len() * 4);
        out.push(self.revision);
        out.push(self.sub_authorities.len() as u8);
        out.extend_from_slice(&self.identifier_authority);
        for &sub in &self.sub_authorities {
            out.extend_from_slice(&sub.to_le_bytes());
        }
        out
    }
}

impl fmt::Display for RpcSid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut auth_be = [0u8; 8];
        auth_be[2..8].copy_from_slice(&self.identifier_authority);
        let auth_val = u64::from_be_bytes(auth_be);
        write!(f, "S-{}-{}", self.revision, auth_val)?;
        for sub in &self.sub_authorities {
            write!(f, "-{}", sub)?;
        }
        Ok(())
    }
}

impl NdrSerialize for RpcSid {
    fn ndr_serialize(&self, writer: &mut NdrWriter) {
        let count = self.sub_authorities.len() as u32;
        writer.write_u32(count); // NDR conformant array max_count
        writer.write_u8(self.revision);
        writer.write_u8(count as u8);
        writer.write_fixed_array(&self.identifier_authority);
        for &sub in &self.sub_authorities {
            writer.write_u32(sub);
        }
    }
}

impl NdrDeserialize for RpcSid {
    fn ndr_deserialize(reader: &mut NdrReader<'_>) -> Result<Self, CoreError> {
        let max_count = reader.read_u32()?;
        let revision = reader.read_u8()?;
        let sub_count = reader.read_u8()?;
        if (sub_count as u32) != max_count || sub_count > 15 {
            return Err(CoreError::ProtocolError(format!(
                "Invalid RPC_SID sub_authority count: max={}, sub={}",
                max_count, sub_count
            )));
        }
        let identifier_authority = reader.read_fixed_array::<6>()?;
        let mut sub_authorities = Vec::with_capacity(sub_count as usize);
        for _ in 0..sub_count {
            sub_authorities.push(reader.read_u32()?);
        }
        Ok(Self {
            revision,
            identifier_authority,
            sub_authorities,
        })
    }
}

/// Declarative compile-time struct generator that automatically implements `NdrSerialize` and
/// `NdrDeserialize` for protocol PDU and MSRPC structures, completely replacing `impacket/structure.py`.
#[macro_export]
macro_rules! ndr_struct {
    (
        $(#[$meta:meta])*
        pub struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                pub $field:ident : $fty:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name {
            $(
                $(#[$field_meta])*
                pub $field : $fty,
            )*
        }

        impl $crate::NdrSerialize for $name {
            #[inline]
            fn ndr_serialize(&self, writer: &mut $crate::NdrWriter) {
                $(
                    <$fty as $crate::NdrSerialize>::ndr_serialize(&self.$field, writer);
                )*
            }
        }

        impl $crate::NdrDeserialize for $name {
            #[inline]
            fn ndr_deserialize(reader: &mut $crate::NdrReader<'_>) -> Result<Self, impacket_core::CoreError> {
                Ok(Self {
                    $(
                        $field: <$fty as $crate::NdrDeserialize>::ndr_deserialize(reader)?,
                    )*
                })
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    ndr_struct! {
        pub struct SamrOpenDomainStub {
            pub context_handle: [u8; 20],
            pub desired_access: u32,
            pub domain_sid: RpcSid,
        }
    }

    #[test]
    fn test_ndr_unicode_string_matches_impacket_w_specifier() {
        // In impacket/structure.py, 'w' packs: <L (len), \x00\x00\x00\x00, <L (len), UTF-16LE + \x00\x00
        let s = NdrUnicodeString::new("ADMIN$");
        let mut writer = NdrWriter::new();
        s.ndr_serialize(&mut writer);
        let bytes = writer.into_bytes();

        // "ADMIN$" is 6 chars + 1 NUL = 7 UTF-16 code units -> 12 bytes header + 14 bytes payload = 26 bytes
        assert_eq!(bytes.len(), 26);
        let mut reader = NdrReader::new(&bytes);
        let decoded = NdrUnicodeString::ndr_deserialize(&mut reader).unwrap();
        assert_eq!(decoded.as_str(), "ADMIN$");
    }

    #[test]
    fn test_ndr_sid_and_macro_struct_roundtrip() {
        let sid = RpcSid::parse("S-1-5-21-3623811015-3361044348-30300820").unwrap();
        let stub = SamrOpenDomainStub {
            context_handle: [0x11; 20],
            desired_access: 0x0002_035A,
            domain_sid: sid.clone(),
        };

        let mut writer = NdrWriter::new();
        stub.ndr_serialize(&mut writer);

        let mut reader = NdrReader::new(writer.as_slice());
        let unpacked = SamrOpenDomainStub::ndr_deserialize(&mut reader).unwrap();
        assert_eq!(unpacked, stub);
        assert_eq!(
            unpacked.domain_sid.to_string(),
            "S-1-5-21-3623811015-3361044348-30300820"
        );
    }
}
