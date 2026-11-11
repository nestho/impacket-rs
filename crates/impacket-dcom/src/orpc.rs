//! `orpc`: `[MS-DCOM]` Object Remote Procedure Call (ORPC) framing, `COMVERSION`, `ORPCTHIS`, and `ORPCTHAT`.

use impacket_core::CoreError;
use impacket_ndr::{NdrReader, NdrWriter, RpcUuid};

/// DCOM Protocol Version (`COMVERSION`, `[MS-DCOM]` Section 2.2.11).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ComVersion {
    pub major: u16,
    pub minor: u16,
}

impl ComVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// COM version 5.7 (Windows Server 2008 R2, 2012, 2016, 2019, 2022, 2025, Windows 7/10/11).
    pub const fn v5_7() -> Self {
        Self { major: 5, minor: 7 }
    }

    /// COM version 5.6 (Windows Vista / Server 2008).
    pub const fn v5_6() -> Self {
        Self { major: 5, minor: 6 }
    }

    /// COM version 5.4 (Windows XP / Server 2003).
    pub const fn v5_4() -> Self {
        Self { major: 5, minor: 4 }
    }

    /// COM version 5.1 (Windows 2000 / NT 4.0).
    pub const fn v5_1() -> Self {
        Self { major: 5, minor: 1 }
    }
}

impl Default for ComVersion {
    fn default() -> Self {
        Self::v5_7()
    }
}

/// `ORPCTHIS`: Header preceding every DCOM ORPC request stub (`[MS-DCOM]` Section 2.2.13.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrpcThis {
    pub version: ComVersion,
    pub flags: u32,
    pub reserved1: u32,
    pub cid: RpcUuid,
}

impl OrpcThis {
    pub fn new(cid: RpcUuid) -> Self {
        Self {
            version: ComVersion::v5_7(),
            flags: 0,
            reserved1: 0,
            cid,
        }
    }

    pub fn serialize(&self, writer: &mut NdrWriter) {
        writer.write_u16(self.version.major);
        writer.write_u16(self.version.minor);
        writer.write_u32(self.flags);
        writer.write_u32(self.reserved1);
        self.cid.to_le_bytes(); // Ensure 16-byte layout
        writer.write_u32(self.cid.data1);
        writer.write_u16(self.cid.data2);
        writer.write_u16(self.cid.data3);
        writer.write_fixed_array(&self.cid.data4);
        writer.write_u32(0); // extensions pointer (NULL)
    }

    pub fn deserialize(reader: &mut NdrReader) -> Result<Self, CoreError> {
        let major = reader.read_u16()?;
        let minor = reader.read_u16()?;
        let flags = reader.read_u32()?;
        let reserved1 = reader.read_u32()?;
        let data1 = reader.read_u32()?;
        let data2 = reader.read_u16()?;
        let data3 = reader.read_u16()?;
        let data4 = reader.read_fixed_array::<8>()?;
        let _extensions_ptr = reader.read_u32()?;

        Ok(Self {
            version: ComVersion::new(major, minor),
            flags,
            reserved1,
            cid: RpcUuid::new(data1, data2, data3, data4),
        })
    }
}

/// `ORPCTHAT`: Header preceding every DCOM ORPC response stub (`[MS-DCOM]` Section 2.2.13.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrpcThat {
    pub flags: u32,
}

impl OrpcThat {
    pub fn new(flags: u32) -> Self {
        Self { flags }
    }

    pub fn serialize(&self, writer: &mut NdrWriter) {
        writer.write_u32(self.flags);
        writer.write_u32(0); // extensions pointer (NULL)
    }

    pub fn deserialize(reader: &mut NdrReader) -> Result<Self, CoreError> {
        let flags = reader.read_u32()?;
        let _extensions_ptr = reader.read_u32()?;
        Ok(Self { flags })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orpc_this_and_that_roundtrip() {
        let cid = RpcUuid::new(0x12345678, 0x1234, 0x5678, [1, 2, 3, 4, 5, 6, 7, 8]);
        let orpc_this = OrpcThis::new(cid);

        let mut writer = NdrWriter::new();
        orpc_this.serialize(&mut writer);

        let mut reader = NdrReader::new(writer.as_slice());
        let decoded = OrpcThis::deserialize(&mut reader).unwrap();

        assert_eq!(decoded.version.major, 5);
        assert_eq!(decoded.version.minor, 7);
        assert_eq!(decoded.cid, cid);

        let orpc_that = OrpcThat::new(0);
        let mut that_writer = NdrWriter::new();
        orpc_that.serialize(&mut that_writer);

        let mut that_reader = NdrReader::new(that_writer.as_slice());
        let decoded_that = OrpcThat::deserialize(&mut that_reader).unwrap();
        assert_eq!(decoded_that.flags, 0);
    }
}
