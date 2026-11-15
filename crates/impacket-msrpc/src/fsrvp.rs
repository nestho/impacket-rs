//! `fsrvp`: `[MS-FSRVP]` File Server Remote VSS Protocol client (`impacket/dcerpc/v5/fsrvp.py`).
//!
//! Provides pure-Rust RPC methods for remote shadow copy operations and path interrogation:
//! - `GetSupportedVersion` (Opnum 8)
//! - `SetContext` (Opnum 9)
//! - `IsPathSupported` (Opnum 10)
//! - `IsPathShadowCopied` (Opnum 11)

use crate::dtypes::{read_string_wchar_pointee, write_string_wchar_pointee, REFERENT_BASE};
use impacket_core::CoreError;
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport, RpcUuid};
use impacket_ndr::{NdrReader, NdrWriter};

/// `[MS-FSRVP]` Interface UUID: `a8e0653c-2744-4389-a61d-7373df8b2292` v1.0
pub const FSRVP_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0xa8e0_653c,
    0x2744,
    0x4389,
    [0xa6, 0x1d, 0x73, 0x73, 0xdf, 0x8b, 0x22, 0x92],
);
pub const FSRVP_VERSION_MAJOR: u16 = 1;
pub const FSRVP_VERSION_MINOR: u16 = 0;
pub const FSRVP_PIPE: &str = r"\PIPE\fssagentrpc";

pub mod opnum {
    pub const GET_SUPPORTED_VERSION: u16 = 8;
    pub const SET_CONTEXT: u16 = 9;
    pub const IS_PATH_SUPPORTED: u16 = 10;
    pub const IS_PATH_SHADOW_COPIED: u16 = 11;
}

pub mod fsrvp_context {
    pub const FSRVP_CTX_BACKUP: u32 = 0x0000_0001;
    pub const FSRVP_CTX_FILE_SHARE_BACKUP: u32 = 0x0000_0010;
}

/// Builds request stub for `GetSupportedVersion` (Opnum 8):
/// Takes no input parameters.
pub fn build_get_supported_version_stub() -> Vec<u8> {
    Vec::new()
}

/// Parses response stub for `GetSupportedVersion` (Opnum 8):
/// - `MinVersion`: [out] DWORD
/// - `MaxVersion`: [out] DWORD
/// - `ErrorCode`: [out] DWORD
pub fn parse_get_supported_version_response(stub: &[u8]) -> Result<(u32, u32), CoreError> {
    let mut r = NdrReader::new(stub);
    let min_ver = r.read_u32()?;
    let max_ver = r.read_u32()?;
    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::ProtocolError(format!(
            "GetSupportedVersion failed with status 0x{:08x}",
            status
        )));
    }
    Ok((min_ver, max_ver))
}

/// Builds request stub for `SetContext` (Opnum 9):
/// - `Context`: [in] unsigned long
pub fn build_set_context_stub(context: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(4);
    w.write_u32(context);
    w.into_bytes()
}

/// Parses response stub for `SetContext` (Opnum 9):
/// - `ErrorCode`: [out] DWORD
pub fn parse_set_context_response(stub: &[u8]) -> Result<u32, CoreError> {
    let mut r = NdrReader::new(stub);
    r.read_u32()
}

/// Builds request stub for `IsPathSupported` (Opnum 10):
/// - `ShareName`: [in, string] wchar_t*
pub fn build_is_path_supported_stub(share_name: &str) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_u32(REFERENT_BASE);
    write_string_wchar_pointee(&mut w, share_name);
    w.into_bytes()
}

/// Parses response stub for `IsPathSupported` (Opnum 10):
/// - `SupportedByThisProvider`: [out] BOOL
/// - `OwnerMachineName`: [out, string] wchar_t**
/// - `ErrorCode`: [out] DWORD
pub fn parse_is_path_supported_response(
    stub: &[u8],
) -> Result<(bool, Option<String>), CoreError> {
    let mut r = NdrReader::new(stub);
    let supported = r.read_u32()? != 0;
    let owner_ref = r.read_u32()?;
    let owner_name = if owner_ref != 0 {
        Some(read_string_wchar_pointee(&mut r)?)
    } else {
        None
    };
    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::ProtocolError(format!(
            "IsPathSupported failed with status 0x{:08x}",
            status
        )));
    }
    Ok((supported, owner_name))
}

/// `[MS-FSRVP]` Client over an RPC transport.
pub struct FsrvpClient<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> FsrvpClient<T> {
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

    /// `GetSupportedVersion` (Opnum 8)
    pub fn get_supported_version(&mut self) -> Result<(u32, u32), CoreError> {
        let stub = build_get_supported_version_stub();
        let resp = self.call(opnum::GET_SUPPORTED_VERSION, stub)?;
        parse_get_supported_version_response(&resp)
    }

    /// `SetContext` (Opnum 9)
    pub fn set_context(&mut self, context: u32) -> Result<u32, CoreError> {
        let stub = build_set_context_stub(context);
        let resp = self.call(opnum::SET_CONTEXT, stub)?;
        parse_set_context_response(&resp)
    }

    /// `IsPathSupported` (Opnum 10)
    pub fn is_path_supported(&mut self, share_name: &str) -> Result<(bool, Option<String>), CoreError> {
        let stub = build_is_path_supported_stub(share_name);
        let resp = self.call(opnum::IS_PATH_SUPPORTED, stub)?;
        parse_is_path_supported_response(&resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fsrvp_get_supported_version_stub_and_response() {
        let stub = build_get_supported_version_stub();
        assert!(stub.is_empty());

        let mut resp = Vec::new();
        resp.extend_from_slice(&1u32.to_le_bytes()); // MinVersion
        resp.extend_from_slice(&2u32.to_le_bytes()); // MaxVersion
        resp.extend_from_slice(&0u32.to_le_bytes()); // ErrorCode: SUCCESS
        let (min, max) = parse_get_supported_version_response(&resp).unwrap();
        assert_eq!(min, 1);
        assert_eq!(max, 2);
    }

    #[test]
    fn test_fsrvp_is_path_supported_stub() {
        let share = r"\\10.0.0.1\share";
        let stub = build_is_path_supported_stub(share);
        let mut r = NdrReader::new(&stub);
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE);
    }
}
