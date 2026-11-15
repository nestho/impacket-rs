//! `efsr`: `[MS-EFSR]` Encrypting File System Remote Protocol client (`impacket/dcerpc/v5/efsr.py`).
//!
//! Provides pure-Rust RPC methods for remote file encryption operations:
//! - `EfsRpcOpenFileRaw` (Opnum 0)
//! - `EfsRpcReadFileRaw` (Opnum 1)
//! - `EfsRpcWriteFileRaw` (Opnum 2)
//! - `EfsRpcCloseRaw` (Opnum 3)
//! - `EfsRpcEncryptFileSrv` (Opnum 4)
//! - `EfsRpcDecryptFileSrv` (Opnum 5)

use crate::dtypes::{write_string_wchar_pointee, REFERENT_BASE};
use impacket_core::CoreError;
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport, RpcUuid};
use impacket_ndr::{NdrReader, NdrWriter};

/// `[MS-EFSR]` Interface UUID: `c681d488-d850-11d0-8c52-00c04fd90f7e` v1.0
pub const EFSR_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0xc681_d488,
    0xd850,
    0x11d0,
    [0x8c, 0x52, 0x00, 0xc0, 0x4f, 0xd9, 0x0f, 0x7e],
);
pub const EFSR_VERSION_MAJOR: u16 = 1;
pub const EFSR_VERSION_MINOR: u16 = 0;
pub const EFSR_PIPE: &str = r"\PIPE\efsrpc";

pub mod opnum {
    pub const EFS_RPC_OPEN_FILE_RAW: u16 = 0;
    pub const EFS_RPC_READ_FILE_RAW: u16 = 1;
    pub const EFS_RPC_WRITE_FILE_RAW: u16 = 2;
    pub const EFS_RPC_CLOSE_RAW: u16 = 3;
    pub const EFS_RPC_ENCRYPT_FILE_SRV: u16 = 4;
    pub const EFS_RPC_DECRYPT_FILE_SRV: u16 = 5;
    pub const EFS_RPC_QUERY_USERS_ON_FILE: u16 = 6;
    pub const EFS_RPC_QUERY_FILE_INFO_ON_ENCRYPTION: u16 = 7;
}

pub mod efs_flags {
    pub const CREATE_FOR_IMPORT: u32 = 0x0000_0001;
    pub const CREATE_FOR_DIR: u32 = 0x0000_0002;
    pub const OVERWRITE_HIDDEN: u32 = 0x0000_0004;
    pub const EFSR_USE_DESCRIPTOR: u32 = 0x0000_0008;
}

/// Builds request stub for `EfsRpcOpenFileRaw` (Opnum 0):
/// - `FileName`: [in, string] wchar_t*
/// - `Flags`: [in] long
pub fn build_efs_rpc_open_file_raw_stub(filename: &str, flags: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_u32(REFERENT_BASE); // FileName referent
    w.write_u32(flags);
    write_string_wchar_pointee(&mut w, filename);
    w.into_bytes()
}

/// Parses response stub for `EfsRpcOpenFileRaw` (Opnum 0):
/// - `hContext`: [out] PEXIMPORT_CONTEXT_HANDLE (20 bytes)
/// - `Return value`: [out] DWORD
pub fn parse_efs_rpc_open_file_raw_response(stub: &[u8]) -> Result<[u8; 20], CoreError> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_fixed_array::<20>()?;
    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::ProtocolError(format!(
            "EfsRpcOpenFileRaw failed with status 0x{:08x}",
            status
        )));
    }
    Ok(handle)
}

/// Builds request stub for `EfsRpcEncryptFileSrv` (Opnum 4):
/// - `FileName`: [in, string] wchar_t*
pub fn build_efs_rpc_encrypt_file_srv_stub(filename: &str) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_u32(REFERENT_BASE); // FileName referent
    write_string_wchar_pointee(&mut w, filename);
    w.into_bytes()
}

/// Builds request stub for `EfsRpcDecryptFileSrv` (Opnum 5):
/// - `FileName`: [in, string] wchar_t*
/// - `OpenFlag`: [in] unsigned long
pub fn build_efs_rpc_decrypt_file_srv_stub(filename: &str, open_flag: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_u32(REFERENT_BASE); // FileName referent
    w.write_u32(open_flag);
    write_string_wchar_pointee(&mut w, filename);
    w.into_bytes()
}

/// Builds request stub for `EfsRpcCloseRaw` (Opnum 3):
/// - `hContext`: [in, out] PEXIMPORT_CONTEXT_HANDLE
pub fn build_efs_rpc_close_raw_stub(handle: &[u8; 20]) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(20);
    w.write_fixed_array(handle);
    w.into_bytes()
}

/// Parses a simple Win32 error code response (4 bytes).
pub fn parse_win32_return_code(stub: &[u8]) -> Result<u32, CoreError> {
    let mut r = NdrReader::new(stub);
    r.read_u32()
}

/// `[MS-EFSR]` Client over an RPC transport.
pub struct EfsrClient<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> EfsrClient<T> {
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

    /// `EfsRpcOpenFileRaw` (Opnum 0)
    pub fn open_file_raw(&mut self, filename: &str, flags: u32) -> Result<[u8; 20], CoreError> {
        let stub = build_efs_rpc_open_file_raw_stub(filename, flags);
        let resp = self.call(opnum::EFS_RPC_OPEN_FILE_RAW, stub)?;
        parse_efs_rpc_open_file_raw_response(&resp)
    }

    /// `EfsRpcEncryptFileSrv` (Opnum 4)
    pub fn encrypt_file_srv(&mut self, filename: &str) -> Result<u32, CoreError> {
        let stub = build_efs_rpc_encrypt_file_srv_stub(filename);
        let resp = self.call(opnum::EFS_RPC_ENCRYPT_FILE_SRV, stub)?;
        parse_win32_return_code(&resp)
    }

    /// `EfsRpcDecryptFileSrv` (Opnum 5)
    pub fn decrypt_file_srv(&mut self, filename: &str, open_flag: u32) -> Result<u32, CoreError> {
        let stub = build_efs_rpc_decrypt_file_srv_stub(filename, open_flag);
        let resp = self.call(opnum::EFS_RPC_DECRYPT_FILE_SRV, stub)?;
        parse_win32_return_code(&resp)
    }

    /// `EfsRpcCloseRaw` (Opnum 3)
    pub fn close_raw(&mut self, handle: &[u8; 20]) -> Result<(), CoreError> {
        let stub = build_efs_rpc_close_raw_stub(handle);
        let _ = self.call(opnum::EFS_RPC_CLOSE_RAW, stub)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_efsr_open_file_raw_stub_format() {
        let filename = r"\\127.0.0.1\pipe\test\file.txt";
        let stub = build_efs_rpc_open_file_raw_stub(filename, 0);
        let mut r = NdrReader::new(&stub);
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE);
        assert_eq!(r.read_u32().unwrap(), 0);
    }

    #[test]
    fn test_efsr_encrypt_decrypt_stub_format() {
        let filename = r"\\10.0.0.1\share\doc.docx";
        let stub_enc = build_efs_rpc_encrypt_file_srv_stub(filename);
        assert!(stub_enc.len() > 16);

        let stub_dec = build_efs_rpc_decrypt_file_srv_stub(filename, 1);
        let mut r = NdrReader::new(&stub_dec);
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE);
        assert_eq!(r.read_u32().unwrap(), 1);
    }

    #[test]
    fn test_efsr_parse_open_file_raw_response() {
        let mut resp = vec![0x42u8; 20];
        resp.extend_from_slice(&0u32.to_le_bytes()); // SUCCESS
        let handle = parse_efs_rpc_open_file_raw_response(&resp).unwrap();
        assert_eq!(handle, [0x42u8; 20]);

        let mut err_resp = vec![0x42u8; 20];
        err_resp.extend_from_slice(&5u32.to_le_bytes()); // ACCESS_DENIED
        assert!(parse_efs_rpc_open_file_raw_response(&err_resp).is_err());
    }
}
