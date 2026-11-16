//! `par`: `[MS-PAR]` Print System Asynchronous Remote Protocol client (`impacket/dcerpc/v5/par.py`).
//!
//! Provides pure-Rust RPC methods for asynchronous remote print spooler management:
//! - `RpcAsyncOpenPrinter` (Opnum 0)
//! - `RpcAsyncClosePrinter` (Opnum 20)
//! - `RpcAsyncEnumPrinters` (Opnum 38)
//! - `RpcAsyncAddPrinterDriver` (Opnum 39)
//! - `RpcAsyncEnumPrinterDrivers` (Opnum 40)
//! - `RpcAsyncGetPrinterDriverDirectory` (Opnum 41)

use crate::dtypes::{write_string_wchar_pointee, REFERENT_BASE};
use impacket_core::CoreError;
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport, RpcUuid};
use impacket_ndr::{NdrReader, NdrWriter};

/// `[MS-PAR]` Interface UUID: `76f03f96-cdfd-44fc-a22c-64950a001209` v1.0
pub const PAR_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0x76f0_3f96,
    0xcdfd,
    0x44fc,
    [0xa2, 0x2c, 0x64, 0x95, 0x0a, 0x00, 0x12, 0x09],
);
pub const PAR_VERSION_MAJOR: u16 = 1;
pub const PAR_VERSION_MINOR: u16 = 0;
pub const PAR_PIPE: &str = r"\PIPE\spoolss";

/// Secondary interface UUID used by winspool / async spooler calls
pub const WINSPOOL_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0x9940_ca8e,
    0x512f,
    0x4c58,
    [0x88, 0xa9, 0x61, 0x09, 0x8d, 0x68, 0x96, 0xbd],
);

pub mod opnum {
    pub const RPC_ASYNC_OPEN_PRINTER: u16 = 0;
    pub const RPC_ASYNC_CLOSE_PRINTER: u16 = 20;
    pub const RPC_ASYNC_ENUM_PRINTERS: u16 = 38;
    pub const RPC_ASYNC_ADD_PRINTER_DRIVER: u16 = 39;
    pub const RPC_ASYNC_ENUM_PRINTER_DRIVERS: u16 = 40;
    pub const RPC_ASYNC_GET_PRINTER_DRIVER_DIRECTORY: u16 = 41;
}

pub mod access {
    pub const SERVER_ALL_ACCESS: u32 = 0x000F_0003;
    pub const SERVER_READ: u32 = 0x0002_0002;
    pub const SERVER_WRITE: u32 = 0x0002_0003;
    pub const SERVER_EXECUTE: u32 = 0x0002_0002;
    pub const SERVER_ACCESS_ADMINISTER: u32 = 0x0000_0001;
    pub const SERVER_ACCESS_ENUMERATE: u32 = 0x0000_0002;
    pub const PRINTER_ALL_ACCESS: u32 = 0x000F_000C;
    pub const PRINTER_ACCESS_ADMINISTER: u32 = 0x0000_0004;
    pub const PRINTER_ACCESS_USE: u32 = 0x0000_0008;
}

pub mod enum_flags {
    pub const PRINTER_ENUM_DEFAULT: u32 = 0x0000_0001;
    pub const PRINTER_ENUM_LOCAL: u32 = 0x0000_0002;
    pub const PRINTER_ENUM_CONNECTIONS: u32 = 0x0000_0004;
    pub const PRINTER_ENUM_NAME: u32 = 0x0000_0008;
    pub const PRINTER_ENUM_REMOTE: u32 = 0x0000_0010;
    pub const PRINTER_ENUM_SHARED: u32 = 0x0000_0020;
    pub const PRINTER_ENUM_NETWORK: u32 = 0x0000_0040;
}

/// Client info container parameter for `RpcAsyncOpenPrinter`.
#[derive(Debug, Clone)]
pub struct SplClientInfo1 {
    pub machine_name: String,
    pub user_name: String,
    pub build_num: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub processor_architecture: u16,
}

impl Default for SplClientInfo1 {
    fn default() -> Self {
        Self {
            machine_name: "\\\\CLIENT".to_string(),
            user_name: "SYSTEM".to_string(),
            build_num: 0,
            major_version: 3,
            minor_version: 0,
            processor_architecture: 9, // AMD64
        }
    }
}

/// Builds request stub for `RpcAsyncOpenPrinter` (Opnum 0).
pub fn build_rpc_async_open_printer_stub(
    printer_name: &str,
    datatype: Option<&str>,
    access_required: u32,
    client_info: Option<&SplClientInfo1>,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(256);
    // 1. pPrinterName pointer referent
    w.write_u32(REFERENT_BASE);

    // 2. pDatatype pointer referent
    let dt_ref = if datatype.is_some() {
        REFERENT_BASE + 4
    } else {
        0
    };
    w.write_u32(dt_ref);

    // 3. pDevModeContainer (cbBuf = 0, pDevMode = 0)
    w.write_u32(0); // cbBuf
    w.write_u32(0); // pDevMode pointer referent

    // 4. AccessRequired
    w.write_u32(access_required);

    // 5. pClientInfo: SPLCLIENT_CONTAINER
    // Level: DWORD (1)
    w.write_u32(1);
    // ClientInfo union: tag = 1, pClientInfo1 pointer referent
    w.write_u32(1); // tag
    let client_ref = REFERENT_BASE + 8;
    w.write_u32(client_ref);

    // Deferred pointees:
    // pPrinterName string
    write_string_wchar_pointee(&mut w, printer_name);

    // pDatatype string
    if let Some(dt) = datatype {
        write_string_wchar_pointee(&mut w, dt);
    }

    // pClientInfo1 struct
    let default_info = SplClientInfo1::default();
    let info = client_info.unwrap_or(&default_info);

    // SPLCLIENT_INFO_1 struct:
    w.write_u32(28); // dwSize
    w.write_u32(REFERENT_BASE + 12); // pMachineName referent
    w.write_u32(REFERENT_BASE + 16); // pUserName referent
    w.write_u32(info.build_num);
    w.write_u32(info.major_version);
    w.write_u32(info.minor_version);
    w.write_u16(info.processor_architecture);
    w.write_u16(0); // padding

    // machine name and username pointees
    write_string_wchar_pointee(&mut w, &info.machine_name);
    write_string_wchar_pointee(&mut w, &info.user_name);

    w.into_bytes()
}

/// Parses response stub for `RpcAsyncOpenPrinter` (Opnum 0):
/// - `pHandle`: [out] PRINTER_HANDLE (20 bytes)
/// - `ErrorCode`: [out] DWORD
pub fn parse_rpc_async_open_printer_response(stub: &[u8]) -> Result<[u8; 20], CoreError> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_fixed_array::<20>()?;
    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::ProtocolError(format!(
            "RpcAsyncOpenPrinter failed with status 0x{:08x}",
            status
        )));
    }
    Ok(handle)
}

/// Builds request stub for `RpcAsyncClosePrinter` (Opnum 20):
/// - `phPrinter`: [in, out] PRINTER_HANDLE (20 bytes)
pub fn build_rpc_async_close_printer_stub(handle: &[u8; 20]) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(20);
    w.write_fixed_array(handle);
    w.into_bytes()
}

/// Parses response stub for `RpcAsyncClosePrinter` (Opnum 20):
/// - `phPrinter`: [out] PRINTER_HANDLE (20 bytes)
/// - `ErrorCode`: [out] DWORD
pub fn parse_rpc_async_close_printer_response(stub: &[u8]) -> Result<u32, CoreError> {
    let mut r = NdrReader::new(stub);
    let _closed = r.read_fixed_array::<20>()?;
    r.read_u32()
}

/// Builds request stub for `RpcAsyncEnumPrinters` (Opnum 38):
/// - Flags: DWORD
/// - Name: STRING_HANDLE
/// - Level: DWORD
/// - pPrinterEnum: PBYTE_ARRAY
/// - cbBuf: DWORD
pub fn build_rpc_async_enum_printers_stub(
    flags: u32,
    name: Option<&str>,
    level: u32,
    buffer_size: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);
    w.write_u32(flags);

    if name.is_some() {
        w.write_u32(REFERENT_BASE);
    } else {
        w.write_u32(0);
    }

    w.write_u32(level);

    if buffer_size > 0 {
        w.write_u32(REFERENT_BASE + 4);
    } else {
        w.write_u32(0);
    }

    w.write_u32(buffer_size);

    if let Some(n) = name {
        write_string_wchar_pointee(&mut w, n);
    }

    if buffer_size > 0 {
        w.write_u32(buffer_size); // MaxCount
        w.write_bytes(&vec![0u8; buffer_size as usize]);
        w.align(4);
    }

    w.into_bytes()
}

/// Result of `RpcAsyncEnumPrinters` or `RpcAsyncEnumPrinterDrivers`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncEnumResult {
    pub buffer: Vec<u8>,
    pub needed: u32,
    pub returned: u32,
    pub status: u32,
}

/// Parses response stub for `RpcAsyncEnumPrinters` (Opnum 38).
pub fn parse_rpc_async_enum_printers_response(stub: &[u8]) -> Result<AsyncEnumResult, CoreError> {
    let mut r = NdrReader::new(stub);
    let buf_ref = r.read_u32()?;
    let buffer = if buf_ref != 0 {
        let count = r.read_u32()?;
        r.read_bytes(count as usize)?.to_vec()
    } else {
        Vec::new()
    };
    r.align(4)?;
    let needed = r.read_u32()?;
    let returned = r.read_u32()?;
    let status = r.read_u32()?;

    Ok(AsyncEnumResult {
        buffer,
        needed,
        returned,
        status,
    })
}

/// Builds request stub for `RpcAsyncGetPrinterDriverDirectory` (Opnum 41).
pub fn build_rpc_async_get_printer_driver_directory_stub(
    name: Option<&str>,
    environment: Option<&str>,
    level: u32,
    buffer_size: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);

    if name.is_some() {
        w.write_u32(REFERENT_BASE);
    } else {
        w.write_u32(0);
    }

    if environment.is_some() {
        w.write_u32(REFERENT_BASE + 4);
    } else {
        w.write_u32(0);
    }

    w.write_u32(level);

    if buffer_size > 0 {
        w.write_u32(REFERENT_BASE + 8);
    } else {
        w.write_u32(0);
    }

    w.write_u32(buffer_size);

    if let Some(n) = name {
        write_string_wchar_pointee(&mut w, n);
    }

    if let Some(env) = environment {
        write_string_wchar_pointee(&mut w, env);
    }

    if buffer_size > 0 {
        w.write_u32(buffer_size);
        w.write_bytes(&vec![0u8; buffer_size as usize]);
        w.align(4);
    }

    w.into_bytes()
}

/// Result of `RpcAsyncGetPrinterDriverDirectory`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsyncDriverDirResult {
    pub buffer: Vec<u8>,
    pub needed: u32,
    pub status: u32,
}

/// Parses response stub for `RpcAsyncGetPrinterDriverDirectory` (Opnum 41).
pub fn parse_rpc_async_get_printer_driver_directory_response(
    stub: &[u8],
) -> Result<AsyncDriverDirResult, CoreError> {
    let mut r = NdrReader::new(stub);
    let buf_ref = r.read_u32()?;
    let buffer = if buf_ref != 0 {
        let count = r.read_u32()?;
        r.read_bytes(count as usize)?.to_vec()
    } else {
        Vec::new()
    };
    r.align(4)?;
    let needed = r.read_u32()?;
    let status = r.read_u32()?;

    Ok(AsyncDriverDirResult {
        buffer,
        needed,
        status,
    })
}

/// `[MS-PAR]` Client over an RPC transport.
pub struct ParClient<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> ParClient<T> {
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

    /// `RpcAsyncOpenPrinter` (Opnum 0).
    pub fn open_printer(
        &mut self,
        printer_name: &str,
        access_required: u32,
        client_info: Option<&SplClientInfo1>,
    ) -> Result<[u8; 20], CoreError> {
        let stub = build_rpc_async_open_printer_stub(
            printer_name,
            None,
            access_required,
            client_info,
        );
        let resp = self.call(opnum::RPC_ASYNC_OPEN_PRINTER, stub)?;
        parse_rpc_async_open_printer_response(&resp)
    }

    /// `RpcAsyncClosePrinter` (Opnum 20).
    pub fn close_printer(&mut self, handle: &[u8; 20]) -> Result<u32, CoreError> {
        let stub = build_rpc_async_close_printer_stub(handle);
        let resp = self.call(opnum::RPC_ASYNC_CLOSE_PRINTER, stub)?;
        parse_rpc_async_close_printer_response(&resp)
    }

    /// `RpcAsyncEnumPrinters` (Opnum 38).
    pub fn enum_printers(
        &mut self,
        flags: u32,
        name: Option<&str>,
        level: u32,
    ) -> Result<AsyncEnumResult, CoreError> {
        // Query required buffer size
        let probe_stub = build_rpc_async_enum_printers_stub(flags, name, level, 0);
        let probe_resp = self.call(opnum::RPC_ASYNC_ENUM_PRINTERS, probe_stub)?;
        let probe_res = parse_rpc_async_enum_printers_response(&probe_resp)?;

        if probe_res.status == 0 || probe_res.needed == 0 {
            return Ok(probe_res);
        }

        // Fetch buffer
        let fetch_stub = build_rpc_async_enum_printers_stub(flags, name, level, probe_res.needed);
        let fetch_resp = self.call(opnum::RPC_ASYNC_ENUM_PRINTERS, fetch_stub)?;
        parse_rpc_async_enum_printers_response(&fetch_resp)
    }

    /// `RpcAsyncGetPrinterDriverDirectory` (Opnum 41).
    pub fn get_printer_driver_directory(
        &mut self,
        name: Option<&str>,
        environment: Option<&str>,
        level: u32,
    ) -> Result<AsyncDriverDirResult, CoreError> {
        let probe_stub =
            build_rpc_async_get_printer_driver_directory_stub(name, environment, level, 0);
        let probe_resp = self.call(opnum::RPC_ASYNC_GET_PRINTER_DRIVER_DIRECTORY, probe_stub)?;
        let probe_res = parse_rpc_async_get_printer_driver_directory_response(&probe_resp)?;

        if probe_res.status == 0 || probe_res.needed == 0 {
            return Ok(probe_res);
        }

        let fetch_stub = build_rpc_async_get_printer_driver_directory_stub(
            name,
            environment,
            level,
            probe_res.needed,
        );
        let fetch_resp = self.call(opnum::RPC_ASYNC_GET_PRINTER_DRIVER_DIRECTORY, fetch_stub)?;
        parse_rpc_async_get_printer_driver_directory_response(&fetch_resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_par_open_printer_stub_roundtrip() {
        let stub = build_rpc_async_open_printer_stub(
            r"\\192.168.1.100\pipe\spoolss",
            None,
            access::SERVER_READ,
            None,
        );
        assert!(!stub.is_empty());
        let mut r = NdrReader::new(&stub);
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE); // name referent
        assert_eq!(r.read_u32().unwrap(), 0); // null datatype
        assert_eq!(r.read_u32().unwrap(), 0); // cbBuf
        assert_eq!(r.read_u32().unwrap(), 0); // pDevMode
        assert_eq!(r.read_u32().unwrap(), access::SERVER_READ);
        assert_eq!(r.read_u32().unwrap(), 1); // Level
        assert_eq!(r.read_u32().unwrap(), 1); // tag
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE + 8); // client referent
    }

    #[test]
    fn test_par_close_printer_stub_and_response() {
        let handle = [0x77u8; 20];
        let stub = build_rpc_async_close_printer_stub(&handle);
        assert_eq!(stub.len(), 20);
        assert_eq!(&stub[..], &handle[..]);

        let mut resp = vec![0u8; 20];
        resp.extend_from_slice(&0u32.to_le_bytes());
        let status = parse_rpc_async_close_printer_response(&resp).unwrap();
        assert_eq!(status, 0);
    }

    #[test]
    fn test_par_enum_printers_stub() {
        let stub = build_rpc_async_enum_printers_stub(
            enum_flags::PRINTER_ENUM_LOCAL,
            Some("PRINT-SRV"),
            1,
            0,
        );
        let mut r = NdrReader::new(&stub);
        assert_eq!(r.read_u32().unwrap(), enum_flags::PRINTER_ENUM_LOCAL);
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE);
        assert_eq!(r.read_u32().unwrap(), 1);
        assert_eq!(r.read_u32().unwrap(), 0); // buffer pointer null
        assert_eq!(r.read_u32().unwrap(), 0); // buffer size
    }

    #[test]
    fn test_par_driver_directory_stub_and_response() {
        let stub = build_rpc_async_get_printer_driver_directory_stub(
            None,
            Some("Windows x64"),
            1,
            0,
        );
        let mut r = NdrReader::new(&stub);
        assert_eq!(r.read_u32().unwrap(), 0); // null name
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE + 4); // env referent
        assert_eq!(r.read_u32().unwrap(), 1); // level
        assert_eq!(r.read_u32().unwrap(), 0); // null buf
        assert_eq!(r.read_u32().unwrap(), 0); // cbBuf 0

        // Mock error 122 (ERROR_INSUFFICIENT_BUFFER) response
        let mut resp = Vec::new();
        resp.extend_from_slice(&0u32.to_le_bytes()); // null buffer pointer
        resp.extend_from_slice(&256u32.to_le_bytes()); // needed
        resp.extend_from_slice(&122u32.to_le_bytes()); // status ERROR_INSUFFICIENT_BUFFER

        let parsed = parse_rpc_async_get_printer_driver_directory_response(&resp).unwrap();
        assert_eq!(parsed.needed, 256);
        assert_eq!(parsed.status, 122);
    }
}
