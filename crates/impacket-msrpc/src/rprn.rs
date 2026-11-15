//! `rprn`: `[MS-RPRN]` Print System Remote Protocol client (`impacket/dcerpc/v5/rprn.py`).
//!
//! Provides pure-Rust RPC methods for remote print spooler management:
//! - `RpcOpenPrinter` (Opnum 1)
//! - `RpcClosePrinter` (Opnum 29)
//! - `RpcRemoteFindFirstPrinterChangeNotificationEx` (Opnum 65)

use crate::dtypes::{write_string_wchar_pointee, REFERENT_BASE};
use impacket_core::CoreError;
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport, RpcUuid};
use impacket_ndr::{NdrReader, NdrWriter};

/// `[MS-RPRN]` Interface UUID: `12345678-1234-abcd-ef00-0123456789ab` v1.0
pub const RPRN_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0x1234_5678,
    0x1234,
    0xabcd,
    [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab],
);
pub const RPRN_VERSION_MAJOR: u16 = 1;
pub const RPRN_VERSION_MINOR: u16 = 0;
pub const RPRN_PIPE: &str = r"\PIPE\spoolss";

pub mod opnum {
    pub const RPC_OPEN_PRINTER: u16 = 1;
    pub const RPC_CLOSE_PRINTER: u16 = 29;
    pub const RPC_REMOTE_FIND_FIRST_PRINTER_CHANGE_NOTIFICATION_EX: u16 = 65;
}

pub mod printer_access {
    pub const PRINTER_ACCESS_ADMINISTER: u32 = 0x0000_0004;
    pub const PRINTER_ACCESS_USE: u32 = 0x0000_0008;
    pub const PRINTER_ALL_ACCESS: u32 = 0x000F_000C;
}

pub mod printer_change {
    pub const PRINTER_CHANGE_ADD_PRINTER: u32 = 0x0000_0001;
    pub const PRINTER_CHANGE_SET_PRINTER: u32 = 0x0000_0002;
    pub const PRINTER_CHANGE_DELETE_PRINTER: u32 = 0x0000_0004;
    pub const PRINTER_CHANGE_PRINTER: u32 = 0x0000_00FF;
    pub const PRINTER_CHANGE_ADD_JOB: u32 = 0x0000_0100;
    pub const PRINTER_CHANGE_SET_JOB: u32 = 0x0000_0200;
    pub const PRINTER_CHANGE_DELETE_JOB: u32 = 0x0000_0400;
    pub const PRINTER_CHANGE_WRITE_JOB: u32 = 0x0000_0800;
    pub const PRINTER_CHANGE_ALL: u32 = 0x00FF_0000;
}

/// Builds request stub for `RpcOpenPrinter` (Opnum 1):
/// - `pPrinterName`: [in, string, unique] STRING_HANDLE
/// - `pDatatype`: [in, string, unique] wchar_t*
/// - `pDevModeContainer`: DEVMODE_CONTAINER (cbBuf: u32, pDevMode: referent)
/// - `AccessRequired`: DWORD
pub fn build_rpc_open_printer_stub(
    printer_name: &str,
    datatype: Option<&str>,
    access_required: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);
    // 1. pPrinterName pointer referent
    w.write_u32(REFERENT_BASE);

    // 2. pDatatype pointer referent (0 if None)
    if datatype.is_some() {
        w.write_u32(REFERENT_BASE + 4);
    } else {
        w.write_u32(0);
    }

    // 3. pDevModeContainer (inline struct: cbBuf = 0, pDevMode referent = 0)
    w.write_u32(0); // cbBuf
    w.write_u32(0); // pDevMode referent (NULL)

    // 4. AccessRequired
    w.write_u32(access_required);

    // Deferred pointees:
    // pPrinterName string pointee
    write_string_wchar_pointee(&mut w, printer_name);

    // pDatatype string pointee if present
    if let Some(dt) = datatype {
        write_string_wchar_pointee(&mut w, dt);
    }

    w.into_bytes()
}

/// Parses response stub for `RpcOpenPrinter` (Opnum 1):
/// - `pHandle`: [out] PRINTER_HANDLE (20 bytes)
/// - `ErrorCode`: [out] DWORD
pub fn parse_rpc_open_printer_response(stub: &[u8]) -> Result<[u8; 20], CoreError> {
    let mut r = NdrReader::new(stub);
    let handle = r.read_fixed_array::<20>()?;
    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::ProtocolError(format!(
            "RpcOpenPrinter failed with status 0x{:08x}",
            status
        )));
    }
    Ok(handle)
}

/// Builds request stub for `RpcClosePrinter` (Opnum 29):
/// - `phPrinter`: [in, out] PRINTER_HANDLE (20 bytes)
pub fn build_rpc_close_printer_stub(handle: &[u8; 20]) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(20);
    w.write_fixed_array(handle);
    w.into_bytes()
}

/// Parses response stub for `RpcClosePrinter` (Opnum 29):
/// - `phPrinter`: [out] PRINTER_HANDLE (20 bytes, zeroed)
/// - `ErrorCode`: [out] DWORD
pub fn parse_rpc_close_printer_response(stub: &[u8]) -> Result<u32, CoreError> {
    let mut r = NdrReader::new(stub);
    let _closed_handle = r.read_fixed_array::<20>()?;
    r.read_u32()
}

/// Builds request stub for `RpcRemoteFindFirstPrinterChangeNotificationEx` (Opnum 65):
/// - `hPrinter`: [in] PRINTER_HANDLE (20 bytes)
/// - `fdwFlags`: [in] DWORD
/// - `fdwOptions`: [in] DWORD
/// - `pszLocalMachine`: [in, string, unique] wchar_t*
/// - `dwPrinterLocal`: [in] DWORD
/// - `pOptions`: [in, unique] RPC_V2_NOTIFY_OPTIONS*
pub fn build_rpc_remote_find_first_printer_change_notification_ex_stub(
    handle: &[u8; 20],
    flags: u32,
    options: u32,
    local_machine: &str,
    printer_local: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);
    // 1. hPrinter handle
    w.write_fixed_array(handle);
    // 2. fdwFlags
    w.write_u32(flags);
    // 3. fdwOptions
    w.write_u32(options);
    // 4. pszLocalMachine pointer referent
    w.write_u32(REFERENT_BASE);
    // 5. dwPrinterLocal
    w.write_u32(printer_local);
    // 6. pOptions pointer referent (0 = NULL)
    w.write_u32(0);

    // Deferred pointees:
    write_string_wchar_pointee(&mut w, local_machine);

    w.into_bytes()
}

/// Parses response stub for `RpcRemoteFindFirstPrinterChangeNotificationEx` (Opnum 65):
/// - `ErrorCode`: [out] DWORD
pub fn parse_rpc_remote_find_first_printer_change_notification_ex_response(
    stub: &[u8],
) -> Result<u32, CoreError> {
    let mut r = NdrReader::new(stub);
    r.read_u32()
}

/// `[MS-RPRN]` Client over an RPC transport.
pub struct RprnClient<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> RprnClient<T> {
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

    /// `RpcOpenPrinter` (Opnum 1) with default access.
    pub fn open_printer(&mut self, printer_name: &str) -> Result<[u8; 20], CoreError> {
        self.open_printer_with_access(printer_name, 0)
    }

    /// `RpcOpenPrinter` (Opnum 1) with specific access flags.
    pub fn open_printer_with_access(
        &mut self,
        printer_name: &str,
        access_required: u32,
    ) -> Result<[u8; 20], CoreError> {
        let stub = build_rpc_open_printer_stub(printer_name, None, access_required);
        let resp = self.call(opnum::RPC_OPEN_PRINTER, stub)?;
        parse_rpc_open_printer_response(&resp)
    }

    /// `RpcRemoteFindFirstPrinterChangeNotificationEx` (Opnum 65)
    pub fn remote_find_first_printer_change_notification_ex(
        &mut self,
        handle: &[u8; 20],
        flags: u32,
        local_machine: &str,
    ) -> Result<u32, CoreError> {
        let stub = build_rpc_remote_find_first_printer_change_notification_ex_stub(
            handle,
            flags,
            0,
            local_machine,
            0,
        );
        let resp = self.call(
            opnum::RPC_REMOTE_FIND_FIRST_PRINTER_CHANGE_NOTIFICATION_EX,
            stub,
        )?;
        parse_rpc_remote_find_first_printer_change_notification_ex_response(&resp)
    }

    /// `RpcClosePrinter` (Opnum 29)
    pub fn close_printer(&mut self, handle: &[u8; 20]) -> Result<u32, CoreError> {
        let stub = build_rpc_close_printer_stub(handle);
        let resp = self.call(opnum::RPC_CLOSE_PRINTER, stub)?;
        parse_rpc_close_printer_response(&resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rprn_open_printer_stub() {
        let printer = r"\\10.0.0.1\pipe\spoolss";
        let stub = build_rpc_open_printer_stub(printer, None, 0);
        let mut r = NdrReader::new(&stub);
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE);
        assert_eq!(r.read_u32().unwrap(), 0); // null datatype
        assert_eq!(r.read_u32().unwrap(), 0); // cbBuf
        assert_eq!(r.read_u32().unwrap(), 0); // pDevMode
        assert_eq!(r.read_u32().unwrap(), 0); // access
    }

    #[test]
    fn test_rprn_close_printer_stub_and_response() {
        let handle = [0x55u8; 20];
        let stub = build_rpc_close_printer_stub(&handle);
        assert_eq!(stub.len(), 20);
        assert_eq!(&stub[..], &handle[..]);

        let mut resp = vec![0u8; 20];
        resp.extend_from_slice(&0u32.to_le_bytes());
        let status = parse_rpc_close_printer_response(&resp).unwrap();
        assert_eq!(status, 0);
    }

    #[test]
    fn test_rprn_notification_ex_stub() {
        let handle = [0x11u8; 20];
        let target = r"\\192.168.1.50";
        let stub = build_rpc_remote_find_first_printer_change_notification_ex_stub(
            &handle,
            printer_change::PRINTER_CHANGE_ADD_JOB,
            0,
            target,
            0,
        );
        let mut r = NdrReader::new(&stub);
        let read_h = r.read_fixed_array::<20>().unwrap();
        assert_eq!(read_h, handle);
        assert_eq!(r.read_u32().unwrap(), printer_change::PRINTER_CHANGE_ADD_JOB);
        assert_eq!(r.read_u32().unwrap(), 0);
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE);
        assert_eq!(r.read_u32().unwrap(), 0);
        assert_eq!(r.read_u32().unwrap(), 0);
    }
}
