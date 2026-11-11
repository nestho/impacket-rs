//! `scmr`: `[MS-SCMR]` Service Control Manager Remote Protocol client (`impacket/dcerpc/v5/scmr.py`).
//!
//! Implements the service control-plane calls that `psexec` / `smbexec` / `services` drive over
//! `\PIPE\svcctl`: `ROpenSCManagerW` (15), `RCreateServiceW` (12), `ROpenServiceW` (16),
//! `RStartServiceW` (19), `RControlService` (1), `RDeleteService` (2), `RQueryServiceStatus` (6),
//! `RCloseServiceHandle` (0). `[string] wchar_t*` parameters are marshalled as referent + NUL-terminated
//! conformant/varying arrays (matching what Windows/Impacket emit). Round-trip tested; pending live
//! confirmation.

use crate::dtypes::{read_string_wchar_pointee, write_string_wchar_pointee, REFERENT_BASE};
use impacket_core::{CoreError, NtStatus};
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport};
use impacket_ndr::{NdrReader, NdrWriter};

/// A 20-byte SCM / service RPC handle (`SC_RPC_HANDLE`).
pub type ScHandle = [u8; 20];

pub mod opnum {
    pub const R_CLOSE_SERVICE_HANDLE: u16 = 0;
    pub const R_CONTROL_SERVICE: u16 = 1;
    pub const R_DELETE_SERVICE: u16 = 2;
    pub const R_QUERY_SERVICE_STATUS: u16 = 6;
    pub const R_CHANGE_SERVICE_CONFIG_W: u16 = 11;
    pub const R_CREATE_SERVICE_W: u16 = 12;
    pub const R_ENUM_SERVICES_STATUS_W: u16 = 14;
    pub const R_OPEN_SC_MANAGER_W: u16 = 15;
    pub const R_OPEN_SERVICE_W: u16 = 16;
    pub const R_QUERY_SERVICE_CONFIG_W: u16 = 17;
    pub const R_START_SERVICE_W: u16 = 19;
}

/// Common access masks / service parameters (`[MS-SCMR] 2.2`).
pub mod access {
    pub const SC_MANAGER_CONNECT: u32 = 0x0001;
    pub const SC_MANAGER_CREATE_SERVICE: u32 = 0x0002;
    pub const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
    pub const SC_MANAGER_LOCK: u32 = 0x0008;
    pub const SC_MANAGER_QUERY_LOCK_STATUS: u32 = 0x0010;
    pub const SC_MANAGER_MODIFY_BOOT_CONFIG: u32 = 0x0020;
    pub const SC_MANAGER_ALL_ACCESS: u32 = 0x000F_003F;

    pub const SERVICE_QUERY_CONFIG: u32 = 0x0001;
    pub const SERVICE_CHANGE_CONFIG: u32 = 0x0002;
    pub const SERVICE_QUERY_STATUS: u32 = 0x0004;
    pub const SERVICE_ENUMERATE_DEPENDENTS: u32 = 0x0008;
    pub const SERVICE_START: u32 = 0x0010;
    pub const SERVICE_STOP: u32 = 0x0020;
    pub const SERVICE_PAUSE_CONTINUE: u32 = 0x0040;
    pub const SERVICE_INTERROGATE: u32 = 0x0080;
    pub const SERVICE_USER_DEFINED_CONTROL: u32 = 0x0100;
    pub const SERVICE_ALL_ACCESS: u32 = 0x000F_01FF;

    pub const SERVICE_WIN32_OWN_PROCESS: u32 = 0x0000_0010;
    pub const SERVICE_DEMAND_START: u32 = 0x0000_0003;
    pub const SERVICE_ERROR_IGNORE: u32 = 0x0000_0000;
    pub const SERVICE_CONTROL_STOP: u32 = 0x0000_0001;
}

pub mod service_state {
    pub const SERVICE_STOPPED: u32 = 0x0000_0001;
    pub const SERVICE_START_PENDING: u32 = 0x0000_0002;
    pub const SERVICE_STOP_PENDING: u32 = 0x0000_0003;
    pub const SERVICE_RUNNING: u32 = 0x0000_0004;
    pub const SERVICE_CONTINUE_PENDING: u32 = 0x0000_0005;
    pub const SERVICE_PAUSE_PENDING: u32 = 0x0000_0006;
    pub const SERVICE_PAUSED: u32 = 0x0000_0007;
    pub const SERVICE_STATE_ALL: u32 = 0x0000_0003;
}

pub mod service_type {
    pub const SERVICE_KERNEL_DRIVER: u32 = 0x0000_0001;
    pub const SERVICE_FILE_SYSTEM_DRIVER: u32 = 0x0000_0002;
    pub const SERVICE_WIN32_OWN_PROCESS: u32 = 0x0000_0010;
    pub const SERVICE_WIN32_SHARE_PROCESS: u32 = 0x0000_0020;
    pub const SERVICE_INTERACTIVE_PROCESS: u32 = 0x0000_0100;
    pub const SERVICE_TYPE_ALL: u32 = SERVICE_WIN32_OWN_PROCESS
        | SERVICE_KERNEL_DRIVER
        | SERVICE_FILE_SYSTEM_DRIVER
        | SERVICE_WIN32_SHARE_PROCESS
        | SERVICE_INTERACTIVE_PROCESS;
}

pub mod start_type {
    pub const SERVICE_BOOT_START: u32 = 0x0000_0000;
    pub const SERVICE_SYSTEM_START: u32 = 0x0000_0001;
    pub const SERVICE_AUTO_START: u32 = 0x0000_0002;
    pub const SERVICE_DEMAND_START: u32 = 0x0000_0003;
    pub const SERVICE_DISABLED: u32 = 0x0000_0004;
    pub const SERVICE_NO_CHANGE: u32 = 0xFFFF_FFFF;
}

/// `SERVICE_STATUS` (28 bytes, `[MS-SCMR] 2.2.47`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServiceStatus {
    pub service_type: u32,
    pub current_state: u32,
    pub controls_accepted: u32,
    pub win32_exit_code: u32,
    pub service_specific_exit_code: u32,
    pub check_point: u32,
    pub wait_hint: u32,
}

impl ServiceStatus {
    pub fn state_str(&self) -> &'static str {
        match self.current_state {
            service_state::SERVICE_STOPPED => "STOPPED",
            service_state::SERVICE_START_PENDING => "START PENDING",
            service_state::SERVICE_STOP_PENDING => "STOP PENDING",
            service_state::SERVICE_RUNNING => "RUNNING",
            service_state::SERVICE_CONTINUE_PENDING => "CONTINUE PENDING",
            service_state::SERVICE_PAUSE_PENDING => "PAUSE PENDING",
            service_state::SERVICE_PAUSED => "PAUSED",
            _ => "UNKNOWN",
        }
    }

    pub fn type_names(&self) -> Vec<&'static str> {
        let mut types = Vec::new();
        if (self.service_type & service_type::SERVICE_KERNEL_DRIVER) != 0 {
            types.push("KERNEL_DRIVER");
        }
        if (self.service_type & service_type::SERVICE_FILE_SYSTEM_DRIVER) != 0 {
            types.push("FILE_SYSTEM_DRIVER");
        }
        if (self.service_type & service_type::SERVICE_WIN32_OWN_PROCESS) != 0 {
            types.push("WIN32_OWN_PROCESS");
        }
        if (self.service_type & service_type::SERVICE_WIN32_SHARE_PROCESS) != 0 {
            types.push("WIN32_SHARE_PROCESS");
        }
        if (self.service_type & service_type::SERVICE_INTERACTIVE_PROCESS) != 0 {
            types.push("INTERACTIVE_PROCESS");
        }
        types
    }
}

pub fn start_type_str(st: u32) -> &'static str {
    match st {
        start_type::SERVICE_BOOT_START => "BOOT START",
        start_type::SERVICE_SYSTEM_START => "SYSTEM START",
        start_type::SERVICE_AUTO_START => "AUTO START",
        start_type::SERVICE_DEMAND_START => "DEMAND START",
        start_type::SERVICE_DISABLED => "DISABLED",
        _ => "UNKNOWN",
    }
}

pub fn error_control_str(ec: u32) -> &'static str {
    match ec {
        0 => "IGNORE",
        1 => "NORMAL",
        2 => "SEVERE",
        3 => "CRITICAL",
        _ => "UNKNOWN",
    }
}

/// Service configuration details (`[MS-SCMR] 2.2.20 QUERY_SERVICE_CONFIGW`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServiceConfig {
    pub service_type: u32,
    pub start_type: u32,
    pub error_control: u32,
    pub binary_path: String,
    pub load_order_group: String,
    pub tag_id: u32,
    pub dependencies: String,
    pub service_start_name: String,
    pub display_name: String,
}

/// Summary of an enumerated Windows service (`[MS-SCMR] 2.2.13 ENUM_SERVICE_STATUSW`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumServiceStatus {
    pub service_name: String,
    pub display_name: String,
    pub status: ServiceStatus,
}

pub fn read_null_terminated_utf16le(data: &[u8]) -> String {
    let mut u16_chars = Vec::new();
    for chunk in data.chunks_exact(2) {
        let code = u16::from_le_bytes([chunk[0], chunk[1]]);
        if code == 0 {
            break;
        }
        u16_chars.push(code);
    }
    String::from_utf16_lossy(&u16_chars)
}

impl ServiceStatus {
    #[cfg(test)]
    fn write(&self, w: &mut NdrWriter) {
        for v in [
            self.service_type,
            self.current_state,
            self.controls_accepted,
            self.win32_exit_code,
            self.service_specific_exit_code,
            self.check_point,
            self.wait_hint,
        ] {
            w.write_u32(v);
        }
    }
    fn read(r: &mut NdrReader<'_>) -> Result<Self, CoreError> {
        Ok(Self {
            service_type: r.read_u32()?,
            current_state: r.read_u32()?,
            controls_accepted: r.read_u32()?,
            win32_exit_code: r.read_u32()?,
            service_specific_exit_code: r.read_u32()?,
            check_point: r.read_u32()?,
            wait_hint: r.read_u32()?,
        })
    }
}

/// Writes a `[string] wchar_t*` parameter (referent + NUL-terminated string), or a NULL pointer.
fn write_opt_wstr(w: &mut NdrWriter, s: Option<&str>, referent: u32) {
    match s {
        Some(v) => {
            w.write_u32(referent);
            write_string_wchar_pointee(w, v);
            w.align(4);
        }
        None => w.write_u32(0),
    }
}

// ---- Request builders ----

/// `ROpenSCManagerW` (15): `MachineName`/`DatabaseName` are `[unique,string]`.
pub fn build_open_sc_manager_stub(machine: Option<&str>, desired_access: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    write_opt_wstr(&mut w, machine, REFERENT_BASE);
    write_opt_wstr(&mut w, None, REFERENT_BASE + 4); // DatabaseName = NULL
    w.write_u32(desired_access);
    w.into_bytes()
}

/// `ROpenServiceW` (16).
pub fn build_open_service_stub(scm: &ScHandle, service_name: &str, desired_access: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_fixed_array(scm);
    write_string_wchar_pointee(&mut w, service_name); // [string] ref (inline, no referent prefix)
    w.align(4);
    w.write_u32(desired_access);
    w.into_bytes()
}

/// `RCreateServiceW` (12). Optional string params default to NULL; no dependencies / start account.
#[allow(clippy::too_many_arguments)]
pub fn build_create_service_stub(
    scm: &ScHandle,
    service_name: &str,
    display_name: Option<&str>,
    desired_access: u32,
    service_type: u32,
    start_type: u32,
    error_control: u32,
    binary_path: &str,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);
    w.write_fixed_array(scm);
    write_string_wchar_pointee(&mut w, service_name); // lpServiceName [string] ref
    w.align(4);
    write_opt_wstr(&mut w, display_name, REFERENT_BASE); // lpDisplayName [unique,string]
    w.write_u32(desired_access);
    w.write_u32(service_type);
    w.write_u32(start_type);
    w.write_u32(error_control);
    write_string_wchar_pointee(&mut w, binary_path); // lpBinaryPathName [string] ref
    w.align(4);
    write_opt_wstr(&mut w, None, REFERENT_BASE + 4); // lpLoadOrderGroup
    w.write_u32(0); // lpdwTagId (unique DWORD*) = NULL
    w.write_u32(0); // lpDependencies (unique) = NULL
    w.write_u32(0); // dwDependSize
    write_opt_wstr(&mut w, None, REFERENT_BASE + 8); // lpServiceStartName
    w.write_u32(0); // lpPassword (unique) = NULL
    w.write_u32(0); // dwPwSize
    w.into_bytes()
}

/// `RStartServiceW` (19) with no arguments (`argc=0`, `argv=NULL`).
pub fn build_start_service_stub(service: &ScHandle) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(32);
    w.write_fixed_array(service);
    w.write_u32(0); // argc
    w.write_u32(0); // argv = NULL
    w.into_bytes()
}

/// `RControlService` (1).
pub fn build_control_service_stub(service: &ScHandle, control: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(32);
    w.write_fixed_array(service);
    w.write_u32(control);
    w.into_bytes()
}

/// A bare handle-only request (`RDeleteService`, `RQueryServiceStatus`, `RCloseServiceHandle`).
pub fn build_handle_stub(handle: &ScHandle) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(20);
    w.write_fixed_array(handle);
    w.into_bytes()
}

/// Builds `RQueryServiceConfigW` (17) stub.
pub fn build_query_service_config_stub(service: &ScHandle, buf_size: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(24);
    w.write_fixed_array(service);
    w.write_u32(buf_size);
    w.into_bytes()
}

/// Builds `REnumServicesStatusW` (14) stub.
pub fn build_enum_services_status_stub(
    scm: &ScHandle,
    service_type: u32,
    service_state: u32,
    buf_size: u32,
    resume_index: Option<u32>,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(40);
    w.write_fixed_array(scm);
    w.write_u32(service_type);
    w.write_u32(service_state);
    w.write_u32(buf_size);
    match resume_index {
        Some(idx) => {
            w.write_u32(REFERENT_BASE);
            w.write_u32(idx);
        }
        None => {
            w.write_u32(0);
        }
    }
    w.into_bytes()
}

/// Builds `RChangeServiceConfigW` (11) stub.
#[allow(clippy::too_many_arguments)]
pub fn build_change_service_config_stub(
    service: &ScHandle,
    service_type: u32,
    start_type: u32,
    error_control: u32,
    binary_path: Option<&str>,
    load_order_group: Option<&str>,
    service_start_name: Option<&str>,
    display_name: Option<&str>,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);
    w.write_fixed_array(service);
    w.write_u32(service_type);
    w.write_u32(start_type);
    w.write_u32(error_control);
    write_opt_wstr(&mut w, binary_path, REFERENT_BASE);
    write_opt_wstr(&mut w, load_order_group, REFERENT_BASE + 4);
    w.write_u32(0); // lpdwTagId = NULL
    w.write_u32(0); // lpDependencies = NULL
    w.write_u32(0); // dwDependSize = 0
    write_opt_wstr(&mut w, service_start_name, REFERENT_BASE + 8);
    w.write_u32(0); // lpPassword = NULL
    w.write_u32(0); // dwPwSize = 0
    write_opt_wstr(&mut w, display_name, REFERENT_BASE + 12);
    w.into_bytes()
}

// ---- Response parsers (test fixtures mirror these) ----

/// Parses `[out] handle(20) + NTSTATUS` (OpenSCManager / OpenService).
pub fn parse_handle_response(stub: &[u8]) -> Result<ScHandle, CoreError> {
    let mut r = NdrReader::new(stub);
    let h = r.read_fixed_array::<20>()?;
    let status = NtStatus(r.read_u32()?);
    if !status.is_success() {
        return Err(CoreError::NtStatus(status));
    }
    Ok(h)
}

/// Parses `RCreateServiceW` response: `[out] lpdwTagId (unique) + ServiceHandle(20) + NTSTATUS`.
pub fn parse_create_service_response(stub: &[u8]) -> Result<ScHandle, CoreError> {
    let mut r = NdrReader::new(stub);
    let tag_ref = r.read_u32()?;
    if tag_ref != 0 {
        let _tag = r.read_u32()?;
    }
    let h = r.read_fixed_array::<20>()?;
    let status = NtStatus(r.read_u32()?);
    if !status.is_success() {
        return Err(CoreError::NtStatus(status));
    }
    Ok(h)
}

/// Parses a response that returns only an `NTSTATUS` (StartService / DeleteService / CloseHandle).
pub fn parse_status_only_response(stub: &[u8]) -> Result<NtStatus, CoreError> {
    let mut r = NdrReader::new(stub);
    // CloseServiceHandle echoes the [out] handle first; skip 20 bytes when present.
    let status = if stub.len() >= 24 {
        let _echo = r.read_fixed_array::<20>()?;
        NtStatus(r.read_u32()?)
    } else {
        NtStatus(r.read_u32()?)
    };
    if !status.is_success() {
        return Err(CoreError::NtStatus(status));
    }
    Ok(status)
}

/// Parses `RControlService` / `RQueryServiceStatus`: `[out] SERVICE_STATUS(28) + NTSTATUS`.
pub fn parse_service_status_response(stub: &[u8]) -> Result<ServiceStatus, CoreError> {
    let mut r = NdrReader::new(stub);
    let st = ServiceStatus::read(&mut r)?;
    let status = NtStatus(r.read_u32()?);
    if !status.is_success() {
        return Err(CoreError::NtStatus(status));
    }
    Ok(st)
}

/// Parses `RQueryServiceConfigW` response: returns `(ServiceConfig, pcbBytesNeeded)`.
pub fn parse_query_service_config_response(stub: &[u8]) -> Result<(ServiceConfig, u32), CoreError> {
    if stub.len() < 8 {
        return Err(CoreError::ProtocolError("Truncated RQueryServiceConfigW response".into()));
    }
    let mut r = NdrReader::new(stub);
    if stub.len() == 8 {
        let needed = r.read_u32()?;
        let err = r.read_u32()?;
        if err == 122 {
            return Ok((ServiceConfig::default(), needed));
        }
        return Err(CoreError::NtStatus(NtStatus(err)));
    }

    let service_type = r.read_u32()?;
    let start_type = r.read_u32()?;
    let error_control = r.read_u32()?;
    let bin_path_ref = r.read_u32()?;
    let group_ref = r.read_u32()?;
    let tag_id = r.read_u32()?;
    let dep_ref = r.read_u32()?;
    let start_name_ref = r.read_u32()?;
    let display_ref = r.read_u32()?;

    let binary_path = if bin_path_ref != 0 {
        read_string_wchar_pointee(&mut r)?
    } else {
        String::new()
    };
    let load_order_group = if group_ref != 0 {
        read_string_wchar_pointee(&mut r)?
    } else {
        String::new()
    };
    let dependencies = if dep_ref != 0 {
        read_string_wchar_pointee(&mut r)?
    } else {
        String::new()
    };
    let service_start_name = if start_name_ref != 0 {
        read_string_wchar_pointee(&mut r)?
    } else {
        String::new()
    };
    let display_name = if display_ref != 0 {
        read_string_wchar_pointee(&mut r)?
    } else {
        String::new()
    };

    let bytes_needed = r.read_u32()?;
    let error_code = r.read_u32()?;
    if error_code != 0 {
        if error_code == 122 {
            return Ok((ServiceConfig::default(), bytes_needed));
        }
        return Err(CoreError::NtStatus(NtStatus(error_code)));
    }

    Ok((
        ServiceConfig {
            service_type,
            start_type,
            error_control,
            binary_path,
            load_order_group,
            tag_id,
            dependencies,
            service_start_name,
            display_name,
        },
        bytes_needed,
    ))
}

/// Parses `REnumServicesStatusW` response: returns `(Vec<EnumServiceStatus>, pcbBytesNeeded)`.
pub fn parse_enum_services_status_response(
    stub: &[u8],
) -> Result<(Vec<EnumServiceStatus>, u32), CoreError> {
    if stub.len() < 12 {
        return Err(CoreError::ProtocolError("Truncated REnumServicesStatusW response".into()));
    }
    let mut r = NdrReader::new(stub);
    let buf_len = r.read_u32()? as usize;
    let raw_buf = r.read_bytes(buf_len)?;
    r.align(4)?;

    let bytes_needed = r.read_u32()?;
    let services_returned = r.read_u32()? as usize;

    let resume_ptr = r.read_u32()?;
    if resume_ptr != 0 {
        let _resume_idx = r.read_u32()?;
    }
    let error_code = r.read_u32()?;

    if error_code != 0 && error_code != 234 {
        return Err(CoreError::NtStatus(NtStatus(error_code)));
    }

    let mut services = Vec::with_capacity(services_returned);
    for i in 0..services_returned {
        let entry_offset = i * 36;
        if entry_offset + 36 > raw_buf.len() {
            break;
        }
        let name_offset = u32::from_le_bytes([
            raw_buf[entry_offset],
            raw_buf[entry_offset + 1],
            raw_buf[entry_offset + 2],
            raw_buf[entry_offset + 3],
        ]) as usize;
        let disp_offset = u32::from_le_bytes([
            raw_buf[entry_offset + 4],
            raw_buf[entry_offset + 5],
            raw_buf[entry_offset + 6],
            raw_buf[entry_offset + 7],
        ]) as usize;

        let status = ServiceStatus::read(&mut NdrReader::new(&raw_buf[entry_offset + 8..entry_offset + 36]))?;

        let service_name = if name_offset < raw_buf.len() {
            read_null_terminated_utf16le(&raw_buf[name_offset..])
        } else {
            String::new()
        };

        let display_name = if disp_offset < raw_buf.len() {
            read_null_terminated_utf16le(&raw_buf[disp_offset..])
        } else {
            String::new()
        };

        services.push(EnumServiceStatus {
            service_name,
            display_name,
            status,
        });
    }

    Ok((services, bytes_needed))
}

/// `[MS-SCMR]` high-level client over a bound [`RpcTransport`] (`\PIPE\svcctl`).
pub struct ScmrClient<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> ScmrClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport, call_id: 1 }
    }

    fn call(&mut self, opnum: u16, stub: Vec<u8>) -> Result<Vec<u8>, CoreError> {
        let call_id = self.call_id;
        self.call_id += 1;
        let pdu = RpcRequestPdu { call_id, context_id: 0, opnum, stub_data: stub }.to_bytes();
        let resp = self.transport.transceive(&pdu)?;
        extract_response_stub(&resp)
    }

    pub fn open_sc_manager(&mut self, machine: Option<&str>, access: u32) -> Result<ScHandle, CoreError> {
        let r = self.call(opnum::R_OPEN_SC_MANAGER_W, build_open_sc_manager_stub(machine, access))?;
        parse_handle_response(&r)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_service(
        &mut self,
        scm: &ScHandle,
        service_name: &str,
        display_name: Option<&str>,
        access: u32,
        service_type: u32,
        start_type: u32,
        error_control: u32,
        binary_path: &str,
    ) -> Result<ScHandle, CoreError> {
        let stub = build_create_service_stub(
            scm, service_name, display_name, access, service_type, start_type, error_control, binary_path,
        );
        let r = self.call(opnum::R_CREATE_SERVICE_W, stub)?;
        parse_create_service_response(&r)
    }

    pub fn open_service(&mut self, scm: &ScHandle, name: &str, access: u32) -> Result<ScHandle, CoreError> {
        let r = self.call(opnum::R_OPEN_SERVICE_W, build_open_service_stub(scm, name, access))?;
        parse_handle_response(&r)
    }

    pub fn start_service(&mut self, service: &ScHandle) -> Result<(), CoreError> {
        let r = self.call(opnum::R_START_SERVICE_W, build_start_service_stub(service))?;
        parse_status_only_response(&r).map(|_| ())
    }

    pub fn control_service(&mut self, service: &ScHandle, control: u32) -> Result<ServiceStatus, CoreError> {
        let r = self.call(opnum::R_CONTROL_SERVICE, build_control_service_stub(service, control))?;
        parse_service_status_response(&r)
    }

    pub fn delete_service(&mut self, service: &ScHandle) -> Result<(), CoreError> {
        let r = self.call(opnum::R_DELETE_SERVICE, build_handle_stub(service))?;
        parse_status_only_response(&r).map(|_| ())
    }

    pub fn query_service_status(&mut self, service: &ScHandle) -> Result<ServiceStatus, CoreError> {
        let r = self.call(opnum::R_QUERY_SERVICE_STATUS, build_handle_stub(service))?;
        parse_service_status_response(&r)
    }

    pub fn query_service_config(&mut self, service: &ScHandle) -> Result<ServiceConfig, CoreError> {
        let stub = build_query_service_config_stub(service, 8192);
        let resp = self.call(opnum::R_QUERY_SERVICE_CONFIG_W, stub)?;
        let (config, needed) = parse_query_service_config_response(&resp)?;
        if config.service_type != 0 || needed <= 8192 {
            return Ok(config);
        }
        let stub2 = build_query_service_config_stub(service, needed);
        let resp2 = self.call(opnum::R_QUERY_SERVICE_CONFIG_W, stub2)?;
        let (config2, _) = parse_query_service_config_response(&resp2)?;
        Ok(config2)
    }

    pub fn enum_services_status(
        &mut self,
        scm: &ScHandle,
        service_type: u32,
        service_state: u32,
    ) -> Result<Vec<EnumServiceStatus>, CoreError> {
        let probe_stub = build_enum_services_status_stub(scm, service_type, service_state, 0, None);
        let resp1 = self.call(opnum::R_ENUM_SERVICES_STATUS_W, probe_stub)?;
        let (_, needed) = parse_enum_services_status_response(&resp1)?;
        if needed == 0 {
            return Ok(Vec::new());
        }
        let fetch_stub = build_enum_services_status_stub(scm, service_type, service_state, needed, None);
        let resp2 = self.call(opnum::R_ENUM_SERVICES_STATUS_W, fetch_stub)?;
        let (services, _) = parse_enum_services_status_response(&resp2)?;
        Ok(services)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn change_service_config(
        &mut self,
        service: &ScHandle,
        service_type: u32,
        start_type: u32,
        error_control: u32,
        binary_path: Option<&str>,
        load_order_group: Option<&str>,
        service_start_name: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<(), CoreError> {
        let stub = build_change_service_config_stub(
            service,
            service_type,
            start_type,
            error_control,
            binary_path,
            load_order_group,
            service_start_name,
            display_name,
        );
        let r = self.call(opnum::R_CHANGE_SERVICE_CONFIG_W, stub)?;
        parse_status_only_response(&r).map(|_| ())
    }

    pub fn close_handle(&mut self, handle: &ScHandle) -> Result<(), CoreError> {
        let r = self.call(opnum::R_CLOSE_SERVICE_HANDLE, build_handle_stub(handle))?;
        parse_status_only_response(&r).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use impacket_dcerpc::{pdu_type, RpcCommonHeader};
    use impacket_ndr::NdrSerialize;
    use std::collections::VecDeque;

    struct MockScm {
        responses: VecDeque<Vec<u8>>,
    }
    impl MockScm {
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
    impl RpcTransport for MockScm {
        fn transceive(&mut self, _r: &[u8]) -> Result<Vec<u8>, CoreError> {
            self.responses.pop_front().ok_or_else(|| CoreError::ProtocolError("no more".into()))
        }
    }

    fn handle_resp(h: [u8; 20]) -> Vec<u8> {
        let mut w = NdrWriter::with_capacity(24);
        w.write_fixed_array(&h);
        w.write_u32(NtStatus::STATUS_SUCCESS.0);
        w.into_bytes()
    }
    fn create_resp(h: [u8; 20]) -> Vec<u8> {
        let mut w = NdrWriter::with_capacity(28);
        w.write_u32(0); // lpdwTagId referent = NULL
        w.write_fixed_array(&h);
        w.write_u32(NtStatus::STATUS_SUCCESS.0);
        w.into_bytes()
    }
    fn status_only() -> Vec<u8> {
        let mut w = NdrWriter::with_capacity(4);
        w.write_u32(NtStatus::STATUS_SUCCESS.0);
        w.into_bytes()
    }

    #[test]
    fn test_scmr_psexec_service_lifecycle() {
        let scm = [0x11u8; 20];
        let svc = [0x22u8; 20];
        let mock = MockScm::new(vec![
            handle_resp(scm),       // OpenSCManagerW
            create_resp(svc),       // CreateServiceW
            status_only(),          // StartServiceW
            {
                let mut w = NdrWriter::with_capacity(32);
                ServiceStatus { current_state: 1, ..Default::default() }.write(&mut w);
                w.write_u32(NtStatus::STATUS_SUCCESS.0);
                w.into_bytes()
            }, // ControlService (stop)
            status_only(),          // DeleteService
            status_only(),          // CloseServiceHandle
        ]);
        let mut c = ScmrClient::new(mock);
        let scm_h = c.open_sc_manager(None, access::SC_MANAGER_ALL_ACCESS).unwrap();
        assert_eq!(scm_h, scm);
        let svc_h = c
            .create_service(
                &scm_h,
                "ImpacketRs",
                Some("Impacket-RS"),
                access::SERVICE_ALL_ACCESS,
                access::SERVICE_WIN32_OWN_PROCESS,
                access::SERVICE_DEMAND_START,
                access::SERVICE_ERROR_IGNORE,
                r"%COMSPEC% /c echo hi",
            )
            .unwrap();
        assert_eq!(svc_h, svc);
        c.start_service(&svc_h).unwrap();
        let st = c.control_service(&svc_h, access::SERVICE_CONTROL_STOP).unwrap();
        assert_eq!(st.current_state, 1);
        c.delete_service(&svc_h).unwrap();
        c.close_handle(&svc_h).unwrap();
    }

    #[test]
    fn test_open_service_builder_shape() {
        let stub = build_open_service_stub(&[0u8; 20], "spooler", access::SERVICE_ALL_ACCESS);
        // 20-byte handle + conformant/varying "spooler\0" (8 wchars = 12+16=28) + access.
        assert_eq!(&stub[0..20], &[0u8; 20]);
        assert_eq!(u32::from_le_bytes([stub[20], stub[21], stub[22], stub[23]]), 8); // MaxCount
    }

    #[test]
    fn test_query_service_config_roundtrip() {
        let mut w = NdrWriter::with_capacity(128);
        w.write_u32(service_type::SERVICE_WIN32_OWN_PROCESS);
        w.write_u32(start_type::SERVICE_AUTO_START);
        w.write_u32(1); // Normal error control
        w.write_u32(REFERENT_BASE);
        w.write_u32(0); // group
        w.write_u32(0); // tag
        w.write_u32(0); // dep
        w.write_u32(REFERENT_BASE + 4);
        w.write_u32(REFERENT_BASE + 8);
        write_string_wchar_pointee(&mut w, r"C:\Windows\System32\spoolsv.exe");
        write_string_wchar_pointee(&mut w, "LocalSystem");
        write_string_wchar_pointee(&mut w, "Print Spooler");
        w.write_u32(256); // pcbBytesNeeded
        w.write_u32(0);   // ErrorCode = 0 (SUCCESS)

        let (config, _) = parse_query_service_config_response(&w.into_bytes()).unwrap();
        assert_eq!(config.service_type, service_type::SERVICE_WIN32_OWN_PROCESS);
        assert_eq!(config.start_type, start_type::SERVICE_AUTO_START);
        assert_eq!(config.binary_path, r"C:\Windows\System32\spoolsv.exe");
        assert_eq!(config.service_start_name, "LocalSystem");
        assert_eq!(config.display_name, "Print Spooler");
    }

    #[test]
    fn test_enum_services_status_roundtrip() {
        // Build mock flat buffer
        let mut flat = Vec::new();
        // Struct offset 0: 36 bytes
        let name_offset = 36u32;
        let disp_offset = 36 + 16u32; // "Spooler\0" = 8 u16s = 16 bytes
        flat.extend_from_slice(&name_offset.to_le_bytes());
        flat.extend_from_slice(&disp_offset.to_le_bytes());
        let mut sw = NdrWriter::new();
        ServiceStatus {
            service_type: service_type::SERVICE_WIN32_OWN_PROCESS,
            current_state: service_state::SERVICE_RUNNING,
            ..Default::default()
        }
        .write(&mut sw);
        flat.extend_from_slice(&sw.into_bytes());

        // Add strings
        for c in "Spooler\0".encode_utf16() {
            flat.extend_from_slice(&c.to_le_bytes());
        }
        for c in "Print Spooler\0".encode_utf16() {
            flat.extend_from_slice(&c.to_le_bytes());
        }

        let mut w = NdrWriter::with_capacity(flat.len() + 32);
        w.write_u32(flat.len() as u32);
        w.write_bytes(&flat);
        w.align(4);
        w.write_u32(flat.len() as u32); // pcbBytesNeeded
        w.write_u32(1);                  // lpServicesReturned
        w.write_u32(0);                  // lpResumeIndex = NULL
        w.write_u32(0);                  // ErrorCode = 0

        let (services, _) = parse_enum_services_status_response(&w.into_bytes()).unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].service_name, "Spooler");
        assert_eq!(services[0].display_name, "Print Spooler");
        assert_eq!(services[0].status.current_state, service_state::SERVICE_RUNNING);
        assert_eq!(services[0].status.state_str(), "RUNNING");
    }
}
