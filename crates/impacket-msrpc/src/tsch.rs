//! `tsch`: `[MS-TSCH]` Task Scheduler Service (ITaskSchedulerService) client
//! (`impacket/dcerpc/v5/tsch.py`). Drives `atexec`-style remote command execution over `\PIPE\atsvc`.
//!
//! Implements `SchRpcRegisterTask` (1), `SchRpcRun` (12), `SchRpcDelete` (13). `[in,string]` ref
//! pointers marshal the conformant/varying wchar array inline; `[unique,string]` ones carry a referent.
//! Round-trip tested; not validated against a live host.

use crate::dtypes::{read_string_wchar_pointee, write_string_wchar_pointee, REFERENT_BASE};
use impacket_core::CoreError;
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport};
use impacket_ndr::{NdrReader, NdrWriter, RpcUuid};

/// MS-TSCH ITaskSchedulerService: `86d35949-83c9-4044-b424-db363231fd0c` v1.0 (`\PIPE\atsvc`).
pub const TSCH_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0x86d3_5949,
    0x83c9,
    0x4044,
    [0xb4, 0x24, 0xdb, 0x36, 0x32, 0x31, 0xfd, 0x0c],
);
pub const TSCH_VERSION_MAJOR: u16 = 1;
pub const TSCH_VERSION_MINOR: u16 = 0;

pub mod opnum {
    pub const SCH_RPC_REGISTER_TASK: u16 = 1;
    pub const SCH_RPC_RETRIEVE_TASK: u16 = 2;
    pub const SCH_RPC_ENUM_FOLDERS: u16 = 6;
    pub const SCH_RPC_ENUM_TASKS: u16 = 7;
    pub const SCH_RPC_RUN: u16 = 12;
    pub const SCH_RPC_DELETE: u16 = 13;
    pub const SCH_RPC_GET_TASK_INFO: u16 = 17;
}

/// Operational state of a scheduled task (`[MS-TSCH] TASK_STATE`).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TaskState {
    Unknown,
    Disabled,
    Queued,
    Ready,
    Running,
    Other(u32),
}

impl TaskState {
    pub const fn from_u32(raw: u32) -> Self {
        match raw {
            0 => Self::Unknown,
            1 => Self::Disabled,
            2 => Self::Queued,
            3 => Self::Ready,
            4 => Self::Running,
            other => Self::Other(other),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Disabled => "Disabled",
            Self::Queued => "Queued",
            Self::Ready => "Ready",
            Self::Running => "Running",
            Self::Other(_) => "Other",
        }
    }
}

/// Information returned by `SchRpcGetTaskInfo` (`[MS-TSCH] 3.2.5.4.18`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskInfo {
    pub enabled: bool,
    pub state: TaskState,
}

/// `SchRpcEnumTasks` / `SchRpcEnumFolders` flags.
pub const TASK_ENUM_HIDDEN: u32 = 0x0000_0001;

/// `SchRpcRegisterTask` flags: `TASK_CREATE`.
pub const TASK_CREATE: u32 = 0x0000_0002;
/// `TASK_LOGON_NONE`.
pub const TASK_LOGON_NONE: u32 = 0;

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

/// `SchRpcRegisterTask` (1): `path` `[unique,string]`, `xml` `[string]`, `flags`, `sddl` NULL,
/// `logonType`, `cCreds=0`, `pCreds=NULL`.
pub fn build_register_task_stub(path: &str, xml: &str, flags: u32, logon_type: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(256 + xml.len() * 2);
    write_opt_wstr(&mut w, Some(path), REFERENT_BASE); // path [unique,string]
    write_string_wchar_pointee(&mut w, xml); // xml [string] ref (inline)
    w.align(4);
    w.write_u32(flags);
    write_opt_wstr(&mut w, None, REFERENT_BASE + 4); // sddl [unique,string] = NULL
    w.write_u32(logon_type);
    w.write_u32(0); // cCreds
    w.write_u32(0); // pCreds [unique] = NULL
    w.into_bytes()
}

/// Parses `SchRpcRegisterTask` response: `pActualPath [out,string]`, `pErrorInfo [out]`, HRESULT.
pub fn parse_register_task_response(stub: &[u8]) -> Result<String, CoreError> {
    let mut r = NdrReader::new(stub);
    let actual_path_ref = r.read_u32()?;
    let actual_path = if actual_path_ref != 0 {
        read_string_wchar_pointee(&mut r)?
    } else {
        String::new()
    };
    let error_info_ref = r.read_u32()?;
    if error_info_ref != 0 {
        // On failure a TASK_XML_ERROR_INFO is returned; the HRESULT will be non-zero and we error out.
        return Err(CoreError::ProtocolError("SchRpcRegisterTask returned error info".into()));
    }
    let hresult = r.read_u32()?;
    accept_hresult(hresult)?;
    Ok(actual_path)
}

/// `SchRpcRun` (12): `path [string]`, `cArgs=0`, `pArgs=NULL`, `flags`, `sessionId=0`, `user=NULL`.
pub fn build_run_stub(path: &str, flags: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    write_string_wchar_pointee(&mut w, path); // [string] ref
    w.align(4);
    w.write_u32(0); // cArgs
    w.write_u32(0); // pArgs [unique] = NULL
    w.write_u32(flags);
    w.write_u32(0); // sessionId
    write_opt_wstr(&mut w, None, REFERENT_BASE); // user [unique,string] = NULL
    w.into_bytes()
}

/// Parses `SchRpcRun` response: `pGuid [out] GUID*`, HRESULT.
pub fn parse_run_response(stub: &[u8]) -> Result<Option<RpcUuid>, CoreError> {
    use impacket_ndr::NdrDeserialize;
    let mut r = NdrReader::new(stub);
    let guid_ref = r.read_u32()?;
    let guid = if guid_ref != 0 {
        Some(RpcUuid::ndr_deserialize(&mut r)?)
    } else {
        None
    };
    let hresult = r.read_u32()?;
    accept_hresult(hresult)?;
    Ok(guid)
}

/// `SchRpcDelete` (13): `path [string]`, `flags`.
pub fn build_delete_stub(path: &str, flags: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(48);
    write_string_wchar_pointee(&mut w, path);
    w.align(4);
    w.write_u32(flags);
    w.into_bytes()
}

/// Parses `SchRpcDelete` response: HRESULT only.
pub fn parse_delete_response(stub: &[u8]) -> Result<(), CoreError> {
    let mut r = NdrReader::new(stub);
    accept_hresult(r.read_u32()?)
}

/// Builds `SchRpcEnumTasks` (7) request stub: `path [string]`, `flags`, `startIndex`, `cRequested`.
pub fn build_enum_tasks_stub(
    path: &str,
    flags: u32,
    start_index: u32,
    c_requested: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    write_string_wchar_pointee(&mut w, path);
    w.align(4);
    w.write_u32(flags);
    w.write_u32(start_index);
    w.write_u32(c_requested);
    w.into_bytes()
}

/// Builds `SchRpcEnumFolders` (6) request stub: `path [string]`, `flags`, `startIndex`, `cRequested`.
pub fn build_enum_folders_stub(
    path: &str,
    flags: u32,
    start_index: u32,
    c_requested: u32,
) -> Vec<u8> {
    build_enum_tasks_stub(path, flags, start_index, c_requested)
}

/// Parses `SchRpcEnumTasks` or `SchRpcEnumFolders` response.
///
/// Returns `(updated_start_index, names)`. Accepts `S_OK` (0) and `S_FALSE` (1).
pub fn parse_enum_names_response(stub: &[u8]) -> Result<(u32, Vec<String>), CoreError> {
    let mut r = NdrReader::new(stub);
    let next_index = r.read_u32()?;
    let count = r.read_u32()? as usize;
    let array_ref = r.read_u32()?;
    let mut names = Vec::new();
    if array_ref != 0 && count > 0 {
        if count > 65_536 {
            return Err(CoreError::ProtocolError("SchRpcEnum*: invalid count".into()));
        }
        let max_count = r.read_u32()? as usize;
        if max_count < count {
            return Err(CoreError::ProtocolError("SchRpcEnum*: MaxCount < count".into()));
        }
        let mut ptrs = Vec::with_capacity(count);
        for _ in 0..count {
            ptrs.push(r.read_u32()?);
        }
        for ptr in ptrs {
            if ptr != 0 {
                names.push(read_string_wchar_pointee(&mut r)?);
            } else {
                names.push(String::new());
            }
        }
    }
    let hresult = r.read_u32()?;
    if hresult != 0 && hresult != 1 {
        return Err(CoreError::ProtocolError(format!("SchRpcEnum* HRESULT 0x{:08X}", hresult)));
    }
    Ok((next_index, names))
}

/// Builds a wire-accurate `SchRpcEnumTasks` or `SchRpcEnumFolders` response stub (test fixture).
pub fn build_enum_names_response(names: &[String], next_index: u32, hresult: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(256);
    w.write_u32(next_index);
    let count = names.len() as u32;
    w.write_u32(count);
    if count == 0 {
        w.write_u32(0); // NULL array pointer
    } else {
        w.write_u32(REFERENT_BASE); // array referent
        w.write_u32(count); // MaxCount
        for i in 0..count {
            w.write_u32(REFERENT_BASE + 4 + i);
        }
        for name in names {
            write_string_wchar_pointee(&mut w, name);
        }
    }
    w.write_u32(hresult);
    w.into_bytes()
}

/// Builds `SchRpcRetrieveTask` (2) request stub: `path [string]`, `lpcwszLanguagesBuffer [string]`, `pulNumLanguages`.
pub fn build_retrieve_task_stub(path: &str) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128 + path.len() * 2);
    write_string_wchar_pointee(&mut w, path);
    w.align(4);
    // lpcwszLanguagesBuffer: empty string
    write_string_wchar_pointee(&mut w, "");
    w.align(4);
    // pulNumLanguages = 0
    w.write_u32(0);
    w.into_bytes()
}

/// Parses `SchRpcRetrieveTask` response: `pXml [out, string]`, HRESULT.
pub fn parse_retrieve_task_response(stub: &[u8]) -> Result<String, CoreError> {
    let mut r = NdrReader::new(stub);
    let xml_ref = r.read_u32()?;
    let xml = if xml_ref != 0 {
        read_string_wchar_pointee(&mut r)?
    } else {
        String::new()
    };
    let hresult = r.read_u32()?;
    accept_hresult(hresult)?;
    Ok(xml)
}

/// Builds a wire-accurate `SchRpcRetrieveTask` response stub (test fixture).
pub fn build_retrieve_task_response(xml: &str, hresult: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128 + xml.len() * 2);
    if xml.is_empty() {
        w.write_u32(0);
    } else {
        w.write_u32(REFERENT_BASE);
        write_string_wchar_pointee(&mut w, xml);
        w.align(4);
    }
    w.write_u32(hresult);
    w.into_bytes()
}

/// Builds `SchRpcGetTaskInfo` (17) request stub: `path [string]`, `flags`.
pub fn build_get_task_info_stub(path: &str, flags: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64 + path.len() * 2);
    write_string_wchar_pointee(&mut w, path);
    w.align(4);
    w.write_u32(flags);
    w.into_bytes()
}

/// Parses `SchRpcGetTaskInfo` response: `pEnabled [out]`, `pState [out]`, HRESULT.
pub fn parse_get_task_info_response(stub: &[u8]) -> Result<TaskInfo, CoreError> {
    let mut r = NdrReader::new(stub);
    let enabled_raw = r.read_u32()?;
    let state_raw = r.read_u32()?;
    let hresult = r.read_u32()?;
    accept_hresult(hresult)?;
    Ok(TaskInfo {
        enabled: enabled_raw != 0,
        state: TaskState::from_u32(state_raw),
    })
}

/// Builds a wire-accurate `SchRpcGetTaskInfo` response stub (test fixture).
pub fn build_get_task_info_response(enabled: bool, state: u32, hresult: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(16);
    w.write_u32(if enabled { 1 } else { 0 });
    w.write_u32(state);
    w.write_u32(hresult);
    w.into_bytes()
}

/// Accepts `S_OK` (0); any non-zero HRESULT is treated as an error.
fn accept_hresult(hr: u32) -> Result<(), CoreError> {
    if hr == 0 {
        Ok(())
    } else {
        Err(CoreError::ProtocolError(format!("SchRpc* HRESULT 0x{:08X}", hr)))
    }
}

/// `[MS-TSCH]` high-level client over a bound [`RpcTransport`] (`\PIPE\atsvc`).
pub struct TschClient<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> TschClient<T> {
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

    pub fn register_task(&mut self, path: &str, xml: &str) -> Result<String, CoreError> {
        let stub = build_register_task_stub(path, xml, TASK_CREATE, TASK_LOGON_NONE);
        let r = self.call(opnum::SCH_RPC_REGISTER_TASK, stub)?;
        parse_register_task_response(&r)
    }

    pub fn run(&mut self, path: &str) -> Result<Option<RpcUuid>, CoreError> {
        let r = self.call(opnum::SCH_RPC_RUN, build_run_stub(path, 0))?;
        parse_run_response(&r)
    }

    pub fn delete(&mut self, path: &str) -> Result<(), CoreError> {
        let r = self.call(opnum::SCH_RPC_DELETE, build_delete_stub(path, 0))?;
        parse_delete_response(&r)
    }

    /// Enumerates task names directly inside `path` with default flags (`TASK_ENUM_HIDDEN`).
    pub fn enum_tasks(&mut self, path: &str) -> Result<Vec<String>, CoreError> {
        self.enum_tasks_with_flags(path, TASK_ENUM_HIDDEN)
    }

    /// Enumerates task names directly inside `path` with custom flags.
    pub fn enum_tasks_with_flags(
        &mut self,
        path: &str,
        flags: u32,
    ) -> Result<Vec<String>, CoreError> {
        let stub = build_enum_tasks_stub(path, flags, 0, 0xFFFF_FFFF);
        let r = self.call(opnum::SCH_RPC_ENUM_TASKS, stub)?;
        let (_, names) = parse_enum_names_response(&r)?;
        Ok(names)
    }

    /// Enumerates subfolder names directly inside `path` with default flags (`TASK_ENUM_HIDDEN`).
    pub fn enum_folders(&mut self, path: &str) -> Result<Vec<String>, CoreError> {
        self.enum_folders_with_flags(path, TASK_ENUM_HIDDEN)
    }

    /// Enumerates subfolder names directly inside `path` with custom flags.
    pub fn enum_folders_with_flags(
        &mut self,
        path: &str,
        flags: u32,
    ) -> Result<Vec<String>, CoreError> {
        let stub = build_enum_folders_stub(path, flags, 0, 0xFFFF_FFFF);
        let r = self.call(opnum::SCH_RPC_ENUM_FOLDERS, stub)?;
        let (_, names) = parse_enum_names_response(&r)?;
        Ok(names)
    }

    /// Recursively enumerates all tasks under `root_path`.
    pub fn enum_all_tasks_recursive(&mut self, root_path: &str) -> Result<Vec<String>, CoreError> {
        let mut results = Vec::new();
        let mut to_visit = vec![root_path.to_string()];
        while let Some(current_path) = to_visit.pop() {
            if let Ok(tasks) = self.enum_tasks(&current_path) {
                for task in tasks {
                    let full_path = if current_path == "\\" {
                        format!("\\{}", task)
                    } else {
                        format!("{}\\{}", current_path.trim_end_matches('\\'), task)
                    };
                    results.push(full_path);
                }
            }
            if let Ok(folders) = self.enum_folders(&current_path) {
                for folder in folders {
                    let full_path = if current_path == "\\" {
                        format!("\\{}", folder)
                    } else {
                        format!("{}\\{}", current_path.trim_end_matches('\\'), folder)
                    };
                    to_visit.push(full_path);
                }
            }
        }
        results.sort();
        Ok(results)
    }

    /// Retrieves the XML definition for a task (`[MS-TSCH]` Opnum 2).
    pub fn retrieve_task(&mut self, path: &str) -> Result<String, CoreError> {
        let stub = build_retrieve_task_stub(path);
        let resp = self.call(opnum::SCH_RPC_RETRIEVE_TASK, stub)?;
        parse_retrieve_task_response(&resp)
    }

    /// Queries state and configuration metadata for a task (`[MS-TSCH]` Opnum 17).
    pub fn get_task_info(&mut self, path: &str) -> Result<TaskInfo, CoreError> {
        let stub = build_get_task_info_stub(path, 0);
        let resp = self.call(opnum::SCH_RPC_GET_TASK_INFO, stub)?;
        parse_get_task_info_response(&resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use impacket_dcerpc::{pdu_type, RpcCommonHeader};
    use impacket_ndr::NdrSerialize;
    use std::collections::VecDeque;

    struct MockTsch {
        responses: VecDeque<Vec<u8>>,
    }
    impl MockTsch {
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
    impl RpcTransport for MockTsch {
        fn transceive(&mut self, _r: &[u8]) -> Result<Vec<u8>, CoreError> {
            self.responses.pop_front().ok_or_else(|| CoreError::ProtocolError("no more".into()))
        }
    }

    fn register_resp(path: &str) -> Vec<u8> {
        let mut w = NdrWriter::with_capacity(64);
        w.write_u32(REFERENT_BASE); // pActualPath referent
        write_string_wchar_pointee(&mut w, path);
        w.align(4);
        w.write_u32(0); // pErrorInfo = NULL
        w.write_u32(0); // HRESULT = S_OK
        w.into_bytes()
    }
    fn run_resp() -> Vec<u8> {
        let mut w = NdrWriter::with_capacity(32);
        w.write_u32(REFERENT_BASE); // pGuid referent
        RpcUuid::new(0x11223344, 0x5566, 0x7788, [0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00])
            .ndr_serialize(&mut w);
        w.write_u32(0); // HRESULT
        w.into_bytes()
    }
    fn delete_resp() -> Vec<u8> {
        let mut w = NdrWriter::with_capacity(4);
        w.write_u32(0);
        w.into_bytes()
    }

    #[test]
    fn test_tsch_atexec_task_lifecycle() {
        let mock = MockTsch::new(vec![
            register_resp(r"\ImpacketRs"),
            run_resp(),
            delete_resp(),
        ]);
        let mut c = TschClient::new(mock);
        let actual = c.register_task(r"\ImpacketRs", "<Task/>").unwrap();
        assert_eq!(actual, r"\ImpacketRs");
        let guid = c.run(r"\ImpacketRs").unwrap();
        assert!(guid.is_some());
        c.delete(r"\ImpacketRs").unwrap();
    }

    #[test]
    fn test_register_hresult_error_surfaces() {
        let mut w = NdrWriter::with_capacity(16);
        w.write_u32(0); // pActualPath = NULL
        w.write_u32(0); // pErrorInfo = NULL
        w.write_u32(0x8007_0005); // E_ACCESSDENIED
        let stub = w.into_bytes();
        assert!(parse_register_task_response(&stub).is_err());
    }

    #[test]
    fn test_enum_tasks_and_folders_roundtrip() {
        let tasks = vec!["TaskA".to_string(), "TaskB".to_string()];
        let wire = build_enum_names_response(&tasks, 2, 0);
        let (next_idx, parsed) = parse_enum_names_response(&wire).unwrap();
        assert_eq!(next_idx, 2);
        assert_eq!(parsed, tasks);

        // Empty response
        let empty_wire = build_enum_names_response(&[], 0, 0);
        let (next_idx2, parsed2) = parse_enum_names_response(&empty_wire).unwrap();
        assert_eq!(next_idx2, 0);
        assert!(parsed2.is_empty());
    }

    #[test]
    fn test_tsch_client_enum_mock() {
        let tasks = vec!["UpdateTask".to_string()];
        let folders = vec!["Microsoft".to_string()];
        let mock = MockTsch::new(vec![
            build_enum_names_response(&tasks, 1, 0),
            build_enum_names_response(&folders, 1, 0),
        ]);
        let mut c = TschClient::new(mock);
        let got_tasks = c.enum_tasks(r"\").unwrap();
        assert_eq!(got_tasks, tasks);
        let got_folders = c.enum_folders(r"\").unwrap();
        assert_eq!(got_folders, folders);
    }

    #[test]
    fn test_retrieve_task_roundtrip() {
        let sample_xml = "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><RegistrationInfo/></Task>";
        let wire = build_retrieve_task_response(sample_xml, 0);
        let parsed = parse_retrieve_task_response(&wire).unwrap();
        assert_eq!(parsed, sample_xml);

        let err_wire = build_retrieve_task_response("", 0x8007_0002); // ERROR_FILE_NOT_FOUND
        assert!(parse_retrieve_task_response(&err_wire).is_err());
    }

    #[test]
    fn test_get_task_info_roundtrip() {
        let wire = build_get_task_info_response(true, 3, 0); // enabled, TASK_STATE_READY
        let info = parse_get_task_info_response(&wire).unwrap();
        assert!(info.enabled);
        assert_eq!(info.state, TaskState::Ready);
        assert_eq!(info.state.name(), "Ready");

        let disabled_wire = build_get_task_info_response(false, 1, 0); // disabled, TASK_STATE_DISABLED
        let info2 = parse_get_task_info_response(&disabled_wire).unwrap();
        assert!(!info2.enabled);
        assert_eq!(info2.state, TaskState::Disabled);
        assert_eq!(info2.state.name(), "Disabled");
    }
}
