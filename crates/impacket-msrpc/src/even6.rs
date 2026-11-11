//! `even6`: `[MS-EVEN6]` Windows EventLog Remoting Protocol Version 6.0 Client
//! (`impacket/dcerpc/v5/even6.py` & `impacket/examples/eventlog.py`).
//!
//! Implements remote event log queries and live event streaming over `\PIPE\eventlog`
//! using DCE/RPC interface UUID `F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C` v1.0:
//! - `EvtRpcRegisterLogQuery` (Opnum 5): register XPath or channel query
//! - `EvtRpcQueryNext` (Opnum 11): batch retrieve event records in BinXml format
//! - `EvtRpcClose` (Opnum 13): close query and operation control context handles

use crate::dtypes::{write_string_wchar_pointee, REFERENT_BASE};
use impacket_core::{decode_utf16le, CoreError};
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport};
use impacket_ndr::{NdrReader, NdrWriter, RpcUuid};

/// MS-EVEN6 Interface UUID: `F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C` v1.0 (`\PIPE\eventlog`).
pub const EVEN6_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0xf6be_aff7,
    0x1e19,
    0x4fbb,
    [0x9f, 0x8f, 0xb8, 0x9e, 0x20, 0x18, 0x33, 0x7c],
);
pub const EVEN6_VERSION_MAJOR: u16 = 1;
pub const EVEN6_VERSION_MINOR: u16 = 0;
pub const EVEN6_NAMED_PIPE: &str = r"\PIPE\eventlog";

pub mod opnum {
    pub const EVT_RPC_REGISTER_LOG_QUERY: u16 = 5;
    pub const EVT_RPC_QUERY_NEXT: u16 = 11;
    pub const EVT_RPC_CLOSE: u16 = 13;
}

pub mod flags {
    pub const EVT_QUERY_CHANNEL_PATH: u32 = 0x0000_0001;
    pub const EVT_QUERY_FILE_PATH: u32 = 0x0000_0002;
    pub const EVT_QUERY_TOLERATE_QUERY_ERRORS: u32 = 0x0000_1000;
    pub const EVT_QUERY_FORWARD_DIRECTION: u32 = 0x0000_0100;
    pub const EVT_QUERY_REVERSE_DIRECTION: u32 = 0x0000_0200;
}

pub mod error_status {
    pub const ERROR_SUCCESS: u32 = 0;
    pub const ERROR_NO_MORE_ITEMS: u32 = 259; // 0x00000103
}

/// Represents an individual Windows Event Log record parsed from `EvtRpcQueryNext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvtEventRecord {
    pub raw_bytes: Vec<u8>,
    pub event_id: Option<u32>,
    pub channel: Option<String>,
    pub provider: Option<String>,
    pub time_created: Option<String>,
    pub computer: Option<String>,
    pub data_strings: Vec<String>,
}

impl EvtEventRecord {
    /// Parses an event record from raw `EvtRpcQueryNext` event bytes (BinXml or XML fragment).
    pub fn parse(bytes: &[u8]) -> Self {
        let mut record = Self {
            raw_bytes: bytes.to_vec(),
            event_id: None,
            channel: None,
            provider: None,
            time_created: None,
            computer: None,
            data_strings: Vec::new(),
        };

        // Scan for UTF-16LE strings and XML tags embedded in the BinXml event payload
        let strings = extract_utf16le_strings(bytes);

        // Extract metadata based on common event log keywords
        let mut i = 0;
        while i < strings.len() {
            let s = &strings[i];
            if s.eq_ignore_ascii_case("EventID") && i + 1 < strings.len() {
                if let Ok(id) = strings[i + 1].trim().parse::<u32>() {
                    record.event_id = Some(id);
                }
            } else if s.eq_ignore_ascii_case("Channel") && i + 1 < strings.len() {
                record.channel = Some(strings[i + 1].clone());
            } else if s.eq_ignore_ascii_case("Computer") && i + 1 < strings.len() {
                record.computer = Some(strings[i + 1].clone());
            } else if (s.eq_ignore_ascii_case("Provider") || s.eq_ignore_ascii_case("ProviderName"))
                && i + 1 < strings.len()
            {
                record.provider = Some(strings[i + 1].clone());
            } else if s.eq_ignore_ascii_case("TimeCreated") && i + 1 < strings.len() {
                record.time_created = Some(strings[i + 1].clone());
            }
            i += 1;
        }

        // Retain readable payload strings
        for s in strings {
            let trimmed = s.trim();
            if trimmed.len() > 1
                && !is_common_xml_schema_token(trimmed)
                && !record.data_strings.contains(&trimmed.to_string())
            {
                record.data_strings.push(trimmed.to_string());
            }
        }

        record
    }

    /// Formats the event into a single-line summary string.
    pub fn to_summary_string(&self) -> String {
        let id_str = self
            .event_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "<unknown>".to_string());
        let chan = self.channel.as_deref().unwrap_or("<channel>");
        let prov = self.provider.as_deref().unwrap_or("<provider>");
        let comp = self.computer.as_deref().unwrap_or("<host>");
        let time = self.time_created.as_deref().unwrap_or("<time>");

        format!(
            "EventID: {:<5} | Channel: {:<12} | Host: {:<16} | Time: {:<20} | Provider: {}",
            id_str, chan, comp, time, prov
        )
    }

    /// Reconstructs a clean XML-like text representation of the event record.
    pub fn to_xml_string(&self) -> String {
        let id_str = self
            .event_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "0".to_string());
        let chan = self.channel.as_deref().unwrap_or("System");
        let prov = self.provider.as_deref().unwrap_or("Microsoft-Windows-Eventlog");
        let comp = self.computer.as_deref().unwrap_or("localhost");
        let time = self.time_created.as_deref().unwrap_or("1601-01-01T00:00:00Z");

        let mut out = String::new();
        out.push_str("<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">\n");
        out.push_str("  <System>\n");
        out.push_str(&format!("    <Provider Name=\"{}\"/>\n", prov));
        out.push_str(&format!("    <EventID>{}</EventID>\n", id_str));
        out.push_str(&format!("    <Channel>{}</Channel>\n", chan));
        out.push_str(&format!("    <Computer>{}</Computer>\n", comp));
        out.push_str(&format!("    <TimeCreated SystemTime=\"{}\"/>\n", time));
        out.push_str("  </System>\n");

        if !self.data_strings.is_empty() {
            out.push_str("  <EventData>\n");
            for (idx, d) in self.data_strings.iter().enumerate() {
                out.push_str(&format!("    <Data Name=\"Param{}\">{}</Data>\n", idx + 1, d));
            }
            out.push_str("  </EventData>\n");
        }
        out.push_str("</Event>");
        out
    }
}

/// Helper extracting valid UTF-16LE strings from arbitrary byte streams.
fn extract_utf16le_strings(bytes: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    let mut i = 0;
    while i + 1 < bytes.len() {
        let code = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        // Check for printable ASCII or common Unicode range
        if (code >= 0x20 && code <= 0x7e) || code == 0x09 || code == 0x0a || code == 0x0d {
            current.push(bytes[i]);
            current.push(bytes[i + 1]);
        } else {
            if current.len() >= 4 {
                // Minimum 2 UTF-16 characters
                if let Ok(s) = decode_utf16le(&current) {
                    let trimmed = s.trim().to_string();
                    if !trimmed.is_empty() {
                        strings.push(trimmed);
                    }
                }
            }
            current.clear();
        }
        i += 2;
    }

    if current.len() >= 4 {
        if let Ok(s) = decode_utf16le(&current) {
            let trimmed = s.trim().to_string();
            if !trimmed.is_empty() {
                strings.push(trimmed);
            }
        }
    }

    strings
}

fn is_common_xml_schema_token(s: &str) -> bool {
    matches!(
        s,
        "Event"
            | "System"
            | "EventData"
            | "UserData"
            | "RenderingInfo"
            | "Provider"
            | "EventID"
            | "Version"
            | "Level"
            | "Task"
            | "Opcode"
            | "Keywords"
            | "TimeCreated"
            | "EventRecordID"
            | "Correlation"
            | "Execution"
            | "Channel"
            | "Computer"
            | "Security"
            | "http://schemas.microsoft.com/win/2004/08/events/event"
    )
}

/// Builds request stub for `EvtRpcRegisterLogQuery` (Opnum 5).
pub fn build_register_log_query_stub(path: Option<&str>, query: &str, flags: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);

    if let Some(p) = path {
        w.write_u32(REFERENT_BASE);
        w.write_u32(REFERENT_BASE + 4);
        w.write_u32(flags);
        write_string_wchar_pointee(&mut w, p);
        write_string_wchar_pointee(&mut w, query);
    } else {
        w.write_u32(0); // NULL path referent
        w.write_u32(REFERENT_BASE);
        w.write_u32(flags);
        write_string_wchar_pointee(&mut w, query);
    }

    w.into_bytes()
}

/// Parses response stub for `EvtRpcRegisterLogQuery` (Opnum 5).
/// Returns `(query_handle, op_control_handle)`.
pub fn parse_register_log_query_response(
    stub: &[u8],
) -> Result<([u8; 20], [u8; 20]), CoreError> {
    if stub.len() < 44 {
        return Err(CoreError::BufferUnderflow {
            needed: 44,
            available: stub.len(),
        });
    }

    let mut r = NdrReader::new(stub);
    let mut query_handle = [0u8; 20];
    let mut op_control_handle = [0u8; 20];

    query_handle.copy_from_slice(r.read_bytes(20)?);
    op_control_handle.copy_from_slice(r.read_bytes(20)?);

    // Remaining stub contains channelInfo array, RpcInfo error, and return code status
    // Status is the last 4 bytes of stub
    let status = u32::from_le_bytes([
        stub[stub.len() - 4],
        stub[stub.len() - 3],
        stub[stub.len() - 2],
        stub[stub.len() - 1],
    ]);

    if status != error_status::ERROR_SUCCESS {
        return Err(CoreError::ProtocolError(format!(
            "EvtRpcRegisterLogQuery failed with status 0x{:08X}",
            status
        )));
    }

    Ok((query_handle, op_control_handle))
}

/// Builds a wire-accurate mock response for `EvtRpcRegisterLogQuery` (test fixture).
pub fn build_register_log_query_response(
    query_handle: &[u8; 20],
    op_control_handle: &[u8; 20],
    status: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    w.write_bytes(query_handle);
    w.write_bytes(op_control_handle);
    w.write_u32(0); // queryChannelInfoSize = 0
    w.write_u32(0); // queryChannelInfo pointer = NULL
    // RpcInfo struct:
    w.write_u32(0); // m_error = 0
    w.write_u32(0); // m_subErr = 0
    w.write_u32(0); // m_subErrParam = NULL
    w.write_u32(status);
    w.into_bytes()
}

/// Builds request stub for `EvtRpcQueryNext` (Opnum 11).
pub fn build_query_next_stub(
    query_handle: &[u8; 20],
    num_requested_records: u32,
    time_out_end: u32,
    flags: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(32);
    w.write_bytes(query_handle);
    w.write_u32(num_requested_records);
    w.write_u32(time_out_end);
    w.write_u32(flags);
    w.into_bytes()
}

/// Parsed result of `EvtRpcQueryNext`.
#[derive(Debug, Clone)]
pub struct EvtQueryNextResult {
    pub actual_records: u32,
    pub event_data: Vec<Vec<u8>>,
    pub status: u32,
}

/// Parses response stub for `EvtRpcQueryNext` (Opnum 11).
pub fn parse_query_next_response(stub: &[u8]) -> Result<EvtQueryNextResult, CoreError> {
    if stub.len() < 24 {
        return Err(CoreError::BufferUnderflow {
            needed: 24,
            available: stub.len(),
        });
    }

    let mut r = NdrReader::new(stub);
    let num_actual_records = r.read_u32()?;
    let _indices_ptr = r.read_u32()?;
    let _sizes_ptr = r.read_u32()?;
    let result_buffer_size = r.read_u32()?;
    let _buffer_ptr = r.read_u32()?;

    // Read deferred indices array: MaxCount + elements
    let mut indices = Vec::new();
    if num_actual_records > 0 {
        let indices_count = r.read_u32()?;
        for _ in 0..indices_count {
            indices.push(r.read_u32()?);
        }
    }

    // Read deferred sizes array: MaxCount + elements
    let mut sizes = Vec::new();
    if num_actual_records > 0 {
        let sizes_count = r.read_u32()?;
        for _ in 0..sizes_count {
            sizes.push(r.read_u32()?);
        }
    }

    // Read deferred buffer array: MaxCount + byte elements
    let mut buffer = Vec::new();
    if result_buffer_size > 0 {
        let buffer_count = r.read_u32()?;
        buffer = r.read_bytes(buffer_count as usize)?.to_vec();
        r.align(4)?;
    }

    let status = r.read_u32()?;

    let mut event_data = Vec::new();
    for i in 0..indices.len().min(sizes.len()) {
        let offset = indices[i] as usize;
        let size = sizes[i] as usize;
        if offset + size <= buffer.len() {
            event_data.push(buffer[offset..offset + size].to_vec());
        }
    }

    Ok(EvtQueryNextResult {
        actual_records: num_actual_records,
        event_data,
        status,
    })
}

/// Builds a wire-accurate mock response for `EvtRpcQueryNext` (test fixture).
pub fn build_query_next_response(records: &[&[u8]], status: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);
    let num_records = records.len() as u32;

    let mut indices = Vec::new();
    let mut sizes = Vec::new();
    let mut full_buffer = Vec::new();

    for r in records {
        indices.push(full_buffer.len() as u32);
        sizes.push(r.len() as u32);
        full_buffer.extend_from_slice(r);
    }

    w.write_u32(num_records);
    w.write_u32(if num_records > 0 { REFERENT_BASE } else { 0 });
    w.write_u32(if num_records > 0 { REFERENT_BASE + 4 } else { 0 });
    w.write_u32(full_buffer.len() as u32);
    w.write_u32(if !full_buffer.is_empty() { REFERENT_BASE + 8 } else { 0 });

    if num_records > 0 {
        w.write_u32(num_records);
        for idx in indices {
            w.write_u32(idx);
        }
        w.write_u32(num_records);
        for sz in sizes {
            w.write_u32(sz);
        }
    }

    if !full_buffer.is_empty() {
        w.write_u32(full_buffer.len() as u32);
        w.write_bytes(&full_buffer);
        w.align(4);
    }

    w.write_u32(status);
    w.into_bytes()
}

/// Builds request stub for `EvtRpcClose` (Opnum 13).
pub fn build_close_stub(handle: &[u8; 20]) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(20);
    w.write_bytes(handle);
    w.into_bytes()
}

/// Parses response stub for `EvtRpcClose` (Opnum 13).
pub fn parse_close_response(stub: &[u8]) -> Result<(), CoreError> {
    if stub.len() < 24 {
        return Err(CoreError::BufferUnderflow {
            needed: 24,
            available: stub.len(),
        });
    }
    let status = u32::from_le_bytes([
        stub[stub.len() - 4],
        stub[stub.len() - 3],
        stub[stub.len() - 2],
        stub[stub.len() - 1],
    ]);
    if status == error_status::ERROR_SUCCESS {
        Ok(())
    } else {
        Err(CoreError::ProtocolError(format!(
            "EvtRpcClose failed with status 0x{:08X}",
            status
        )))
    }
}

/// `[MS-EVEN6]` Windows EventLog client driving remote event queries over [`RpcTransport`].
pub struct Even6Client<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> Even6Client<T> {
    /// Creates a new `Even6Client` over the given RPC transport.
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

    /// Registers a remote log query with the server. Returns `(query_handle, op_control_handle)`.
    pub fn register_log_query(
        &mut self,
        path: Option<&str>,
        query: &str,
        flags: u32,
    ) -> Result<([u8; 20], [u8; 20]), CoreError> {
        let stub = build_register_log_query_stub(path, query, flags);
        let resp = self.call(opnum::EVT_RPC_REGISTER_LOG_QUERY, stub)?;
        parse_register_log_query_response(&resp)
    }

    /// Fetches the next batch of raw event records from the query handle.
    pub fn query_next_raw(
        &mut self,
        query_handle: &[u8; 20],
        num_records: u32,
        timeout_ms: u32,
    ) -> Result<Vec<Vec<u8>>, CoreError> {
        let stub = build_query_next_stub(query_handle, num_records, timeout_ms, 0);
        let resp = self.call(opnum::EVT_RPC_QUERY_NEXT, stub)?;
        let result = parse_query_next_response(&resp)?;

        if result.status == error_status::ERROR_SUCCESS {
            Ok(result.event_data)
        } else if result.status == error_status::ERROR_NO_MORE_ITEMS {
            Ok(result.event_data)
        } else {
            Err(CoreError::ProtocolError(format!(
                "EvtRpcQueryNext returned error status 0x{:08X}",
                result.status
            )))
        }
    }

    /// Closes an open context handle on the server.
    pub fn close_handle(&mut self, handle: &[u8; 20]) -> Result<(), CoreError> {
        let stub = build_close_stub(handle);
        let resp = self.call(opnum::EVT_RPC_CLOSE, stub)?;
        parse_close_response(&resp)
    }

    /// High-level method: queries events from a channel and returns parsed [`EvtEventRecord`] items.
    pub fn fetch_events(
        &mut self,
        channel: &str,
        xpath_query: &str,
        max_events: u32,
        reverse: bool,
    ) -> Result<Vec<EvtEventRecord>, CoreError> {
        let dir_flag = if reverse {
            flags::EVT_QUERY_REVERSE_DIRECTION
        } else {
            flags::EVT_QUERY_FORWARD_DIRECTION
        };
        let query_flags = flags::EVT_QUERY_CHANNEL_PATH
            | flags::EVT_QUERY_TOLERATE_QUERY_ERRORS
            | dir_flag;

        let (q_handle, op_handle) = self.register_log_query(Some(channel), xpath_query, query_flags)?;

        let mut events = Vec::new();
        let batch_size = max_events.min(50);

        while (events.len() as u32) < max_events {
            let needed = max_events - (events.len() as u32);
            let request_count = needed.min(batch_size);

            let raw_records = match self.query_next_raw(&q_handle, request_count, 3000) {
                Ok(r) => r,
                Err(e) => {
                    self.close_handle(&op_handle).ok();
                    self.close_handle(&q_handle).ok();
                    return Err(e);
                }
            };

            if raw_records.is_empty() {
                break;
            }

            for raw in raw_records {
                events.push(EvtEventRecord::parse(&raw));
            }
        }

        self.close_handle(&op_handle).ok();
        self.close_handle(&q_handle).ok();

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_log_query_stub_and_response_roundtrip() {
        let channel = "Security";
        let query = "*[System[(EventID=4624)]]";
        let stub = build_register_log_query_stub(
            Some(channel),
            query,
            flags::EVT_QUERY_CHANNEL_PATH | flags::EVT_QUERY_FORWARD_DIRECTION,
        );

        assert!(!stub.is_empty());

        let fake_qhandle = [0x11u8; 20];
        let fake_ophandle = [0x22u8; 20];
        let resp_stub = build_register_log_query_response(
            &fake_qhandle,
            &fake_ophandle,
            error_status::ERROR_SUCCESS,
        );

        let (q, op) = parse_register_log_query_response(&resp_stub).unwrap();
        assert_eq!(q, fake_qhandle);
        assert_eq!(op, fake_ophandle);
    }

    #[test]
    fn test_query_next_stub_and_response_roundtrip() {
        let fake_qhandle = [0xaa; 20];
        let req_stub = build_query_next_stub(&fake_qhandle, 5, 2000, 0);
        assert_eq!(req_stub.len(), 32);

        // Mock 2 event byte payloads
        let event1 = b"Sample Event Payload 1";
        let event2 = b"Sample Event Payload 2";
        let resp_stub =
            build_query_next_response(&[event1, event2], error_status::ERROR_SUCCESS);

        let parsed = parse_query_next_response(&resp_stub).unwrap();
        assert_eq!(parsed.actual_records, 2);
        assert_eq!(parsed.event_data.len(), 2);
        assert_eq!(parsed.event_data[0], event1);
        assert_eq!(parsed.event_data[1], event2);
        assert_eq!(parsed.status, error_status::ERROR_SUCCESS);
    }

    #[test]
    fn test_evt_event_record_parse_and_xml_render() {
        // Build mock UTF-16LE event strings
        let mut mock_bytes = Vec::new();
        let fragments = [
            "Provider",
            "Microsoft-Windows-Security-Auditing",
            "EventID",
            "4624",
            "Channel",
            "Security",
            "Computer",
            "DC01.corp.contoso.com",
            "TimeCreated",
            "2026-11-10T15:30:00.0000000Z",
            "TargetUserName",
            "Administrator",
            "LogonType",
            "3",
        ];

        for f in fragments {
            mock_bytes.extend_from_slice(&impacket_core::encode_utf16le(f));
            mock_bytes.extend_from_slice(&[0, 0]); // null terminator
            mock_bytes.extend_from_slice(&[0x0f, 0x01]); // simulated binxml token separator
        }

        let record = EvtEventRecord::parse(&mock_bytes);
        assert_eq!(record.event_id, Some(4624));
        assert_eq!(record.channel.as_deref(), Some("Security"));
        assert_eq!(record.computer.as_deref(), Some("DC01.corp.contoso.com"));
        assert_eq!(
            record.provider.as_deref(),
            Some("Microsoft-Windows-Security-Auditing")
        );

        let xml = record.to_xml_string();
        assert!(xml.contains("<EventID>4624</EventID>"));
        assert!(xml.contains("DC01.corp.contoso.com"));
        assert!(xml.contains("Administrator"));

        let summary = record.to_summary_string();
        assert!(summary.contains("4624"));
        assert!(summary.contains("Security"));
    }

    struct MockEven6Transport {
        responses: std::collections::VecDeque<Vec<u8>>,
    }

    impl RpcTransport for MockEven6Transport {
        fn transceive(&mut self, _request_pdu: &[u8]) -> Result<Vec<u8>, CoreError> {
            let stub = self
                .responses
                .pop_front()
                .ok_or_else(|| CoreError::ProtocolError("No mock response".into()))?;

            // Wrap in standard RPC Response PDU
            let mut pdu = Vec::new();
            pdu.extend_from_slice(&[
                5, 0, 2, 3, // Version 5.0, Response PDU (ptype 2), PFC_FIRST_FRAG | PFC_LAST_FRAG (3)
                16, 0, 0, 0, // Data representation
            ]);
            let frag_len = (24 + stub.len()) as u16;
            pdu.extend_from_slice(&frag_len.to_le_bytes());
            pdu.extend_from_slice(&[0, 0]); // auth_length = 0
            pdu.extend_from_slice(&[1, 0, 0, 0]); // call_id = 1
            pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
            pdu.extend_from_slice(&[0, 0]); // context_id = 0
            pdu.extend_from_slice(&[0]); // cancel_count = 0
            pdu.extend_from_slice(&[0]); // reserved
            pdu.extend_from_slice(&stub);
            Ok(pdu)
        }
    }

    #[test]
    fn test_even6_client_high_level_flow() {
        let q_handle = [0x55; 20];
        let op_handle = [0x66; 20];

        let mut queue = std::collections::VecDeque::new();
        // 1. EvtRpcRegisterLogQuery response
        queue.push_back(build_register_log_query_response(
            &q_handle,
            &op_handle,
            error_status::ERROR_SUCCESS,
        ));
        // 2. EvtRpcQueryNext response
        let mock_event = b"EventID\0\0\x34\x36\x32\x34Channel\0\0Security";
        queue.push_back(build_query_next_response(
            &[mock_event],
            error_status::ERROR_SUCCESS,
        ));
        // 3. EvtRpcClose for op_handle
        queue.push_back(vec![0u8; 24]);
        // 4. EvtRpcClose for q_handle
        queue.push_back(vec![0u8; 24]);

        let transport = MockEven6Transport { responses: queue };
        let mut client = Even6Client::new(transport);

        let events = client
            .fetch_events("Security", "*", 1, false)
            .unwrap();

        assert_eq!(events.len(), 1);
    }
}
