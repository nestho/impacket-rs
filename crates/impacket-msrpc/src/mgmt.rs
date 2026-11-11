//! `mgmt`: `[C706]` Remote Management Interface implementation (`impacket/dcerpc/v5/mgmt.py`).
//!
//! Provides the standard DCE/RPC Management interface (`afa8bd80-7d8a-11c9-bef4-08002b102989` v1.0)
//! for discovering listening interface UUIDs (`inq_if_ids`), query server listening state
//! (`is_server_listening`), and query principal names (`inq_princ_name`).

use impacket_core::{CoreError, NtStatus};
use impacket_dcerpc::{extract_response_stub, pdu_type, RpcRequestPdu, RpcTransport, RpcUuid};
use impacket_ndr::{NdrReader, NdrWriter};

pub const MGMT_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0xafa8_bd80,
    0x7d8a,
    0x11c9,
    [0xbe, 0xf4, 0x08, 0x00, 0x2b, 0x10, 0x29, 0x89],
);
pub const MGMT_VERSION_MAJOR: u16 = 1;
pub const MGMT_VERSION_MINOR: u16 = 0;

pub mod opnum {
    pub const INQ_IF_IDS: u16 = 0;
    pub const INQ_STATS: u16 = 1;
    pub const IS_SERVER_LISTENING: u16 = 2;
    pub const STOP_SERVER_LISTENING: u16 = 3;
    pub const INQ_PRINC_NAME: u16 = 4;
}

/// An interface identifier returned by `inq_if_ids` (`RPC_IF_ID`, `[C706] 13.2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcIfId {
    pub uuid: RpcUuid,
    pub vers_major: u16,
    pub vers_minor: u16,
}

impl std::fmt::Display for RpcIfId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}.{}", self.uuid, self.vers_major, self.vers_minor)
    }
}

pub fn build_inq_princ_name_stub(authn_proto: u32, size: u32) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(8);
    w.write_u32(authn_proto);
    w.write_u32(size);
    w.into_bytes()
}

pub fn parse_inq_if_ids_response(stub: &[u8]) -> Result<Vec<RpcIfId>, CoreError> {
    if stub.len() < 8 {
        return Err(CoreError::ProtocolError("Truncated inq_if_ids response".into()));
    }
    let mut r = NdrReader::new(stub);
    let ptr = r.read_u32()?;
    if ptr == 0 {
        let status = r.read_u32()?;
        if status != 0 {
            return Err(CoreError::NtStatus(NtStatus(status)));
        }
        return Ok(Vec::new());
    }

    let count = r.read_u32()? as usize;
    if count > 10_000 {
        return Err(CoreError::ProtocolError(format!("Unreasonable interface count {}", count)));
    }
    let max_count = r.read_u32()? as usize;
    if max_count != count {
        return Err(CoreError::ProtocolError("Array count mismatch in inq_if_ids".into()));
    }

    let mut ptrs = Vec::with_capacity(count);
    for _ in 0..count {
        ptrs.push(r.read_u32()?);
    }

    let mut if_ids = Vec::with_capacity(count);
    for &p in &ptrs {
        if p != 0 {
            let uuid = RpcUuid::new(
                r.read_u32()?,
                r.read_u16()?,
                r.read_u16()?,
                r.read_fixed_array::<8>()?,
            );
            let vers_major = r.read_u16()?;
            let vers_minor = r.read_u16()?;
            if_ids.push(RpcIfId {
                uuid,
                vers_major,
                vers_minor,
            });
        }
    }

    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::NtStatus(NtStatus(status)));
    }

    Ok(if_ids)
}

pub fn parse_is_server_listening_response(stub: &[u8]) -> Result<bool, CoreError> {
    if stub.len() < 4 {
        return Err(CoreError::ProtocolError("Truncated is_server_listening response".into()));
    }
    let mut r = NdrReader::new(stub);
    let status = r.read_u32()?;
    Ok(status == 0)
}

pub fn parse_inq_princ_name_response(stub: &[u8]) -> Result<String, CoreError> {
    if stub.len() < 8 {
        return Err(CoreError::ProtocolError("Truncated inq_princ_name response".into()));
    }
    let mut r = NdrReader::new(stub);
    let _max_count = r.read_u32()?;
    let _offset = r.read_u32()?;
    let actual_count = r.read_u32()? as usize;
    let bytes = r.read_bytes(actual_count)?;
    let name = String::from_utf8_lossy(bytes).trim_matches('\0').to_string();
    r.align(4)?;
    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::NtStatus(NtStatus(status)));
    }
    Ok(name)
}

/// High-level client for the `[C706]` DCE/RPC Management interface.
pub struct MgmtClient<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> MgmtClient<T> {
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

    /// Queries the server for all registered interface UUIDs and versions.
    pub fn inq_if_ids(&mut self) -> Result<Vec<RpcIfId>, CoreError> {
        let resp = self.call(opnum::INQ_IF_IDS, Vec::new())?;
        parse_inq_if_ids_response(&resp)
    }

    /// Checks if the RPC server is currently listening.
    pub fn is_server_listening(&mut self) -> Result<bool, CoreError> {
        let resp = self.call(opnum::IS_SERVER_LISTENING, Vec::new())?;
        parse_is_server_listening_response(&resp)
    }

    /// Queries the server's principal name for a given authentication service.
    pub fn inq_princ_name(&mut self, authn_proto: u32) -> Result<String, CoreError> {
        let stub = build_inq_princ_name_stub(authn_proto, 256);
        let resp = self.call(opnum::INQ_PRINC_NAME, stub)?;
        parse_inq_princ_name_response(&resp)
    }
}

/// Status classification of an individual RPC Opnum probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpnumStatus {
    /// Server accepted the call or returned normal RPC response.
    Success,
    /// Call rejected with Access Denied (0x00000005).
    AccessDenied,
    /// Opnum is outside valid range (nca_s_op_rng_error: 0x1C010002). Interface has no further opnums.
    OpnumOutOfRange,
    /// Server returned another RPC Fault code.
    Fault(u32),
    /// Transport or IO error occurred.
    Error(String),
}

impl std::fmt::Display for OpnumStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpnumStatus::Success => write!(f, "SUCCESS"),
            OpnumStatus::AccessDenied => write!(f, "ACCESS_DENIED (0x00000005)"),
            OpnumStatus::OpnumOutOfRange => write!(f, "OUT_OF_RANGE (0x1C010002)"),
            OpnumStatus::Fault(code) => write!(f, "FAULT (0x{:08X})", code),
            OpnumStatus::Error(e) => write!(f, "ERROR ({})", e),
        }
    }
}

/// Probes opnums 0..`max_opnums` on an already-bound RPC transport.
///
/// Stops probing when encountering `nca_s_op_rng_error` (0x1C010002) indicating
/// the opnum table boundary was reached.
pub fn probe_opnums<T: RpcTransport>(
    transport: &mut T,
    max_opnums: u16,
) -> Vec<(u16, OpnumStatus)> {
    let mut results = Vec::new();
    for opnum in 0..max_opnums {
        let req = RpcRequestPdu {
            call_id: (opnum as u32) + 1,
            context_id: 0,
            opnum,
            stub_data: vec![0u8; 4],
        };
        match transport.transceive(&req.to_bytes()) {
            Ok(resp) => {
                if resp.len() >= 16 {
                    let ptype = resp[2];
                    if ptype == pdu_type::RPC_FAULT {
                        let status = if resp.len() >= 28 {
                            u32::from_le_bytes([resp[24], resp[25], resp[26], resp[27]])
                        } else {
                            0
                        };
                        if status == 0x1c01_0002 {
                            results.push((opnum, OpnumStatus::OpnumOutOfRange));
                            break;
                        } else if status == 0x0000_0005 {
                            results.push((opnum, OpnumStatus::AccessDenied));
                        } else {
                            results.push((opnum, OpnumStatus::Fault(status)));
                        }
                    } else if ptype == pdu_type::RPC_RESPONSE {
                        results.push((opnum, OpnumStatus::Success));
                    } else {
                        results.push((opnum, OpnumStatus::Fault(ptype as u32)));
                    }
                } else {
                    results.push((opnum, OpnumStatus::Error("Response too short".into())));
                }
            }
            Err(e) => {
                results.push((opnum, OpnumStatus::Error(e.to_string())));
                break;
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_inq_if_ids_fixture() {
        let mut w = NdrWriter::with_capacity(128);
        w.write_u32(0x0002_0000); // pointer referent
        w.write_u32(2);           // count = 2
        w.write_u32(2);           // max_count = 2
        w.write_u32(0x0002_0004); // ptr 1
        w.write_u32(0x0002_0008); // ptr 2

        // iface 1: EPM
        let epm_uuid = impacket_dcerpc::EPM_INTERFACE_UUID;
        w.write_u32(epm_uuid.data1);
        w.write_u16(epm_uuid.data2);
        w.write_u16(epm_uuid.data3);
        w.write_fixed_array(&epm_uuid.data4);
        w.write_u16(3);
        w.write_u16(0);

        // iface 2: SAMR
        let samr_uuid = impacket_dcerpc::WELL_KNOWN_INTERFACES[1].uuid;
        w.write_u32(samr_uuid.data1);
        w.write_u16(samr_uuid.data2);
        w.write_u16(samr_uuid.data3);
        w.write_fixed_array(&samr_uuid.data4);
        w.write_u16(1);
        w.write_u16(0);

        w.write_u32(0); // status = 0 (SUCCESS)

        let ids = parse_inq_if_ids_response(&w.into_bytes()).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0].uuid, epm_uuid);
        assert_eq!(ids[0].vers_major, 3);
        assert_eq!(ids[0].vers_minor, 0);
        assert_eq!(ids[1].uuid, samr_uuid);
        assert_eq!(ids[1].vers_major, 1);
        assert_eq!(ids[1].vers_minor, 0);
    }

    #[test]
    fn test_is_server_listening_fixture() {
        let mut w = NdrWriter::with_capacity(4);
        w.write_u32(0); // status = 0
        assert!(parse_is_server_listening_response(&w.into_bytes()).unwrap());

        let mut w2 = NdrWriter::with_capacity(4);
        w2.write_u32(5); // status = access denied
        assert!(!parse_is_server_listening_response(&w2.into_bytes()).unwrap());
    }

    struct MockOpnumTransport {
        opnum_responses: std::collections::HashMap<u16, Vec<u8>>,
    }

    impl RpcTransport for MockOpnumTransport {
        fn transceive(&mut self, req: &[u8]) -> Result<Vec<u8>, CoreError> {
            let opnum = u16::from_le_bytes([req[22], req[23]]);
            if let Some(resp) = self.opnum_responses.get(&opnum) {
                Ok(resp.clone())
            } else {
                Err(CoreError::ProtocolError("Unexpected opnum".into()))
            }
        }
    }

    #[test]
    fn test_probe_opnums_flow() {
        use std::collections::HashMap;

        // Build mock responses:
        // Opnum 0: RPC_RESPONSE (ptype 2)
        let mut r0 = vec![5, 0, 2, 3, 0x10, 0, 0, 0, 24, 0, 0, 0, 1, 0, 0, 0];
        r0.extend_from_slice(&[0u8; 8]); // alloc_hint etc.

        // Opnum 1: RPC_FAULT (ptype 3) with status 0x00000005 (Access Denied)
        let mut r1 = vec![5, 0, 3, 3, 0x10, 0, 0, 0, 32, 0, 0, 0, 2, 0, 0, 0];
        r1.extend_from_slice(&[0u8; 8]); // alloc_hint etc.
        r1.extend_from_slice(&5u32.to_le_bytes()); // status = 5
        r1.extend_from_slice(&[0u8; 4]); // reserved

        // Opnum 2: RPC_FAULT (ptype 3) with status 0x1c010002 (OpnumOutOfRange)
        let mut r2 = vec![5, 0, 3, 3, 0x10, 0, 0, 0, 32, 0, 0, 0, 3, 0, 0, 0];
        r2.extend_from_slice(&[0u8; 8]);
        r2.extend_from_slice(&0x1c01_0002u32.to_le_bytes());
        r2.extend_from_slice(&[0u8; 4]);

        let mut map = HashMap::new();
        map.insert(0, r0);
        map.insert(1, r1);
        map.insert(2, r2);

        let mut transport = MockOpnumTransport { opnum_responses: map };
        let results = probe_opnums(&mut transport, 10);

        assert_eq!(results.len(), 3);
        assert_eq!(results[0], (0, OpnumStatus::Success));
        assert_eq!(results[1], (1, OpnumStatus::AccessDenied));
        assert_eq!(results[2], (2, OpnumStatus::OpnumOutOfRange));
    }
}
