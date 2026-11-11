//! `exporter`: `IObjectExporter` interface implementation (`[MS-DCOM]` Section 3.1.2.5.1).
//!
//! Provides DCOM ping (`ServerAlive`) and network interface binding resolution (`ServerAlive2`).

use crate::bindings::DualStringArray;
use crate::orpc::ComVersion;
use impacket_core::CoreError;
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport, TcpRpcTransport};
use impacket_ndr::{NdrReader, RpcUuid};
use std::time::Duration;

/// Interface UUID for `IObjectExporter`: `99fcf743-a754-1113-17cb-0000f020bed8`, version 0.0.
pub const IOBJECTEXPORTER_UUID: RpcUuid = RpcUuid::new(
    0x99fcf743,
    0xa754,
    0x1113,
    [0x17, 0xcb, 0x00, 0x00, 0xf0, 0x20, 0xbe, 0xd8],
);

pub const OPNUM_SERVER_ALIVE: u16 = 3;
pub const OPNUM_RESOLVE_OXID2: u16 = 4;
pub const OPNUM_SERVER_ALIVE2: u16 = 5;

/// Output of `IObjectExporter::ServerAlive2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAlive2Result {
    pub com_version: ComVersion,
    pub bindings: DualStringArray,
    pub error_code: u32,
}

/// Calls `IObjectExporter::ServerAlive` (opnum 3) to verify that the DCOM subsystem is alive.
pub fn server_alive(transport: &mut dyn RpcTransport) -> Result<u32, CoreError> {
    let req = RpcRequestPdu {
        call_id: 1,
        context_id: 0,
        opnum: OPNUM_SERVER_ALIVE,
        stub_data: Vec::new(),
    };

    let resp_pdu = transport.transceive(&req.to_bytes())?;
    let stub = extract_response_stub(&resp_pdu)?;

    let mut reader = NdrReader::new(&stub);
    let error_code = reader.read_u32()?;
    Ok(error_code)
}

/// Calls `IObjectExporter::ServerAlive2` (opnum 5) to query the host's DCOM bindings and interfaces.
pub fn server_alive2(transport: &mut dyn RpcTransport) -> Result<ServerAlive2Result, CoreError> {
    let req = RpcRequestPdu {
        call_id: 1,
        context_id: 0,
        opnum: OPNUM_SERVER_ALIVE2,
        stub_data: Vec::new(),
    };

    let resp_pdu = transport.transceive(&req.to_bytes())?;
    let stub = extract_response_stub(&resp_pdu)?;

    let mut reader = NdrReader::new(&stub);
    let major = reader.read_u16()?;
    let minor = reader.read_u16()?;
    let com_version = ComVersion::new(major, minor);

    let dsa_ptr = reader.read_u32()?;
    let reserved_ptr = reader.read_u32()?;

    let bindings = if dsa_ptr != 0 {
        DualStringArray::deserialize(&mut reader)?
    } else {
        DualStringArray::default()
    };

    if reserved_ptr != 0 && reader.remaining() >= 8 {
        reader.read_u32().ok();
    }

    let error_code = if reader.remaining() >= 4 {
        reader.read_u32()?
    } else {
        0
    };

    Ok(ServerAlive2Result {
        com_version,
        bindings,
        error_code,
    })
}

/// Performs a live OXID network interface query against a target over TCP (port 135 default).
pub fn oxid_query_live(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<ServerAlive2Result, CoreError> {
    let mut transport =
        TcpRpcTransport::connect_and_bind(host, port, IOBJECTEXPORTER_UUID, 0, 0, timeout)?;
    server_alive2(&mut transport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bindings::{authn_svc, tower_id, SecurityBinding, StringBinding};
    use impacket_ndr::NdrWriter;

    struct MockExporterTransport {
        resp_bytes: Vec<u8>,
    }

    impl RpcTransport for MockExporterTransport {
        fn transceive(&mut self, _req: &[u8]) -> Result<Vec<u8>, CoreError> {
            Ok(self.resp_bytes.clone())
        }
    }

    #[test]
    fn test_server_alive2_mock_response_parse() {
        let mut dsa = DualStringArray::new();
        dsa.string_bindings.push(StringBinding::new(
            tower_id::NCACN_IP_TCP,
            "10.0.0.1",
        ));
        dsa.security_bindings.push(SecurityBinding::new(
            authn_svc::KERBEROS,
            0xFFFF,
            "RPCSS/DC01",
        ));

        let mut dsa_writer = NdrWriter::new();
        dsa.serialize(&mut dsa_writer);
        let dsa_bytes = dsa_writer.into_bytes();

        let mut stub = NdrWriter::new();
        stub.write_u16(5); // major
        stub.write_u16(7); // minor
        stub.write_u32(0x00020000); // ppdsaOrBindings pointer
        stub.write_u32(0); // pReserved pointer NULL
        stub.write_bytes(&dsa_bytes);
        stub.write_u32(0); // ErrorCode S_OK

        // Build valid RPC Response PDU with 24-byte header
        let stub_data = stub.into_bytes();
        let frag_len = (24 + stub_data.len()) as u16;
        let mut resp_pdu = vec![
            5, 0, 2, 3, // vers=5, vers_minor=0, ptype=RESPONSE(2), pfc_flags=FIRST|LAST(3)
            0x10, 0, 0, 0, // drep LE
            (frag_len & 0xFF) as u8, (frag_len >> 8) as u8,
            0, 0, // auth_length=0
            1, 0, 0, 0, // call_id=1
            (stub_data.len() & 0xFF) as u8, (stub_data.len() >> 8) as u8, 0, 0, // alloc_hint
            0, 0, // context_id=0
            0, 0, // cancel_count=0, reserved=0
        ];
        resp_pdu.extend_from_slice(&stub_data);

        let mut transport = MockExporterTransport { resp_bytes: resp_pdu };
        let result = server_alive2(&mut transport).unwrap();

        assert_eq!(result.com_version.major, 5);
        assert_eq!(result.com_version.minor, 7);
        assert_eq!(result.bindings.string_bindings.len(), 1);
        assert_eq!(result.bindings.string_bindings[0].network_addr, "10.0.0.1");
        assert_eq!(result.bindings.security_bindings.len(), 1);
        assert_eq!(result.bindings.security_bindings[0].princ_name, "RPCSS/DC01");
        assert_eq!(result.error_code, 0);
    }
}
