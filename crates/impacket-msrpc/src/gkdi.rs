//! `gkdi`: `[MS-GKDI]` Group Key Distribution Protocol client (`impacket/dcerpc/v5/gkdi.py`).
//!
//! Implements MSRPC wire bindings for Active Directory Group Key Distribution Service:
//! - Interface UUID: `b9785960-524f-11df-8b6d-83dcded72085` v1.0
//! - Named Pipe: `\PIPE\protected_storage`
//! - `GetKey` (Opnum 0): Requests group seed / L2 keys used in DPAPI-NG and Windows LAPS v2.

use crate::dtypes::REFERENT_BASE;
use impacket_core::CoreError;
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport, RpcUuid};
use impacket_ndr::{NdrReader, NdrWriter};

/// `[MS-GKDI]` Interface UUID: `b9785960-524f-11df-8b6d-83dcded72085` v1.0
pub const GKDI_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0xb978_5960,
    0x524f,
    0x11df,
    [0x8b, 0x6d, 0x83, 0xdc, 0xde, 0xd7, 0x20, 0x85],
);
pub const GKDI_VERSION_MAJOR: u16 = 1;
pub const GKDI_VERSION_MINOR: u16 = 0;
pub const GKDI_PIPE: &str = r"\PIPE\protected_storage";

pub mod opnum {
    pub const GKDI_GET_KEY: u16 = 0;
}

/// Parsed Group Key Envelope returned by `GetKey` (`[MS-GKDI]` Section 2.2.4).
#[derive(Debug, Clone)]
pub struct GroupKeyEnvelope {
    pub version: u32,
    pub flags: u32,
    pub l0_index: i32,
    pub l1_index: i32,
    pub l2_index: i32,
    pub root_key_id: [u8; 16],
    pub kdf_algorithm: String,
    pub domain_name: String,
    pub forest_name: String,
    pub l1_key: Option<Vec<u8>>,
    pub l2_key: Option<Vec<u8>>,
}

impl GroupKeyEnvelope {
    /// Parses a raw `GROUP_KEY_ENVELOPE` byte slice.
    pub fn parse(data: &[u8]) -> Result<Self, CoreError> {
        if data.len() < 80 {
            return Err(CoreError::ProtocolError(format!(
                "GroupKeyEnvelope buffer too short: {} bytes (minimum 80)",
                data.len()
            )));
        }

        let version = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let magic = &data[4..8];
        if magic != b"KDSK" && magic != b"DSKB" {
            return Err(CoreError::ProtocolError(format!(
                "Invalid GroupKeyEnvelope magic: {:02x?}",
                magic
            )));
        }

        let flags = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let l0_index = i32::from_le_bytes(data[12..16].try_into().unwrap());
        let l1_index = i32::from_le_bytes(data[16..20].try_into().unwrap());
        let l2_index = i32::from_le_bytes(data[20..24].try_into().unwrap());

        let mut root_key_id = [0u8; 16];
        root_key_id.copy_from_slice(&data[24..40]);

        let cb_kdf_algo = u32::from_le_bytes(data[40..44].try_into().unwrap()) as usize;
        let cb_kdf_params = u32::from_le_bytes(data[44..48].try_into().unwrap()) as usize;
        let cb_sec_algo = u32::from_le_bytes(data[48..52].try_into().unwrap()) as usize;
        let cb_sec_params = u32::from_le_bytes(data[52..56].try_into().unwrap()) as usize;
        let _cb_priv_key = u32::from_le_bytes(data[56..60].try_into().unwrap()) as usize;
        let _cb_pub_key = u32::from_le_bytes(data[60..64].try_into().unwrap()) as usize;
        let cb_l1_key = u32::from_le_bytes(data[64..68].try_into().unwrap()) as usize;
        let cb_l2_key = u32::from_le_bytes(data[68..72].try_into().unwrap()) as usize;
        let cb_domain = u32::from_le_bytes(data[72..76].try_into().unwrap()) as usize;
        let cb_forest = u32::from_le_bytes(data[76..80].try_into().unwrap()) as usize;

        let mut offset = 80;

        let kdf_algorithm = if offset + cb_kdf_algo <= data.len() {
            let slice = &data[offset..offset + cb_kdf_algo];
            offset += cb_kdf_algo;
            decode_utf16_or_utf8(slice)
        } else {
            String::new()
        };

        if offset + cb_kdf_params <= data.len() {
            offset += cb_kdf_params;
        }

        if offset + cb_sec_algo <= data.len() {
            offset += cb_sec_algo;
        }

        if offset + cb_sec_params <= data.len() {
            offset += cb_sec_params;
        }

        let domain_name = if offset + cb_domain <= data.len() {
            let slice = &data[offset..offset + cb_domain];
            offset += cb_domain;
            decode_utf16_or_utf8(slice)
        } else {
            String::new()
        };

        let forest_name = if offset + cb_forest <= data.len() {
            let slice = &data[offset..offset + cb_forest];
            offset += cb_forest;
            decode_utf16_or_utf8(slice)
        } else {
            String::new()
        };

        let l1_key = if cb_l1_key > 0 && offset + cb_l1_key <= data.len() {
            let slice = data[offset..offset + cb_l1_key].to_vec();
            offset += cb_l1_key;
            Some(slice)
        } else {
            None
        };

        let l2_key = if cb_l2_key > 0 && offset + cb_l2_key <= data.len() {
            let slice = data[offset..offset + cb_l2_key].to_vec();
            Some(slice)
        } else {
            None
        };

        Ok(Self {
            version,
            flags,
            l0_index,
            l1_index,
            l2_index,
            root_key_id,
            kdf_algorithm,
            domain_name,
            forest_name,
            l1_key,
            l2_key,
        })
    }
}

fn decode_utf16_or_utf8(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes.len() % 2 == 0 {
        let u16s: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        if let Ok(s) = String::from_utf16(&u16s) {
            return s;
        }
    }
    let s = String::from_utf8_lossy(bytes);
    s.trim_end_matches('\0').to_string()
}

/// Builds request stub for `GetKey` (Opnum 0):
/// - `cbTargetSD`: [in] unsigned long
/// - `pbTargetSD`: [in, size_is(cbTargetSD)] unsigned char*
/// - `pRootKeyID`: [in, unique] const GUID*
/// - `L0KeyID`: [in] long
/// - `L1KeyID`: [in] long
/// - `L2KeyID`: [in] long
pub fn build_get_key_stub(
    target_sd: Option<&[u8]>,
    root_key_id: Option<&[u8; 16]>,
    l0: i32,
    l1: i32,
    l2: i32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);

    if let Some(sd) = target_sd {
        w.write_u32(sd.len() as u32);
        w.write_u32(REFERENT_BASE); // pointer
        w.write_u32(sd.len() as u32); // conformant max count
        w.write_bytes(sd);
        let rem = sd.len() % 4;
        if rem != 0 {
            for _ in 0..(4 - rem) {
                w.write_u8(0);
            }
        }
    } else {
        w.write_u32(0); // cbTargetSD = 0
        w.write_u32(0); // pbTargetSD = null
    }

    if let Some(guid) = root_key_id {
        w.write_u32(REFERENT_BASE + 4); // pRootKeyID pointer
        w.write_bytes(guid);
    } else {
        w.write_u32(0); // null pointer
    }

    w.write_u32(l0 as u32);
    w.write_u32(l1 as u32);
    w.write_u32(l2 as u32);

    w.into_bytes()
}

/// Parses response stub for `GetKey` (Opnum 0):
/// - `pcbOut`: [out] unsigned long*
/// - `ppbOut`: [out, size_is(, *pcbOut)] unsigned char**
/// - Return value: HRESULT
pub fn parse_get_key_response(stub: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut r = NdrReader::new(stub);
    let pcb_out = r.read_u32()? as usize;
    let ppb_out_ref = r.read_u32()?;
    if ppb_out_ref == 0 {
        return Err(CoreError::ProtocolError(
            "GKDI GetKey returned null output pointer".into(),
        ));
    }
    let max_count = r.read_u32()? as usize;
    if max_count < pcb_out {
        return Err(CoreError::ProtocolError(format!(
            "GKDI GetKey max count ({}) less than byte count ({})",
            max_count, pcb_out
        )));
    }
    let envelope_bytes = r.read_bytes(pcb_out)?.to_vec();
    let rem = pcb_out % 4;
    if rem != 0 {
        let _ = r.read_bytes(4 - rem);
    }
    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::ProtocolError(format!(
            "GKDI GetKey failed with status 0x{:08x}",
            status
        )));
    }
    Ok(envelope_bytes)
}

/// High-level client for `[MS-GKDI]` Group Key Distribution Protocol.
pub struct GkdiClient<'a, T: RpcTransport> {
    transport: &'a mut T,
    call_id: u32,
}

impl<'a, T: RpcTransport> GkdiClient<'a, T> {
    pub fn new(transport: &'a mut T) -> Self {
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

    /// Calls `GetKey` (Opnum 0) to retrieve and parse the Group Key Envelope.
    pub fn get_key(
        &mut self,
        target_sd: Option<&[u8]>,
        root_key_id: Option<&[u8; 16]>,
        l0: i32,
        l1: i32,
        l2: i32,
    ) -> Result<GroupKeyEnvelope, CoreError> {
        let stub = build_get_key_stub(target_sd, root_key_id, l0, l1, l2);
        let resp_stub = self.call(opnum::GKDI_GET_KEY, stub)?;
        let env_bytes = parse_get_key_response(&resp_stub)?;
        GroupKeyEnvelope::parse(&env_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_get_key_stub() {
        let root_key = [0xabu8; 16];
        let stub = build_get_key_stub(None, Some(&root_key), 100, 2, 3);
        assert!(!stub.is_empty());

        let mut r = NdrReader::new(&stub);
        assert_eq!(r.read_u32().unwrap(), 0); // cbTargetSD
        assert_eq!(r.read_u32().unwrap(), 0); // pbTargetSD ptr
        assert_ne!(r.read_u32().unwrap(), 0); // pRootKeyID ptr
        let read_guid = r.read_bytes(16).unwrap();
        assert_eq!(read_guid, root_key);
        assert_eq!(r.read_u32().unwrap() as i32, 100);
        assert_eq!(r.read_u32().unwrap() as i32, 2);
        assert_eq!(r.read_u32().unwrap() as i32, 3);
    }

    #[test]
    fn test_group_key_envelope_parse() {
        let mut buf = vec![0u8; 80];
        // Version
        buf[0..4].copy_from_slice(&1u32.to_le_bytes());
        // Magic
        buf[4..8].copy_from_slice(b"KDSK");
        // Flags
        buf[8..12].copy_from_slice(&0x4000_0000u32.to_le_bytes());
        // L0, L1, L2
        buf[12..16].copy_from_slice(&123i32.to_le_bytes());
        buf[16..20].copy_from_slice(&4i32.to_le_bytes());
        buf[20..24].copy_from_slice(&5i32.to_le_bytes());
        // RootKeyId
        buf[24..40].copy_from_slice(&[0x11; 16]);

        // Lengths: cbL2Key = 64
        buf[68..72].copy_from_slice(&64u32.to_le_bytes());

        // L2 key payload
        let fake_l2 = vec![0x77u8; 64];
        buf.extend_from_slice(&fake_l2);

        let env = GroupKeyEnvelope::parse(&buf).expect("GroupKeyEnvelope parse failed");
        assert_eq!(env.version, 1);
        assert_eq!(env.l0_index, 123);
        assert_eq!(env.l1_index, 4);
        assert_eq!(env.l2_index, 5);
        assert_eq!(env.root_key_id, [0x11; 16]);
        assert_eq!(env.l2_key.as_deref(), Some(fake_l2.as_slice()));
    }
}
