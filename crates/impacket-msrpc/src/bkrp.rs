//! `bkrp`: `[MS-BKRP]` BackupKey Remote Protocol client (`impacket/dcerpc/v5/bkrp.py`).
//!
//! Implements MSRPC wire bindings for Windows Data Protection API (DPAPI) domain backup keys:
//! - Interface UUID: `3dde7c30-165d-11d1-ab8f-00805f14db40` v1.0
//! - Named Pipe: `\PIPE\protected_storage`
//! - `BackuprKey` (Opnum 0):
//!   - `BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID`: queries domain public backup certificate.
//!   - `BACKUPKEY_RESTORE_GUID`: unwraps/decrypts user DPAPI MasterKey backup blobs via DC.
//!   - `BACKUPKEY_BACKUP_GUID`: server-side wraps DPAPI secret.
//!   - `BACKUPKEY_RESTORE_GUID_WIN2K`: legacy Windows 2000 secret unwrap.

use crate::dtypes::REFERENT_BASE;
use impacket_core::CoreError;
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport, RpcUuid};
use impacket_ndr::{NdrReader, NdrWriter};

/// `[MS-BKRP]` Interface UUID: `3dde7c30-165d-11d1-ab8f-00805f14db40` v1.0
pub const BKRP_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0x3dde_7c30,
    0x165d,
    0x11d1,
    [0xab, 0x8f, 0x00, 0x80, 0x5f, 0x14, 0xdb, 0x40],
);
pub const BKRP_VERSION_MAJOR: u16 = 1;
pub const BKRP_VERSION_MINOR: u16 = 0;
pub const BKRP_PIPE: &str = r"\PIPE\protected_storage";

pub mod opnum {
    pub const BACKUPR_KEY: u16 = 0;
}

/// Action GUIDs (`pguidActionAgent`, `[MS-BKRP]` Section 2.2.1):
/// BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID: `{018ff48a-eaba-40c6-8f6d-72370240e967}`
pub const BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID: [u8; 16] = [
    0x8a, 0xf4, 0x8f, 0x01, 0xba, 0xea, 0xc6, 0x40, 0x8f, 0x6d, 0x72, 0x37, 0x02, 0x40, 0xe9, 0x67,
];

/// BACKUPKEY_RESTORE_GUID: `{47270c64-2fc7-499b-ac5b-0e37cdce899a}`
pub const BACKUPKEY_RESTORE_GUID: [u8; 16] = [
    0x64, 0x0c, 0x27, 0x47, 0xc7, 0x2f, 0x9b, 0x49, 0xac, 0x5b, 0x0e, 0x37, 0xcd, 0xce, 0x89, 0x9a,
];

/// BACKUPKEY_BACKUP_GUID: `{7f752b10-178e-11d1-ab8f-00805f14db40}`
pub const BACKUPKEY_BACKUP_GUID: [u8; 16] = [
    0x10, 0x2b, 0x75, 0x7f, 0x8e, 0x17, 0xd1, 0x11, 0xab, 0x8f, 0x00, 0x80, 0x5f, 0x14, 0xdb, 0x40,
];

/// BACKUPKEY_RESTORE_GUID_WIN2K: `{7fe94d50-178e-11d1-ab8f-00805f14db40}`
pub const BACKUPKEY_RESTORE_GUID_WIN2K: [u8; 16] = [
    0x50, 0x4d, 0xe9, 0x7f, 0x8e, 0x17, 0xd1, 0x11, 0xab, 0x8f, 0x00, 0x80, 0x5f, 0x14, 0xdb, 0x40,
];

/// Builds request stub for `BackuprKey` (Opnum 0):
/// - `pguidActionAgent`: [in] GUID*
/// - `cbDataIn`: [in] DWORD
/// - `pDataIn`: [in, size_is(cbDataIn)] BYTE*
/// - `dwParam`: [in] DWORD
pub fn build_backupr_key_stub(
    action_guid: &[u8; 16],
    data_in: Option<&[u8]>,
    param: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);

    // pguidActionAgent pointer
    w.write_u32(REFERENT_BASE);

    // cbDataIn
    let data_len = data_in.map(|d| d.len() as u32).unwrap_or(0);
    w.write_u32(data_len);

    // pDataIn pointer
    if let Some(data) = data_in {
        if !data.is_empty() {
            w.write_u32(REFERENT_BASE + 4);
        } else {
            w.write_u32(0);
        }
    } else {
        w.write_u32(0);
    }

    // dwParam
    w.write_u32(param);

    // Pointee: pguidActionAgent (16 bytes GUID)
    w.write_bytes(action_guid);

    // Pointee: pDataIn (conformant array)
    if let Some(data) = data_in {
        if !data.is_empty() {
            w.write_u32(data.len() as u32); // MaxCount
            w.write_bytes(data);
            let rem = data.len() % 4;
            if rem != 0 {
                for _ in 0..(4 - rem) {
                    w.write_u8(0);
                }
            }
        }
    }

    w.into_bytes()
}

/// Parses response stub for `BackuprKey` (Opnum 0):
/// - `ppDataOut`: [out, size_is(, *pcbDataOut)] BYTE**
/// - `pcbDataOut`: [out] DWORD*
/// - Return value: NET_API_STATUS / WERROR
pub fn parse_backupr_key_response(stub: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut r = NdrReader::new(stub);
    let first = r.read_u32()?;
    let second = r.read_u32()?;

    let (data_len, ptr_ref) = if first >= REFERENT_BASE && second < REFERENT_BASE {
        (second as usize, first)
    } else {
        (first as usize, second)
    };

    if ptr_ref == 0 || data_len == 0 {
        let status = if r.remaining() >= 4 {
            r.read_u32().unwrap_or(0)
        } else {
            0
        };
        if status != 0 {
            return Err(CoreError::ProtocolError(format!(
                "BackuprKey failed with error 0x{:08x}",
                status
            )));
        }
        return Ok(Vec::new());
    }

    let max_count = r.read_u32()? as usize;
    if max_count < data_len {
        return Err(CoreError::ProtocolError(format!(
            "BackuprKey max count ({}) less than data count ({})",
            max_count, data_len
        )));
    }

    let data_bytes = r.read_bytes(data_len)?.to_vec();
    let rem = data_len % 4;
    if rem != 0 {
        let _ = r.read_bytes(4 - rem);
    }

    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::ProtocolError(format!(
            "BackuprKey failed with status 0x{:08x}",
            status
        )));
    }

    Ok(data_bytes)
}

/// High-level client for `[MS-BKRP]` BackupKey Remote Protocol.
pub struct BkrpClient<'a, T: RpcTransport> {
    transport: &'a mut T,
    call_id: u32,
}

impl<'a, T: RpcTransport> BkrpClient<'a, T> {
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

    /// Invokes `BackuprKey` (Opnum 0) with the specified action GUID and input data.
    pub fn backupr_key(
        &mut self,
        action_guid: &[u8; 16],
        data_in: Option<&[u8]>,
        param: u32,
    ) -> Result<Vec<u8>, CoreError> {
        let stub = build_backupr_key_stub(action_guid, data_in, param);
        let resp_stub = self.call(opnum::BACKUPR_KEY, stub)?;
        parse_backupr_key_response(&resp_stub)
    }

    /// Retrieves the domain backup public key certificate (`BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID`).
    pub fn retrieve_backup_key(&mut self) -> Result<Vec<u8>, CoreError> {
        self.backupr_key(&BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID, None, 0)
    }

    /// Unwraps / restores an encrypted DPAPI MasterKey backup blob via Domain Controller
    /// (`BACKUPKEY_RESTORE_GUID`). Strips leading asymmetric padding to yield the cleartext key.
    pub fn restore_master_key(&mut self, wrapped_blob: &[u8]) -> Result<Vec<u8>, CoreError> {
        let resp = self.backupr_key(&BACKUPKEY_RESTORE_GUID, Some(wrapped_blob), 0)?;
        if resp.len() >= 64 {
            // MasterKeys are 64 bytes in length
            Ok(resp[resp.len() - 64..].to_vec())
        } else {
            // Strip leading zero padding if any
            let start = resp.iter().position(|&b| b != 0).unwrap_or(0);
            Ok(resp[start..].to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_backupr_key_stub() {
        let stub = build_backupr_key_stub(&BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID, None, 0);
        assert!(!stub.is_empty());
        assert_eq!(&stub[16..32], &BACKUPKEY_RETRIEVE_BACKUP_KEY_GUID);

        let data = b"SampleEncryptedMasterKeyDataForRestoration";
        let stub2 = build_backupr_key_stub(&BACKUPKEY_RESTORE_GUID, Some(data), 0);
        assert!(stub2.len() > data.len());
    }

    #[test]
    fn test_parse_backupr_key_response_roundtrip() {
        let mut w = NdrWriter::with_capacity(128);
        let payload = vec![0x11u8; 64];

        w.write_u32(payload.len() as u32); // pcbDataOut
        w.write_u32(REFERENT_BASE);        // ppDataOut pointer
        w.write_u32(payload.len() as u32); // max_count
        w.write_bytes(&payload);
        w.write_u32(0);                    // ErrorCode: 0 (WERR_OK)

        let resp_bytes = w.into_bytes();
        let parsed = parse_backupr_key_response(&resp_bytes).expect("parse failed");
        assert_eq!(parsed, payload);
    }
}
