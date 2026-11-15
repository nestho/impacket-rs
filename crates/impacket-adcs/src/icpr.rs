//! `icpr`: `[MS-ICPR]` ICertPassage Remote Protocol client (`impacket/dcerpc/v5/icpr.py`).
//!
//! Implements pure-Rust RPC methods for certificate enrollment directly against
//! Active Directory Certificate Services (ADCS) CAs over named pipe `\PIPE\cert` or TCP RPC:
//! - `CertServerRequest` (Opnum 0)

use impacket_core::{decode_utf16le, encode_utf16le, CoreError};
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport, RpcUuid};
use impacket_msrpc::dtypes::{write_string_wchar_pointee, REFERENT_BASE};
use impacket_ndr::{NdrReader, NdrWriter};

/// `[MS-ICPR]` Interface UUID: `91ae6020-9e3c-11cf-8d7c-00aa00c091be` v0.0
pub const ICPR_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0x91ae_6020,
    0x9e3c,
    0x11cf,
    [0x8d, 0x7c, 0x00, 0xaa, 0x00, 0xc0, 0x91, 0xbe],
);
pub const ICPR_VERSION_MAJOR: u16 = 0;
pub const ICPR_VERSION_MINOR: u16 = 0;
pub const ICPR_PIPE: &str = r"\PIPE\cert";

pub mod cert_request_flags {
    pub const CR_IN_BASE64HEADER: u32 = 0x0000_0000;
    pub const CR_IN_BASE64: u32 = 0x0000_0001;
    pub const CR_IN_BINARY: u32 = 0x0000_0002;
    pub const CR_IN_ENCODEANY: u32 = 0x0000_00FF;
    pub const CR_IN_PKCS10: u32 = 0x0000_0100;
    pub const CR_IN_KEYGEN: u32 = 0x0000_0200;
    pub const CR_IN_PKCS7: u32 = 0x0000_0300;
    pub const CR_IN_CMC: u32 = 0x0000_0400;
}

pub mod cert_disposition {
    pub const CR_DISP_INCOMPLETE: u32 = 0;
    pub const CR_DISP_ERROR: u32 = 1;
    pub const CR_DISP_DENIED: u32 = 2;
    pub const CR_DISP_ISSUED: u32 = 3;
    pub const CR_DISP_ISSUED_OUT_OF_BAND: u32 = 4;
    pub const CR_DISP_UNDER_SUBMISSION: u32 = 5;

    pub fn name(disp: u32) -> &'static str {
        match disp {
            CR_DISP_INCOMPLETE => "CR_DISP_INCOMPLETE",
            CR_DISP_ERROR => "CR_DISP_ERROR",
            CR_DISP_DENIED => "CR_DISP_DENIED",
            CR_DISP_ISSUED => "CR_DISP_ISSUED",
            CR_DISP_ISSUED_OUT_OF_BAND => "CR_DISP_ISSUED_OUT_OF_BAND",
            CR_DISP_UNDER_SUBMISSION => "CR_DISP_UNDER_SUBMISSION",
            _ => "UNKNOWN",
        }
    }
}

/// Certificate enrollment response from `CertServerRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertServerResponse {
    pub request_id: u32,
    pub disposition: u32,
    pub encoded_cert_der: Vec<u8>,
    pub disposition_message: String,
}

/// Marshals `CERTTRANSBLOB` (inline header + deferred bytes).
fn write_cert_trans_blob(w: &mut NdrWriter, data: &[u8], ref_id: u32) {
    w.write_u32(data.len() as u32);
    if data.is_empty() {
        w.write_u32(0);
    } else {
        w.write_u32(ref_id);
    }
}

/// Marshals deferred conformant array of bytes for `CERTTRANSBLOB`.
fn write_cert_trans_blob_pointee(w: &mut NdrWriter, data: &[u8]) {
    if !data.is_empty() {
        w.write_u32(data.len() as u32); // MaxCount
        w.write_bytes(data);
        w.align(4);
    }
}

/// Reads a `CERTTRANSBLOB` from response.
fn read_cert_trans_blob(r: &mut NdrReader<'_>) -> Result<Vec<u8>, CoreError> {
    let cb = r.read_u32()? as usize;
    let ptr = r.read_u32()?;
    if ptr == 0 || cb == 0 {
        return Ok(Vec::new());
    }
    let max_count = r.read_u32()? as usize;
    if max_count < cb {
        return Err(CoreError::ProtocolError("Invalid CERTTRANSBLOB byte count".into()));
    }
    let bytes = r.read_bytes(cb)?;
    r.align(4)?;
    Ok(bytes.to_vec())
}

/// Builds request stub for `CertServerRequest` (Opnum 0):
pub fn build_cert_server_request_stub(
    flags: u32,
    authority: &str,
    request_id: u32,
    attribs: &str,
    request_der_or_b64: &[u8],
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(256 + request_der_or_b64.len());
    let mut ref_id = REFERENT_BASE;

    // 1. Flags
    w.write_u32(flags);

    // 2. pwszAuthority pointer referent
    let auth_ref = if authority.is_empty() {
        0
    } else {
        let r = ref_id;
        ref_id += 4;
        r
    };
    w.write_u32(auth_ref);

    // 3. pdwRequestId (in, out, ref)
    w.write_u32(request_id);

    // Encode attributes as NUL-terminated UTF-16LE
    let mut attribs_bytes = encode_utf16le(attribs);
    if !attribs.is_empty() {
        attribs_bytes.extend_from_slice(&[0, 0]);
    }

    // 4. pctbAttribs (CERTTRANSBLOB)
    let attrib_ref = if attribs_bytes.is_empty() {
        0
    } else {
        let r = ref_id;
        ref_id += 4;
        r
    };
    write_cert_trans_blob(&mut w, &attribs_bytes, attrib_ref);

    // 5. pctbRequest (CERTTRANSBLOB)
    let req_ref = if request_der_or_b64.is_empty() {
        0
    } else {
        let r = ref_id;
        r
    };
    write_cert_trans_blob(&mut w, request_der_or_b64, req_ref);

    // Deferred pointees:
    if auth_ref != 0 {
        write_string_wchar_pointee(&mut w, authority);
    }
    if attrib_ref != 0 {
        write_cert_trans_blob_pointee(&mut w, &attribs_bytes);
    }
    if req_ref != 0 {
        write_cert_trans_blob_pointee(&mut w, request_der_or_b64);
    }

    w.into_bytes()
}

/// Parses response stub for `CertServerRequest` (Opnum 0).
pub fn parse_cert_server_request_response(stub: &[u8]) -> Result<CertServerResponse, CoreError> {
    let mut r = NdrReader::new(stub);
    let request_id = r.read_u32()?;
    let disposition = r.read_u32()?;

    let _cert_chain = read_cert_trans_blob(&mut r)?;
    let encoded_cert = read_cert_trans_blob(&mut r)?;
    let disp_msg_bytes = read_cert_trans_blob(&mut r)?;

    let status = r.read_u32()?;
    if status != 0 && disposition != cert_disposition::CR_DISP_UNDER_SUBMISSION {
        return Err(CoreError::ProtocolError(format!(
            "CertServerRequest failed with status 0x{:08x} (disposition: {})",
            status,
            cert_disposition::name(disposition)
        )));
    }

    let disposition_message = if !disp_msg_bytes.is_empty() {
        decode_utf16le(&disp_msg_bytes).unwrap_or_default()
    } else {
        String::new()
    };

    Ok(CertServerResponse {
        request_id,
        disposition,
        encoded_cert_der: encoded_cert,
        disposition_message,
    })
}

/// `[MS-ICPR]` Client over an RPC transport.
pub struct IcprClient<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> IcprClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            call_id: 1,
        }
    }

    /// Submits a Certificate Request via `CertServerRequest` (Opnum 0).
    pub fn cert_server_request(
        &mut self,
        ca_name: &str,
        template_name: &str,
        csr_der: &[u8],
    ) -> Result<CertServerResponse, CoreError> {
        let flags = cert_request_flags::CR_IN_BINARY | cert_request_flags::CR_IN_PKCS10;
        let attribs = format!("CertificateTemplate:{}\r\n", template_name);
        let stub = build_cert_server_request_stub(flags, ca_name, 0, &attribs, csr_der);

        let pdu = RpcRequestPdu {
            call_id: self.call_id,
            context_id: 0,
            opnum: 0,
            stub_data: stub,
        }
        .to_bytes();
        self.call_id += 1;

        let resp = self.transport.transceive(&pdu)?;
        let r_stub = extract_response_stub(&resp)?;
        parse_cert_server_request_response(&r_stub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icpr_build_cert_server_request_stub() {
        let csr_bytes = vec![0x30, 0x82, 0x01, 0x0a];
        let stub = build_cert_server_request_stub(
            cert_request_flags::CR_IN_BINARY | cert_request_flags::CR_IN_PKCS10,
            "CORP-CA",
            0,
            "CertificateTemplate:User\r\n",
            &csr_bytes,
        );
        assert!(!stub.is_empty());
        let mut r = NdrReader::new(&stub);
        let flags = r.read_u32().unwrap();
        assert_eq!(flags, 0x00000102);
    }
}
