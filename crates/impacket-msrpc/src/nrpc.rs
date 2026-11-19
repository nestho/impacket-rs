//! `nrpc`: `[MS-NRPC]` Netlogon Remote Protocol client (`impacket/dcerpc/v5/nrpc.py`).
//!
//! Provides pure-Rust RPC methods for Netlogon secure channel negotiation,
//! domain trust enumeration, and Zerologon validation:
//! - `NetrServerReqChallenge` (Opnum 4)
//! - `NetrServerAuthenticate3` (Opnum 26)
//! - `NetrServerPasswordSet2` (Opnum 30)
//! - `NetrEnumerateTrustedDomainsEx` (Opnum 36)
//! - `NetrGetDCName` (Opnum 11)

use crate::dtypes::{read_string_wchar_pointee, write_string_wchar_pointee, REFERENT_BASE};
use impacket_core::CoreError;
use impacket_dcerpc::{extract_response_stub, RpcRequestPdu, RpcTransport, RpcUuid};
use impacket_ndr::{NdrDeserialize, NdrReader, NdrWriter, RpcSid};

/// `[MS-NRPC]` Interface UUID: `12345678-1234-abcd-ef00-01234567cffb` v1.0
pub const NRPC_INTERFACE_UUID: RpcUuid = RpcUuid::new(
    0x1234_5678,
    0x1234,
    0xabcd,
    [0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb],
);
pub const NRPC_VERSION_MAJOR: u16 = 1;
pub const NRPC_VERSION_MINOR: u16 = 0;
pub const NRPC_PIPE: &str = r"\PIPE\netlogon";

pub mod opnum {
    pub const NETR_SERVER_REQ_CHALLENGE: u16 = 4;
    pub const NETR_GET_DC_NAME: u16 = 11;
    pub const NETR_SERVER_AUTHENTICATE2: u16 = 15;
    pub const NETR_SERVER_AUTHENTICATE3: u16 = 26;
    pub const NETR_SERVER_PASSWORD_SET2: u16 = 30;
    pub const NETR_ENUMERATE_TRUSTED_DOMAINS_EX: u16 = 36;
}

pub mod channel_type {
    pub const NULL: u16 = 0;
    pub const MSV_AP: u16 = 1;
    pub const WORKSTATION: u16 = 2;
    pub const TRUSTED_DNS_DOMAIN: u16 = 3;
    pub const TRUSTED_DOMAIN: u16 = 4;
    pub const UAS_SERVER: u16 = 5;
    pub const SERVER: u16 = 6;
    pub const CDC_SERVER: u16 = 7;
}

pub mod negotiate_flags {
    pub const FULL_SYNC: u32 = 0x0000_0001;
    pub const REDO: u32 = 0x0000_0002;
    pub const STRONG_KEYS: u32 = 0x0000_0004;
    pub const TRANSITIVE: u32 = 0x0000_0008;
    pub const DNS_DOMAIN_NAME: u32 = 0x0000_0800;
    pub const DNS_HOST_NAME: u32 = 0x0000_1000;
    pub const AES_SHA2: u32 = 0x0080_0000;
    pub const AES: u32 = 0x0100_0000;
    /// Standard client negotiate flags for modern Windows DCs
    pub const CLIENT_DEFAULT: u32 = 0x212F_FFFF;
}

/// Information about a trusted domain returned by `NetrEnumerateTrustedDomainsEx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsDomainTrust {
    pub netbios_name: String,
    pub dns_name: String,
    pub flags: u32,
    pub parent_index: u32,
    pub trust_type: u32,
    pub trust_attributes: u32,
    pub sid: Option<RpcSid>,
    pub guid: [u8; 16],
}

/// Builds request stub for `NetrServerReqChallenge` (Opnum 4):
/// - `PrimaryName`: [in, string, unique] wchar_t*
/// - `ComputerName`: [in, string] wchar_t*
/// - `ClientChallenge`: [in] NETLOGON_CREDENTIAL (8 bytes)
pub fn build_netr_server_req_challenge_stub(
    primary_name: Option<&str>,
    computer_name: &str,
    client_challenge: &[u8; 8],
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);
    // PrimaryName pointer referent
    if primary_name.is_some() {
        w.write_u32(REFERENT_BASE);
    } else {
        w.write_u32(0);
    }

    // ComputerName pointer referent
    w.write_u32(REFERENT_BASE + 4);

    // ClientChallenge (8 bytes)
    w.write_fixed_array(client_challenge);

    // Deferred pointees:
    if let Some(pn) = primary_name {
        write_string_wchar_pointee(&mut w, pn);
    }
    write_string_wchar_pointee(&mut w, computer_name);

    w.into_bytes()
}

/// Parses response stub for `NetrServerReqChallenge` (Opnum 4):
/// - `ServerChallenge`: [out] NETLOGON_CREDENTIAL (8 bytes)
/// - `ErrorCode`: [out] NTSTATUS (u32)
pub fn parse_netr_server_req_challenge_response(stub: &[u8]) -> Result<[u8; 8], CoreError> {
    let mut r = NdrReader::new(stub);
    let server_challenge = r.read_fixed_array::<8>()?;
    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::ProtocolError(format!(
            "NetrServerReqChallenge failed with status 0x{:08x}",
            status
        )));
    }
    Ok(server_challenge)
}

/// Builds request stub for `NetrServerAuthenticate3` (Opnum 26):
/// - `PrimaryName`: [in, string, unique] wchar_t*
/// - `AccountName`: [in, string] wchar_t*
/// - `SecureChannelType`: [in] NETLOGON_SECURE_CHANNEL_TYPE (u16)
/// - `ComputerName`: [in, string] wchar_t*
/// - `ClientCredential`: [in] NETLOGON_CREDENTIAL (8 bytes)
/// - `NegotiateFlags`: [in, out] ULONG (u32)
pub fn build_netr_server_authenticate3_stub(
    primary_name: Option<&str>,
    account_name: &str,
    channel_type: u16,
    computer_name: &str,
    client_credential: &[u8; 8],
    negotiate_flags: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(256);
    // PrimaryName pointer referent
    if primary_name.is_some() {
        w.write_u32(REFERENT_BASE);
    } else {
        w.write_u32(0);
    }

    // AccountName pointer referent
    w.write_u32(REFERENT_BASE + 4);

    // SecureChannelType (u16) + 2 bytes padding
    w.write_u16(channel_type);
    w.write_u16(0);

    // ComputerName pointer referent
    w.write_u32(REFERENT_BASE + 8);

    // ClientCredential (8 bytes)
    w.write_fixed_array(client_credential);

    // NegotiateFlags
    w.write_u32(negotiate_flags);

    // Deferred pointees:
    if let Some(pn) = primary_name {
        write_string_wchar_pointee(&mut w, pn);
    }
    write_string_wchar_pointee(&mut w, account_name);
    write_string_wchar_pointee(&mut w, computer_name);

    w.into_bytes()
}

/// Response of `NetrServerAuthenticate3`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetrAuthenticate3Result {
    pub server_credential: [u8; 8],
    pub negotiate_flags: u32,
    pub account_rid: u32,
    pub status: u32,
}

/// Parses response stub for `NetrServerAuthenticate3` (Opnum 26):
/// - `ServerCredential`: [out] NETLOGON_CREDENTIAL (8 bytes)
/// - `NegotiateFlags`: [out] ULONG (u32)
/// - `AccountRid`: [out] ULONG (u32)
/// - `ErrorCode`: [out] NTSTATUS (u32)
pub fn parse_netr_server_authenticate3_response(
    stub: &[u8],
) -> Result<NetrAuthenticate3Result, CoreError> {
    let mut r = NdrReader::new(stub);
    let server_credential = r.read_fixed_array::<8>()?;
    let negotiate_flags = r.read_u32()?;
    let account_rid = r.read_u32()?;
    let status = r.read_u32()?;

    Ok(NetrAuthenticate3Result {
        server_credential,
        negotiate_flags,
        account_rid,
        status,
    })
}

/// Builds request stub for `NetrServerPasswordSet2` (Opnum 30):
/// - `PrimaryName`: [in, string, unique] wchar_t*
/// - `AccountName`: [in, string] wchar_t*
/// - `SecureChannelType`: [in] NETLOGON_SECURE_CHANNEL_TYPE (u16)
/// - `ComputerName`: [in, string] wchar_t*
/// - `Authenticator`: [in] NETLOGON_AUTHENTICATOR (12 bytes)
/// - `ClearNewPassword`: [in] NL_TRUST_PASSWORD_FIXED_ARRAY (516 bytes)
pub fn build_netr_server_password_set2_stub(
    primary_name: Option<&str>,
    account_name: &str,
    channel_type: u16,
    computer_name: &str,
    authenticator: &[u8; 12],
    clear_new_password: &[u8; 516],
) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(1024);
    if primary_name.is_some() {
        w.write_u32(REFERENT_BASE);
    } else {
        w.write_u32(0);
    }

    w.write_u32(REFERENT_BASE + 4);

    w.write_u16(channel_type);
    w.write_u16(0);

    w.write_u32(REFERENT_BASE + 8);

    w.write_fixed_array(authenticator);
    w.write_fixed_array(clear_new_password);

    if let Some(pn) = primary_name {
        write_string_wchar_pointee(&mut w, pn);
    }
    write_string_wchar_pointee(&mut w, account_name);
    write_string_wchar_pointee(&mut w, computer_name);

    w.into_bytes()
}

/// Parses response stub for `NetrServerPasswordSet2` (Opnum 30):
/// - `ReturnAuthenticator`: [out] NETLOGON_AUTHENTICATOR (12 bytes)
/// - `ErrorCode`: [out] NTSTATUS (u32)
pub fn parse_netr_server_password_set2_response(stub: &[u8]) -> Result<u32, CoreError> {
    let mut r = NdrReader::new(stub);
    let _return_authenticator = r.read_fixed_array::<12>()?;
    r.read_u32()
}

/// Builds request stub for `NetrEnumerateTrustedDomainsEx` (Opnum 36):
/// - `ServerName`: [in, string, unique] wchar_t*
pub fn build_netr_enumerate_trusted_domains_ex_stub(server_name: Option<&str>) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(64);
    if let Some(name) = server_name {
        w.write_u32(REFERENT_BASE);
        write_string_wchar_pointee(&mut w, name);
    } else {
        w.write_u32(0);
    }
    w.into_bytes()
}

/// Parses response stub for `NetrEnumerateTrustedDomainsEx` (Opnum 36):
/// - `Domains`: NETLOGON_TRUSTED_DOMAIN_ARRAY
///   - `DomainCount`: DWORD
///   - `Domains`: pointer referent + array of `DS_DOMAIN_TRUSTSW`
/// - `ErrorCode`: NTSTATUS
pub fn parse_netr_enumerate_trusted_domains_ex_response(
    stub: &[u8],
) -> Result<Vec<DsDomainTrust>, CoreError> {
    let mut r = NdrReader::new(stub);
    let count = r.read_u32()?;
    let array_ref = r.read_u32()?;

    if array_ref == 0 || count == 0 {
        return Ok(Vec::new());
    }

    let actual_count = r.read_u32()?;
    let mut headers = Vec::with_capacity(actual_count as usize);

    for _ in 0..actual_count {
        let netbios_ref = r.read_u32()?;
        let dns_ref = r.read_u32()?;
        let flags = r.read_u32()?;
        let parent_index = r.read_u32()?;
        let trust_type = r.read_u32()?;
        let trust_attributes = r.read_u32()?;
        let sid_ref = r.read_u32()?;
        let guid = r.read_fixed_array::<16>()?;
        headers.push((
            netbios_ref,
            dns_ref,
            flags,
            parent_index,
            trust_type,
            trust_attributes,
            sid_ref,
            guid,
        ));
    }

    let mut domains = Vec::with_capacity(headers.len());
    for (nb_ref, dns_ref, flags, parent_idx, ttype, tattrs, sid_ref, guid) in headers {
        let netbios_name = if nb_ref != 0 {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };

        let dns_name = if dns_ref != 0 {
            read_string_wchar_pointee(&mut r)?
        } else {
            String::new()
        };

        let sid = if sid_ref != 0 {
            Some(RpcSid::ndr_deserialize(&mut r)?)
        } else {
            None
        };

        domains.push(DsDomainTrust {
            netbios_name,
            dns_name,
            flags,
            parent_index: parent_idx,
            trust_type: ttype,
            trust_attributes: tattrs,
            sid,
            guid,
        });
    }

    Ok(domains)
}

/// Builds request stub for `NetrGetDCName` (Opnum 11):
/// - `ServerName`: [in, string] wchar_t*
/// - `DomainName`: [in, string, unique] wchar_t*
pub fn build_netr_get_dc_name_stub(server_name: &str, domain_name: Option<&str>) -> Vec<u8> {
    let mut w = NdrWriter::with_capacity(128);
    w.write_u32(REFERENT_BASE);

    if domain_name.is_some() {
        w.write_u32(REFERENT_BASE + 4);
    } else {
        w.write_u32(0);
    }

    write_string_wchar_pointee(&mut w, server_name);
    if let Some(dn) = domain_name {
        write_string_wchar_pointee(&mut w, dn);
    }

    w.into_bytes()
}

/// Parses response stub for `NetrGetDCName` (Opnum 11):
/// - `DCName`: [out, string] wchar_t*
/// - `ErrorCode`: [out] DWORD
pub fn parse_netr_get_dc_name_response(stub: &[u8]) -> Result<String, CoreError> {
    let mut r = NdrReader::new(stub);
    let dc_ref = r.read_u32()?;
    if dc_ref == 0 {
        return Err(CoreError::ProtocolError("NetrGetDCName returned null string".into()));
    }
    let dc_name = read_string_wchar_pointee(&mut r)?;
    let status = r.read_u32()?;
    if status != 0 {
        return Err(CoreError::ProtocolError(format!(
            "NetrGetDCName failed with error 0x{:08x}",
            status
        )));
    }
    Ok(dc_name)
}

/// `[MS-NRPC]` Client over an RPC transport.
pub struct NrpcClient<T: RpcTransport> {
    transport: T,
    call_id: u32,
}

impl<T: RpcTransport> NrpcClient<T> {
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

    /// `NetrServerReqChallenge` (Opnum 4).
    pub fn req_challenge(
        &mut self,
        primary_name: Option<&str>,
        computer_name: &str,
        client_challenge: &[u8; 8],
    ) -> Result<[u8; 8], CoreError> {
        let stub =
            build_netr_server_req_challenge_stub(primary_name, computer_name, client_challenge);
        let resp = self.call(opnum::NETR_SERVER_REQ_CHALLENGE, stub)?;
        parse_netr_server_req_challenge_response(&resp)
    }

    /// `NetrServerAuthenticate3` (Opnum 26).
    pub fn server_authenticate3(
        &mut self,
        primary_name: Option<&str>,
        account_name: &str,
        channel_type: u16,
        computer_name: &str,
        client_credential: &[u8; 8],
        negotiate_flags: u32,
    ) -> Result<NetrAuthenticate3Result, CoreError> {
        let stub = build_netr_server_authenticate3_stub(
            primary_name,
            account_name,
            channel_type,
            computer_name,
            client_credential,
            negotiate_flags,
        );
        let resp = self.call(opnum::NETR_SERVER_AUTHENTICATE3, stub)?;
        parse_netr_server_authenticate3_response(&resp)
    }

    /// `NetrServerPasswordSet2` (Opnum 30).
    pub fn server_password_set2(
        &mut self,
        primary_name: Option<&str>,
        account_name: &str,
        channel_type: u16,
        computer_name: &str,
        authenticator: &[u8; 12],
        clear_new_password: &[u8; 516],
    ) -> Result<u32, CoreError> {
        let stub = build_netr_server_password_set2_stub(
            primary_name,
            account_name,
            channel_type,
            computer_name,
            authenticator,
            clear_new_password,
        );
        let resp = self.call(opnum::NETR_SERVER_PASSWORD_SET2, stub)?;
        parse_netr_server_password_set2_response(&resp)
    }

    /// `NetrEnumerateTrustedDomainsEx` (Opnum 36).
    pub fn enumerate_trusted_domains_ex(
        &mut self,
        server_name: Option<&str>,
    ) -> Result<Vec<DsDomainTrust>, CoreError> {
        let stub = build_netr_enumerate_trusted_domains_ex_stub(server_name);
        let resp = self.call(opnum::NETR_ENUMERATE_TRUSTED_DOMAINS_EX, stub)?;
        parse_netr_enumerate_trusted_domains_ex_response(&resp)
    }

    /// `NetrGetDCName` (Opnum 11).
    pub fn get_dc_name(
        &mut self,
        server_name: &str,
        domain_name: Option<&str>,
    ) -> Result<String, CoreError> {
        let stub = build_netr_get_dc_name_stub(server_name, domain_name);
        let resp = self.call(opnum::NETR_GET_DC_NAME, stub)?;
        parse_netr_get_dc_name_response(&resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nrpc_req_challenge_stub_and_response() {
        let challenge = [1, 2, 3, 4, 5, 6, 7, 8];
        let stub = build_netr_server_req_challenge_stub(
            Some(r"\\DC01"),
            "CLIENT$",
            &challenge,
        );
        assert!(!stub.is_empty());

        let mut r = NdrReader::new(&stub);
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE); // PrimaryName
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE + 4); // ComputerName
        assert_eq!(r.read_fixed_array::<8>().unwrap(), challenge);

        // Mock response
        let srv_chal = [8, 7, 6, 5, 4, 3, 2, 1];
        let mut resp = srv_chal.to_vec();
        resp.extend_from_slice(&0u32.to_le_bytes()); // STATUS_SUCCESS

        let parsed = parse_netr_server_req_challenge_response(&resp).unwrap();
        assert_eq!(parsed, srv_chal);
    }

    #[test]
    fn test_nrpc_server_authenticate3_stub_and_response() {
        let client_cred = [0xAA; 8];
        let stub = build_netr_server_authenticate3_stub(
            Some(r"\\DC01"),
            "DC01$",
            channel_type::SERVER,
            "DC01",
            &client_cred,
            negotiate_flags::CLIENT_DEFAULT,
        );
        let mut r = NdrReader::new(&stub);
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE);
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE + 4);
        assert_eq!(r.read_u16().unwrap(), channel_type::SERVER);
        assert_eq!(r.read_u16().unwrap(), 0);
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE + 8);
        assert_eq!(r.read_fixed_array::<8>().unwrap(), client_cred);
        assert_eq!(r.read_u32().unwrap(), negotiate_flags::CLIENT_DEFAULT);

        // Mock response
        let srv_cred = [0xBB; 8];
        let mut resp = srv_cred.to_vec();
        resp.extend_from_slice(&negotiate_flags::CLIENT_DEFAULT.to_le_bytes());
        resp.extend_from_slice(&1000u32.to_le_bytes()); // account RID
        resp.extend_from_slice(&0u32.to_le_bytes()); // status 0

        let auth_res = parse_netr_server_authenticate3_response(&resp).unwrap();
        assert_eq!(auth_res.server_credential, srv_cred);
        assert_eq!(auth_res.negotiate_flags, negotiate_flags::CLIENT_DEFAULT);
        assert_eq!(auth_res.account_rid, 1000);
        assert_eq!(auth_res.status, 0);
    }

    #[test]
    fn test_nrpc_server_password_set2_stub() {
        let auth = [0x55; 12];
        let pass = [0x00; 516];
        let stub = build_netr_server_password_set2_stub(
            None,
            "DC01$",
            channel_type::SERVER,
            "DC01",
            &auth,
            &pass,
        );
        let mut r = NdrReader::new(&stub);
        assert_eq!(r.read_u32().unwrap(), 0); // null PrimaryName
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE + 4);
        assert_eq!(r.read_u16().unwrap(), channel_type::SERVER);
        assert_eq!(r.read_u16().unwrap(), 0);
        assert_eq!(r.read_u32().unwrap(), REFERENT_BASE + 8);
        assert_eq!(r.read_fixed_array::<12>().unwrap(), auth);
        assert_eq!(r.read_fixed_array::<516>().unwrap(), pass);
    }

    #[test]
    fn test_nrpc_get_dc_name_roundtrip() {
        let stub = build_netr_get_dc_name_stub(r"\\192.168.1.10", Some("CORP.LOCAL"));
        assert!(!stub.is_empty());

        let mut resp = Vec::new();
        resp.extend_from_slice(&REFERENT_BASE.to_le_bytes());
        let mut w = NdrWriter::new();
        write_string_wchar_pointee(&mut w, r"\\DC01.corp.local");
        resp.extend_from_slice(&w.into_bytes());
        resp.extend_from_slice(&0u32.to_le_bytes()); // status 0

        let dc = parse_netr_get_dc_name_response(&resp).unwrap();
        assert_eq!(dc, r"\\DC01.corp.local");
    }
}
