//! `impacket-relay`: Cross-protocol NTLMSSP authentication relay engine (`impacket/examples/ntlmrelayx/*`).
//!
//! Provides a Sans-I/O authentication message relay state machine, protocol adapters
//! (HTTP, SMB, LDAP), and relay target orchestration.

pub mod http;
pub mod ldap;
pub mod server;
pub mod session;
pub mod smb;

pub use http::{
    build_http_401_challenge_response, extract_ntlm_token_from_header,
    format_ntlm_authorization_header, format_ntlm_challenge_header,
};
pub use ldap::{build_ldap_sasl_bind_request, extract_spnego_from_ldap_bind_response};
pub use server::{RelayEngine, RelayTarget};
pub use session::{
    strip_channel_bindings_from_challenge, strip_mic_from_authenticate, NtlmRelaySession,
    RelayProtocol, RelayState,
};
pub use smb::{
    extract_ntlm_from_smb2_security_buffer, wrap_ntlm_challenge_in_spnego,
    wrap_ntlm_negotiate_in_spnego,
};
