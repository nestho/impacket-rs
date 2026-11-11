//! `impacket-mssql`: Pure-Rust Microsoft SQL Server TDS Protocol Engine (`[MS-TDS]`).
//!
//! Features:
//! - Full TDS 7.x packet fragmentation, reassembly, and framing (`packet`)
//! - PRELOGIN negotiation with encryption capability advertisement (`prelogin`)
//! - LOGIN7 authentication with SQL authentication (symmetric nibble-swap XOR 0xA5 obfuscation) (`login`)
//! - Windows Integrated Authentication (SSPI/NTLMv2) over TDS (`login`, `client`)
//! - Tabular Result token parsing: COLMETADATA, ROW, ENVCHANGE, LOGINACK, INFO, ERROR, DONE (`tokens`)
//! - High-level `MssqlClient` supporting SQL queries, batches, and `xp_cmdshell` execution (`client`)

pub mod browser;
pub mod client;
pub mod login;
pub mod packet;
pub mod prelogin;
pub mod tokens;

pub use browser::{
    parse_sql_browser_response, parse_sql_browser_text, query_sql_instances_udp,
    SqlBrowserInstance, CLNT_UCAST_EX, CLNT_UCAST_INST, SQLR_DEFAULT_PORT, SVR_RESP,
};
pub use client::{MssqlClient, QueryResult};
pub use login::{
    build_login7_payload, deobfuscate_sql_password, obfuscate_sql_password, Login7Params,
    TDS_VERSION_7_1, TDS_VERSION_7_4,
};
pub use packet::{
    packet_status, packet_type, read_full_tds_message, read_tds_packet, write_tds_message,
    TdsHeader, DEFAULT_PACKET_SIZE, TDS_HEADER_LEN,
};
pub use prelogin::{
    build_prelogin_request, encrypt_mode, parse_prelogin_response, prelogin_token, PreloginResponse,
};
pub use tokens::{
    data_type, parse_tds_tokens, token_id, ColumnMetadata, LoginAck, MssqlError, MssqlRow, TdsToken,
};
