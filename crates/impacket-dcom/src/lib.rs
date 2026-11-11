//! `impacket-dcom`: Distributed Component Object Model `[MS-DCOM]` Object RPC (ORPC) framing,
//! `DUALSTRINGARRAY`, and `IObjectExporter` network interface resolver.

pub mod bindings;
pub mod exporter;
pub mod orpc;

pub use bindings::{
    authn_svc, tower_id, DualStringArray, SecurityBinding, StringBinding,
};
pub use exporter::{
    oxid_query_live, server_alive, server_alive2, ServerAlive2Result, IOBJECTEXPORTER_UUID,
    OPNUM_RESOLVE_OXID2, OPNUM_SERVER_ALIVE, OPNUM_SERVER_ALIVE2,
};
pub use orpc::{ComVersion, OrpcThat, OrpcThis};
