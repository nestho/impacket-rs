//! `impacket-msrpc`: High-level Active Directory MSRPC interface clients (`impacket/dcerpc/v5/*`).
//!
//! Each interface is a module named after its Python counterpart, implementing the real
//! `[MS-*]` / NDR20 wire format over the shared `impacket_dcerpc::RpcTransport` (so the same client
//! runs over `ncacn_ip_tcp` or an `ncacn_np` SMB named pipe):
//!
//! - [`samr`] — `[MS-SAMR]` Security Account Manager (`SamrConnect5`, `SamrEnumerateDomainsInSamServer`,
//!   `SamrLookupDomainInSamServer`, `SamrOpenDomain`, `SamrEnumerateUsersInDomain`, `SamrOpenUser`).
//!   Powers `samrdump` / `lookupsid` RID resolution.
//! - [`lsat`] — `[MS-LSAT]`/`[MS-LSAD]` Local Security Authority translation (`LsarOpenPolicy2`,
//!   `LsarLookupSids`, `LsarClose`). Powers `lookupsid`.
//! - [`srvs`] — `[MS-SRVS]` Server Service (`NetrShareEnum`). Powers `netview` / `smbclient` shares.
//!
//! Low-level NDR pointer/string helpers shared by the modules live in [`dtypes`].

pub(crate) mod dtypes;
pub mod dfsnm;
pub mod drsr;
pub mod even6;
pub mod exec;
pub mod lsat;
pub mod mgmt;
pub mod rrp;
pub mod samr;
pub mod scmr;
pub mod srvs;
pub mod transport;
pub mod tsch;
pub mod wkst;

pub use dfsnm::{
    namespace_flavor, storage_state, volume_state, DfsClient, DfsInfo1, DfsInfo2, DfsInfo3,
    DfsInfo300, DfsStorageInfo, DFSNM_INTERFACE_UUID, DFSNM_PIPE, DFSNM_VERSION_MAJOR,
    DFSNM_VERSION_MINOR,
};
pub use drsr::{DrsClient, DrsHandle, DrsSyncAccount};
pub use even6::{Even6Client, EvtEventRecord, EVEN6_INTERFACE_UUID, EVEN6_NAMED_PIPE, EVEN6_VERSION_MAJOR, EVEN6_VERSION_MINOR};
pub use exec::{atexec, dcomexec, psexec, smbexec, wmiexec, DcomObject};
pub use lsat::{LsatClient, SidNameUse, TranslatedName};
pub use mgmt::{
    probe_opnums, MgmtClient, OpnumStatus, RpcIfId, MGMT_INTERFACE_UUID, MGMT_VERSION_MAJOR,
    MGMT_VERSION_MINOR,
};
pub use samr::{
    user_access as samr_user_access, DomainEnumEntry, SamrClient, SamprHandle,
};
pub use scmr::{
    access as scmr_access, error_control_str, service_state, service_type, start_type,
    start_type_str, EnumServiceStatus, ScmrClient, ServiceConfig, ServiceStatus,
};
pub use srvs::{
    FileInfo3, SessionInfo10, ShareInfo1, ShareType, SrvsClient, PERM_FILE_CREATE, PERM_FILE_READ,
    PERM_FILE_WRITE,
};
pub use transport::SmbPipeTransport;
pub use tsch::{TaskInfo, TaskState, TschClient};
pub use wkst::{
    NetJoinStatus, WkstClient, WkstaInfo100, WkstaUserInfo1, WKST_INTERFACE_UUID,
    WKST_VERSION_MAJOR, WKST_VERSION_MINOR,
};
