//! `impacket-adcs`: Active Directory Certificate Services (ADCS) protocol engine & auditor.
//!
//! Provides:
//! - `[MS-ICPR]`: Certificate enrollment over DCE/RPC (`icpr::IcprClient`).
//! - PKCS#10 CSR generation with custom SAN extensions (`csr::generate_pkcs10_csr`).
//! - ESC1 through ESC15 vulnerability auditing (`auditor::audit_certificate_template`).

pub mod auditor;
pub mod csr;
pub mod icpr;

pub use auditor::{
    audit_certificate_template, audit_enterprise_ca, CertificateTemplateInfo, EscVulnerability,
};
pub use csr::{generate_pkcs10_csr, parse_rsa_private_key, CsrOptions};
pub use icpr::{
    cert_disposition, cert_request_flags, CertServerResponse, IcprClient, ICPR_INTERFACE_UUID,
    ICPR_PIPE, ICPR_VERSION_MAJOR, ICPR_VERSION_MINOR,
};
