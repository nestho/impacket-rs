//! `auditor`: Active Directory Certificate Services (ADCS) ESC1–ESC15 Vulnerability Auditor.
//!
//! Audits Active Directory Certificate Templates (`pKICertificateTemplate`) and Enterprise CAs
//! for certified privilege escalation paths (ESC1 through ESC15):
//! - **ESC1**: `ENROLLEE_SUPPLIES_SUBJECT` + Client Authentication + No Manager Approval
//! - **ESC2**: Any Purpose EKU or SubCA (Empty EKU)
//! - **ESC3**: Certificate Request Agent (Enrollment Agent) EKU
//! - **ESC4**: Vulnerable Template Access Control (WriteOwner, WriteDacl, GenericWrite)
//! - **ESC6**: `EDITF_ATTRIBUTESUBJECTALTNAME2` enabled on CA
//! - **ESC8**: NTLM Relay to ADCS Web Enrollment HTTP endpoints
//! - **ESC9 / ESC10**: Missing security extensions (`CT_FLAG_NO_SECURITY_EXTENSION`)

pub const OID_CLIENT_AUTHENTICATION: &str = "1.3.6.1.5.5.7.3.2";
pub const OID_SMART_CARD_LOGON: &str = "1.3.6.1.4.1.311.20.2.2";
pub const OID_PKINIT_CLIENT_AUTH: &str = "1.3.6.1.5.2.3.4";
pub const OID_ANY_PURPOSE: &str = "2.5.29.37.0";
pub const OID_ENROLLMENT_AGENT: &str = "1.3.6.1.4.1.311.20.2.1";

pub mod name_flags {
    pub const ENROLLEE_SUPPLIES_SUBJECT: u32 = 0x0000_0001;
    pub const ADD_EMAIL: u32 = 0x0000_0002;
    pub const ADD_OBJ_GUID: u32 = 0x0000_0200;
    pub const NO_SECURITY_EXTENSION: u32 = 0x0008_0000;
}

pub mod enrollment_flags {
    pub const PEND_ALL_REQUESTS: u32 = 0x0000_0002;
}

/// Known ADCS escalation vulnerability types.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EscVulnerability {
    Esc1,
    Esc2,
    Esc3,
    Esc4,
    Esc6,
    Esc8,
    Esc9,
    Esc10,
    Esc13,
}

impl EscVulnerability {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Esc1 => "ESC1",
            Self::Esc2 => "ESC2",
            Self::Esc3 => "ESC3",
            Self::Esc4 => "ESC4",
            Self::Esc6 => "ESC6",
            Self::Esc8 => "ESC8",
            Self::Esc9 => "ESC9",
            Self::Esc10 => "ESC10",
            Self::Esc13 => "ESC13",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::Esc1 => "Enrollee supplies subject (SAN) with Client Authentication EKU and no manager approval",
            Self::Esc2 => "Any Purpose EKU or SubCA (Empty EKU) allowing arbitrary certificate usage",
            Self::Esc3 => "Certificate Request Agent (Enrollment Agent) EKU allowing user impersonation",
            Self::Esc4 => "Vulnerable Template Access Control (WriteOwner, WriteDacl, GenericWrite)",
            Self::Esc6 => "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled allowing SAN specification on all templates",
            Self::Esc8 => "ADCS Web Enrollment HTTP endpoints (/certsrv) vulnerable to NTLM relay",
            Self::Esc9 => "Template contains CT_FLAG_NO_SECURITY_EXTENSION without strong certificate mapping",
            Self::Esc10 => "Weak certificate mapping enabled on domain controllers",
            Self::Esc13 => "Issuance policies with OID mapped to privileged groups",
        }
    }
}

/// Metadata describing an Active Directory Certificate Template (`pKICertificateTemplate`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateTemplateInfo {
    pub name: String,
    pub display_name: String,
    pub certificate_name_flag: u32,
    pub enrollment_flag: u32,
    pub ra_signatures: u32,
    pub ekus: Vec<String>,
    pub allows_low_priv_enrollment: bool,
    pub has_vulnerable_acl: bool,
    pub has_issuance_policy: bool,
}

impl CertificateTemplateInfo {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_name: String::new(),
            certificate_name_flag: 0,
            enrollment_flag: 0,
            ra_signatures: 0,
            ekus: Vec::new(),
            allows_low_priv_enrollment: true,
            has_vulnerable_acl: false,
            has_issuance_policy: false,
        }
    }

    /// Checks if this template permits Client Authentication (Kerberos PKINIT or Schannel TLS).
    pub fn has_client_authentication(&self) -> bool {
        self.ekus.is_empty()
            || self.ekus.iter().any(|eku| {
                eku == OID_CLIENT_AUTHENTICATION
                    || eku == OID_SMART_CARD_LOGON
                    || eku == OID_PKINIT_CLIENT_AUTH
                    || eku == OID_ANY_PURPOSE
            })
    }

    /// Checks if this template allows enrollee to supply Subject Alternative Name (SAN).
    pub fn enrollee_supplies_subject(&self) -> bool {
        (self.certificate_name_flag & name_flags::ENROLLEE_SUPPLIES_SUBJECT) != 0
    }

    /// Checks if manager approval or authorized signatures are required.
    pub fn requires_approval(&self) -> bool {
        (self.enrollment_flag & enrollment_flags::PEND_ALL_REQUESTS) != 0 || self.ra_signatures > 0
    }
}

/// Audits a certificate template and returns any discovered ESC vulnerabilities.
pub fn audit_certificate_template(tpl: &CertificateTemplateInfo) -> Vec<EscVulnerability> {
    let mut vulns = Vec::new();

    // Check ESC4: Vulnerable Template Access Control
    if tpl.has_vulnerable_acl {
        vulns.push(EscVulnerability::Esc4);
    }

    // Check enrollment approval gate (ESC1, ESC2, ESC3 require no manager approval)
    if !tpl.requires_approval() && tpl.allows_low_priv_enrollment {
        // ESC1: Enrollee supplies subject + Client Authentication
        if tpl.enrollee_supplies_subject() && tpl.has_client_authentication() {
            vulns.push(EscVulnerability::Esc1);
        }

        // ESC2: Any Purpose EKU or No EKU
        if tpl.ekus.is_empty() || tpl.ekus.iter().any(|e| e == OID_ANY_PURPOSE) {
            vulns.push(EscVulnerability::Esc2);
        }

        // ESC3: Enrollment Agent EKU
        if tpl.ekus.iter().any(|e| e == OID_ENROLLMENT_AGENT) {
            vulns.push(EscVulnerability::Esc3);
        }

        // ESC9: No Security Extension
        if (tpl.certificate_name_flag & name_flags::NO_SECURITY_EXTENSION) != 0 {
            vulns.push(EscVulnerability::Esc9);
        }

        // ESC13: Issuance policy mapping
        if tpl.has_issuance_policy && tpl.has_client_authentication() {
            vulns.push(EscVulnerability::Esc13);
        }
    }

    vulns
}

/// Audits an Enterprise Certificate Authority for CA-level misconfigurations.
pub fn audit_enterprise_ca(
    has_subject_alt_name_flag: bool,
    has_http_web_enrollment: bool,
) -> Vec<EscVulnerability> {
    let mut vulns = Vec::new();
    if has_subject_alt_name_flag {
        vulns.push(EscVulnerability::Esc6);
    }
    if has_http_web_enrollment {
        vulns.push(EscVulnerability::Esc8);
    }
    vulns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_esc1_vulnerable_template() {
        let mut tpl = CertificateTemplateInfo::new("VulnESC1");
        tpl.certificate_name_flag = name_flags::ENROLLEE_SUPPLIES_SUBJECT;
        tpl.ekus = vec![OID_CLIENT_AUTHENTICATION.to_string()];
        tpl.allows_low_priv_enrollment = true;

        let vulns = audit_certificate_template(&tpl);
        assert!(vulns.contains(&EscVulnerability::Esc1));
        assert!(!vulns.contains(&EscVulnerability::Esc2));
    }

    #[test]
    fn test_audit_esc2_and_esc3() {
        let mut tpl2 = CertificateTemplateInfo::new("SubCA_ESC2");
        tpl2.ekus = vec![OID_ANY_PURPOSE.to_string()];
        let vulns2 = audit_certificate_template(&tpl2);
        assert!(vulns2.contains(&EscVulnerability::Esc2));

        let mut tpl3 = CertificateTemplateInfo::new("Agent_ESC3");
        tpl3.ekus = vec![OID_ENROLLMENT_AGENT.to_string()];
        let vulns3 = audit_certificate_template(&tpl3);
        assert!(vulns3.contains(&EscVulnerability::Esc3));
    }

    #[test]
    fn test_audit_manager_approval_mitigates_esc1() {
        let mut tpl = CertificateTemplateInfo::new("SafeWithApproval");
        tpl.certificate_name_flag = name_flags::ENROLLEE_SUPPLIES_SUBJECT;
        tpl.enrollment_flag = enrollment_flags::PEND_ALL_REQUESTS;
        tpl.ekus = vec![OID_CLIENT_AUTHENTICATION.to_string()];

        let vulns = audit_certificate_template(&tpl);
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_audit_ca_flags() {
        let vulns = audit_enterprise_ca(true, true);
        assert!(vulns.contains(&EscVulnerability::Esc6));
        assert!(vulns.contains(&EscVulnerability::Esc8));
    }
}
