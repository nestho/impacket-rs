# Security Policy

The **Impacket-RS** project takes the security of its code, protocols, and users seriously. This document outlines our vulnerability disclosure process, response timelines, supported versions, and security architecture.

---

## Supported Versions

We provide security updates and patches for the current release series:

| Version | Supported | Security Maintenance Status |
|:-------:|:---------:|:----------------------------|
| `v0.2.x` | :white_check_mark: | Current active release branch |
| `v0.2.0` | :white_check_mark: | Supported |
| `v0.1.x` | :x: | Superseded by `v0.2.x` (upgrade recommended) |

---

## Reporting a Vulnerability

**Please DO NOT report security vulnerabilities through public GitHub issues or discussions.**

If you believe you have discovered a vulnerability in Impacket-RS:

1. **GitHub Private Vulnerability Reporting (Preferred)**:
   - Navigate to the [Security Advisories](https://github.com/nestho/impacket-rs/security/advisories) tab on GitHub.
   - Click **"Report a vulnerability"** to open a confidential report.
2. **Direct Email Reporting**:
   - Send an email to the project maintainer: **`nestho@icloud.com`**
   - Please include:
     - Component / crate affected (e.g., `impacket-krb5`, `impacket-smb`, `impacket-auth`, `impacket-rs`)
     - Description of the potential impact and vulnerability class
     - Steps to reproduce or proof-of-concept (PoC) code
     - Affected version(s)

---

## Response Timeline & SLA

We follow responsible disclosure principles and commit to the following response targets:

* **Initial Acknowledgment**: Within **48 hours** of report receipt.
* **Triage & Assessment**: Within **5 business days**, confirming whether the issue is accepted as a vulnerability, its severity (CVSS 3.1), and an estimated remediation plan.
* **Remediation & Patch Release**:
  * **Critical / High Severity**: Patch developed, verified, and released within **14 days**.
  * **Medium / Low Severity**: Patch released within **30 days** (and strictly under 60 days per OpenSSF standards).
* **Public Disclosure**: Coordinated release and public advisory published simultaneously with the patch.

---

## Safe Harbor for Security Researchers

Impacket-RS supports ethical security research conducted in good faith:

* If you conduct research in compliance with this policy, we will not pursue civil or criminal action against you.
* We ask that you give us reasonable time to investigate and resolve reported issues before disclosing them publicly.
* Do not exploit vulnerabilities beyond the minimum necessary to demonstrate the issue.
* Do not access, modify, or destroy user data or target infrastructure during testing.

---

## Cryptographic Architecture & Active Directory Legacy Standards

Impacket-RS is a protocol toolkit designed for Active Directory, Windows networking, and security auditing:

1. **Protocol Backward Compatibility**:
   - Some legacy Windows Active Directory protocols require outdated algorithms (e.g., DES, RC4, MD4, NTLMv1) to interact with older domain controllers (Windows 2000 through 2008 R2).
   - These legacy algorithms are strictly isolated and guarded behind the `AdCompatProfile` security profile engine (`AdCompatProfile::LegacyWin2000`, `AdCompatProfile::UniversalAuto`, `AdCompatProfile::ModernHardened2025`).
2. **Modern Security Enforcement**:
   - By default, modern hardened environments enforce Extended Protection for Authentication (EPA), LDAP Channel Binding Tokens (RFC 5929 `tls-server-end-point`), SMB3 AES-128-GCM / AES-256-GCM signing/sealing, and Kerberos FAST (RFC 6113).
3. **Memory Safety**:
   - All protocol decoders, ASN.1 parsers, and DCE/RPC NDR stubs are implemented in pure safe Rust with strict bounds-checking to prevent buffer overflows, use-after-free, and memory corruption vulnerabilities.

---

## Dependency & Supply Chain Auditing

* Every commit and release is continuously audited using **Trivy** and **`cargo-audit`** against the [RustSec Advisory Database](https://rustsec.org).
* All released binary assets are signed and built with reproducible GitHub Actions release workflows.
