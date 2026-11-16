# Impacket-RS Project Governance

This document describes the organizational structure, decision-making processes, leadership roles, and long-term sustainability policies for the **Impacket-RS** project.

Impacket-RS follows open, transparent, and merit-based open-source governance principles designed to align with the [Rust Innovation Lab (RIL) Governance Policy](https://github.com/rustfoundation/rust-innovation-lab/blob/main/governance.md).

---

## 1. Mission and Core Philosophy

Impacket-RS is a memory-safe, high-performance, pure-Rust reimplementation and modernization of Active Directory protocols and network security assessment tools.

Our core commitments:
1. **100% Pure Rust**: Zero C/Python runtime dependencies.
2. **Memory Safety & High Assurance**: Rigorous bounds-checking, constant-time cryptography where applicable, zero unhandled panics on untrusted input.
3. **Open Collaboration**: Permissively licensed under **Apache-2.0**, welcoming global contributions and maintaining strict architectural discipline.

---

## 2. Project Leadership & Key Contacts

The project designates the following individuals as primary leadership and official contacts for operational, administrative, and fiscal matters with the **Rust Foundation** and external partners:

* **Project Lead & Principal Architect**:
  * **Name**: Ghader Ahmadi (Nestho)
  * **GitHub**: [@nestho](https://github.com/nestho)
  * **Email**: `nestho@icloud.com`
  * **Role**: Technical direction, architectural decisions, core releases, security response lead, and primary administrative contact for the Rust Foundation.

Changes to project leadership will be documented publicly in this file and communicated promptly to the Rust Foundation.

---

## 3. Roles and Responsibilities

| Role | Responsibilities | Requirements |
| :--- | :--- | :--- |
| **Project Lead** | Overall project vision, roadmap milestones, architectural sign-off, release tagging, security advisory coordination, Foundation relations. | Founder / Designated successor |
| **Maintainers** | Code reviews, triage of issues and PRs, CI/CD maintenance, test suite integrity, security auditing. | Demonstrated track record of quality contributions, security-conscious Rust engineering. |
| **Contributors** | Authoring pull requests, documentation, bug reports, feature requests, testing. | Open to all individuals adhering to the [Code of Conduct](CODE_OF_CONDUCT.md). |

### Becoming a Maintainer
Contributor advancement is merit-based. Regular contributors who demonstrate:
- Consistent high-quality Rust code contributions adhering to the project's zero-dependency pure-Rust standard,
- Respectful collaboration and peer reviews adhering to the Code of Conduct,
- Proactive triaging of security, protocol RFCs, or compatibility reports,

may be invited by the Project Lead to become a Maintainer with triage and review privileges.

---

## 4. Decision-Making Process

Impacket-RS operates on a **consensus-seeking model**:

1. **Everyday Changes**: Bug fixes, documentation, test additions, and protocol edge-case fixes are proposed via Pull Request and require review and approval from at least one Maintainer.
2. **Major Architectural Changes**: Breaking protocol API changes, new crate additions to the workspace, C ABI modifications, or dependency additions require an RFC issue discussed publicly on GitHub Discussions or Issues. Consensus is sought among maintainers, with the Project Lead holding ultimate tie-breaking responsibility.
3. **Security Releases**: Managed confidentially via GitHub Security Advisories per [SECURITY.md](SECURITY.md) before synchronized public disclosure.

---

## 5. Succession Planning

Leadership transitions are planned to ensure stability and continuity:

1. **Maintainer Stepping Down**: A maintainer who wishes to step down provides written notice via GitHub or email. Their administrative permissions are amicably revoked with gratitude, and active responsibilities are redistributed to remaining maintainers.
2. **Project Lead Transition**: If the Project Lead is unable or chooses not to continue, leadership will be transferred to a designated co-maintainer selected by consensus among the active maintainers and endorsed by the Rust Foundation.
3. **Emergency Contact**: If the Project Lead becomes unreachable for more than 90 days, the active maintainers may vote by two-thirds majority to elect a new Project Lead.

---

## 6. Project Cessation & Wind-Down Policy

In the event that the Impacket-RS project can no longer be sustained or actively maintained:

1. **Notice**: The leadership will post a public notice at least 60 days prior to cessation.
2. **Code & IP Preservation**: The codebase will remain permanently available under the **Apache-2.0** license. Intellectual property, trademarks, and repository custody may be transferred to the **Rust Foundation** or another 501(c)(3) open-source stewardship organization to preserve the ecosystem's public goods.
3. **Disbursement of Remaining Funds**: Any remaining ringfenced project funds held under fiscal hosting (e.g., with the Rust Foundation) will be disbursed in accordance with the host's fiscal policy (e.g., allocated to related Rust ecosystem security initiatives).

---

## 7. Code of Conduct & Standards

All participants, contributors, and leaders are bound by the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md) and the [Rust Foundation Code of Conduct](https://github.com/rustfoundation/rust-innovation-lab/blob/main/CODE_OF_CONDUCT.md).

Violations can be reported to the Project Lead (`nestho@icloud.com`) or directly to the Rust Foundation conduct team.
