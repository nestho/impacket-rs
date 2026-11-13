# Contributing to Impacket-RS

Thank you for your interest in contributing to **Impacket-RS**! This project is a pure-Rust, memory-safe, high-performance redesign of core Active Directory and network protocol tools. We welcome community contributions, bug reports, and feature enhancements.

To ensure stability, security, and consistent architecture across all 74+ tools and internal crates, all contributions follow the guidelines outlined below.

---

## Code of Conduct & Core Philosophy

1. **Pure-Rust & Zero C/Python Runtime Dependencies**:
   All crates must compile natively with standard `cargo build` across Linux, macOS, and Windows without requiring external C libraries, Python interpreters, or dynamic wrappers.
2. **Memory Safety & High Performance**:
   Leverage zero-allocation parsing, compile-time layout verification, and idiomatic Rust. Keep `unsafe` code to an absolute minimum (ideally zero); any necessary `unsafe` blocks require an explicit `// SAFETY:` rationale.
3. **Security-First**:
   Cryptographic operations must be constant-time where applicable, network buffers must be rigorously bounds-checked, and protocol parsers must handle malformed input gracefully without panicking.

---

## Branch Protection & Pull Request Policy

- **The `main` branch is protected**:
  Direct pushes to `main` are disabled. All updates must arrive via Pull Requests.
- **Maintainer Review & Verification**:
  Every Pull Request is thoroughly reviewed by the maintainer ([@nestho](https://github.com/nestho)) with deep architectural and security scrutiny.
- **Review Criteria**:
  - **Language & Idioms**: Idiomatic, modern Rust (2021 edition).
  - **Architectural Fit**: Clear separation of concerns between protocol crates (`crates/impacket-*`) and the CLI dispatcher (`bins/impacket-rs`).
  - **Security & Reliability**: No memory leaks, no unhandled unwraps in network paths, clean SonarCloud / SAST results.
  - **Test Coverage**: Appropriate unit and/or integration tests for new features and bug fixes.
  - Once reviewed, verified, and approved, the maintainer will merge the PR into `main`.

---

## Development Workflow

### 1. Fork & Clone
Fork the repository on GitHub and clone your fork locally:
```bash
git clone https://github.com/<your-username>/impacket-rs.git
cd impacket-rs
git remote add upstream https://github.com/nestho/impacket-rs.git
```

### 2. Create a Feature Branch
Branch off the latest `main`:
```bash
git checkout -b feat/your-feature-name
# or for bug fixes:
git checkout -b fix/issue-description
```

### 3. Repository Architecture
See [**`docs/ARCHITECTURE.md`**](docs/ARCHITECTURE.md) for full crate design, compatibility tiers, and engineering details.

Place your changes in the appropriate crate or directory:
- `crates/impacket-core`: Core primitives, target parsing, NTSTATUS, `AdCompatProfile`.
- `crates/impacket-crypto`: Cryptographic algorithms (AES, DES, RC4, MD4/5, Kerberos n-fold, etc.).
- `crates/impacket-ndr`: NDR / NDR64 serialization engine and procedural derive macros.
- `crates/impacket-auth`: NTLM, SPNEGO, GSS-API, and session security.
- `crates/impacket-krb5`: Kerberos protocol, FAST armor, ticket manipulation, PKINIT.
- `crates/impacket-smb`: SMB1/2/3 transport, file server, and pipe operations.
- `crates/impacket-dcerpc`: DCE/RPC v5 PDU framing and security contexts.
- `crates/impacket-msrpc`: MS-RPC interfaces (SAMR, LSAT, SRVS, SCMR, RRP, etc.).
- `crates/impacket-sam`: Offline hive parsers (SAM, SYSTEM, SECURITY, NTDS.dit, DPAPI).
- `crates/impacket-ldap`: ASN.1 BER LDAP/LDAPS client and Active Directory queries.
- `crates/impacket-dcom`: DCOM, WMI, and ORPC client interfaces.
- `crates/impacket-mssql`: TDS 7.x/8.0 database protocol client.
- `crates/impacket-relay`: Cross-protocol relay state machine.
- `bins/impacket-rs`: Command-line interface, tool arguments, and dispatching.
- `docs/COMMAND_REFERENCE.md`: Documentation for tools and usage syntax.

### 4. Code Standards, Automated Testing & Verification

Per our [OpenSSF Best Practices](https://www.bestpractices.dev/) standards, all contributions must adhere to these policies:

- **Automated Test Requirement**: Every new feature, protocol implementation, or bug fix **MUST** include corresponding automated unit or integration tests (`cargo test`).
- **Compiler Warnings Policy**: Code must compile cleanly without compiler errors (`cargo check --workspace --all-targets`).
- **Code Formatting & Linting**: Code must follow standard Rust style guidelines.

Verify locally before committing:

```bash
# 1. Compile all workspace crates
cargo check --workspace --all-targets

# 2. Run full automated test suite
cargo test --workspace

# 3. Check code formatting
cargo fmt --all -- --check

# 4. Run Clippy static analysis
cargo clippy --workspace --all-targets
```

### 5. Commit Guidelines
We use [Conventional Commits](https://www.conventionalcommits.org/):
- `feat: <description>` — New feature or tool capability
- `fix: <description>` — Bug fix
- `docs: <description>` — Documentation improvements
- `perf: <description>` — Performance optimizations
- `refactor: <description>` — Code refactoring without behavioral changes
- `test: <description>` — Adding or improving tests
- `chore: <description>` — Build, CI, or dependency updates

### 6. Submitting a Pull Request
1. Push your branch to your fork:
   ```bash
   git push origin feat/your-feature-name
   ```
2. Open a Pull Request against `nestho/impacket-rs` targeting `main`.
3. Complete the Pull Request template checklist.
4. Ensure all GitHub Actions CI checks (Linux, macOS, Windows builds, Trivy, Cargo Audit, SonarCloud) pass green.
5. Participate in the code review discussion.

---

## Community Code of Conduct

Participation in this project is governed by the [**`CODE_OF_CONDUCT.md`**](CODE_OF_CONDUCT.md) (Contributor Covenant v2.1).

---

## Reporting Vulnerabilities

If you discover a security vulnerability in `impacket-rs`, please **do not** open a public issue. See [**`SECURITY.md`**](SECURITY.md) for full vulnerability reporting procedures, SLAs, and safe harbor terms, or contact **nestho@icloud.com** directly.
