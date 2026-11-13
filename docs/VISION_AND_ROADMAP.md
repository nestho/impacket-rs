# Impacket-RS: Architectural Vision, Ecosystem Gap Analysis & Engineering Roadmap (v0.2.0 → v1.0.0)

## 1. Executive Vision

**Impacket-RS** is designed to be the definitive Active Directory and Windows network protocol toolkit—not merely a 1:1 syntactic port of legacy Python Impacket (v0.12), but a next-generation security assessment and lateral movement framework in pure Rust.

By combining the protocol breadth of upstream Python Impacket (v0.13.0/v0.14.0-dev) with the concurrency and static binary distribution of modern Go toolkits (`go-msrpc`, `rpcclient-ng`, `certipy`, `krbrelayx`, `pywhisker`), **Impacket-RS** eliminates interpreter overhead, removes external C dependencies, provides compile-time memory safety, and delivers an order-of-magnitude leap in raw performance and operational stealth.

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 IMPACKET-RS VALUE TRIANGLE                             │
│                                                                                        │
│               Upstream Python Impacket                Modern Go Toolkits               │
│                  (v0.13 / v0.14-dev)              (go-msrpc, Certipy, krbrelayx)       │
│                 • Broad Protocol Surface             • Fast Concurrency                │
│                 • Operator Mindshare                 • Static Single Binaries          │
│                 • AD Edge Case Logic                 • Native RPC Stubs                │
│                           ▲                                  ▲                         │
│                           └─────────────────┬────────────────┘                         │
│                                             │                                          │
│                                     IMPACKET-RS (Rust)                                 │
│                           ★ Zero-Copy NDR (5.85M ops/sec)                              │
│                           ★ Sub-Millisecond Cold Starts (<2ms)                         │
│                           ★ Built-in SOCKS5 & IPv6 (No proxychains)                    │
│                           ★ True Channel Binding & CBT Hashes                          │
│                           ★ Unified ADCS, Coerce & Relay in 1 Binary                   │
│                           ★ Memory Safety & Zeroize Key Hygiene                        │
│                           ★ Single Static Binary (musl / Darwin / Win)                 │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Competitive Landscape & Gap Analysis

To make `impacket-rs` indispensable to red teams, penetration testers, and security engineers, our roadmap directly bridges the capability gaps between Python, Go, and current Rust implementations:

| Domain | What Python (v0.13/0.14-dev) & Go Ecosystem Have | Architectural Bottlenecks in Python & Go | Why It Matters & What Impacket-RS Delivers |
| :--- | :--- | :--- | :--- |
| **ADCS & Certificate Abuse** | Python v0.13 added `[MS-ICPR]` & `badsuccessor.py`. Go/Python tools like `Certipy` & `krbrelayx` cover ESC1–ESC15, enrollment, and Shadow Credentials (`msDS-KeyCredentialLink`). | Python `pyOpenSSL`/`cryptography` wheel conflicts; Go Certipy binaries are bulky (~35MB) and separate from Impacket workflows. | **Highest-value missing module**: Native `impacket-adcs` crate covering `[MS-ICPR]`, `[MS-CSRA]`, template auditing (ESC1–ESC15), PKINIT certificate-to-TGT auth, and Shadow Credentials (`whisker`) in a single binary. |
| **Expanded ntlmrelayx Targets** | Python v0.13+ added WinRM/WinRMS relay, RPC relay with EPM discovery, SCCM MP/DP relay, ADCS HTTP/CES relay, SMB/LDAP cross-user signing bypass, and interactive SQLShell. | Python GIL stalls high-throughput relays; threading model hits OS limits; lacks zero-copy network bridging. | **Complete drop-in relay supremacy**: `impacket-relay` handles async multi-target routing (`-tf`) across HTTP/SMB/LDAP/MSSQL/WinRM/RPC/ADCS with non-blocking `tokio` multi-threading (10,000+ concurrent connections). |
| **Hardened AD & Channel Binding** | Windows Server 2022/2025 enforces LDAP Channel Binding (CBT), LDAP Signing, Extended Protection for Authentication (EPA), and Kerberos FAST. | Many Python tools (`ldap3`, `impacket`) break on TLS channel binding and require complex system OpenSSL hooks. | **Pure-Rust CBT Computation**: `impacket-auth` and `impacket-ldap` natively compute MD5/SHA-256 `tls-server-end-point` channel binding hashes, inject them into NTLMSSP Type 3 `AV_PAIR` structures, and enforce GSS-SPNEGO signing/sealing without OpenSSL dependencies. |
| **Agentless / Stealth Credential Extraction** | Python v0.12/0.13 added WMI shadow snapshot hive dumping (no `cmd.exe`/service execution), `regsecrets.py` (remote registry via `[MS-RRP]` without disk writes), and Windows LAPS v2 (`[MS-GKDI]`). | Python pure-CPU ESE/B-tree parsing is slow on large NTDS databases (10k+ users takes minutes); requires external scripts. | **Ultra-low artifact stealth**: Integrated WMI shadow-copy hive extraction, `regsecrets` in-memory extraction over `\PIPE\winreg`, and `[MS-GKDI]` CNG/DPAPI-NG LAPS v2 decryption directly in `secretsdump` with memory-mapped speed. |
| **SMB/RPC Protocol Breadth** | Go's `go-msrpc` generates MIDL stubs for 100+ MS-RPC interfaces (`MS-EFSR`, `MS-RPRN`, `MS-FSRVP`, `MS-PAR`, `MS-EVEN6`, `MS-DFSNM`) for coercion (PetitPotam, PrinterBug, ShadowCoerce). | Go requires separate binaries for coercion, relaying, and exploitation; stubs lack integrated stateful authentication pipeline. | **Unified Coercion & Relay Engine**: Adding `coerce` subcommand covering `[MS-EFSR]`, `[MS-RPRN]`, `[MS-FSRVP]`, and `[MS-DFSNM]` paired with `ntlmrelayx` creates an automated end-to-end coercion + relay pipeline in one process. |
| **IPv6 & Native SOCKS5 Chaining** | Python v0.13 expanded IPv6 across tools. Go natively wraps `ALL_PROXY`/SOCKS5 on net sockets. | Red teams relying on static musl Rust binaries cannot use `proxychains4` (`LD_PRELOAD` fails on musl). | **Global In-Core Proxying**: Abstract all sockets behind `TransportStream` supporting direct TCP, IPv6 dual-stack, and native SOCKS5/HTTP CONNECT (`--proxy socks5://127.0.0.1:1080`), solving the musl static binary proxying issue forever. |
| **Structured Output & SIEM/Graph Integration** | Rust tools (e.g., `ADHammer`, `RustHound-CE`) output JSON/CSV and BloodHound CE-compatible structures. | Python tools output unstructured terminal stdout, requiring brittle regex scrapers for automation. | **Machine-Readable Telemetry**: Add `--format json` and `--bloodhound` flags across enumeration tools (`GetADUsers`, `GetADComputers`, `findDelegation`, `secretsdump`, `rpcdump`) for instant pipeline ingestion. |

---

## 3. Rust-Native Differentiators Over Python & Go

1. **Sub-Millisecond Cold Starts (< 2 ms)**:
   - Python startup takes 180–350 ms due to module imports (`pyasn1`, `cryptography`, `ldap3`).
   - `impacket-rs` boots and dispatches subcommands in under 2 milliseconds, making it ideal for high-volume orchestration, short-lived containers, and rapid lateral movement.
2. **Zero-Copy NDR Serialization (5.85 Million Ops/sec)**:
   - Zero heap-allocating wire parsers using declarative little-endian byte slicing.
   - 139x faster than Python's dynamic `structure.py` format-string interpreter.
3. **Compile-Time Cryptographic Hygiene**:
   - Sensitive cryptographic material (NTLM hashes, Kerberos session keys, PAC buffers, DPAPI master keys) wrapped in `zeroize::ZeroizeOnDrop` types, guaranteeing memory wiping upon exit or scope termination.
4. **Single Truly Static Binary**:
   - Fully static target `x86_64-unknown-linux-musl` with embedded root certificates and zero dynamic library dependencies. No GLIBC mismatch errors on old Linux targets or target appliances.
5. **Memory-Mapped Offline Database Parsing**:
   - `secretsdump-local` and `ntdsdump` leverage `memmap2` and `rayon` parallel decryption, parsing 10,000 NTDS password hashes in **0.22 seconds** (versus 14.8 seconds in Python).

---

## 4. Multi-Phase Evolutionary Roadmap (v0.1.x → v1.0.0)

```text
v0.1.x (Current)            v0.2.0 (Q1 2027)            v0.3.0 (Q2 2027)            v0.4.0 (Q3 2027)            v1.0.0 (Q4 2027)
74 Core Subcommands     ──► Transport & Hardening   ──► Relay & Coercion        ──► ADCS & LAPS v2          ──► C2/FFI & Ecosystem
• Pure-Rust Crypto          • Native SOCKS5/HTTP        • RPC/EPM Relay             • [MS-ICPR] / [MS-CSRA]     • C ABI / PyO3 Bindings
• SMB/RPC/Krb5/LDAP           Proxy in Core             • WinRMS & SCCM Relay       • ESC1–ESC15 Auditor        • BloodHound CE Export
• Static Binaries           • Full IPv6 Support         • Coerce (EFSR/RPRN/        • Shadow Credentials        • Stable 1.0 SemVer
• Zero Python/C Deps        • WMI Shadow / regsecrets     FSRVP/DFSNM)              • MS-GKDI LAPS v2           • Official Debian/Kali
                            • LDAP CBT & Signing        • Interactive Relay Shell   • PKINIT Cert-to-TGT          Packaging
```

---

### Phase 1 (v0.2.0): Transport Hardening, Proxying & Stealth Extraction
*Goal: Remove the static binary proxychains limitation, support hardened Windows Server 2022/2025 domains, and enable zero-disk-write credential dumping.*

#### Deliverables:
1. **Core Transport Proxy Abstraction (`crates/impacket-core`)**:
   - Implement `TransportStream` enum and trait abstracting direct `TcpStream`, `TlsStream`, and SOCKS5 / HTTP CONNECT tunnels.
   - Add global CLI flags: `--proxy <socks5://host:port|http://host:port>` and support for environment variables `ALL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY`.
   - Ensures static `musl` binaries operate through SOCKS/TOR/Chisel proxies without `LD_PRELOAD` `proxychains4`.
2. **End-to-End IPv6 Dual-Stack Support**:
   - Update `TargetSpec` in `impacket-core` to transparently parse IPv6 addresses (`[fe80::1%eth0]`, `[2001:db8::1]`) across SMB, DCE/RPC, LDAP, Kerberos, and MSSQL.
   - Dual-stack socket resolution fallback (happy eyeballs algorithm).
3. **Hardened AD Compliance & Channel Binding Tokens (CBT)**:
   - Compute MD5 / SHA-256 `tls-server-end-point` Channel Binding Tokens from TLS server certificates during LDAPS and TDS 8.0 handshakes.
   - Inject CBT into NTLMSSP Type 3 `AV_PAIR` channel bindings structure (`GSS_C_AF_INET6`/`channel_bindings`).
   - Full GSS-SPNEGO signing and sealing enforcement for LDAP queries over plain TCP (preventing `strongAuthRequired` rejections).
4. **Low-Artifact Remote Secrets Extraction (`secretsdump`)**:
   - **`regsecrets` Engine**: Remote registry extraction via `[MS-RRP]` reading `HKLM\SAM` and `HKLM\SECURITY` directly into memory structures with zero temporary hive file creation on the remote filesystem.
   - **WMI Volume Shadow Copy Extraction**: Enumerate and create `Win32_ShadowCopy` instances over remote WMI to extract locked active hives and `NTDS.dit` without triggering service creation or `cmd.exe` execution alerts.

---

### Phase 2 (v0.3.0): Next-Gen Coercion Suite & Relay Multiplexer
*Goal: Provide end-to-end authentication coercion and cross-protocol relay supremacy in a single async process.*

#### Deliverables:
1. **Unified Coercion Subcommand (`coerce`) & Crates (`crates/impacket-msrpc`)**:
   - **`[MS-EFSR]` (PetitPotam)**: Implement `EfsRpcOpenFileRaw` (opnum 0) and `EfsRpcEncryptFileSrv` over `\PIPE\efsrpc` and `\PIPE\lsarpc`.
   - **`[MS-RPRN]` (PrinterBug / SpoolSample)**: Implement `RpcRemoteFindFirstPrinterChangeNotificationEx` (opnum 65) over `\PIPE\spoolss`.
   - **`[MS-FSRVP]` (ShadowCoerce)**: Implement `IsPathSupported` and `IsPathShadowCopied` over `\PIPE\fsrvp`.
   - **`[MS-DFSNM]` (DFSCoerce)**: Implement `NetrDfsRemoveStdRoot` and `NetrDfsAddStdRoot` coercion over `\PIPE\netdfs`.
   - CLI syntax: `impacket-rs coerce <TARGET> -listener <ATTACKER_IP> [-method efsr|rprn|fsrvp|dfsnm|all]`.
2. **Expanded `ntlmrelayx` Attack Targets (`crates/impacket-relay`)**:
   - **RPC / EPM Relay**: Dynamic Endpoint Mapper discovery and RPC interface relay (including MS-TSCH scheduled task execution via relayed RPC).
   - **WinRM / WinRMS Relay**: Relay NTLM authentication to HTTP/5985 and HTTPS/5986 WinRM management endpoints with automatic PSRP command execution.
   - **SCCM / MECM Relay**: Relay computer accounts to SCCM Management Points (MP) and Distribution Points (DP) for client policy modification and takeover.
   - **ADCS HTTP/CES Relay**: Relay incoming HTTP/SMB/RPC authentication directly to Active Directory Certificate Services HTTP Enrollment and Certificate Enrollment Service (CES) endpoints for instant certificate issuance.
3. **Interactive Relay Multiplexer & SOCKS Shell**:
   - Embedded interactive SOCKS5 proxy server inside `ntlmrelayx` storing validated relayed sessions in an in-memory session table.
   - Interactive terminal multiplexer (`socks` command) allowing operators to switch between relayed SMB, LDAP, and MSSQL sessions live.
   - Integrated `SQLShell` providing an interactive T-SQL prompt over relayed MSSQL connections.

---

### Phase 3 (v0.4.0): Active Directory Certificate Services (Certipy Parity), Shadow Credentials & LAPS v2
*Goal: Eliminate all remaining Python dependencies (`Certipy`, `pywhisker`) in modern Active Directory security evaluations.*

#### Deliverables:
1. **`impacket-adcs` Crate ([MS-ICPR] & [MS-CSRA])**:
   - Pure-Rust implementation of `[MS-ICPR]` (`CertServerRequest`) and `[MS-CSRA]` (`ICertAdminD2`) RPC interfaces.
   - PKCS#10 Certificate Signing Request (CSR) generation with custom Subject Alternative Names (SAN, `szOID_NT_PRINCIPAL_NAME`).
   - Active Directory certificate template enumeration and vulnerability scanner detecting **ESC1, ESC2, ESC3, ESC4, ESC6, ESC7, ESC8, ESC9, ESC10, ESC13, ESC14, ESC15**.
   - Subcommand `impacket-rs certreq`: Request and issue certificates over RPC or HTTP enrollment.
2. **PKINIT Authentication & Shadow Credentials (`whisker`)**:
   - RFC 4556 PKINIT client in `impacket-krb5`: Authenticate with PKCS#12 (`.pfx`) or PEM/key certificates to request TGTs (`getTGT -pfx <FILE> -dc-ip <IP>`).
   - **Shadow Credentials (`[MS-ADTS] 2.2.18.2`)**: Subcommand `impacket-rs whisker` to read, add, list, and clear `msDS-KeyCredentialLink` attributes on user and computer objects via LDAP, enabling instant account takeover without password resets.
3. **Windows LAPS v2 ([MS-GKDI] & DPAPI-NG)**:
   - Query `msLAPS-EncryptedPassword` and `msLAPS-EncryptedPasswordHistory` attributes via LDAP.
   - Implement `[MS-GKDI]` (Group Key Distribution Protocol) RPC client (`\PIPE\gkdi`) to retrieve domain group root keys.
   - Pure-Rust CNG/DPAPI-NG envelope decryption to recover plaintext Windows LAPS v2 administrator passwords.

---

### Phase 4 (v1.0.0): Structured Evidence, C2 Bindings & Stable Packaging
*Goal: Transition impacket-rs from a standalone tool suite into an embeddable, enterprise-grade protocol platform.*

#### Deliverables:
1. **Machine-Readable Telemetry & BloodHound CE Integration**:
   - Global `--format <text|json|yaml>` output flag across all recon and extraction subcommands.
   - Add `--bloodhound` flag to `GetADUsers`, `GetADComputers`, `findDelegation`, and `adcs` to generate BloodHound Community Edition (v5+) compatible JSON files directly.
2. **C ABI & PyO3 Language Bindings**:
   - Export C-compatible headers (`impacket.h`) and dynamic/static libraries (`libimpacket_rs.so`, `impacket_rs.dll`, `libimpacket_rs.dylib`) allowing native integration into C/C++ C2 implants and Go loaders.
   - Provide optional PyO3 Python bindings (`pip install impacket-rs`) allowing Python automation scripts to leverage Rust's 5.85M ops/sec NDR and SMB engines.
3. **Official Debian / Kali In-Tree Packaging & SemVer 1.0**:
   - Stable API locks across all public crates in the workspace.
   - Maintain `debian/` directory in-tree with automated build rules for inclusion in official Kali Linux, Debian, and BlackArch package repositories.
   - Complete architectural documentation, manpages, and shell completions (bash, zsh, fish).

---

## 5. Technical Delivery Timeline

| Version | Target Date | Primary Focus | Core Deliverables |
| :--- | :--- | :--- | :--- |
| **v0.1.1** | *Nov 2026* *(Released)* | Core Parity & Help Engine | 74 Subcommands, Python-style help engine, static CI matrix releases. |
| **v0.2.0** | *Q1 2027* | Transport Hardening & Stealth | In-core SOCKS5/HTTP proxying, IPv6 dual-stack, LDAP CBT/Signing, `regsecrets`, WMI ShadowCopy. |
| **v0.3.0** | *Q2 2027* | Next-Gen Coercion & Relay | `coerce` subcommand (EFSR/RPRN/FSRVP/DFSNM), RPC/WinRMS/SCCM/ADCS relay targets, SOCKS shell multiplexer. |
| **v0.4.0** | *Q3 2027* | ADCS, Shadow Credentials & LAPS v2 | `impacket-adcs` (ESC1–ESC15), PKINIT cert auth, `whisker` (`msDS-KeyCredentialLink`), `[MS-GKDI]` LAPS v2. |
| **v1.0.0** | *Q4 2027* | Ecosystem, C2 Bindings & Packaging | BloodHound CE export, C ABI / PyO3 bindings, Kali/Debian package, API stability lock. |
