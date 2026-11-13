# Impacket-RS: System Architecture & Component Specification

## 1. High-Level Architecture Overview

**Impacket-RS** is engineered as a multi-tier, modular workspace in pure Rust. It separates low-level wire serialization, sans-I/O protocol state machines, and network transports from high-level Active Directory RPC interfaces and operator CLI tooling.

```text
========================================================================================================================
TIER 4: CLI, TOOLING & ECOSYSTEM LAYER (`bins/impacket-rs`, C-ABI, PyO3)
  • 74 Core CLI Subcommands (psexec, wmiexec, secretsdump, getTGT, getST, ticketer, ldapclient, ntlmrelayx, ...)
  • Coercion & ADCS Suites: coerce (EFSR/RPRN/FSRVP/DFSNM), whisker (Shadow Credentials), certreq, adcs (ESC1-ESC15)
  • Machine Output & Graph Integration: --format <text|json|yaml>, --bloodhound (BloodHound CE v5+ export)
  • Embedded Telemetry: High-speed logging (tracing), zero-allocation hex dumpers, and interactive terminal shells
========================================================================================================================
                                                            ▲
                                                            │
========================================================================================================================
TIER 3: HIGH-LEVEL PROTOCOL & INTERFACE CRATES
  • crates/impacket-msrpc   : [MS-SAMR], [MS-LSAT], [MS-SRVS], [MS-SCMR], [MS-TSCH], [MS-RRP], [MS-DRSR], [MS-EFSR],
                              [MS-RPRN], [MS-FSRVP], [MS-DFSNM], [MS-EVEN6], [MS-GKDI]
  • crates/impacket-adcs    : [MS-ICPR] (CertServerRequest), [MS-CSRA] (ICertAdminD2), PKCS#10 CSR, ESC1-ESC15 Scanner
  • crates/impacket-sam     : Offline SAM/SYSTEM/SECURITY regf parser, LSA Secrets, DPAPI, NTDS.dit ESE, WMI ShadowCopy
  • crates/impacket-ldap    : AD LDAP/LDAPS engine, RFC 4511 BER codec, [MS-DTYP] SD/ACL, msDS-KeyCredentialLink
  • crates/impacket-relay   : Async NTLM Relay: HTTP, SMB, LDAP, MSSQL, WinRM/WinRMS, RPC/EPM, SCCM MP/DP, ADCS CES
  • crates/impacket-dcom    : [MS-DCOM] ORPC framing, COMVERSION, DUALSTRINGARRAY, IObjectExporter, WMI Automation
========================================================================================================================
                                                            ▲
                                                            │
========================================================================================================================
TIER 2: SANS-I/O PROTOCOL ENGINES & CRYPTOGRAPHIC PROTOCOLS
  • crates/impacket-auth    : NTLMSSP Type 1/2/3, AV_PAIRs, Channel Binding Tokens (CBT MD5/SHA256), SPNEGO, ccache v4
  • crates/impacket-krb5    : ASN.1 DER, AS-REQ/REP, TGS-REQ/REP, RFC 3962 AES, FAST Armor (RFC 6113), PKINIT (RFC 4556)
  • crates/impacket-smb     : SMB 2.0.2–3.1.1 Negotiate, SessionSetup, TreeConnect, Named Pipes, SMB Direct (RDMA)
  • crates/impacket-dcerpc  : MS-RPCE v5 Bind/Ack, AlterContext, Request/Response, NDR reassembly, Sign/Seal trailers
  • crates/impacket-mssql   : Pure-Rust TDS 7.x/8.0 database client, pre-login TLS negotiation, SQLShell REPL
========================================================================================================================
                                                            ▲
                                                            │
========================================================================================================================
TIER 1: CORE FOUNDATION & NETWORK TRANSPORT LAYER (Zero Dynamic Dependencies)
  • crates/impacket-core    : TransportStream (Direct TCP, IPv6 dual-stack, SOCKS5 / HTTP CONNECT tunnels, TLS),
                              TargetSpec CLI parser, AdCompatProfile, NtStatus/HResult, FileTime, Zeroize types
  • crates/impacket-crypto  : Constant-time pure-Rust crypto: MD4, MD5, SHA-1/256/512, RC4, DES, 3DES, AES-CBC/CTS/GCM,
                              AES-CMAC, HMAC, PBKDF2, Kerberos n-fold key derivation
  • crates/impacket-ndr     : NdrReader, NdrWriter, NdrUnicodeString, RpcSid, RpcUuid, ndr_struct! (5.85M ops/sec)
========================================================================================================================
```

---

## 2. Detailed Crate Specifications & Technical Boundaries

### Tier 1: Core Foundation Layer

#### 1. `crates/impacket-core`
- **Purpose**: Foundational primitives, error representations, target specifications, and universal network transport abstractions.
- **Key Modules**:
  - `transport`: `TransportStream` enum and trait providing transparent asynchronous socket I/O. Supports:
    - Direct IPv4 and IPv6 (`TcpStream`).
    - SOCKS5 proxy tunneling with optional authentication (`tokio-socks`).
    - HTTP `CONNECT` proxy tunneling.
    - Transparent TLS wrapping for LDAPS, WinRMS, and TDS 8.0.
  - `target`: `TargetSpec` parser supporting `[[domain/]username[:password]@]<host|ipv4|[ipv6]>[:port]`, `-hashes LM:NT`, `-k`, `-no-pass`, and global `--proxy`.
  - `error`: Complete strongly-typed enumerations for `NtStatus` (NTSTATUS), `HResult` (HRESULT), and protocol-level errors with human-readable descriptions.
  - `time`: `FileTime` conversions between Windows 64-bit 100ns intervals and standard ISO 8601 / `chrono::DateTime<Utc>`.
  - `security`: `SecretString`, `NtlmHashes`, and `SecretBytes` implementing `zeroize::ZeroizeOnDrop` for automatic credential purging from RAM.

#### 2. `crates/impacket-crypto`
- **Purpose**: Constant-time, pure-Rust cryptographic algorithms required for Windows protocols without relying on platform OpenSSL or dynamic C libraries.
- **Algorithms**:
  - Hashing: MD4, MD5, SHA-1, SHA-256, SHA-512.
  - Message Authentication: HMAC-MD5, HMAC-SHA1, HMAC-SHA256, AES-CMAC.
  - Ciphers: RC4, Single-DES (DES-56 ECB/CBC), 3DES, AES-128/256 (ECB, CBC, CTS-CS3, GCM, CCM).
  - Key Derivation: PBKDF2, Kerberos RFC 3961 `n-fold` and `DK(key, usage)`.
  - Checksums: CRC32, RFC 4120 Kerberos unkeyed & keyed checksums.

#### 3. `crates/impacket-ndr`
- **Purpose**: Network Data Representation (NDR) serialization and deserialization engine for DCE/RPC.
- **Key Features**:
  - `NdrReader` & `NdrWriter`: Zero-allocation little-endian byte readers and writers with bounds-checking.
  - Core Primitive Types: `NdrUnicodeString`, `RpcSid` (MS-DTYP 2.4.2), `RpcUuid` / `GUID`, `RpcContextHandle`.
  - `ndr_struct!` Macro: Declarative compile-time NDR struct definitions achieving **5.85 million ops/sec** (139x faster than Python).

---

### Tier 2: Sans-I/O Protocol Engines

#### 4. `crates/impacket-auth`
- **Purpose**: Authentication protocols, credential representation, and security context negotiation.
- **Key Features**:
  - NTLMSSP: Type 1 (Negotiate), Type 2 (Challenge) parsing `AV_PAIR` target info, and Type 3 (Authenticate) calculation for LMv1, NTLMv1, NTLMv2, and NTLM2 Session Response.
  - Channel Binding Tokens (CBT): MD5 and SHA-256 `tls-server-end-point` hash computation and injection into `MsvAvChannelBindings` (satisfying Windows Server 2022/2025 LDAP Channel Binding requirements).
  - SPNEGO: ASN.1 DER `NegTokenInit` and `NegTokenResp` state machine wrapping NTLMSSP and Kerberos mechanisms.
  - Ticket Formats: MIT Kerberos `.ccache` v4 and Windows Mimikatz `.kirbi` (KRB-CRED) bidirectional parser and writer.

#### 5. `crates/impacket-krb5`
- **Purpose**: Kerberos v5 protocol implementation per RFC 4120, RFC 3962, RFC 4556, and RFC 6113.
- **Key Features**:
  - Message Codecs: ASN.1 DER encoders and decoders for `AS-REQ`, `AS-REP`, `TGS-REQ`, `TGS-REP`, `AP-REQ`, `AP-REP`, and `KRB-ERROR`.
  - Encryption Systems: RFC 3962 AES-128-CTS-HMAC-SHA1-96 (etype 17) and AES-256-CTS-HMAC-SHA1-96 (etype 18), RC4-HMAC (etype 23).
  - Kerberos Extensions:
    - S4U2self & S4U2proxy ([MS-SFU]).
    - User-to-User (U2U) authentication (`enc-tkt-in-skey`).
    - Flexible Authentication Secure Tunneling (FAST Armor, RFC 6113) with `PA-FX-FAST` and `KRB-FX-CF2` key combining.
    - PKINIT (RFC 4556): Certificate-based pre-authentication using RSA/ECDSA keys and CMS `AuthPack`.
  - Ticket Manipulation: Golden, Silver, and Diamond ticket forgery engine (`ticketer`).

#### 6. `crates/impacket-smb`
- **Purpose**: Client implementation of SMB 2.0.2, 2.1, 3.0, 3.0.2, and 3.1.1, plus SMB Direct (RDMA).
- **Key Features**:
  - Commands: `NEGOTIATE`, `SESSION_SETUP`, `LOGOFF`, `TREE_CONNECT`, `TREE_DISCONNECT`, `CREATE`, `CLOSE`, `READ`, `WRITE`, `IOCTL`, `QUERY_DIRECTORY`, `QUERY_INFO`, `SET_INFO`.
  - Security: AES-CMAC and HMAC-SHA256 message signing; AES-128-GCM, AES-256-GCM, and AES-128-CCM transparent session encryption.
  - Transports: Direct TCP/445, NetBIOS TCP/139, named pipes (`\PIPE\<name>`), and RDMA SMB Direct (`[MS-SMBD]`).

#### 7. `crates/impacket-dcerpc`
- **Purpose**: DCE/RPC v5 transport, framing, and PDU reassembly.
- **Key Features**:
  - PDU Framing: `Bind`, `BindAck`, `AlterContext`, `AlterContextResp`, `Request`, `Response`, `Fault`.
  - Multi-PDU Fragment Assembly: Handles fragmented RPC responses across arbitrary pipe buffer boundaries.
  - Transports: Named pipes over SMB (`ncacn_np`), dynamic TCP (`ncacn_ip_tcp`), and HTTP (`ncacn_http`).
  - Endpoint Mapper (EPM): `ept_lookup` client with 5-floor Tower decoder.

#### 8. `crates/impacket-mssql`
- **Purpose**: Pure-Rust Tabular Data Stream (TDS 7.x/8.0) protocol client.
- **Key Features**:
  - Authentication: SQL Server Authentication and Windows Integrated NTLM / Kerberos SSPI authentication.
  - Queries: Batch query execution, RPC function execution (`sp_executesql`, `xp_cmdshell`), and tabular row decoding.
  - Pre-Login: Pre-login packet negotiation, encryption requirement auditing (`ENCRYPT_OFF`, `ENCRYPT_ON`, `ENCRYPT_REQ`), and MARS support.

---

### Tier 3: High-Level Feature Crates

#### 9. `crates/impacket-msrpc`
- **Purpose**: High-level Microsoft RPC protocol interfaces.
- **Supported Interfaces**:
  - `samr`: `[MS-SAMR]` Security Account Manager (users, groups, aliases, password changes).
  - `lsat` / `lsad`: `[MS-LSAT]` / `[MS-LSAD]` Local Security Authority (SID/RID lookup, account rights).
  - `srvs`: `[MS-SRVS]` Server Service (share enumeration, session listing, open file listing).
  - `scmr`: `[MS-SCMR]` Service Control Manager (create, start, stop, query, delete services).
  - `tsch`: `[MS-TSCH]` Task Scheduler (register, run, list, delete scheduled tasks).
  - `rrp`: `[MS-RRP]` Remote Registry (open, query, create, delete, dump, export keys/values).
  - `drsuapi`: `[MS-DRSR]` Directory Replication Service (live DCSync credential replication).
  - `dfsnm`: `[MS-DFSNM]` Distributed File System Namespace Management.
  - `even6`: `[MS-EVEN6]` Windows Event Log Remoting Protocol v6.0.
  - `efsr`: `[MS-EFSR]` Encrypting File System Remote Protocol (coercion via `EfsRpcOpenFileRaw`).
  - `rprn`: `[MS-RPRN]` Print System Remote Protocol (coercion via `RpcRemoteFindFirstPrinterChangeNotificationEx`).
  - `fsrvp`: `[MS-FSRVP]` File Server Resource VSS Protocol (coercion via `IsPathSupported`).
  - `gkdi`: `[MS-GKDI]` Group Key Distribution Protocol (Windows LAPS v2 group key retrieval).

#### 10. `crates/impacket-adcs` *(New in v0.4.0)*
- **Purpose**: Active Directory Certificate Services manipulation and auditing.
- **Key Features**:
  - `[MS-ICPR]`: Interface `91AE6020-9E3C-11CF-8D7C-00AA00C091BE` v0.0 (`CertServerRequest`).
  - `[MS-CSRA]`: Interface `D99E6E74-FC88-11D0-B498-00A0C90312F3` v0.0 (`ICertAdminD2`).
  - Vulnerability Auditor: Full enumeration and vulnerability detection for **ESC1 through ESC15**.
  - PKCS#10 CSR Engine: Generate certificate requests with subject alternative names (SAN).
  - Certificate Issuance: Submit and retrieve certificates over RPC or HTTP Enrollment endpoints.

#### 11. `crates/impacket-ldap`
- **Purpose**: Active Directory LDAP/LDAPS query, administration, and access control engine.
- **Key Features**:
  - BER Codec: RFC 4511 message encoding/decoding (Bind, Search, Modify, Add, Delete).
  - Security Descriptors: `[MS-DTYP]` 2.4.6 security descriptor parser and evaluator (DACL, SACL, Owner, Group).
  - AD Administration: Resource-Based Constrained Delegation (`rbcd`), Owner modification (`owneredit`), Shadow Credentials (`msDS-KeyCredentialLink`), and AD DNS (`dnstool`).
  - Interactive Shell: `LdapShellSession` interactive REPL for directory exploration.

#### 12. `crates/impacket-sam`
- **Purpose**: Offline storage parsing, hive extraction, and credential decryption.
- **Key Features**:
  - Registry Hives: Offline `regf` B-tree parser for `SAM`, `SYSTEM`, and `SECURITY`.
  - Hashes & Secrets: BootKey calculation, RC4/AES-128-CBC local hash decryption, LSA Secrets, Netlogon keys (`NL$KM`), cached credentials (`DCC2`).
  - ESE Database: Extensible Storage Engine (`NTDS.dit`) B-tree parser with PEK decryption for offline domain hash extraction.
  - DPAPI: MasterKey file decryption, DPAPI Blob decryption, and Chrome/Edge credential recovery.
  - Stealth Extraction: WMI `Win32_ShadowCopy` volume snapshot reader for locked files.

#### 13. `crates/impacket-relay`
- **Purpose**: Non-blocking asynchronous multi-protocol NTLM relay engine.
- **Key Features**:
  - Relay Ingestion: HTTP/HTTPS, SMB2, and RPC listening servers capturing NTLMSSP Type 1/3 authentication.
  - Relay Targets: SMB2, LDAP/LDAPS, MSSQL, HTTP/HTTPS, WinRM/WinRMS, RPC/EPM, SCCM, and ADCS CES.
  - Evasion & Stripping: Automatic NTLMSSP MIC stripping, Channel Binding token removal, and SMB signing bypass.
  - Multiplexer: Embedded SOCKS5 proxy server holding relayed sessions with live terminal interaction (`SQLShell`).

---

## 3. High-Level Engineering Roadmap & Milestones

| Milestone | Target | Focus | Primary Deliverables |
| :--- | :--- | :--- | :--- |
| **v0.1.1** | *Nov 2026* *(Done)* | Parity & Help Engine | 74 subcommands, Python-Impacket-style help engine, static binary CI releases. |
| **v0.2.0** | *Q1 2027* | Transport Hardening & Stealth | `TransportStream` SOCKS5/HTTP proxying, IPv6 dual-stack, LDAP CBT/Signing, `regsecrets`, WMI ShadowCopy. |
| **v0.3.0** | *Q2 2027* | Coercion & Relay Multiplexer | `coerce` subcommand (EFSR/RPRN/FSRVP/DFSNM), RPC/WinRMS/SCCM/ADCS relay targets, SOCKS multiplexer. |
| **v0.4.0** | *Q3 2027* | ADCS, Shadow Credentials & LAPS v2 | `impacket-adcs` (ESC1-ESC15), PKINIT auth, `whisker` (msDS-KeyCredentialLink), `[MS-GKDI]` LAPS v2. |
| **v1.0.0** | *Q4 2027* | Ecosystem, C2 Bindings & Packaging | BloodHound CE JSON export, C ABI / PyO3 bindings, official Kali/Debian package, API stability lock. |

---

## 4. Quality Gate & Continuous Integration Standard

Every pull request and merge into `dev` or `main` must strictly satisfy:
```bash
cargo check --workspace --all-targets   # 0 warnings
cargo test --workspace                  # 100% test pass rate
cargo clippy --workspace --all-targets  # clean
cargo audit                             # 0 CVEs
```
Release tags (`v*`) are cut exclusively from `main` and trigger automated multi-platform matrix builds for:
- Linux x86_64 (`gnu` and static `musl`)
- macOS Apple Silicon (`aarch64-apple-darwin`) and Intel (`x86_64-apple-darwin`)
- Windows x86_64 (`x86_64-pc-windows-msvc`)
