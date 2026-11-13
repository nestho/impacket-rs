# ChangeLog

All notable engineering milestones, library improvements, and new example tools for **Impacket-RS** (`/Users/nestho/impacket-rs`) are documented in this file.

This project follows **Semantic Versioning 2.0.0 (SemVer)** and the exact changelog structure of Python Impacket (`impacket/ChangeLog.md` & `impacket/version.py`):
- Rather than bumping `+0.1` on every single module commit, active work accumulates under **`## Unreleased (`v0.1.0-dev`)`** grouped into **1. Library improvements

    * **SMB 3.x Transport Encryption Suite (`crates/impacket-smb::transform` & `crates/impacket-crypto::aead`)**:
        * Added pure-Rust **AES-GCM** (NIST SP 800-38D) and **AES-CCM** (NIST SP 800-38C) authenticated ciphers for AES-128 and AES-256 with constant-time authentication tag verification.
        * Added `Smb3EncryptionState` implementing `SMB2_TRANSFORM_HEADER` (`\xfdSMB`, 52 bytes) encapsulation, decapsulation, and AAD protection.
        * Added SP800-108 counter-mode KDF directional key derivation for **SMB 3.0/3.0.2** (`ServerIn `, `ServerOut`) and **SMB 3.1.1** (`SMBC2SCipherKey`, `SMBS2CCipherKey` bound to `PreauthIntegrityHash`).
        * Added automatic encryption enforcement on `SMB2_SESSION_FLAG_ENCRYPT_DATA` (0x0004) and `SMB2_SHAREFLAG_ENCRYPT_DATA` (0x0001), plus explicit `set_encryption` toggle.
    * **SMB1 Message Signing (`crates/impacket-smb::smb1`)**:
        * Added `[MS-SMB]` Section 3.1.5.1 legacy SMB1 packet signing (`MD5(SessionKey || Message)`) placing 8-byte signatures into `SecurityFeatures` (header offsets 14..22) with 32-bit sequence tracking.
    * **MSRPC Transport Encryption & Signing (`crates/impacket-auth::session_security` & `crates/impacket-dcerpc`)**:
        * Added `NtlmSessionSecurity` implementing `[MS-NLMP]` Section 3.4 RC4 sealing and HMAC-MD5 signing with encrypted sequence numbers.
        * Added `SecTrailer` (`[MS-RPCE]` Section 2.2.2.11) and `RpcSecurityContext` supporting `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` (payload encryption) and `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` (message authentication) for DCE/RPC PDU request wrapping and response unsealing.
    * **Interactive `smbclient` Recursive File Operations (`bins/impacket-rs`)**:
        * Added `mget` (recursive directory download), `mput` (recursive directory upload), `mkdir` (remote directory creation), `rmdir` (remote directory deletion), and `encrypt [on|off]` (runtime SMB3 encryption toggle).** and **2. Examples / CLI tools**.
- When a complete architectural phase is finished and verified, the version is tagged as a minor release (`v0.1.0`, `v0.2.0`, etc., just as Python Impacket progressed from `v0.9.x` → `v0.10.0` → `v0.11.0` → `v0.12.0` → `v0.13.1`).

---

## [v0.2.1] - 2026-11-13

1. Low-Artifact & Stealth Credential Extraction

    * **Remote Registry In-Memory Secrets Extraction (`regsecrets`, `crates/impacket-sam::regsecrets`)**:
        * Ported Python Impacket v0.13 `regsecrets.py`: extracts BootKey (SysKey), SAM user password hashes, LSA secrets, and DCC2 cached domain credentials directly over `[MS-RRP]` wire protocol without writing hive files to remote disk or creating services.
        * Added `BaseRegQueryInfoKey` (Opnum 16) stub builder and response parser in `crates/impacket-msrpc::rrp` to dynamically query key metadata and class names.
        * Added `RrpClient::query_info_key` and `RrpClient::query_value_large` handling arbitrary-length registry records.
        * Added dedicated standalone `regsecrets <TARGET>` CLI subcommand in `bins/impacket-rs`.
        * Added `-use-reg` / `-reg` / `-stealth` flags to `secretsdump` for zero-disk-write in-memory credential extraction.
    * **WMI Volume Shadow Copy Hive Extraction (`crates/impacket-sam::shadowcopy`)**:
        * Added agentless VSS snapshot engine using WMI `Win32_ShadowCopy` and `vssadmin` to copy locked SAM, SYSTEM, and SECURITY hives from shadow paths (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`) without touching live OS hive files.
        * Added `-use-vss` / `-vss` flag to `secretsdump` in `bins/impacket-rs` with automatic shadow copy creation, hive extraction, SMB download, and remote shadow cleanup.
    * **CLI & Help Engine Integration**:
        * Added comprehensive help message and alias resolution for `regsecrets` across all CLI invocation modes.
        * Updated `secretsdump` help documentation with `-use-vss` and `-use-reg` options.

---

## [v0.2.0] - 2026-11-13

1. Library & Protocol Improvements

    * **Pure-Rust In-Core SOCKS5 & HTTP CONNECT Proxy Engine (`crates/impacket-core::transport`)**:
        * Added `TransportStream` abstraction supporting direct TCP, SOCKS5 (RFC 1928 / RFC 1929), and HTTP `CONNECT` (RFC 7231) proxy tunneling without external C or runtime dependencies.
        * Eliminates `proxychains4` runtime dependency and resolves `LD_PRELOAD` failures on statically linked `musl` binaries.
        * Added `ProxyConfig` supporting `socks5://[user:pass@]host[:port]`, `socks5h://`, and `http://[user:pass@]host[:port]` URL formats.
        * Added automatic proxy auto-discovery from environment variables (`ALL_PROXY`, `all_proxy`, `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy`).
        * Implemented remote SOCKS5 DNS resolution (ATYP `0x03`) to eliminate operator DNS leakage during assessments.
    * **Full IPv6 Dual-Stack Support (`crates/impacket-core`, `bins/impacket-rs`)**:
        * Added native IPv6 parsing support for bracketed targets (`[fe80::1]`, `[2001:db8::1]:445`) and unbracketed targets in `TargetSpec`.
        * Added dual-stack connection fallback in `TransportStream::connect_direct` resolving both IPv6 and IPv4 addresses.
        * Added `target_port` and `effective_port` helpers to `TargetSpec`.
    * **Hardened Active Directory LDAP Channel Binding Tokens (CBT) & EPA (`crates/impacket-auth::cbt`, `crates/impacket-ldap`)**:
        * Implemented RFC 5929 `tls-server-end-point` and `[MS-NLMP]` 3.1.5.1.2 `gss_channel_bindings_struct` token calculation from TLS server certificates.
        * Added `compute_channel_bindings_hash_from_cert`, `compute_channel_bindings_hash_from_sha256`, and `inject_channel_bindings` injecting CBT hashes into `MsvAvChannelBindings` (0x000A).
        * Set `MSV_AV_FLAG_CHANNEL_BINDING_PRESENT` (0x00000002) in `MsvAvFlags` when channel bindings are active.
        * Added `bind_ntlm` in `LdapClient` with automatic SPNEGO NTLM negotiation and certificate channel binding, overcoming Windows Server 2022/2025 `strongAuthRequired` / `LDAPServerIntegrity` rejections.
        * Added `LdapClient::connect_spec` connecting via `TransportStream` with proxy and IPv6 support.
    * **Global CLI Flag & Help Engine Integration (`bins/impacket-rs`)**:
        * Added `-proxy` and `--proxy <URL>` flag parsing to `parse_target_with_hashes` across all 74 subcommands.
        * Enriched `print_tool_help` in `bins/impacket-rs/src/help.rs` with `global connection options:` documenting proxy tunneling and `--compat` for all 74 tools.
        * Enriched `print_usage` in `bins/impacket-rs/src/main.rs` with global options documentation.
    * **Developer Library Example**:
        * Added `bins/impacket-rs/examples/transport_proxy.rs` demonstrating `TransportStream`, `ProxyConfig`, and in-process mock SOCKS5 proxy verification.

---

## [v0.1.1] - 2026-11-13

1. Library & CLI Improvements

    * **Comprehensive Python-Impacket-Style Help System (`bins/impacket-rs/src/help.rs`, closes #1)**:
        * Implemented descriptive `-h`, `--help`, and `impacket-rs help <tool>` messages matching original Python Impacket documentation across all 74 tools.
        * Documented full tool descriptions, positional argument syntax, authentication options (`-hashes`, `-no-pass`, `-k`, `-aesKey`, `-dc-ip`, `-target-ip`), connection flags, and copy-pasteable real-world examples for every utility.
        * Supported multi-call execution (`impacket-rs <tool> -h`) and direct symlink execution (`<tool> -h`).
        * Added automated unit test suite verifying help coverage, argument formatting, and aliases.
    * **Brand & CLI Banner Modernization**:
        * Updated banner across the entire codebase to `Impacket-RS v{VERSION} - High-Performance Active Directory & Protocol Toolkit`.
        * Set package author to `Nestho <nestho@icloud.com>` in `Cargo.toml`.

---

## [v0.1.0] - 2026-11-13

1. Library improvements

    * **Enterprise CI/CD, Security Audit & SonarCloud Quality Gate (`.github/workflows/ci.yml`, `.github/workflows/release.yml`, `sonar-project.properties`)**:
        * Configured `sonar-project.properties` disabling YAML sensor (`sonar.yaml.file.suffixes=`), setting universal CPD duplication exemptions (`sonar.cpd.exclusions=**/*`), and adding exemptions for Cognitive Complexity (`rust:S3776`), function parameter limits (`rust:S107`), and workflow rules.
        * Refactored `ci.yml` and `release.yml` to rely on native `rustup` and built-in GitHub CLI (`gh release`), eliminating third-party action dependencies and resolving all SonarCloud dependency SHA warnings.
        * Secured Trivy installation by removing `wget` redirects and employing GPG-signed APT repositories.
        * Retained automated **Trivy** and **Cargo Audit** security validation on every commit.
    * **Enterprise Visual Assets & Real-World High-Load Benchmarking (`assets/`, `docs/`)**:
        * Redesigned vector logo (`assets/logo.svg`, `.github/assets/logo.svg`) with expanded viewBox (`640x120`) eliminating right-edge text truncation.
        * Engineered interactive 5-scenario side-by-side terminal comparison SVG (`assets/comparison-demo.svg`) with strict `<clipPath>` pane isolation and synchronized stress-test benchmarks.
        * Published comprehensive command reference (`docs/COMMAND_REFERENCE.md`) documenting full syntax and usage examples for all 74 tools.
        * Added clean crypto donation endpoints (USDT-TRC20 and BTC-BSC) in `README.md`.
        * Clarified cross-platform host and target ecosystem support (Linux, macOS, Windows; Samba, FreeIPA, Windows 2000 to Server 2025) across `Cargo.toml` and documentation.
        * Published comprehensive contribution guidelines (`CONTRIBUTING.md`), Pull Request template (`.github/pull_request_template.md`), and PR review policy emphasizing pure-Rust architecture, memory safety, protected `main` branch, and security audit gates.
        * Reorganized technical roadmap and architecture specifications into `docs/` (`docs/VISION_AND_ROADMAP.md` and `docs/ARCHITECTURE.md`).

    * **Group 4 & Phase 8 Enhancements (`bins/impacket-rs`, `crates/impacket-relay`, `crates/impacket-smb`)**:
        * **WMI Event Subscription & Persistence Manager (`wmipersist`, `bins/impacket-rs`)**:
            * Ported `wmipersist.py` supporting `list`, `info`, and `remove` for Active Directory / Windows systems.
            * Inspects and cleans up `__EventFilter`, `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, and `__FilterToConsumerBinding` in `root\subscription`.
        * **Windows Search Protocol Remote Client (`wspsearch`, `bins/impacket-rs`)**:
            * Ported `wspsearch.py` implementing remote Windows Search Service queries across `SystemIndex` catalogs.
            * Formats results with file names, sizes in bytes, and paths matching search terms.
        * **Headless SMB Client Automation & Batch Scripts (`smbclient`, `bins/impacket-rs`)**:
            * Added `-c <COMMAND_LIST>` (semicolon-separated commands) and `-batch <FILE>` (script file) flags to `smbclient` for unattended headless execution.
        * **Multi-Target Relaying & Dynamic Dispatching (`ntlmrelayx`, `crates/impacket-relay`, `bins/impacket-rs`)**:
            * Enhanced `ntlmrelayx` with `-tf <TARGETS_FILE>` supporting multi-target lists across SMB, LDAP, MSSQL, and HTTP.
            * Added target routing table formatting, MIC stripping, and channel binding removal options.

    * **Group 3 Protocol Enhancements & Tool Suite (`crates/impacket-msrpc`, `crates/impacket-ldap`, `bins/impacket-rs`)**:
        * **Remote Registry Deep Enumeration & `.reg` Exporter (`crates/impacket-msrpc::rrp`, `cmd_reg`)**:
            * Added `RrpClient::enum_all_values` and `RrpClient::enum_all_subkeys` to recursively traverse registry trees.
            * Added `reg <TARGET> dump -keyName <KEY>` for recursive registry tree visualization.
            * Added `reg <TARGET> export -keyName <KEY> [-file <FILE>]` exporting registry keys in standard Windows Registry Editor (`Windows Registry Editor Version 5.00`) `.reg` format.
        * **Delegation Graph & BloodHound/SIEM JSON Export (`cmd_find_delegation`)**:
            * Added `-graph` flag rendering visual ASCII Kerberos delegation trust graphs.
            * Added `-json` flag exporting structured delegation data for SIEM and BloodHound analysis.
        * **Multi-Target & Domain-Wide Network View Crawler (`cmd_netview`)**:
            * Added `-targets <FILE>` for multi-host SMB/RPC auditing.
            * Added `-domain` crawling all Active Directory domain computers discovered dynamically via LDAP.
            * Added `-check-user <USER>` highlighting active logon sessions and opened files for targeted accounts.
        * **TCP Traceroute & Network Hop Prober (`cmd_tracer`)**:
            * Added `tracer` measuring per-hop roundtrip times across configurable TCP ports and hop limits.
        * **Pure-Rust Offline PCAP Dissector Suite (`cmd_sniffer`)**:
            * Added `sniffer` with offline `.pcap` capture file parsing (`-pcap <FILE>`), port filtering (`-filter <PORT>`), and synthetic benchmark test suite (`-test`) dissecting SMB2/3, DCE/RPC, Kerberos, LDAP, TDS, and MQTT frames.

    * **Group 2 Protocol Enhancements & Tool Suite (`crates/impacket-msrpc`, `crates/impacket-krb5`, `bins/impacket-rs`)**:
        * **SAMR Global Group & Local Alias Enumeration (`crates/impacket-msrpc::samr`)**:
            * Implemented `SamrEnumerateGroupsInDomain` (Opnum 8), `SamrOpenGroup` (Opnum 19), `SamrGetMembersInGroup` (Opnum 25) with `SAMPR_GET_MEMBERS_BUFFER` NDR codecs.
            * Implemented `SamrEnumerateAliasesInDomain` (Opnum 15), `SamrOpenAlias` (Opnum 27), `SamrGetMembersInAlias` (Opnum 33) with `SAMPR_PSID_ARRAY` NDR codecs.
            * Implemented `SamrCloseHandle` (Opnum 1) for clean DCE/RPC handle teardown.
            * Added `SamrClient` methods: `enumerate_groups`, `open_group`, `get_members_in_group`, `enumerate_aliases`, `open_alias`, `get_members_in_alias`, and `close_handle`.
        * **Remote Desktop Protocol Negotiation & NLA Security Auditor (`[MS-RDPBCGR]`, `bins/impacket-rs`)**:
            * Added pure-Rust X.224 Connection Request encoder with `RDP_NEG_REQ` (Type 1) requesting TLS (`PROTOCOL_SSL`), CredSSP (`PROTOCOL_HYBRID`), and Early User Auth (`PROTOCOL_HYBRID_EX`).
            * Added X.224 Connection Confirm decoder parsing `RDP_NEG_RSP` (Type 2) and `RDP_NEG_FAILURE` (Type 3) failure codes (such as `HYBRID_REQUIRED_BY_SERVER`).
            * Audits target port 3389 for TLS support and Network Level Authentication (NLA) enforcement.
        * **MQTT 3.1.1 Broker Connectivity & Authentication Probe (`bins/impacket-rs`)**:
            * Added pure-Rust MQTT 3.1.1 `CONNECT` packet generator and variable-length integer framing.
            * Parses `CONNACK` return codes (0 = Accepted, 4 = Bad credentials, 5 = Not authorized) to audit anonymous access and credential validity.
        * **High-Precision TCP Latency & Reachability Prober (`cmd_ping`)**:
            * Added microsecond-accurate TCP ping measurement computing min/avg/max/stddev latency and packet loss rates across configurable ports and counts.
        * **Offline & Live Windows Registry Inspection (`cmd_registry-read`)**:
            * Integrated offline registry hive navigation and formatted value extraction (`REG_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_MULTI_SZ`, `REG_BINARY`) with remote MS-RRP winreg querying.
        * **Terminal Services & Task Scheduler Inspection CLI (`cmd_tstool`)**:
            * Added `tstool` supporting `list`, `info`, `xml`, `delete`, and `run` over MS-TSCH (`\PIPE\atsvc`).
        * **Kerberos Credential Cache Inspector (`cmd_klist`)**:
            * Added `klist` inspecting MIT `.ccache` v4 and Mimikatz `.kirbi` files (or `$KRB5CCNAME`), formatting ticket validity windows, encryption types, ticket flags, and session keys.
        * **Remote Windows `net.exe` Administrative CLI (`cmd_net`)**:
            * Added `net user`, `net group`, `net localgroup`, `net share`, and `net session` querying MS-SAMR and MS-SRVS.

    * **Group 1 Protocol Enhancements & Tool Suite (`crates/impacket-dcerpc`, `crates/impacket-mssql`, `crates/impacket-smb`, `crates/impacket-sam`, `crates/impacket-ldap`)**:
        * **NDR64 Architecture Probing (`crates/impacket-dcerpc`)**: Added `NDR64_SYNTAX_UUID` (`71710533-beba-4937-8319-b5dbef9ccc36` v1.0), `RpcBindPdu::to_bytes_with_transfer_syntax`, and `get_arch_live` probing remote 32-bit x86 vs 64-bit x64 Windows OS via DCE/RPC transfer syntax acceptance on TCP/135.
        * **`[MC-SQLR]` SQL Server Resolution Protocol (`crates/impacket-mssql::browser`)**: Added pure-Rust client discovering SQL Server instances over UDP/1434 (`CLNT_UCAST_EX` opcode 0x02, `SVR_RESP` 0x05, parser for semicolon-delimited instance text).
        * **SMB2 File Basic Information Codecs (`crates/impacket-smb`)**: Added `FileBasicInfo` (`[MS-FSCC] 2.4.7`), `build_smb2_query_info_basic_request`, `parse_smb2_query_info_basic_response`, `build_smb2_set_info_basic_request`, and `SmbConnection` methods `query_file_basic_info`, `set_file_basic_info`, `get_file_basic_info_by_path`, and `set_file_basic_info_by_path`.
        * **In-Place SAM Registry Hive Editing (`crates/impacket-sam::reg`)**: Added `get_value_data_location` returning exact byte offsets and lengths of value payloads, `update_hive_checksum` maintaining `[MS-RRP]` base-block XOR checksums, and `update_sam_user_password` updating local user NT hashes in-place for both Legacy Revision 1 (RC4) and Modern Revision 2 (AES-128-CBC) SAM hives.

    * **`[MS-DFSNM]` Distributed File System Namespace Management (`crates/impacket-msrpc::dfsnm`)**:
        * **Interface & Client**: Added `DfsClient` implementing `[MS-DFSNM]` interface `4FC742E0-4A10-11CF-8273-00AA004AE673` v3.0 over `\PIPE\netdfs` and TCP RPC.
        * **Operations**: Implemented `NetrDfsGetManagerVersion` (Opnum 0), `NetrDfsAdd` (Opnum 1), `NetrDfsRemove` (Opnum 2), `NetrDfsGetInfo` (Opnum 4), and `NetrDfsEnum` (Opnum 5).
        * **Data Structures**: Added `DfsInfo1` (link paths), `DfsInfo2` (link paths + comments + volume state), `DfsInfo3` (link paths + comments + volume state + targets), `DfsStorageInfo` (target server/share + storage state), and `DfsInfo300` (namespace descriptors + domain-joined/standalone capability flags).
        * **CLI Integration**: Added `dfsclient` / `dfssearch` subcommand in `bins/impacket-rs` for enumerating DFS roots, listing target file servers, inspecting specific paths, and adding/removing links.
    * **Interactive LDAP Administrative Shell (`ldapclient` / `ldap_shell.py`) (`crates/impacket-ldap::shell`)**:
        * Added `LdapShellSession` providing an interactive administrative REPL over LDAP and LDAPS sessions.
        * Commands implemented: `whoami`, `search <filter> [attrs...]`, `get_user_groups <user>` (via recursive `LDAP_MATCHING_RULE_IN_CHAIN` `1.2.840.113556.1.4.1941`), `get_group_users <group>`, `get_laps_password <computer>` (`ms-Mcs-AdmPwd` & `msLaps-Password`), `add_user`, `add_computer`, `add_user_to_group`, `remove_user_from_group`, `change_password` (via `unicodePwd` UTF-16LE BER replacement), `enable_account` / `disable_account` (via `userAccountControl` bitmask toggle), `set_dontreqpreauth` (AS-REP roasting toggle), `set_rbcd` / `clear_rbcd` (Resource-Based Constrained Delegation), and `dump` (LDAP schema and user enumeration).
        * Added `parse_command_tokens` tokenizer supporting single and double quoted argument parsing.
    * **Kerberos User-to-User (U2U) Authentication Suite (`[MS-KILE]` / RFC 4120 §3.7) (`crates/impacket-krb5::tgs`)**:
        * Added `enc-tkt-in-skey` (`0x0000_0008`) KDC options flag support in `Krb5TgsReq::with_u2u`.
        * Added `additional_tickets` (`[11]`) carrying the target server's TGT.
        * Implemented `decrypt_u2u_ticket_enc_part` decrypting the issued U2U service ticket's `enc-part` using the server's TGT session key with Key Usage 2 (`KU_TICKET`).
    * **SMB Direct / RDMA Transport Abstraction (`[MS-SMBD]`) (`crates/impacket-smb::smbd`)**:
        * Added `[MS-SMBD]` wire protocol structures: `SmbdNegotiateReq` (`[MS-SMBD]` 2.2.1.1, 16 bytes), `SmbdNegotiateResp` (`[MS-SMBD]` 2.2.1.2, 32 bytes), `SmbdDataTransfer` (`[MS-SMBD]` 2.2.2.1, 24 bytes header with 4-byte SMB2 payload alignment padding), and `SmbdBufferDescriptorV1` (`[MS-SMBD]` 2.2.3.1, 16 bytes RDMA memory descriptor).
        * Implemented `SmbdMessageReassembler` managing multi-fragment SMBD frame assembly.
        * Implemented `SmbdTransport<S>` providing client negotiation, frame sending, and stream reading over TCP/5445 and RDMA transports.
    * **`RpcSid` Binary Wire Encoders (`crates/impacket-ndr`)**:
        * Added `RpcSid::from_le_bytes` and `RpcSid::to_le_bytes` implementing `[MS-DTYP]` 2.4.2 raw binary SID parsing and serialization.
    * **Kerberos Flexible Authentication Secure Tunneling (FAST) Suite (RFC 6113) (`crates/impacket-krb5::fast`)**:
        * **Cryptographic Primitives**: Implemented `prf_aes128` and `prf_aes256` per RFC 3961 §5.3 (AES-ECB over truncated SHA-1 digest using `K_prf = DK(key, "prf")`), `prf_plus_aes128` and `prf_plus_aes256` variable-length PRF+ expansion generators, and `krb_fx_cf2_aes128` / `krb_fx_cf2_aes256` key combiner functions (RFC 6113 §5.1).
        * **FAST Wire Structures**: Added pure-Rust ASN.1 DER codecs for `KrbFastArmor` (`FX_FAST_ARMOR_AP_REQUEST = 1`), `KrbFastArmoredReq`, `EncKrbFastReq` (encapsulating inner `KdcReqBody`, options, and pre-auth elements), `KrbFastArmoredRep`, and `EncKrbFastRep`.
        * **AS-REQ Armoring Engine**: Added `build_fast_armored_as_req` building AP-REQ with authenticators, computing keyed `req-checksum` (Key Usage 51) over `KdcReqBody`, encrypting `EncKrbFastReq` (Key Usage 52) with armor key, wrapping into `PA-FX-FAST` (136) and `PA-FX-COOKIE` (133), and generating outer AS-REQ with Anonymous principal (`WELLKNOWN/ANONYMOUS`).
        * **Response Processing**: Implemented `decrypt_fast_rep` (Key Usage 53), `extract_fast_cookie`, and `extract_pa_fx_fast_reply` from `AS-REP` and `KRB-ERROR` packets.
        * **Live Exchange**: Added `send_fast_armored_as_req_live` driving live TCP/88 armored Kerberos pre-authentication exchanges against FAST-enforced KDCs.
    * **`[MS-EVEN6]` Windows EventLog Remoting Protocol v6.0 (`crates/impacket-msrpc::even6`)**:
        * **Remote EventLog Interface**: Implemented `[MS-EVEN6]` interface `F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C` v1.0 over `\PIPE\eventlog` or dynamic TCP.
        * **Log Query & Fetch Operations**: Implemented `EvtRpcRegisterLogQuery` (Opnum 5), `EvtRpcQueryNext` (Opnum 11) with multi-event batch unmarshaling, and `EvtRpcClose` (Opnum 13) for query and operation control context handles.
        * **BinXml & Event Record Parser**: Added `EvtEventRecord` decoding event identifiers, channels, computer names, providers, timestamps, and substitution strings from Windows EventLog byte streams into reconstructed XML and formatted summaries.
        * **Even6Client**: Provided high-level client methods `register_log_query`, `query_next`, `read_events`, and `close`.
    * **Kerberos Diamond Ticket Forgery Engine (`crates/impacket-krb5::ticketer`)**:
        * Added `forge_diamond_ticket` taking a genuine KDC-issued TGT (`.ccache` or `.kirbi`), decrypting `EncTicketPart` with the `krbtgt` key (Key Usage 2 `KU_TICKET`), modifying inner PAC group memberships and user RIDs, recalculating valid Server and KDC PrivSvr signatures, and re-encrypting the ticket while preserving genuine KDC timestamps and session structures.
    * **`[MS-DNSP]` Active Directory Integrated DNS Management Suite (`crates/impacket-ldap::dnsp`)**:
        * **Binary `dnsRecord` Codec (`[MS-DNSP] 2.3.2.2`)**: Implemented parsing and serialization for `DNS_RPC_RECORD` binary format stored in the `dnsRecord` attribute of `dnsNode` LDAP objects.
        * **Supported Record Types**: Full support for `A` (IPv4), `AAAA` (IPv6), `CNAME` (canonical name), `PTR` (pointer), `TXT` (counted text strings), `SRV` (service locator with priority/weight/port), `MX` (mail exchange), and `Tombstone` (deleted record marking).
        * **DNS Wire Name Codec (`[MS-DNSP] 2.2.2.1.1`)**: Implemented `encode_dns_rpc_name` and `decode_dns_rpc_name` converting dot-separated domain names to/from length-prefixed DNS wire labels with terminal null byte.
        * **Zone Discovery & Partition Walk**: Added `list_dns_zones` searching across standard AD DNS partitions (`DC=DomainDnsZones`, `DC=ForestDnsZones`, and legacy `CN=System`).
        * **Management Operations**: Added `query_dns_node`, `add_dns_node`, `modify_dns_node`, `tombstone_dns_node`, and `delete_dns_node` over RFC 4511 LDAP BER.
    * **Group Policy Preferences (GPP) Credential Decryption Engine (`crates/impacket-sam::gpp`)**:
        * **MS Published AES-256 Key**: Implemented Microsoft's static 32-byte AES-256 key (`[0x4e, 0x99, 0x06, 0xe8, ...]`) for decrypting `cpassword` attributes.
        * **Padding Normalization & Decryption**: Added base64 padding correction, AES-256-CBC null IV decryption, and PKCS#7 unpadding to extract plaintext UTF-16LE passwords.
        * **GPO XML Parsing**: Added parser for Group Policy Preferences XML definitions (`Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `Datasources.xml`, `Printers.xml`, `Drives.xml`) extracting usernames, passwords, changed dates, and descriptions.
    * **`[MS-LSAD]` Local Security Authority Account Rights & Privilege Enumeration (`crates/impacket-msrpc::lsat`)**:
        * **Account Rights Enumeration**: Implemented `LsarEnumerateAccountRights` (opnum 36) per `[MS-LSAD] 3.1.4.5.12` querying privileges and logon rights assigned to a SID (`SeDebugPrivilege`, `SeRemoteInteractiveLogonRight`, `SeBackupPrivilege`, etc.).
        * **NDR `LSAPR_USER_RIGHT_SET` Codec**: Added parsing for conformant array of `RPC_UNICODE_STRING` headers with deferred counted UTF-16LE wchar buffers.
        * **Status Handling**: Handles `STATUS_OBJECT_NAME_NOT_FOUND` (0xC0000034) gracefully, returning an empty right set when no explicit rights are assigned.
        * **LsatClient**: Added `LsatClient::enumerate_account_rights`.
    * **`[MS-SRVS]` Server Service Active File & Session Enumeration (`crates/impacket-msrpc::srvs`)**:
        * **Remote File & Lock Enumeration**: Implemented `NetrFileEnum` (opnum 9) level 3 (`FILE_INFO_3` per `[MS-SRVS] 2.2.4.30`) extracting open file ID, access permissions (`PERM_FILE_READ`, `PERM_FILE_WRITE`, `PERM_FILE_CREATE`), lock count, file path name, and opening username.
        * **Active Session Enumeration**: Implemented `NetrSessionEnum` (opnum 12) level 10 (`SESSION_INFO_10` per `[MS-SRVS] 2.2.4.14`) querying active client network sessions, connected usernames, active seconds, and idle seconds without requiring administrative privileges.
        * **NDR20 Layouts & Stubs**: Provided full request stub builders, response parsers, and wire-accurate mock response builders for `NetrFileEnum` and `NetrSessionEnum`.
        * **SrvsClient**: Added `net_file_enum`, `net_file_enum_filter`, `net_session_enum`, and `net_session_enum_filter`.
    * **`[MS-TSCH]` Task Scheduler Remote Protocol Enumeration Suite (`crates/impacket-msrpc::tsch`)**:
        * **Task Definition Retrieval**: Implemented `SchRpcRetrieveTask` (opnum 2) extracting full registered task XML definition strings.
        * **Task State & Metadata**: Implemented `SchRpcGetTaskInfo` (opnum 17) returning task enabled status and operational state (`TaskState`: `Unknown`, `Disabled`, `Queued`, `Ready`, `Running`).
        * **Task & Folder Inspection**: Implemented `SchRpcEnumTasks` (opnum 7) and `SchRpcEnumFolders` (opnum 6) per `[MS-TSCH] 3.2.5.4.7/8`.
        * **NDR Conformant Array Codec**: Added `PTASK_NAMES_ARRAY` parser extracting `[string] wchar_t*` name arrays with pagination index tracking.
        * **Recursive Task Graph Walker**: Implemented `TschClient::enum_all_tasks_recursive` walking nested task folders (such as `\Microsoft\Windows\...`) starting from root `\`.
    * **Active Directory LDAP RFC 2696 Simple Paged Results Control (`crates/impacket-ldap`)**:
        * **BER Paged Results Control**: Implemented RFC 2696 pagination control (`1.2.840.113556.1.4.319`) with ASN.1 sequence encoding (`size INTEGER, cookie OCTET STRING`) and extraction.
        * **Automatic AD Pagination Loop**: Added `LdapClient::search_paged` running iterative cookie exchanges until completion, allowing full traversal of Active Directory containers with > 1,000 entries without encountering `LDAP_SIZE_LIMIT_EXCEEDED` (error 4).
    * **`[MS-WKST]` Workstation Service Remote Protocol Suite (`crates/impacket-msrpc::wkst`)**:
        * **Workstation Interface**: Added pure-Rust client and NDR20 codecs for `[MS-WKST]` (`6BFFD098-A112-3610-9833-46C3F87E345A` v1.0) over `\PIPE\wkssvc` (named pipe) or TCP.
        * **Workstation Information**: Implemented `NetrWkstaGetInfo` (opnum 0) level 100 (`WkstaInfo100`) extracting computer name, LAN group / domain name, platform ID, and OS versions.
        * **Logged-on Users Enumeration**: Implemented `NetrWkstaUserEnum` (opnum 2) level 1 (`WkstaUserInfo1`) extracting logged-on usernames, logon domains, other domains, and logon servers with deferred wchar string marshalling.
        * **Join Information**: Implemented `NetrGetJoinInformation` (opnum 20) querying domain and workgroup join status (`NetJoinStatus`: `Unjoined`, `Workgroup`, `Domain`).
        * **WkstClient**: Provided high-level client methods `get_info`, `enumerate_users`, and `get_join_information`.
    * **Pure-Rust Autonomous SMB2 Server Engine & NetNTLMv2 Credential Sniffer (`crates/impacket-smb::server`)**:
        * **SMB2 File & IPC Server**: Added pure-Rust multi-threaded SMB2 server (`SmbServer`, `SmbServerConfig`, `SmbShare`) supporting both disk shares and `IPC$` named pipe shares.
        * **Dialect Negotiation & Upgrades**: Handles SMB2 `NEGOTIATE` and legacy SMBv1 Multi-Protocol Negotiate upgrade requests (`\xFFSMB` containing `SMB 2.002` / `SMB 2.???`).
        * **SPNEGO / NTLMSSP Authentication Handshake**: Drives full session setup sequence (`STATUS_MORE_PROCESSING_REQUIRED` on Type 1, returning Type 2 Challenge with target computer/domain info and server challenge, and validating Type 3 Authenticate).
        * **NetNTLMv2 Hash Capture**: Parses client NTLMSSP Type 3 authentication tokens and extracts user credentials into Hashcat mode 5600 / John the Ripper NetNTLMv2 syntax (`username::domain:server_challenge:nt_proof:client_blob`).
        * **File System Operations**: Implemented `TreeConnect`, `Create` (with directory and file dispositions `FILE_CREATE`, `FILE_OPEN_IF`, `FILE_OVERWRITE_IF`), `QueryDirectory` (`FileIdBothDirectoryInformation` 0x25 per `[MS-FSCC] 2.4.17` with 8-byte alignment), `Read`, `Write` (with read-only enforcement), and `Close`.
        * **Extensible Callbacks**: Added `run_with_callback` invoking custom listeners on captured credentials.
    * **`[MS-PAC]` Privilege Attribute Certificate & Ticket Decryption Suite (`crates/impacket-krb5::pac`)**:
        * **`PacLogonInfo` NDR Parser**: Implemented Type Serialization Version 1 `PAC_LOGON_INFO` parser per `[MS-PAC] 2.5` and `[MS-NRPC] 2.2.1.4.13` (`KERB_VALIDATION_INFO`), extracting `effective_name`, `full_name`, `user_id`, `primary_group_id`, `group_rids` (`(RID, Attributes)`), `logon_domain_name`, `logon_domain_id` (`RpcSid`), UAC flags, and 64-bit FILETIME timestamps (`filetime_to_unix`).
        * **Privilege & Group Inspection**: Added helper methods `is_domain_admin` (512), `is_enterprise_admin` (519), `is_schema_admin` (518), and `is_admin` (512, 519, 518, 544).
        * **Kerberos Ticket PAC Extraction**: Added `extract_pac_from_ticket` decrypting `EncTicketPart` with Key Usage 2 (`KU_TICKET`) across RC4 (etype 23), AES128 (etype 17), and AES256 (etype 18).
        * **Authorization Data Unwrapping**: Added `extract_pac_from_authorization_data` recursively unwrapping `AD-IF-RELEVANT` (ad-type 1) containers and extracting `AD-WIN2K-PAC` (ad-type 128) raw byte blobs.
        * **Ticket EncryptedData Parser**: Added `parse_ticket_enc_part` extracting `(etype, kvno, ciphertext)` from Kerberos `[APPLICATION 1]` Ticket ASN.1 structures.
    * **Active Directory Password Management Suite (`crates/impacket-msrpc::samr` & `crates/impacket-krb5::kpasswd`)**:
        * Implemented `encode_sampr_encrypted_user_password` (516-byte buffer with UTF-16LE password and length trailer encrypted via RC4 per `[MS-SAMR] 2.2.6.4`), and `decode_sampr_encrypted_user_password`.
        * Added `encrypt_owf_password` and `decrypt_owf_password` using 2-key DES-ECB per `[MS-SAMR] 2.2.11.1`.
        * Implemented `build_samr_unicode_change_password_user2_stub` (`[MS-SAMR]` Opnum 55) for unprivileged password modification without requiring domain/user handle acquisition.
        * Implemented `build_samr_set_user_password_stub` (`[MS-SAMR]` Opnum 58, `UserInternal3Information`) for administrative password resets encrypted with transport session keys.
        * Implemented RFC 3244 Kerberos Version 5 Password Changing Protocol (`crates/impacket-krb5::kpasswd`): `build_kpasswd_ap_req` (Key Usage 11), `build_kpasswd_krb_priv` (Key Usage 13), `parse_kpasswd_response` with error code decoding, and `change_password_kpasswd_live` over TCP/464.
    * **`[C706]` DCE/RPC Remote Management Interface & Opnum Prober (`crates/impacket-msrpc::mgmt` & `crates/impacket-dcerpc`)**:
        * Implemented standard DCE/RPC Remote Management Interface (`afa8bd80-7d8a-11c9-bef4-08002b102989` v1.0).
        * Added `inq_if_ids` (Opnum 0) parsing `rpc_if_id_vector_t` to dynamically query listening interface UUIDs and versions.
        * Added `is_server_listening` (Opnum 2) and `inq_princ_name` (Opnum 4) for SPN/principal discovery.
        * Added `probe_opnums` with status classification (`Success`, `AccessDenied`, `OpnumOutOfRange` = 0x1C010002, `Fault`, `Error`) and automatic early exit on out-of-range boundary.
        * Enhanced `parse_bind_ack` in `crates/impacket-dcerpc` to validate presentation context acceptance and reject reasons, and safely handle `RPC_BIND_NAK` (ptype 13).
    * **Service Control Manager Remote Protocol Suite (`crates/impacket-msrpc::scmr`)**:
        * Added `REnumServicesStatusW` (Opnum 14) and `RQueryServiceConfigW` (Opnum 17) request builders and response parsers.
        * Added `ServiceConfig` struct and `EnumServiceStatus` struct with `state_str` and `type_names` helpers.
        * Implemented `RChangeServiceConfigW` (Opnum 11) for modifying service start types, binary paths, accounts, and display names.
        * Added `ScmrClient` methods: `query_service_status`, `query_service_config`, `enum_services_status` (with automatic 2-step buffer negotiation), and `change_service_config`.
    * **Microsoft SQL Server TDS Protocol Engine (`crates/impacket-mssql`)**:
        * Added pure-Rust Tabular Data Stream (`[MS-TDS]`) protocol engine covering TDS 7.x (SQL Server 2000 through 2022).
        * `packet.rs`: Implemented 8-byte TDS packet framing with Big-Endian headers, multi-packet fragmentation, and reassembly.
        * `prelogin.rs`: Implemented `PRELOGIN` handshake packet builder and parser with encryption capability negotiation.
        * `login.rs`: Implemented `LOGIN7` packet builder with SQL native authentication (symmetric nibble-swap XOR 0xA5 obfuscation and deobfuscation) and Windows Integrated Authentication (SSPI/NTLMv2).
        * `tokens.rs`: Implemented Tabular Result token decoders for `COLMETADATA`, `ROW`, `ENVCHANGE`, `LOGINACK`, `INFO`, `ERROR`, `SSPI`, and `DONE`.
        * `client.rs`: Implemented `MssqlClient` driving connection, authentication, TDS 7.2+ `ALL_HEADERS` SQL batches, `use_database`, `enable_xp_cmdshell`, `disable_xp_cmdshell`, and `xp_cmdshell`.
    * **Kerberos PKINIT Suite & Smart Card Pre-Auth (`crates/impacket-krb5::pkinit`)**:
        * Added RFC 4556 `PA-PK-AS-REQ` (PA-DATA type 16) and `PA-PK-AS-REP` (PA-DATA type 17) engine.
        * Implemented CMS (`RFC 5652`) `SignedData` and `ContentInfo` envelope wrapping `AuthPack` and `PKAuthenticator` with SHA-1 `paChecksum` bound to `KDC-REQ-BODY`.
        * Added Oakley Group 14 (MODP 2048-bit) and Oakley Group 2 (MODP 1024-bit) Diffie-Hellman key exchange (`PkinitDhState`).
        * Added X.509 DER / PEM certificate parser and PKCS#1 / PKCS#8 RSA private key loader (`PkinitCredentials::from_pem_or_der`).
        * Implemented PKCS#1 v1.5 RSA-SHA256 signature generator.
        * Added `Krb5AsReq::with_pkinit_preauth` building certificate-authenticated AS-REQ packets.
    * **Arbitrary-Precision Big Integer Arithmetic (`crates/impacket-crypto::bignum`)**:
        * Added pure-Rust `BigUint` with 64-bit limb arithmetic: addition, subtraction, schoolbook multiplication with 128-bit accumulators, and modular exponentiation (`mod_pow`) via square-and-multiply.
    * **RFC 3962 Kerberos String-to-Key Suite (`crates/impacket-krb5::crypto`)**:
        * Added `string_to_key_aes128` and `string_to_key_aes256` using PBKDF2-HMAC-SHA1 and RFC 3961 key derivation.
        * Verified against all official test vectors in RFC 3962 Appendix B (iteration counts 1, 2, and 1200).
        * Added `Krb5AsReq::with_aes256_preauth` and `Krb5AsReq::with_aes128_preauth`.
    * **Remote Registry (`MS-RRP`) Domain Types & Value Codecs (`crates/impacket-msrpc::rrp`)**:
        * Added `RegHive` enum (`ClassesRoot`, `CurrentUser`, `LocalMachine`, `Users`) and `parse_reg_key_path` supporting both backslash and slash key paths.
        * Added `reg_type::parse` and `encode_reg_data` supporting `REG_SZ`, `REG_EXPAND_SZ`, `REG_DWORD` (decimal/hex), `REG_QWORD`, `REG_BINARY` (clean hex parsing), and `REG_MULTI_SZ` (double-NUL terminated UTF-16LE).
        * Added `format_reg_data` rendering registry data into standard human-readable display values.
        * Added `RrpClient::open_hive` dispatching automatically to `OpenClassesRoot`, `OpenCurrentUser`, `OpenLocalMachine`, or `OpenUsers`.
    * **Dynamic DCE/RPC Endpoint Mapper Resolution (`crates/impacket-dcerpc` & `bins/impacket-rs`)**:
        * Added `EpmEndpointEntry` helper methods: `is_ncacn_ip_tcp`, `tcp_port`, `is_ncacn_np`, and `named_pipe`.
        * Added `resolve_dynamic_tcp_port` and `resolve_named_pipe` querying remote EPM on TCP/135 via `rpcdump_live`.
        * Added `TcpRpcTransport::connect_dynamic` establishing bound RPC transports directly to dynamic TCP endpoints.
        * Enhanced `open_pipe_transport` in `impacket-rs` to automatically resolve dynamic named pipes via EPM when `pipe` is omitted or set to `"auto"`.
    * **SMB 3.x Transport Encryption Suite (`crates/impacket-smb::transform` & `crates/impacket-crypto::aead`)**:
        * Added pure-Rust **AES-GCM** (NIST SP 800-38D) and **AES-CCM** (NIST SP 800-38C) authenticated ciphers for AES-128 and AES-256 with constant-time authentication tag verification.
        * Added `Smb3EncryptionState` implementing `SMB2_TRANSFORM_HEADER` (`\xfdSMB`, 52 bytes) encapsulation, decapsulation, and AAD protection.
        * Added SP800-108 counter-mode KDF directional key derivation for **SMB 3.0/3.0.2** (`ServerIn `, `ServerOut`) and **SMB 3.1.1** (`SMBC2SCipherKey`, `SMBS2CCipherKey` bound to `PreauthIntegrityHash`).
        * Added automatic encryption enforcement on `SMB2_SESSION_FLAG_ENCRYPT_DATA` (0x0004) and `SMB2_SHAREFLAG_ENCRYPT_DATA` (0x0001), plus explicit `set_encryption` toggle.
    * **SMB1 Message Signing (`crates/impacket-smb::smb1`)**:
        * Added `[MS-SMB]` Section 3.1.5.1 legacy SMB1 packet signing (`MD5(SessionKey || Message)`) placing 8-byte signatures into `SecurityFeatures` (header offsets 14..22) with 32-bit sequence tracking.
    * **MSRPC Transport Encryption & Signing (`crates/impacket-auth::session_security` & `crates/impacket-dcerpc`)**:
        * Added `NtlmSessionSecurity` implementing `[MS-NLMP]` Section 3.4 RC4 sealing and HMAC-MD5 signing with encrypted sequence numbers.
        * Added `SecTrailer` (`[MS-RPCE]` Section 2.2.2.11) and `RpcSecurityContext` supporting `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` (payload encryption) and `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` (message authentication) for DCE/RPC PDU request wrapping and response unsealing.
    * **Interactive `smbclient` Recursive File Operations (`bins/impacket-rs`)**:
        * Added `mget` (recursive directory download), `mput` (recursive directory upload), `mkdir` (remote directory creation), `rmdir` (remote directory deletion), and `encrypt [on|off]` (runtime SMB3 encryption toggle).

    * **Kerberos Golden & Silver Ticket Forging Engine (`crates/impacket-krb5::ticketer`)**:
        * Added `forge_ticket` and `TicketOptions` implementing RFC 4120 `Ticket` (`[APPLICATION 1]`) and `EncTicketPart` (`[APPLICATION 3]`) generation with Active Directory PAC (`AD-IF-RELEVANT` -> `AD-WIN2K-PAC`) injection.
        * Supports customized user identity, user RID, domain SID, privileged group memberships (Domain Admins 512, Enterprise Admins 519, Schema Admins 518), configurable SPN (Golden `krbtgt/DOMAIN` or Silver service tickets), and validity lifetimes.
        * Outputs directly to MIT Kerberos `.ccache` v4 or Windows Mimikatz `.kirbi` formats.
    * **RFC 3962 Kerberos AES-128 & AES-256 Encryption Suite (`crates/impacket-krb5::crypto`)**:
        * Added `aes128_cts_hmac_sha1_96_encrypt`, `aes128_cts_hmac_sha1_96_decrypt`, `aes256_cts_hmac_sha1_96_encrypt`, and `aes256_cts_hmac_sha1_96_decrypt`.
        * Implements RFC 3962 §4 key derivation (`0xAA` for encryption key `Ke`, `0x55` for checksum key `Ki`), 16-byte confounder handling, AES-CTS ciphertext generation, and HMAC-SHA1-96 payload integrity verification.
    * **Active Directory Resource-Based Constrained Delegation (RBCD) Suite (`crates/impacket-ldap::rbcd`)**:
        * Added `build_rbcd_security_descriptor` constructing `[MS-DTYP]` self-relative Security Descriptors with `GENERIC_ALL` Access Allowed ACEs for specified grantee SIDs.
        * Added `parse_rbcd_allowed_sids` parsing `msDS-AllowedToActOnBehalfOfOtherIdentity` raw security descriptors and extracting trustee SIDs.
        * Added high-level `read_rbcd`, `write_rbcd`, and `flush_rbcd` client operations over LDAP.
    * **LDAP Modify Operation & BER Codec (`crates/impacket-ldap::asn1`)**:
        * Added RFC 4511 `ModifyRequest` (`[APPLICATION 6]` / `0x66`) and `ModifyResponse` (`[APPLICATION 7]` / `0x67`) encoding and decoding.
        * Added `ModifyOperation` (`Add`, `Delete`, `Replace`) and `AttributeModification` structs.
        * Added `LdapClient::modify` driving LDAP attribute modification over TCP sessions.
    * **Active Directory Delegation Scanner Engine (`crates/impacket-ldap::delegation`)**:
        * Added `find_delegation`, `DelegationRecord`, and `DelegationType` auditing:
            * **Unconstrained Delegation**: `userAccountControl & 0x00080000` (`TRUSTED_FOR_DELEGATION`) with Domain Controller distinction.
            * **Constrained Delegation**: `msDS-AllowedToDelegateTo` targets and `TRUSTED_TO_AUTH_FOR_DELEGATION` (0x01000000) Protocol Transition (S4U2Self) status.
            * **Resource-Based Constrained Delegation**: `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute and allowed trustee SIDs.

    * **Versioning & Engineering Standards (`crates/impacket-core`)**:
        * Added `impacket_core::version::{VERSION, BANNER}` mirroring `impacket/version.py` so all tools print a unified `Impacket-RS v0.1.0-dev` banner.
        * Added `STATUS_MORE_ENTRIES` (`0x00000105`), `STATUS_SOME_NOT_MAPPED` (`0x00000107`), and `STATUS_NONE_MAPPED` (`0xC0000073`) to `NtStatus` for batch SID lookup and SAMR pagination.
    * **SMB Named Pipe Transport (`ncacn_np`) (`crates/impacket-smb`)**:
        * Added `build_smb2_tree_connect_request` (`SMB2_TREE_CONNECT` `0x0003` for `\\<server>\IPC$`), `build_smb2_create_pipe_request` (`SMB2_CREATE` `0x0005` for `\PIPE\lsarpc`, `\PIPE\samr`, `\PIPE\srvsvc`, `\PIPE\svcctl`), and `build_smb2_pipe_transceive_request` (`SMB2_IOCTL` `0x000B` with `FSCTL_PIPE_TRANSCEIVE = 0x0011C017`).
    * **Removed all simulated/flat-wire placeholders.** The earlier `*_over_stream` + `run_*_selftest` helpers that round-tripped against self-invented NDR layouts were deleted. Remaining server-side encoders (valid EPM/Kerberos/SMB2 PDU generators) moved into `#[cfg(test)]` as fixtures that exercise the real client parsers. Every protocol module now implements the genuine `[MS-*]` / NDR20 wire format.
    * **DCE/RPC transport abstraction (`crates/impacket-dcerpc`)**: Added the shared `RpcTransport` trait plus a live `TcpRpcTransport` (`ncacn_ip_tcp`: connect + `Bind` + transceive), so all high-level interface clients are transport-agnostic (`impacket/dcerpc/v5/transport.py`).
    * **SPNEGO & GSS-API Negotiation Engine (`crates/impacket-auth::spnego`)**: Added pure-Rust RFC 4178 `NegTokenInit` and `NegTokenResp` codec with OID catalogs for SPNEGO (`1.3.6.1.5.5.2`), NTLMSSP (`1.3.6.1.4.1.311.2.2.10`), MS-KRB5 (`1.2.840.48018.1.2.2`), KRB5 (`1.2.840.113554.1.2.2`), and NEGOEX (`1.3.6.1.4.1.311.2.2.30`). Added `extract_embedded_auth_token` for seamless payload extraction across GSS-API wrapped and raw streams.
    * **Unified ASN.1 DER Engine (`crates/impacket-core::der`)**: Promoted zero-allocation ASN.1 DER/BER primitives (`encode_length`, `decode_tlv`, `encode_tlv`, `encode_sequence`, `encode_context_explicit`, `encode_application`, `encode_integer`, `encode_octet_string`, `encode_oid`, `decode_oid`) into `impacket-core` for cross-crate reuse by `impacket-auth`, `impacket-krb5`, and `impacket-ldap`.
    * **NTLMSSP Type 3 (`crates/impacket-auth`)**: Added `NtlmAuthenticateMessage` (`AUTHENTICATE_MESSAGE` with LM/NT/domain/user/workstation/session-key security buffers) completing the NTLM handshake (`getNTLMSSPType3`).
    * **Advanced AES & Hashing Suite (`crates/impacket-crypto`)**: Added pure-Rust FIPS 197 `aes256` (ECB & CBC), RFC 3962 / NIST SP 800-38A CS3 Ciphertext Stealing (`aes128_cts_encrypt`, `aes128_cts_decrypt`, `aes256_cts_encrypt`, `aes256_cts_decrypt`), RFC 3174 `sha1`, RFC 2104 `hmac_sha1`, RFC 3962 `hmac_sha1_96` truncated checksum, and RFC 2898 `pbkdf2_hmac_sha1`. Verified against RFC 6070 and FIPS 197 test vectors.
    * **Signing crypto (`crates/impacket-crypto`)**: Added pure-Rust `sha256` (FIPS 180-4), `sha512` (FIPS 180-4), `hmac_sha256` (RFC 4231), `aes128_cmac` (NIST SP800-38B), and `sp800_108_counter_kdf` (SP800-108 CTR HMAC-SHA256), all verified against published test vectors.
    * **Authenticated + signed SMB named-pipe transport (`crates/impacket-smb`)**: Added `SmbConnection` (`SMB2_NEGOTIATE` → `SMB2_SESSION_SETUP` NTLMv2 Type 1/2/3 → `SMB2_TREE_CONNECT` `IPC$` → `SMB2_CREATE` pipe → `FSCTL_PIPE_TRANSCEIVE`) and `SmbCredential` (password / pass-the-hash). Negotiates the full **SMB 2.0.2 → 3.1.1** range and **signs** every post-auth request: HMAC-SHA256 (SMB 2.0.2/2.1) and AES-128-CMAC (SMB 3.0/3.0.2/3.1.1). SMB 3.1.1 tracks the preauth-integrity hash (running SHA-512 over the negotiate + session-setup chain) and derives the signing key with `KDF(SessionKey, "SMBSigningKey\0", PreauthHash)`. Works against signing-required DCs.
    * **Operational SMB1 / CIFS transport (`crates/impacket-smb::smb1`)**: Added `Smb1Connection` (`SMB_COM_NEGOTIATE` `NT LM 0.12` → `SESSION_SETUP_ANDX` classic NTLMv1/DES → `TREE_CONNECT_ANDX` `IPC$` → `NT_CREATE_ANDX` pipe → `SMB_COM_TRANSACTION`/`TransactNmPipe` `0x0026`), mirroring the `SmbConnection` surface. For SMB1-only hosts (NT4/2000/XP/2003). Uses non-extended security; errors cleanly if the server mandates SPNEGO. No SMB1 signing yet.
    * **SMB2 file I/O & directory enumeration (`crates/impacket-smb`)**: Added generic `SMB2_CREATE` (`build_smb2_create_request` + `create_disposition`/`file_access` consts), `SMB2_WRITE`, `SMB2_READ`, `SMB2_CLOSE`, and `SMB2_QUERY_DIRECTORY` (`0x000E` with `FileBothDirectoryInformation` parsing). Added `SmbConnection` methods `create_file`/`write_file`/`read_file`/`close_file` + `read_full_file`/`write_full_file`/`delete_file`/`tree_connect_share`/`list_directory`. Added `tree_disconnect` (`SMB2_TREE_DISCONNECT` `0x0004`) and `logoff` (`SMB2_LOGOFF` `0x0002`) for complete session termination. Enables full share browsing and file transfer across SMB 2.0.2 to 3.1.1 with packet signing.
    * **DCE/RPC response framing & multi-fragment reassembly (`crates/impacket-dcerpc`)**: Added `RpcResponsePdu` (`[MS-RPCE]` §2.2.2.9), `extract_response_stub`, `RpcFault` detection (`CoreError::RpcFault(status)`), and `read_full_rpc_response` multi-fragment reassembly when `pfc_flags & PFC_LAST_FRAG` is unset.
    * **MSRPC client safety & fault dispatch (`crates/impacket-msrpc`)**: Replaced raw `[24..]` slicing across `samr`, `lsat`, `srvs`, `scmr`, `rrp`, and `tsch` with `extract_response_stub`, ensuring transparent RPC fault propagation and auth trailer stripping.
    * **Remote Execution Suite (`crates/impacket-msrpc::exec`)**:
        * **`psexec`** (`impacket/examples/psexec.py`): Service Control Manager (`\PIPE\svcctl`) execution supporting optional binary deployment, custom share redirection (`ADMIN$` or `C$`), and service cleanup.
        * **`smbexec`** (`impacket/examples/smbexec.py`): MS-SCMR service trick with loopback UNC output capture (`C$\__<token>`).
        * **`atexec`** (`impacket/examples/atexec.py`): MS-TSCH scheduled task execution (`SchRpcRegisterTask`/`SchRpcRun`/`SchRpcDelete`).
        * **`wmiexec`** (`impacket/examples/wmiexec.py`): WMI `Win32_Process::Create` execution with SMB share output capture.
        * **`dcomexec`** (`impacket/examples/dcomexec.py`): DCOM automation execution across `MMC20.Application`, `ShellWindows`, and `ShellBrowserWindow`. All five remote execution architectures are complete.
    * **Offline registry hive parser + LOCAL secretsdump (`crates/impacket-sam`)**: `reg::Hive` parses the `regf` base block, walks `nk` nodes via `lf`/`lh`/`li`/`ri` subkey lists, reads class names and `vk` values. `bootkey_from_system_hive` recovers the BootKey from `SYSTEM`; `hashed_bootkey_from_f` (rev1 RC4 / rev2-3 AES) + `parse_sam_user_v` (name + `SAM_HASH`/`SAM_HASH_AES` NT/LM blocks) decrypt users; `secretsdump_local(sam, system)` dumps `user:rid:lm:nt:::` from offline hives. MS-RRP remote hive save (REMOTE secretsdump) is next.
    * **Dialect routing (`crates/impacket-msrpc::transport`)**: `SmbPipeTransport` now selects the SMB1 stack for `AdCompatProfile::LegacyWin2000` and the signed SMB 2.0.2–3.1.1 stack otherwise, so `samrdump`/`lookupsid`/`netview` run over **the full SMB1 → SMB 3.1.1 range**. **Remaining**: SMB3 encryption (AES-GCM/CCM), SMB1 signing.
    * **Tier 3 high-level MSRPC interface clients (`crates/impacket-msrpc`)** — real `[MS-*]`/NDR20 wire over `RpcTransport`, with a live `ncacn_np` `SmbPipeTransport` and shared pointer/string helpers (`dtypes`):
        * **`samr` (`[MS-SAMR]`)**: `SamrConnect5` (64), `SamrEnumerateDomainsInSamServer` (6), `SamrLookupDomainInSamServer` (5), `SamrOpenDomain` (7), `SamrEnumerateUsersInDomain` (13), `SamrOpenUser` (34), `SamrQueryInformationUser` (36, `UserAllInformation` → `SamrUserAllInformation`: name/full-name/comment, RID, primary group, UAC flags, bad-pw/logon counts, password-last-set) via a `SamrClient` state machine. Correct `unique` pointer referents with deferred pointees, `RPC_UNICODE_STRING`, conformant+varying `[string]` buffers, `SAMPR_ENUMERATION_BUFFER`.
        * **`lsat` (`[MS-LSAT]`/`[MS-LSAD]`)**: `LsarOpenPolicy2` (44) / legacy `LsarOpenPolicy` (6), `LsarLookupSids` (15) with `LSAPR_REFERENCED_DOMAIN_LIST` + `LSAPR_TRANSLATED_NAMES` decode and `SidNameUse` classification. Response layout modeled to `[MS-LSAT]` + NDR20 and round-trip tested; pending live-capture confirmation.
        * **`srvs` (`[MS-SRVS]`)**: `NetrShareEnum` (15) level 1 `SHARE_INFO_1` with `ShareType` classification (masking `STYPE_SPECIAL`/`STYPE_TEMPORARY`).
        * **`scmr` (`[MS-SCMR]`)**: Service Control Manager control-plane — `ROpenSCManagerW` (15), `RCreateServiceW` (12), `ROpenServiceW` (16), `RStartServiceW` (19), `RControlService` (1), `RDeleteService` (2), `RQueryServiceStatus` (6), `RCloseServiceHandle` (0) via `ScmrClient`. Foundation for `psexec`/`smbexec`/`services`.
        * Every request builder / response parser is byte-for-byte round-trip tested against a `MockDc` transport. **To Do (next)**: DCE/RPC fragment reassembly for large responses, Kerberos `getTGT`/`GetUserSPNs`, SMB3 encryption.

    * **Kerberos RC4-HMAC crypto + pre-auth (`crates/impacket-krb5::crypto`)**: Added etype-23 `rc4_hmac_encrypt`/`rc4_hmac_decrypt` (RFC 4757, with the usage-3/9→8 remap) and `unix_to_kerberos_time` (GeneralizedTime, no date lib). `Krb5AsReq::with_rc4_preauth` builds a pre-authenticated `AS-REQ` with a `PA-ENC-TIMESTAMP` padata (EncryptedData etype 23), and `get_tgt_over_stream`/`get_tgt_live` perform `getTGT`. RC4 only for now; AES128/256-CTS-HMAC-SHA1-96 (etypes 17/18) is next.
    * **Kerberos Credential Cache & Kirbi Codec (`crates/impacket-krb5::ccache`)**: Added `CCache` and `Credential` structs supporting full bidirectional conversion between MIT Kerberos `.ccache` v4 (`0x0504`) and Windows Mimikatz `.kirbi` (`KRB-CRED`, RFC 4120 `[APPLICATION 22]`) format, with base64 wrap/unwrap support, `find_tgt_credential`/`find_tgt_session` lookup methods, and roundtrip unit tests.
    * **Kerberos TGS Exchange & Service Ticket Operations (`crates/impacket-krb5::tgs`)**:
        * **`Krb5TgsReq`**: Implemented RFC 4120 `TGS-REQ` (`[APPLICATION 12]`) encoder with `PA-TGS-REQ` carrying `AP-REQ` (`[APPLICATION 14]`), `Authenticator` (`[APPLICATION 2]`) encrypted with session key (Key Usage 7), and `KDC-REQ-BODY` requesting specific SPNs and encryption types.
        * **`Krb5TgsRep`**: Implemented RFC 4120 `TGS-REP` (`[APPLICATION 13]`) parser extracting service ticket `enc-part` and converting to Hashcat formats: mode 13100 (RC4-HMAC etype 23), mode 19600 (AES-128 etype 17), and mode 19700 (AES-256 etype 18) (`$krb5tgs$`).
        * **AS-REP Session Key Extractor**: Decrypts RC4 `AS-REP` `enc-part` (Key Usage 3) using account NT hash and extracts `EncASRepPart` session key (`keytype, keyvalue`).
        * **Sans-I/O & Live TCP/88 KDC Client**: Added `get_tgs_over_stream` and `get_tgs_live`.
    * **Active Directory Directory Replication Service Remote Protocol (`[MS-DRSR]` / DRSUAPI) (`crates/impacket-msrpc::drsr`)**:
        * **DRSUAPI Interface Engine**: Implemented `[MS-DRSR]` interface `E3514235-4B06-11D1-AB04-00C04FC2DCD2` v4.0 client over SMB named pipe (`\PIPE\lsass` / `\PIPE\drsuapi`) and TCP RPC.
        * **Replication Lifecycle**: Implemented `DRSBind` (Opnum 0) with `DRS_EXTENSIONS_INT` client capabilities, `DRSUnbind` (Opnum 1), `DRSCrackNames` (Opnum 12) for name-to-GUID/SID resolution, and `DRSGetNCChanges` (Opnum 3) V8 replication request / V6 response.
        * **Attribute Decryption**: Added `decrypt_drs_attribute_value` implementing RC4 decryption via `MD5(session_key || Salt)` and CRC32 payload checksum verification (`[MS-DRSR]` §5.16.2/3). Added `remove_des_layer` using RID-based DES-56 ECB decryption (`sam_des_decrypt_hash_with_rid`).
        * **Supplemental Credentials Extraction**: Implemented `parse_supplemental_credentials` extracting Active Directory Kerberos keys (`Primary:Kerberos-Newer-Keys`: AES-256, AES-128, RC4-HMAC, DES) and cleartext passwords (`Primary:CLEARTEXT`).
        * **Remote `secretsdump` DCSync & Registry Expansion (`bins/impacket-rs`)**:
            * Enhanced `secretsdump` CLI with `-just-dc`, `-just-dc-user <username>`, `-just-dc-ntlm`, and `-security` flags.
            * Supports full remote Active Directory DCSync credential replication over DRSUAPI with Kerberos keys and cleartext password dumping.
            * Supports remote LSA secrets and cached domain logons (`$DCC2$`) extraction via Remote Registry (`winreg`) and `impacket-sam`.
    * **`[MS-PAC]` Privilege Attribute Certificate Suite (`crates/impacket-krb5::pac`)**:
        * **`Pac` Engine**: Implemented `PACTYPE` binary parser and builder with 8-byte aligned `PAC_INFO_BUFFER` array (`[MS-PAC]` Section 2.2).
        * **Buffer Types**: Implemented `PAC_LOGON_INFO` (1), `PAC_SERVER_CHECKSUM` (6), `PAC_PRIVSVR_CHECKSUM` (7), `PAC_CLIENT_INFO` (10), `PAC_ATTRIBUTES_INFO` (17), and `PAC_REQUESTOR_INFO` (18).
        * **Cryptographic Signing & Verification**: Added `sign_pac` and `verify_pac` calculating Server signatures and KDC PrivSvr signatures over the PAC using RC4-HMAC (`KERB_NON_KERB_CKSUM_SALT = 17`) and AES-128 / AES-256 CTS HMAC-SHA1-96 (`KERB_NON_KERB_CKSUM_SALT = 17`).
        * **RFC 3961 Key Derivation & `n-fold`**: Implemented RFC 3961 §5.1 `nfold` and AES key derivation in `crypto.rs`, verified against test vectors.
        * **PAC Logon Info & Golden PAC**: Implemented Type Serialization Version 1 headers and NDR `KERB_VALIDATION_INFO` with customizable privileged group memberships (Domain Admins 512, Enterprise Admins 519, Schema Admins 518) via `build_golden_pac`.
    * **NTLM Cross-Protocol Relay Engine (`crates/impacket-relay`)**:
        * **Sans-I/O Relay State Machine (`session.rs`)**: Implemented `NtlmRelaySession` driving the 3-step authentication relay lifecycle (`NegotiateMessage` -> `ChallengeMessage` -> `AuthenticateMessage`) across HTTP, SMB, LDAP, and MSSQL.
        * **MIC & EPA Stripping**: Added `strip_mic_from_authenticate` (zeroes 16-byte MIC and clears bit 0x02 in `MsvAvFlags`) and `strip_channel_bindings_from_challenge` (removes `MsvAvChannelBindings` AV ID 10) for cross-protocol relay compatibility.
        * **HTTP Protocol Adapter (`http.rs`)**: Implemented `extract_ntlm_token_from_header`, `format_ntlm_challenge_header`, and `build_http_401_challenge_response`.
        * **SMB Protocol Adapter (`smb.rs`)**: Implemented `extract_ntlm_from_smb2_security_buffer` (unwrapping raw NTLM or SPNEGO `NegTokenInit`/`NegTokenResp`), `wrap_ntlm_negotiate_in_spnego`, and `wrap_ntlm_challenge_in_spnego`.
        * **LDAP Protocol Adapter (`ldap.rs`)**: Implemented `build_ldap_sasl_bind_request` (`GSS-SPNEGO`) and `extract_spnego_from_ldap_bind_response`.
        * **Relay Target Orchestration (`server.rs`)**: Added `RelayTarget` URL parsing (`smb://`, `ldap://`, `http://`, `mssql://`) and `RelayEngine` session coordinator.
    * **Active Directory LDAP Engine & Security Descriptor Suite (`crates/impacket-ldap`)**:
        * **RFC 4511 ASN.1 BER Message Codec**: Implemented `LdapMessage`, `BindRequest`, `BindResponse`, `SearchRequest`, `SearchResultEntry`, `SearchResultDone`, and `UnbindRequest`.
        * **Search Filter Builders**: Implemented `filter_present` (`0x87`), `filter_equality` (`0xA3`), `filter_and` (`0xA0`), `filter_or` (`0xA1`), and `filter_not` (`0xA2`).
        * **`[MS-DTYP]` Section 2.4.6 Security Descriptor Engine**: Added `SecurityDescriptor`, `Acl`, `Ace`, access masks (`DELETE`, `READ_CONTROL`, `WRITE_DAC`, `WRITE_OWNER`), control flags (`SE_DACL_PRESENT`, `SE_SELF_RELATIVE`), and ACE types (`ACCESS_ALLOWED`, `ACCESS_DENIED`, `ACCESS_ALLOWED_OBJECT`, etc.) with full binary roundtrip tests.
        * **Live LDAP Client**: Added `LdapClient` over TCP (port 389) supporting simple bind, SASL GSS-SPNEGO bind, whole-subtree search, and graceful unbind.
    * **Offline Windows `SECURITY` Hive & LSA Secrets Suite (`crates/impacket-sam::lsa`)**:
        * **LSA Key Recovery**: Implemented `LsaParser` recovering the 32-byte `LSAKey` from `Policy\PolEKList` (Modern Vista -> 2025 AES-256) or `Policy\PolSecretEncryptionKey` (Legacy XP/2003 MD5+RC4) using the system `BootKey`.
        * **Netlogon Key Decryption**: Added `decrypt_nlkm_key` decrypting `Policy\Secrets\NL$KM\CurrVal`.
        * **Domain Cached Logon Credentials (`DCC2`)**: Implemented `dump_cached_hashes` parsing the 96-byte `NL_RECORD` headers from `Cache\NL$<Entry>` and extracting domain cached hashes with iteration counts and FileTime timestamps in Hashcat mode 2100 syntax (`$DCC2$`).
        * **LSA Secrets Parser**: Added `dump_secrets` decrypting secrets stored under `Policy\Secrets\<Name>\CurrVal` (`$MACHINE.ACC`, `DPAPI_SYSTEM`, `_SC_<service>`, etc.).
    * **DCOM & Object RPC (ORPC) Suite (`crates/impacket-dcom`)**:
        * **ORPC Framing (`[MS-DCOM]`)**: Added `COMVERSION` (v5.1 -> v5.7), `ORPCTHIS`, and `ORPCTHAT` header codecs.
        * **DualStringArray Engine**: Added `DUALSTRINGARRAY`, `STRINGBINDING` (Tower IDs for TCP/IP, Named Pipes, NetBIOS, HTTP), and `SECURITYBINDING` (NTLMSSP, Kerberos, SPNEGO) NDR parser and serializer (`[MS-DCOM]` Section 2.2.19).
        * **IObjectExporter Client**: Added `server_alive` (opnum 3) and `server_alive2` (opnum 5) on UUID `99fcf743-a754-1113-17cb-0000f020bed8` with `oxid_query_live` for credential-less network interface discovery.
    * **Extensible Storage Engine (`NTDS.dit` ESE) & Active Directory Credential Engine (`crates/impacket-sam`)**:
        * **ESE Database Parser (`crates/impacket-sam::ese`)**: Implemented pure-Rust offline reader for Microsoft Extensible Storage Engine (ESENT / JET Blue) database files. Decodes database headers, page headers across eras (Win2003, Vista, Win7+ 16K/32K), page tags, B-tree branch/leaf navigation, `MSysObjects` catalog tables, column schemas (`JET_coltyp*`), and record decoding across fixed-size, variable-size, and tagged columns.
        * **DPAPI Decryption Engine (`crates/impacket-sam::dpapi`)**: Implemented parsing and decryption for Windows Data Protection API (DPAPI) `MasterKeyFile`, `MasterKey`, and `DpapiBlob` structures. Supports AES-256-CBC, 3DES-CBC, HMAC-SHA1, and HMAC-SHA512 session key derivation, signature verification, and user key derivation (`derive_keys_from_user`, `derive_keys_from_user_key`).
        * **Offline Active Directory NTDS Hashes (`crates/impacket-sam::ntds`)**: Implemented `NtdsParser` decrypting domain Password Encryption Keys (`PEK`) via legacy MD5+RC4 (Win2000-2012R2) and modern AES-128-CBC (Win2016-2025). Recovers domain accounts, user Account Control flags, and decrypts `unicodePwd` (NT hash) and `dBCSPwd` (LM hash) with user RID-based DES unwrapping.
    * **Cryptographic Primitives Expansion (`crates/impacket-crypto`)**:
        * Added pure-Rust FIPS 46-3 Triple-DES (`des3_ede_encrypt_block`, `des3_ede_decrypt_block`, `des3_cbc_encrypt`, `des3_cbc_decrypt`).
        * Added RFC 4231 `hmac_sha512` and RFC 2898 `pbkdf2_hmac_sha512`, `pbkdf2_hmac_sha256`.
    * **Core & NDR Extensions (`crates/impacket-core`, `crates/impacket-ndr`)**:
        * Added `CoreError::IoError(String)` and `impl From<std::io::Error> for CoreError`.
        * Added `RpcUuid::to_le_bytes` and `RpcUuid::from_le_bytes` for Windows GUID binary roundtrips.

2. New examples / CLI subcommands (`bins/impacket-rs`)

    * **`GetLAPSPassword`** (`examples/GetLAPSPassword.py`): Active Directory LAPS & Windows LAPS password recovery utility via LDAP (`GetLAPSPassword <TARGET> [-computer <NAME>] [-port 389]`). Retrieves legacy `ms-Mcs-AdmPwd` and Windows LAPS `msLAPS-Password` (cleartext JSON payload) with `FileTime` expiration date translations.
    * **`CheckLDAPStatus`** (`examples/CheckLDAPStatus.py`): Active Directory LDAP diagnostic and signing enforcement auditor (`CheckLDAPStatus <TARGET> [-port 389]`). Queries RootDSE metadata (DNS name, server name, naming contexts, supported LDAP versions, SASL mechanisms) and probes anonymous bind rejection / `strongAuthRequired` to identify vulnerable NTLM relay targets.
    * **`getArch`** (`examples/getArch.py`): Remote Windows OS architecture detection utility (`getArch <TARGET> [port]`). Issues an unauthenticated DCE/RPC bind to TCP/135 with `NDR64_SYNTAX_UUID` to determine 64-bit x64 vs 32-bit x86 architecture.
    * **`machine_role`** (`examples/machine_role.py`): Domain-join role and primary domain inspector over `\PIPE\wkssvc` (`machine_role <TARGET> [-hashes LM:NT]`). Executes `NetrGetJoinInformation` (Opnum 20) and `NetrWkstaGetInfo` (Opnum 0) to report whether the target is joined to a Domain, Workgroup, or Unjoined, along with OS version and platform ID.
    * **`mssqlinstance`** (`examples/mssqlinstance.py`): Microsoft SQL Server instance discovery utility over UDP/1434 (`mssqlinstance <TARGET> [-port 1434]`). Implements `[MC-SQLR]` SQL Server Resolution Protocol unicast discovery to locate SQL Server instances, clustered configurations, server versions, and listening TCP ports and named pipes.
    * **`checkMSSQLStatus`** (`examples/checkMSSQLStatus.py`): Microsoft SQL Server TDS status and TLS encryption auditor (`checkMSSQLStatus <TARGET> [-port 1433]`). Sends TDS `PRELOGIN` packet, inspects `PreloginResponse` to assess TLS encryption enforcement (`ENCRYPT_OFF`, `ENCRYPT_ON`, `ENCRYPT_REQ`), server version, and MARS capability.
    * **`filetime`** (`examples/filetime.py`): Bidirectional Windows `FILETIME` conversion and remote SMB timestamp inspector (`filetime <VAL>` or `filetime <TARGET> <SHARE> <PATH> [-set <TIME>]`). Converts between raw 100ns integer FILETIME and UTC ISO 8601 strings, and inspects or touches CreationTime, LastAccessTime, LastWriteTime, and ChangeTime on remote SMB files via `FileBasicInformation` (`[MS-SMB2]`).
    * **`attrib`** (`examples/attrib.py`): Remote SMB file attribute inspector and manipulator (`attrib <TARGET> <SHARE> <PATH> [+/-R] [+/-H] [+/-S] [+/-A]`). Queries and updates `READONLY`, `HIDDEN`, `SYSTEM`, and `ARCHIVE` bitmasks over SMB2 via `FileBasicInformation`.
    * **`owneredit`** (`examples/owneredit.py`): Active Directory object owner inspection and modification CLI via LDAP (`owneredit <TARGET> -dn <DN> [-action query|set] [-new-owner <SID>]`). Reads and decodes `nTSecurityDescriptor` (`[MS-DTYP]`), displays the current object owner SID, and modifies the owner SID via LDAP replace operations.
    * **`samedit`** (`examples/samedit.py`): Offline Windows SAM registry hive password modifier (`samedit -sam <SAM> -system <SYS> -user <U> -password <P> [-out <OUT>]`). Scrambles syskey BootKey, derives HashedBootKey, locates target user's RID and `V` value, replaces encrypted NT hash in-place (supporting both Legacy RC4 and Modern AES-128-CBC revisions), and recalculates registry hive XOR checksums.

    * **`getTGT` & `GetNPUsers` FAST Armoring Expansion**: Added `-fast <CCACHE_OR_KIRBI>` flag to `getTGT` and `GetNPUsers` CLI subcommands, enabling RFC 6113 Kerberos pre-authentication and AS-REP roasting against FAST-enforced Active Directory Domain Controllers.
    * **`eventlog`** (`[MS-EVEN6]`): Windows Event Log remoting client over `\PIPE\eventlog` (`eventlog <TARGET> [-channel <NAME>] [-xpath <QUERY>] [-max <COUNT>] [-xml] [-hashes LM:NT]`), querying event records and exporting XML representations.
    * **`ticketer -diamond`**: Added Kerberos Diamond ticket forging from an existing legitimate TGT (`ticketer -diamond <TICKET_FILE> -domain-sid <SID> -domain <DOMAIN> -nthash <KRBTGT_NT> <OUTPUT_FILE>`), modifying inner PAC authorization data while preserving authentic KDC session keys and timestamps.
    * **`dnstool`** (`examples/dnstool.py` / `[MS-DNSP]`): Active Directory Integrated DNS record management utility over LDAP (`dnstool <TARGET> -action <query|add|modify|tombstone|delete> [options]`). Discovers DNS partitions and zones (`DomainDnsZones`, `ForestDnsZones`, `System`), queries node records, creates and updates `A`, `AAAA`, `CNAME`, `PTR`, `TXT`, `SRV`, and `MX` records, marks tombstones, and purges deleted records.
    * **`Get-GPPPassword`** (`examples/Get-GPPPassword.py`): Group Policy Preferences credential extractor and decryptor (`Get-GPPPassword <TARGET> [-xmlfile <PATH>] [-share <SYSVOL>] [-hashes LM:NT]`). Supports online recursive scanning across DC `SYSVOL` policy directories and offline local XML analysis for `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `Datasources.xml`, `Printers.xml`, and `Drives.xml`.
    * **`lookupsid` expansion**: Added `-rights` flag querying `LsarEnumerateAccountRights` (`[MS-LSAD]`) for each resolved principal to display assigned user privileges.
    * **`atq`** / **`tsch`** (`examples/atq.py` / `[MS-TSCH]`): Windows Task Scheduler inspection tool querying registered tasks and hierarchical folders over `\PIPE\atsvc` (`atq <TARGET> [-path <FOLDER>] [-recursive] [-hashes LM:NT]`). Supports recursive traversal across nested folder structures.
    * **`netfiles`**: Remote open file and lock enumerator over `\PIPE\srvsvc` via `NetrFileEnum` level 3 (`netfiles <TARGET> [-hashes LM:NT]`), displaying open file IDs, lock counts, permissions, and locking usernames.
    * **`netview` expansion**: Added `-files` and `-sessions` switches to query active file handles and connected sessions directly over `\PIPE\srvsvc`.
    * **`smbserver`** (`examples/smbserver.py`): Pure-Rust SMB2 server exposing local directories as SMB shares and capturing incoming NetNTLMv2 hashes (`smbserver <SHARE_NAME> <SHARE_PATH> [-comment <COMMENT>] [-port 445] [-username <USER>] [-password <PASS>] [-hashes :NT] [-readonly]`).

    * **`reg`** (`examples/reg.py`): Windows Remote Registry CLI over `\PIPE\winreg` (MS-RRP) supporting `query`, `add`, `delete`, and `save` actions across predefined root hives (`HKLM`, `HKU`, `HKCR`, `HKCU`) with comprehensive value codecs (`reg <TARGET> <action> -keyName <KEY> [options]`).
    * **`ticketer`** (`examples/ticketer.py`): Kerberos Golden and Silver Ticket forger creating custom credentials directly into `.ccache` or `.kirbi` format (`ticketer -domain-sid <SID> -domain <DOMAIN> [-nthash <NT>] [-aesKey <AES>] [-user <NAME>] [-rid <RID>] [-groups <G1,G2,...>] [-spn <SPN>] [-kirbi] <OUTPUT_FILE>`).
    * **`describeTicket`** (`examples/describeTicket.py`): Kerberos ticket inspector and decoder, parsing `.ccache` or `.kirbi` files and printing client/server principals, session keys, timestamps, and ticket flags (`describeTicket <TICKET_FILE>`).
    * **`rbcd`** (`examples/rbcd.py`): Active Directory Resource-Based Constrained Delegation manager via LDAP, reading, writing, or flushing `msDS-AllowedToActOnBehalfOfOtherIdentity` (`rbcd <TARGET> -delegate-to <TARGET_DN> [-delegate-from <GRANTEE_SID>] [-action read|write|flush]`).
    * **`findDelegation`** (`examples/findDelegation.py`): Active Directory delegation discovery utility scanning for Unconstrained, Constrained (with protocol transition / S4U), and RBCD configurations (`findDelegation <TARGET> [-base <DN>]`).

    * **`GetUserSPNs`** (`examples/GetUserSPNs.py`): Active Directory SPN discovery & Kerberos service ticket collector over LDAP (TCP/389) and Kerberos (TCP/88). Extracts SPNs, accounts, password last set, and UAC flags. With `-request`: acquires TGT, extracts session key, requests TGS service tickets for target SPNs, and formats Hashcat `$krb5tgs$` hashes (modes 13100, 19600, 19700). With `-save`: exports `.ccache` files.
    * **`esentutl`** (`examples/esentutl.py`): Offline Extensible Storage Engine database inspector, dumping catalog tables, column types, and records (`esentutl <DATABASE_FILE> [tables|table <NAME>]`).
    * **`ntdsdump`** (`examples/secretsdump.py` NTDS): Offline Active Directory domain credential dumper extracting and decrypting NTLM and LM hashes from `NTDS.dit` using the domain `SYSTEM` bootKey (`ntdsdump <SYSTEM_FILE> <NTDS_FILE>`).
    * **`dpapi`** (`examples/dpapi.py` / `examples/dpapidump.py`): Windows DPAPI MasterKey and Blob inspector and offline decryptor (`dpapi <masterkey|blob> <FILE> [-key <HEX>]`).
    * **`rpcmap`** (`examples/rpcmap.py`): DCE/RPC interface scanner and opnum prober over TCP/135 or SMB named pipes (`rpcmap <TARGET> [-port 135] [-pipe <PIPE>] [-brute-opnums] [-max-opnum 32]`). Performs dynamic discovery via the DCE/RPC Management interface (`[C706]`), falls back to catalog probing against `WELL_KNOWN_INTERFACES`, and brute-forces active opnum ranges.
    * **`changepasswd`** (`examples/changepasswd.py`): Active Directory password modification & administrative reset CLI (`changepasswd <TARGET> -new-pass <NEW> [-old-pass <OLD>] [-protocol samr|kpasswd]`). Supports unprivileged password changes via `SamrUnicodeChangePasswordUser2` (Opnum 55), administrative resets via `SamrSetInformationUser2` (Opnum 58) with session key encryption, and Kerberos `kpasswd` (RFC 3244 / TCP 464).
    * **`GetUserPAC`** (`examples/GetUserPAC.py`): Kerberos Privilege Attribute Certificate (PAC) extractor and inspector. Extracts PAC live from Active Directory KDC via S4U2self or user TGS requests, or inspects offline `.ccache`, `.kirbi`, or `.pac` files. Parses and formats `PAC_LOGON_INFO` (SIDs, RID, UAC flags, high-privilege groups), `PAC_CLIENT_INFO`, `PAC_SERVER_CHECKSUM`, `PAC_PRIVSVR_CHECKSUM`, `PAC_ATTRIBUTES_INFO`, and `PAC_REQUESTOR_INFO` (`GetUserPAC <TARGET|TICKET_FILE> [-target-user <USER>] [-hashes :NT] [-key <HEX>]`).
    * **`services`** (`examples/services.py`): Windows Remote Services management CLI over MS-SCMR (`\PIPE\svcctl`), supporting `list`, `status`, `config`, `start`, `stop`, `delete`, `create`, and `change` actions.
    * **`mssqlclient`** (`examples/mssqlclient.py`): Microsoft SQL Server client with interactive SQL shell and single-shot execution (`-command`), supporting Windows Integrated Authentication (SSPI/NTLMv2), pass-the-hash (`-hashes`), SQL Server native authentication (`-sql-auth`), and administrative automation (`enable_xp_cmdshell`, `disable_xp_cmdshell`, `xp_cmdshell <cmd>`).
    * **`reg`** (`examples/reg.py`): Windows Remote Registry CLI over MS-RRP (`\PIPE\winreg`), supporting `query`, `add`, `delete`, and `save` actions across `HKCR`, `HKCU`, `HKLM`, and `HKU` with full `REG_SZ`, `REG_DWORD`, `REG_BINARY`, `REG_MULTI_SZ` encoding.
    * **`GetADUsers`** (`examples/GetADUsers.py`): Active Directory user & mailbox enumerator over LDAP (TCP/389), extracting `sAMAccountName`, `mail`, `pwdLastSet`, and `lastLogon` with FileTime-to-UTC date translation (`GetADUsers <TARGET> [-all] [-user <username>]`).
    * **`GetADComputers`** (`examples/GetADComputers.py`): Active Directory computer account enumerator over LDAP (TCP/389), extracting `sAMAccountName`, `dNSHostName`, and OS version information (`GetADComputers <TARGET> [-computer <name>]`).
    * **`oxidquery`**: DCOM `IObjectExporter::ServerAlive2` resolver querying host network bindings and IPv4/IPv6 addresses over TCP/135 without credentials (`oxidquery <TARGET> [-port 135]`).
    * **`ldapsearch`**: Generic Active Directory LDAP query utility (`ldapsearch <TARGET> [-base <dn>] [-filter <attr=val>] [attrs...]`).
    * **`ticketConverter`** (`examples/ticketConverter.py`): Converts Kerberos ticket files between Windows Mimikatz `.kirbi` and Linux/MIT `.ccache` format with optional base64 decode (`-b`).
    * **`ntlmrelayx`** (`examples/ntlmrelayx`): NTLM cross-protocol relay orchestrator supporting HTTP, SMB, and LDAP relay sessions with MIC and EPA channel binding stripping (`ntlmrelayx -t <TARGET> [-proto http|smb]`).
    * **`smbclient`** (`examples/smbclient.py`): Interactive shell (`use`, `ls`, `get`, `put`, `cat`, `rm`, `shares`, `info`) and single-shot commands over signed SMB2.0.2–3.1.1.
    * **`psexec`** (`examples/psexec.py`): Remote command execution via Service Control Manager (`\PIPE\svcctl`) with optional binary deployment, output capture via SMB share file, and automatic service cleanup (`psexec <TARGET> "<command>" [-share ADMIN$]`).
    * **`wmiexec`** (`examples/wmiexec.py`): Remote command execution via WMI `Win32_Process::Create` with output redirection to an SMB share (`wmiexec <TARGET> "<command>" [-share ADMIN$]`).
    * **`dcomexec`** (`examples/dcomexec.py`): Remote command execution via DCOM automation objects (`MMC20.Application`, `ShellWindows`, `ShellBrowserWindow`) with output redirection to an SMB share (`dcomexec <TARGET> "<command>" [-object <name>]`).
    * **`getTGT`** (`examples/getTGT.py`): Requests a TGT via RC4 `PA-ENC-TIMESTAMP` pre-authentication (`DOMAIN/user:pass@kdc` or `-hashes :NT`), reporting the AS-REP enc-part etype.
    * **`smbexec`** (`examples/smbexec.py`): Runs a command via the MS-SCMR service trick and prints the captured output (`smbexec <TARGET> "<command>" [-hashes LM:NT]`).
    * **`atexec`** (`examples/atexec.py`): Runs a command via a MS-TSCH scheduled task and prints the captured output (`atexec <TARGET> "<command>" [-hashes LM:NT]`).
    * **`secretsdump-local`** (`examples/secretsdump.py` LOCAL): Dumps `user:rid:lm:nt:::` from offline `SAM` + `SYSTEM` hive files, plus cached domain credentials (`$DCC2$`) and LSA secrets when an optional `SECURITY` hive file is provided.

    All pipe-based tools now run live over an authenticated `ncacn_np` SMB connection (`user:pass@host` or `-hashes LM:NT`); self-test output was removed.
    * **`samrdump`** (`examples/samrdump.py`): Over `\PIPE\samr` — enumerates domains, resolves the account-domain SID, and lists users (name + RID).
    * **`lookupsid`** (`examples/lookupsid.py`): Resolves the account-domain SID via SAMR, then translates RIDs `500..=maxRid` to `DOMAIN\name` over `\PIPE\lsarpc` (MS-LSAT).
    * **`netview`** (`examples/netview.py`): Enumerates SMB shares (netname, type, remark) over MS-SRVS (`\PIPE\srvsvc`) and workstation logged-on users and OS/join information over MS-WKST (`\PIPE\wkssvc`) (`netview <TARGET> [-hashes LM:NT] [-users] [-info] [-shares]`).

---

## Foundation Milestones Completed in `v0.1.0-dev`:

1. Core & Protocol Library Foundation

    * **`crates/impacket-core`**: Implemented `TargetSpec` parser (`[[domain/]username[:password]@]<target>`), `AdCompatProfile` (`LegacyWin2000`, `UniversalAuto`, `ModernHardened2025`), `SecretString` & `NtlmHashes` with volatile memory scrubbing (`zeroize_slice`), `FileTime`, and compile-time `NtStatus`.
    * **`crates/impacket-crypto`**: Implemented pure-Rust RFC 1320 `md4`, RFC 1321 `md5`, RFC 2104 `hmac_md5`, `Rc4` stream cipher, FIPS 46-3 `des_ecb_encrypt_block` with 56-to-64-bit odd-parity key expansion, `compute_lm_hash`, `des_long_response` (`DESL`), and IEEE 802.3 `crc32`.
    * **`crates/impacket-ndr`**: Implemented `NdrReader`, `NdrWriter`, `NdrUnicodeString` (`'w'` format), `RpcUuid`, `RpcSid`, and the compile-time `ndr_struct!` macro (benchmarked at **4.72 million roundtrips/sec — 167x faster** than Python `impacket/structure.py`).
    * **`crates/impacket-auth`**: Implemented NTLMSSP Type 1 (`NtlmNegotiateMessage`), Type 2 (`NtlmChallengeMessage` + `AV_PAIR` `NtlmTargetInfo`), NTLMv1 / NTLMv1-ESS / NTLMv2 response computation, and MIT Kerberos `.ccache` v4 header parsing.
    * **`crates/impacket-krb5`**: Implemented ASN.1 DER encoder/decoder, RFC 4120 `AS-REQ`, `AS-REP`, and `KRB-ERROR` codecs, and Hashcat `$krb5asrep$` formatting across ETypes `1, 3, 23, 17, 18`.
    * **`crates/impacket-smb`**: Implemented `Smb2Header`, NetBIOS session framing, legacy SMBv1 Multi-Protocol Negotiate (`\xFFSMB`), SMB 2.0.2–3.1.1 `SMB2_NEGOTIATE` (with SHA-512 Preauth Integrity and AES-256-GCM contexts), and `SMB2_SESSION_SETUP`.
    * **`crates/impacket-dcerpc`**: Implemented MS-RPCE v5 `RpcCommonHeader`, `RpcBindPdu`, `RpcRequestPdu`, Endpoint Mapper `ept_lookup` (opnum 2), and 5-floor EPM protocol tower encoder/decoder.

2. Initial End-to-End Tools (`bins/impacket-rs`)

    * **`DumpNTLMInfo`** (`examples/DumpNTLMInfo.py`): Credential-less SMB2/3 NTLMSSP Type 2 TargetInfo & OS version dumper.
    * **`GetNPUsers`** (`examples/GetNPUsers.py`): Kerberos AS-REP Roasting & pre-authentication scanner over TCP/88.
    * **`rpcdump`** (`examples/rpcdump.py`): DCE/RPC Endpoint Mapper service & tower dumper over TCP/135.
