# Impacket-RS — Work Handoff

Resume point for the Python-Impacket → Rust port. When you say "continue", pick up at
**Next step** below.

## How to verify state
```bash
cd /Users/nestho/impacket-rs
cargo build --workspace     # zero warnings
cargo test --workspace      # currently 171+ passing
```
Do NOT run `graft build` without explicit confirmation.

## Current Tool Count (70 Subcommands / 60 End-to-End Tools)
- Group 4 Tools (Remote Execution, Relaying & Search): `wmipersist`, `wspsearch`, `smbclient` (batch scripts & headless mode), `ntlmrelayx` (multi-target `-tf` routing).
- Group 3 Tools (Network, RPC & Discovery Services): `netview` (multi-target & domain crawl), `findDelegation` (graph & JSON export), `reg` (tree dump & `.reg` export), `tracer`, `sniffer` (offline PCAP parser & dissectors).
- Group 2 Tools (Kerberos, Admin & Network Suite): `klist`, `net`, `wmiquery`, `rdp_check`, `registry-read`, `getPac`, `tstool`, `getST`, `ping`, `mqtt_check`.
- Group 1 Tools (Admin, Recon & Config): `GetLAPSPassword`, `CheckLDAPStatus`, `getArch`, `machine_role`, `mssqlinstance`, `checkMSSQLStatus`, `filetime`, `attrib`, `owneredit`, `samedit`.
- Kerberos Suite: `GetUserPAC`, `GetNPUsers` (with RFC 6113 `-fast` armoring), `GetUserSPNs`, `getTGT` (with `-fast` armoring & PKINIT), `getST` (with S4U and U2U `ENC-TICKET-IN-SKEY`), `ticketer` (Golden, Silver, and Diamond tickets), `describeTicket`, `ticketConverter`, `klist`.
- Remote Event Log: `eventlog` (`[MS-EVEN6]` Windows Event Log remoting over `\PIPE\eventlog` with XPath filtering & XML reconstruction).
- Distributed File System: `dfsclient` (`dfssearch` Active Directory DFS namespace & referral targets manager over `\PIPE\netdfs`).
- Active Directory Integrated DNS: `dnstool` (MS-DNSP DNS record query, add, modify, tombstone, delete over LDAP).
- Active Directory & LDAP Administration: `ldapclient` (`ldap_shell` interactive administrative shell REPL), `GetADUsers`, `GetADComputers`, `ldapsearch`, `rbcd`, `findDelegation`, `addcomputer`, `dacledit`.
- Group Policy Preferences: `Get-GPPPassword` (online SYSVOL DC crawler & offline XML GPP AES-256 cpassword decryptor).
- Server & Credential Sniffing: `smbserver` (pure-Rust SMB2 file/IPC server & NetNTLMv2 credential sniffer).
- Scheduled Tasks: `tstool`, `atq` (MS-TSCH scheduled task and folder hierarchy inspector), `atexec`.
- Password Management: `changepasswd` (modify or reset passwords via MS-SAMR or Kerberos kpasswd TCP/464).
- Services Management: `services` (list, status, config, start, stop, create, delete, change over `\PIPE\svcctl`).
- Database & TDS: `mssqlclient` (interactive SQL shell, single-shot query, Windows NTLM/SSPI auth, SQL auth, pass-the-hash, `xp_cmdshell` execution).
- Remote Registry: `registry-read`, `reg` (query, dump, export, add, delete, save over `\PIPE\winreg` across `HKLM`, `HKCU`, `HKCR`, `HKU`).
- Execution: `psexec`, `smbexec`, `atexec`, `wmiexec`, `dcomexec`, `wmipersist`.
- Credentials & Offline Analysis: `secretsdump`, `secretsdump-local`, `ntdsdump`, `esentutl`, `dpapi`.
- RPC & Network Recon: `DumpNTLMInfo`, `rpcdump`, `rpcmap`, `oxidquery`, `lookupsid`, `samrdump`, `netview`, `netfiles`, `smbclient`, `net`, `wmiquery`, `rdp_check`, `ping`, `tracer`, `sniffer`, `mqtt_check`, `wspsearch`.
- Relay Suite: `ntlmrelayx` (multi-target routing table).

## Latest Additions
- **Group 4 Tools (`bins/impacket-rs`, `crates/impacket-relay`, `crates/impacket-smb`)**:
  - `wmipersist`: WMI persistence and event subscription manager supporting `list`, `info`, and `remove` for `__EventFilter`, `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, and `__FilterToConsumerBinding` in `root\subscription`.
  - `wspsearch`: Remote Windows Search Protocol client querying `SystemIndex` catalogs across filenames, file sizes, and paths.
  - `smbclient`: Headless automation with `-batch <FILE>` and `-c "<cmd1>; <cmd2>"` executing commands unattended.
  - `ntlmrelayx`: Multi-target relaying with `-tf <TARGETS_FILE>` routing table dispatch across SMB, LDAP, MSSQL, and HTTP with MIC stripping and channel binding removal.
- **Group 3 Tools & Protocol Suite (`crates/impacket-msrpc`, `crates/impacket-ldap`, `bins/impacket-rs`)**:
  - `netview`: Multi-target crawler via `-targets <FILE>`, domain-wide computer crawl via `-domain` over LDAP, user hunting via `-check-user <USER>`, and file lock enumeration via `-files` over MS-SRVS (`\PIPE\srvsvc`).
  - `findDelegation`: Active Directory delegation discovery with ASCII trust graph rendering (`-graph`) and BloodHound/SIEM JSON export (`-json`).
  - `reg`: Windows Remote Registry CLI with recursive registry tree dump (`reg dump`) and standard Windows Registry Editor (`Windows Registry Editor Version 5.00`) `.reg` export (`reg export`), powered by `RrpClient::enum_all_values` and `RrpClient::enum_all_subkeys`.
  - `tracer`: TCP SYN/connect traceroute network hop probing across configurable ports, timeouts, and max hops.
  - `sniffer`: Pure-Rust offline PCAP packet parser (`-pcap <FILE>`), port filter (`-filter <PORT>`), and synthetic benchmark test suite (`-test`) dissecting SMB2/3, DCE/RPC, Kerberos, LDAP, TDS, and MQTT frames.
- **Group 2 Tools & Protocol Suite (`crates/impacket-msrpc`, `crates/impacket-krb5`, `bins/impacket-rs`)**:
  - `klist`: Kerberos credential cache inspector supporting both Linux MIT `.ccache` v4 and Windows Mimikatz `.kirbi` (KRB-CRED App 22) formats, reading from file or `$KRB5CCNAME`, formatting validity windows, encryption types, ticket flags, session keys, and ticket sizes.
  - `net`: Remote Windows `net.exe` administrative CLI over MS-SAMR and MS-SRVS (`net user`, `net user -name <U>`, `net group`, `net group -name <G>`, `net localgroup`, `net localgroup -name <L>`, `net share`, `net session`).
  - `wmiquery`: WMI / WQL query client and schema inspector over remote WMI executing WQL queries (`SELECT * FROM <Class>`) and formatting tabular output.
  - `rdp_check`: Remote Desktop Protocol connection and security protocol auditor (`[MS-RDPBCGR]`). Negotiates X.224 Connection Request/Confirm with `RDP_NEG_REQ`/`RDP_NEG_RSP`/`RDP_NEG_FAILURE` to audit TLS and CredSSP NLA enforcement on port 3389.
  - `registry-read`: Windows Registry reader for both offline registry hive files and live remote Windows hosts over MS-RRP (`\PIPE\winreg`) with formatted value codecs (`REG_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_MULTI_SZ`, `REG_BINARY`).
  - `getPac`: Active Directory Kerberos PAC acquisition via S4U2self + U2U (`[MS-SFU]` + RFC 4120 U2U) and offline ticket PAC validation inspection.
  - `tstool`: Windows Terminal Services and Task Scheduler inspection utility (`tstool <TARGET> [-action list|info|xml|delete|run]`).
  - `ping` / `ping6`: Network latency and TCP reachability prober with roundtrip timing statistics (min/avg/max/stddev).
  - `mqtt_check`: MQTT 3.1.1 protocol broker status, broker discovery, and authentication auditor over TCP/1883.
  - SAMR Global Group & Local Alias wire codecs: `SamrEnumerateGroupsInDomain` (Opnum 8), `SamrOpenGroup` (Opnum 19), `SamrGetMembersInGroup` (Opnum 25), `SamrEnumerateAliasesInDomain` (Opnum 15), `SamrOpenAlias` (Opnum 27), `SamrGetMembersInAlias` (Opnum 33), `SamrCloseHandle` (Opnum 1).
- **Group 1 Tools & Protocol Engines (`crates/impacket-dcerpc`, `crates/impacket-mssql`, `crates/impacket-smb`, `crates/impacket-sam`, `crates/impacket-ldap`, `bins/impacket-rs`)**:
  - `GetLAPSPassword`: Queries Active Directory legacy LAPS (`ms-Mcs-AdmPwd`) and Windows LAPS (`msLAPS-Password` JSON payload) across computers via LDAP with FileTime-to-UTC conversion.
  - `CheckLDAPStatus`: Audits LDAP RootDSE metadata and tests anonymous bind rejection / `strongAuthRequired` to identify signing enforcement and NTLM relay vulnerability.
  - `getArch`: Probes remote OS architecture (32-bit x86 vs 64-bit x64) via `NDR64_SYNTAX_UUID` bind over TCP/135.
  - `machine_role`: Queries workstation/server domain-join status, role, and OS version via `NetrGetJoinInformation` and `NetrWkstaGetInfo` (`[MS-WKST]`).
  - `mssqlinstance`: Discovers SQL Server instances, clustered setups, versions, and ports via `[MC-SQLR]` over UDP/1434.
  - `checkMSSQLStatus`: Inspects MSSQL TDS pre-login packets for TLS encryption requirements (`ENCRYPT_OFF`, `ENCRYPT_ON`, `ENCRYPT_REQ`), server version, and MARS support.
  - `filetime`: Converts between raw 100ns FileTime integers and UTC ISO 8601 strings, and queries/modifies remote SMB file timestamps via `FileBasicInformation` (`[MS-SMB2]`).
  - `attrib`: Queries and modifies remote SMB file attributes (`READONLY`, `HIDDEN`, `SYSTEM`, `ARCHIVE`) over SMB2.
  - `owneredit`: Queries and modifies Active Directory object owner SIDs via LDAP `nTSecurityDescriptor` (`[MS-DTYP]`).
  - `samedit`: Modifies local user passwords directly in offline SAM and SYSTEM registry hives in-place (supporting both Legacy RC4 and Modern AES-128-CBC revisions) and recalculates base block checksums.
- **`[MS-DFSNM]` Distributed File System Namespace Management (`dfsclient` / `dfssearch` & `crates/impacket-msrpc::dfsnm`)**:
  - `DfsClient` implementing `[MS-DFSNM]` interface `4FC742E0-4A10-11CF-8273-00AA004AE673` v3.0 over `\PIPE\netdfs` and TCP RPC.
  - RPC operations: `NetrDfsGetManagerVersion` (Opnum 0), `NetrDfsAdd` (Opnum 1), `NetrDfsRemove` (Opnum 2), `NetrDfsGetInfo` (Opnum 4), and `NetrDfsEnum` (Opnum 5).
  - Codecs and models: `DfsInfo1`, `DfsInfo2`, `DfsInfo3`, `DfsStorageInfo`, and `DfsInfo300`.
  - CLI subcommand in `bins/impacket-rs`: `dfsclient` / `dfssearch <TARGET> [-enum|-info <PATH>|-add|-remove]`.
- **Interactive Active Directory Administrative Shell (`ldapclient` / `ldap_shell` & `crates/impacket-ldap::shell`)**:
  - `LdapShellSession` interactive REPL shell over LDAP/LDAPS.
  - Commands implemented: `whoami`, `search`, `get_user_groups` (`1.2.840.113556.1.4.1941`), `get_group_users`, `get_laps_password`, `add_user`, `add_computer`, `add_user_to_group`, `remove_user_from_group`, `change_password` (UTF-16LE `unicodePwd`), `enable_account`, `disable_account`, `set_dontreqpreauth`, `set_rbcd`, `clear_rbcd`, `dump`.
  - Added quoted command-line tokenizer `parse_command_tokens`.
  - CLI subcommands in `bins/impacket-rs`: `ldapclient` / `ldap_shell`, `GetADComputers`, `ldapsearch`.
- **Kerberos User-to-User (U2U) Authentication Suite (`[MS-KILE]` / RFC 4120 §3.7) (`crates/impacket-krb5::tgs`)**:
  - `Krb5TgsReq::with_u2u`: Sets `enc-tkt-in-skey` (`0x0000_0008`) and embeds server TGT in `additional_tickets` (`[11]`).
  - Added `decrypt_u2u_ticket_enc_part`: Decrypts U2U service ticket `enc-part` using server TGT session key (Key Usage 2 `KU_TICKET`).
  - CLI integration: Added `-u2u <SERVER_TGT_FILE>` flag to `getST`.
- **SMB Direct / RDMA Transport Abstraction (`[MS-SMBD]`) (`crates/impacket-smb::smbd`)**:
  - `SmbdNegotiateReq` (`[MS-SMBD] 2.2.1.1`, 16 bytes), `SmbdNegotiateResp` (`[MS-SMBD] 2.2.1.2`, 32 bytes).
  - `SmbdDataTransfer` (`[MS-SMBD] 2.2.2.1`, 24 bytes header with 4-byte SMB2 payload alignment padding).
  - `SmbdBufferDescriptorV1` (`[MS-SMBD] 2.2.3.1`, 16 bytes RDMA memory registration).
  - `SmbdMessageReassembler` managing multi-fragment frame assembly.
  - `SmbdTransport<S>` providing client negotiation, frame sending, and stream reading over TCP/5445.
- **`RpcSid` Binary Wire Encoders (`crates/impacket-ndr`)**:
  - Added `RpcSid::from_le_bytes` and `RpcSid::to_le_bytes` implementing `[MS-DTYP]` 2.4.2 raw binary SID parsing and serialization.
- **Kerberos Flexible Authentication Secure Tunneling (FAST) Suite (RFC 6113 & `crates/impacket-krb5::fast`)**:
  - `prf_aes128` and `prf_aes256`: RFC 3961 §5.3 PRF using AES-ECB over truncated SHA-1 digest with `K_prf = DK(key, "prf")`.
  - `prf_plus_aes128` and `prf_plus_aes256`: RFC 6113 §5.1 variable-length PRF+ expansion generators.
  - `krb_fx_cf2_aes128` and `krb_fx_cf2_aes256`: RFC 6113 §5.1 key combiner functions.
  - Wire codecs: `KrbFastArmor` (`FX_FAST_ARMOR_AP_REQUEST = 1`), `KrbFastArmoredReq`, `EncKrbFastReq` (encapsulating `KdcReqBody` and pre-auth data), `KrbFastArmoredRep`, and `EncKrbFastRep`.
  - Armoring engine: `build_fast_armored_as_req` building AP-REQ with authenticators, keyed `req-checksum` (Key Usage 51) over `KdcReqBody`, encrypting `EncKrbFastReq` (Key Usage 52), wrapping into `PA-FX-FAST` (136) and `PA-FX-COOKIE` (133), and generating outer AS-REQ with Anonymous principal (`WELLKNOWN/ANONYMOUS`).
  - Response processing: `decrypt_fast_rep` (Key Usage 53), `extract_fast_cookie`, `extract_pa_fx_fast_reply`.
  - Live client: `send_fast_armored_as_req_live` driving live TCP/88 exchanges.
  - CLI integration: Added `-fast <CCACHE_OR_KIRBI>` flag to `getTGT` and `GetNPUsers` in `bins/impacket-rs`.
- **`[MS-EVEN6]` Windows EventLog Remoting Protocol v6.0 (`eventlog` & `crates/impacket-msrpc::even6`)**:
  - Interface `F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C` v1.0 over `\PIPE\eventlog` or dynamic TCP.
  - `EvtRpcRegisterLogQuery` (Opnum 5), `EvtRpcQueryNext` (Opnum 11) with multi-event batch unmarshaling, and `EvtRpcClose` (Opnum 13).
  - `EvtEventRecord`: Decodes event IDs, channels, computer names, providers, timestamps, and substitution strings from Windows EventLog byte streams into reconstructed XML and formatted summaries.
  - CLI subcommand in `bins/impacket-rs`: `eventlog <TARGET> [-channel <NAME>] [-xpath <QUERY>] [-max <COUNT>] [-xml] [-hashes LM:NT]`.
- **Kerberos Diamond Ticket Forgery Engine (`crates/impacket-krb5::ticketer`)**:
  - Added `forge_diamond_ticket`: Decrypts a genuine KDC-issued TGT (`.ccache` or `.kirbi`) with the `krbtgt` key (Key Usage 2 `KU_TICKET`), modifies inner PAC group memberships and user RIDs, recalculates valid Server and KDC PrivSvr signatures, and re-encrypts the ticket while preserving genuine KDC timestamps and session structures.
  - CLI subcommand in `bins/impacket-rs`: `ticketer -diamond <TICKET_FILE> -domain-sid <SID> -domain <DOMAIN> -nthash <KRBTGT_NT> <OUTPUT_FILE>`.
- **`[MS-DNSP]` Active Directory Integrated DNS Management Suite (`dnstool` & `crates/impacket-ldap::dnsp`)**:
  - `DnsRpcRecord` codec per `[MS-DNSP] 2.3.2.2`: Full parsing and serialization for binary `dnsRecord` attributes on `dnsNode` LDAP objects.
  - Record types supported: `A`, `AAAA`, `CNAME`, `PTR`, `TXT`, `SRV`, `MX`, and `Tombstone`.
  - DNS wire label codec per `[MS-DNSP] 2.2.2.1.1`: `encode_dns_rpc_name` and `decode_dns_rpc_name`.
  - AD partition and zone walker: `list_dns_zones` discovering zones in `DomainDnsZones`, `ForestDnsZones`, and legacy `System`.
  - Management API: `query_dns_node`, `add_dns_node`, `modify_dns_node`, `tombstone_dns_node`, `delete_dns_node`.
  - CLI subcommand in `bins/impacket-rs`: `dnstool <TARGET> -action <query|add|modify|tombstone|delete> [options]`.
- **Group Policy Preferences (GPP) `cpassword` Decryption Engine (`Get-GPPPassword` & `crates/impacket-sam::gpp`)**:
  - Static AES-256 key implementation (`[0x4e, 0x99, 0x06, 0xe8, ...]`).
  - Base64 padding normalization, null IV CBC decryption, and PKCS#7 unpadding to extract plaintext UTF-16LE passwords.
  - GPO XML definitions parser: `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `Datasources.xml`, `Printers.xml`, and `Drives.xml`.
  - CLI subcommand in `bins/impacket-rs`: `Get-GPPPassword <TARGET> [-xmlfile <PATH>] [-share <SYSVOL>] [-hashes LM:NT]`.

## 100% Example & Protocol Parity Achieved
All Python Impacket tools and protocols are fully ported to pure-Rust in `impacket-rs`.
- Total subcommands: 70
- All crates compile cleanly with 0 warnings.
- 173 automated unit & integration tests pass across the entire workspace.

## Next step (START HERE on "continue")
1. **Packaging, Benchmarks & Release Polish**:
   - Run end-to-end performance benchmarks (`bench-ndr`, throughput across SMB2/3 and RPC engines).
   - Verify CLI documentation and `--help` output across all 70 subcommands.
   - Prepare SemVer release tag `v0.1.0`.
