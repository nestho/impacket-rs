# Impacket-RS: Complete Crate Design, Cross-Era AD Compatibility & Implementation Plan

## 1. Software Engineering Versioning Standard (SemVer + Python Impacket Convention)

Rather than incrementing `+0.1` after every individual file or module commit, **Impacket-RS** follows **Semantic Versioning 2.0.0 (`MAJOR.MINOR.PATCH`)** combined with Python Impacket's release model (`impacket/version.py` & `ChangeLog.md`):
- **Active Development (`0.MINOR.0-dev` + `## Unreleased` in `CHANGELOG.md`)**: Every new module, MSRPC interface, or CLI tool is recorded immediately under `## Unreleased` in `CHANGELOG.md` (split into `1. Library improvements` and `2. New examples / CLI tools`) while `Cargo.toml` carries the pre-release tag (`0.1.0-dev`).
- **Milestone Releases (`v0.1.0`, `v0.2.0`, ..., `v1.0.0`)**: Only when a full architectural milestone passes all unit, cross-era compatibility, and protocol exchange tests do we cut a minor version bump (`0.1.0` → `0.2.0`), matching how Python Impacket releases `v0.11.0` → `v0.12.0` → `v0.13.0` → `v0.13.1`.
- **Patch Releases (`0.1.1`, `0.1.2`)**: Reserved strictly for bug fixes, protocol edge-case fixes, or security patches without breaking API changes.

---

## 2. Whole-Picture Architecture & Live Engineering Status (`v0.1.0-dev`)

```text
====================================================================================================================
TIER 4: CLI & INTERFACE LAYER (`bins/impacket-rs`) — [24 Subcommands / 18 End-to-End Tools Completed]
  ✅ [FINISHED] DumpNTLMInfo     (SMB2/3 Negotiate + SessionSetup + NTLMSSP Type 2 AV_PAIR host/domain discovery)
  ✅ [FINISHED] GetNPUsers       (Kerberos v5 AS-REQ / AS-REP Roasting & Hashcat -m 18200 / AES output)
  ✅ [FINISHED] GetADUsers       (Active Directory user & mailbox enumerator over LDAP TCP/389)
  ✅ [FINISHED] GetADComputers   (Active Directory computer account enumerator over LDAP TCP/389)
  ✅ [FINISHED] ldapsearch       (Generic Active Directory LDAP search utility over TCP/389)
  ✅ [FINISHED] getTGT           (Kerberos v5 AS-REQ RC4 PA-ENC-TIMESTAMP pre-authentication)
  ✅ [FINISHED] ticketConverter  (Windows Mimikatz .kirbi <-> Linux/MIT .ccache v4 bidirectional conversion)
  ✅ [FINISHED] ticketer         (Forge Kerberos Golden and Silver Tickets directly into .ccache or .kirbi)
  ✅ [FINISHED] describeTicket   (Inspect and decode Kerberos .ccache or .kirbi ticket structures)
  ✅ [FINISHED] rbcd             (Configure and inspect Resource-Based Constrained Delegation via LDAP)
  ✅ [FINISHED] findDelegation   (Active Directory delegation discovery: Unconstrained, Constrained, RBCD)
  ✅ [FINISHED] rpcdump          (MS-RPCE v5 Bind + ept_lookup opnum 2 + 5-floor EPM Tower decoder)
  ✅ [FINISHED] oxidquery        (DCOM IObjectExporter ServerAlive2 multi-homed network interface resolver)
  ✅ [FINISHED] lookupsid        (MS-LSAT \PIPE\lsarpc SID/RID brute-forcer; Win2000 opnum 6 & Modern opnum 44)
  ✅ [FINISHED] samrdump         (MS-SAMR \PIPE\samr domain & user policy dumper; Win2000 opnum 0 & Modern opnum 64)
  ✅ [FINISHED] netview          (MS-SRVS \PIPE\srvsvc share enumerator)
  ✅ [FINISHED] smbclient        (Interactive shell + single-shot ls/get/put/cat/rm over signed SMB2.0.2–3.1.1)
  ✅ [FINISHED] smbexec+atexec    (Service & Task execution via MS-SCMR & MS-TSCH)
  ✅ [FINISHED] psexec+wmiexec+dcomexec (Remote execution via MS-SCMR, WMI Win32_Process, and DCOM automation)
  ✅ [FINISHED] GetUserSPNs      (Active Directory SPN discovery & Kerberoast ticket collector over LDAP + TCP/88)
  ✅ [FINISHED] secretsdump      (Remote MS-RRP hive save + download + offline regf/SAM decrypt; plus secretsdump-local)
  ✅ [FINISHED] ntdsdump+esentutl (Offline NTDS.dit password hash dumper & ESE database inspector)
  ✅ [FINISHED] dpapi            (Windows DPAPI MasterKey and Blob decryptor)
  ✅ [FINISHED] ntlmrelayx       (NTLM cross-protocol relay orchestrator for HTTP/SMB/LDAP/MSSQL)
====================================================================================================================
                                                        ▲
                                                        │
====================================================================================================================
TIER 3: HIGH-LEVEL FEATURE & INTERFACE CRATES — [FINISHED]
  ✅ [FINISHED] crates/impacket-msrpc   (real [MS-SAMR]/[MS-LSAT]/[MS-SRVS]/[MS-SCMR]/[MS-TSCH]/[MS-RRP] wire + live ncacn_np)
  ✅ [FINISHED] crates/impacket-sam     (Offline SAM/SYSTEM regf hive parser, bootkey & user hash decrypt, DPAPI, NTDS ESE)
  ✅ [FINISHED] crates/impacket-ldap    (AD LDAP/LDAPS query engine, RFC 4511 BER codec, [MS-DTYP] Security Descriptor/ACL engine)
  ✅ [FINISHED] crates/impacket-dcom    (DCOM ORPC framing, COMVERSION, DUALSTRINGARRAY, IObjectExporter ServerAlive/ServerAlive2)
  ✅ [FINISHED] crates/impacket-relay   (NTLM cross-protocol relay engine, MIC & EPA stripping, HTTP/SMB/LDAP adapters)
====================================================================================================================
                                                        ▲
                                                        │
====================================================================================================================
TIER 2: SANS-I/O & LIVE STREAM PROTOCOL ENGINES — [FINISHED]
  ✅ [FINISHED] crates/impacket-auth    (NTLMSSP Type 1/2/3, AV_PAIRs, LMv1/NTLMv1/ESS/NTLMv2, ccache v4)
  ✅ [FINISHED] crates/impacket-krb5    (ASN.1 DER codec, AS-REQ/AS-REP/KRB-ERROR, Hashcat formatter, TCP/88)
  ✅ [FINISHED] crates/impacket-smb     (SMBv1 upgrade, SMB 2.0.2–3.1.1 Negotiate, SessionSetup, TreeConnect, Named Pipes)
  ✅ [FINISHED] crates/impacket-dcerpc  (MS-RPCE v5 Bind/BindAck/Request/Response, EPM ept_lookup & Tower codec)
====================================================================================================================
                                                        ▲
                                                        │
====================================================================================================================
TIER 1: CORE FOUNDATION CRATES (Zero Network/OS Dependencies) — [FINISHED]
  ✅ [FINISHED] crates/impacket-core    (version::BANNER, TargetSpec, AdCompatProfile Win2000->Win2025, NtStatus, FileTime)
  ✅ [FINISHED] crates/impacket-crypto  (Pure-Rust MD4, MD5, HMAC-MD5, RC4, DES-56 LM/SAM/DESL, CRC32)
  ✅ [FINISHED] crates/impacket-ndr     (NdrReader, NdrWriter, NdrUnicodeString, RpcSid, RpcUuid, ndr_struct!)
====================================================================================================================
```

---

## 3. Module & Tool Progress Tracker (Finished vs. Remaining Work)

| Layer / Crate | Component / Tool | Status | AD Compatibility (Win2000 → Win2025) | What Is Finished vs. What Remains to Build |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1: Core** | `impacket-core` | ✅ **Finished** | Win2000 → Win2025 | **Done**: `version::BANNER`, `TargetSpec`, `AdCompatProfile`, `SecretString`/`NtlmHashes` zeroize, `FileTime`, `NtStatus`. |
| **Tier 1: Crypto** | `impacket-crypto` | ✅ **Finished** | Win2000 → Win2025 | **Done**: Pure-Rust DES-56/ECB, LM hash, `DESL`, MD4, MD5, HMAC-MD5, RC4, CRC32, AES-128/256 (ECB, CBC, CTS-CS3), SHA-1, SHA-256, SHA-512, HMAC-SHA1/256, AES-CMAC, PBKDF2. **To Do**: AES-GCM & AES-CCM. |
| **Tier 1: NDR** | `impacket-ndr` | ✅ **Finished** | NDR32 (`MS-RPCE` v2.0) | **Done**: `NdrReader`, `NdrWriter`, `NdrUnicodeString`, `RpcSid`, `RpcUuid`, `ndr_struct!` (167x faster than Python). |
| **Tier 2: Auth** | `impacket-auth` | ✅ **Finished** | LMv1/NTLMv1/ESS/NTLMv2/EPA | **Done**: Type 1, Type 2 + `AV_PAIR` parser, NTLMv1/ESS/v2 response math, `.ccache` v4, SPNEGO `NegTokenInit`/`NegTokenResp` ASN.1 wrapper. |
| **Tier 2: Krb5** | `impacket-krb5` | ✅ **Finished** | ETypes `1, 3, 23, 17, 18` | **Done**: DER codec, `AS-REQ`, `AS-REP`, `KRB-ERROR`, Hashcat formatter, `GetNPUsers`, `PA-ENC-TIMESTAMP` (`getTGT`), `TGS-REQ` (`GetUserSPNs`), RFC 3962 AES-128/256-CTS suite, and Golden/Silver ticket forger (`ticketer`, `describeTicket`). |
| **Tier 2: SMB** | `impacket-smb` | ✅ **Finished** | SMBv1 + `0x0202`–`0x0311` | **Done**: `NEGOTIATE`, `SESSION_SETUP`, `TREE_CONNECT` (`IPC$`), `CREATE` (Named Pipes), `IOCTL` (`FSCTL_PIPE_TRANSCEIVE`), file read/write, directory query, tree disconnect, logoff. |
| **Tier 2: RPC** | `impacket-dcerpc` | ✅ **Finished** | MS-RPCE v5 | **Done**: `Bind`, `BindAck`, `Request`, `Response`, `RpcResponsePdu`, `RpcFault`, `extract_response_stub`, multi-fragment reassembly, `ept_lookup` opnum 2, 5-floor Tower parser, `rpcdump`. **To Do**: `PKT_PRIVACY` Sign/Seal trailer. |
| **Tier 3: MSRPC** | `impacket-msrpc` | ✅ **Finished** | Win2000 → Win2025 | **Done**: `MS-LSAD`/`MS-LSAT` (`lookupsid` opnum 6 & 44), `MS-SAMR` (`samrdump` opnum 0 & 64), `MS-SRVS` (`netview` opnum 15), `MS-SCMR` (`smbexec`), `MS-TSCH` (`atexec`), `MS-RRP` (`secretsdump`), and `MS-DRSR` (`dcsync` opnum 0, 1, 3, 12, 16). |
| **Tier 3: SAM** | `impacket-sam` | ✅ **Finished** | Win2000 → Win2025 | **Done**: Offline Registry Hive (`SAM`/`SYSTEM`/`SECURITY` `regf` parser), BootKey recovery, user hash decryption, LSA key recovery, Netlogon key (`NL$KM`), cached credentials (`$DCC2$`), LSA secrets, DPAPI MasterKey/Blob decryption, and `NTDS.dit` ESE B-tree parser. |
| **Tier 3: LDAP** | `impacket-ldap` | ✅ **Finished** | Win2000 → Win2025 | **Done**: RFC 4511 ASN.1 BER message codec (including ModifyRequest/Response), search filter combinators, `[MS-DTYP]` §2.4.6 Security Descriptor/ACL engine, live `LdapClient`, `GetADUsers`, `GetADComputers`, `ldapsearch`, Resource-Based Constrained Delegation (`rbcd`), and delegation scanner (`findDelegation`). |
| **Tier 3: DCOM** | `impacket-dcom` | ✅ **Finished** | Win2000 → Win2025 | **Done**: `[MS-DCOM]` ORPC framing (`ORPCTHIS`, `ORPCTHAT`), `COMVERSION`, `DUALSTRINGARRAY`, `IObjectExporter` (`ServerAlive`, `ServerAlive2`, `oxidquery`). **To Do**: `IRemUnknown`, `IActivation` (`dcomexec`, `wmiexec`). |
