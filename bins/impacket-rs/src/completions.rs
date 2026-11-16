//! Shell auto-completion generation for Bash, Zsh, Fish, and PowerShell.

pub const SUBCOMMANDS: &[(&str, &str)] = &[
    ("DumpNTLMInfo", "Dump remote host NetBIOS, DNS computer name, domain name, forest, and OS version without authentication"),
    ("GetNPUsers", "Harvest non-preauth AS-REP hashes for Kerberoasting / offline cracking (ASREPRoast)"),
    ("GetUserSPNs", "Enumerate SPNs and request Kerberos TGS tickets for offline cracking (Kerberoast)"),
    ("GetADUsers", "Enumerate domain users, descriptions, UAC flags, and password metadata over LDAP"),
    ("GetADComputers", "Enumerate domain computer accounts, operating systems, and SPNs over LDAP"),
    ("GetLAPSPassword", "Retrieve plaintext LAPS / LAPS v2 administrator passwords over LDAP"),
    ("getGMSAPassword", "Read and decrypt Group Managed Service Account (gMSA) passwords over LDAP"),
    ("CheckLDAPStatus", "Audit LDAP server RootDSE, supported capabilities, TLS/SSL configuration, and signing enforcement"),
    ("addcomputer", "Create or inject a new Active Directory computer account via LDAP SAMR or SAMAccountAdd"),
    ("badsuccessor", "Windows Server 2025 Delegated Managed Service Account (dMSA) exploitation suite (BadSuccessor)"),
    ("dacledit", "Inspect, modify, or add discretionary access control entries (ACEs) to AD objects"),
    ("owneredit", "Inspect and change Active Directory object owner SID via LDAP security descriptors"),
    ("dnstool", "Active Directory Integrated DNS (ADIDNS) record query, creation, modification, and tombstoning"),
    ("ldapsearch", "Execute arbitrary RFC 4511 LDAP search queries and filter attributes"),
    ("ldapclient", "Interactive administrative LDAP/LDAPS shell REPL for object queries and ACL audits"),
    ("dfsclient", "Query and crawl Active Directory Distributed File System (DFS) namespaces and referrals"),
    ("certipy", "Active Directory Certificate Services (ADCS) template auditor and certificate requester"),
    ("adcs", "Alias for certipy ADCS template auditor and certificate requester"),
    ("whisker", "Shadow Credentials manager: read, add, and clear msDS-KeyCredentialLink on AD accounts"),
    ("bloodhound", "BloodHound CE v5+ collector generating zip/json data bundles over LDAP"),
    ("coerce", "Multi-protocol coercion suite using MS-EFSR, MS-RPRN, MS-FSRVP, and MS-DFSNM"),
    ("getTGT", "Request a Kerberos Ticket Granting Ticket (TGT) using password, NT hash, or PKINIT certificate"),
    ("getST", "Request a Service Ticket (ST) via Kerberos TGS, S4U2self/S4U2proxy, or U2U"),
    ("getArch", "Detect target architecture (x86, x64, ARM) over DCE/RPC"),
    ("machine_role", "Determine Windows domain role (Standalone, Workstation, Server, DC) over MS-WKST"),
    ("rpcdump", "Dump DCE/RPC Endpoint Mapper (EPM) registered interfaces on TCP/135"),
    ("rpcmap", "Enumerate reachable RPC endpoints and test interface binding over TCP or named pipes"),
    ("oxidquery", "Resolve remote network interfaces via DCOM IObjectExporter::ServerAlive2 on TCP/135"),
    ("lookupsid", "Enumerate local or domain users and groups by SID/RID cycling over MS-LSAT"),
    ("samrdump", "Enumerate domain users, groups, and aliases via MS-SAMR named pipe"),
    ("samedit", "Directly update SAM user AccountControl flags, passwords, and password expiry via MS-SAMR"),
    ("changepasswd", "Modify or reset user passwords over MS-SAMR or Kerberos kpasswd (TCP/464)"),
    ("netview", "Enumerate network shares, sessions, logged-on users, and file locks over MS-SRVS"),
    ("netfiles", "Enumerate open files and file locks across remote shares"),
    ("reg", "Windows Remote Registry manager over MS-RRP (query, add, delete, dump, export .reg)"),
    ("services", "Windows Service Control Manager (SCM) client over MS-SCMR (list, status, start, stop, create, delete)"),
    ("mssqlclient", "Interactive SQL shell and query client for Microsoft SQL Server with TDS 7/8, NTLM, and Kerberos"),
    ("mssqlinstance", "Query SQL Server Browser service over UDP/1434 to locate named instances"),
    ("checkMSSQLStatus", "Audit Microsoft SQL Server connectivity, TLS configuration, and instance metadata"),
    ("attrib", "Query and modify remote SMB file attributes (Hidden, ReadOnly, System, Archive)"),
    ("filetime", "View and tamper remote SMB file timestamps (Creation, LastWrite, LastAccess)"),
    ("smbclient", "Interactive SMB2/3 file share explorer, upload/download, batch scripts, and tree navigation"),
    ("smbserver", "Pure-Rust standalone SMB2/3 file server and NetNTLM credential capture listener"),
    ("psexec", "Execute remote commands by creating and starting a Windows Service via MS-SCMR"),
    ("smbexec", "Stealth command execution using native cmd.exe service-less redirection over SMB"),
    ("atexec", "Execute remote commands via Windows Task Scheduler MS-TSCH"),
    ("atq", "Inspect, list, and query scheduled tasks and folder hierarchy over MS-TSCH"),
    ("eventlog", "Read, export, and clear Windows Event Logs over MS-EVEN6 named pipe"),
    ("wmiexec", "Execute remote commands stealthily via WMI Win32_Process over DCOM"),
    ("dcomexec", "Execute remote commands via DCOM interfaces (MMC20, ShellWindows, ShellBrowserWindow)"),
    ("secretsdump", "Extract NT/LM hashes, Kerberos keys, and plaintext secrets from SAM, LSA, and NTDS.dit"),
    ("secretsdump-local", "Extract secrets locally from offline SAM, SECURITY, SYSTEM hives, or NTDS.dit"),
    ("regsecrets", "Low-artifact in-memory extraction of SAM/LSA secrets over MS-RRP without writing hives to disk"),
    ("ntdsdump", "Dump Active Directory database (NTDS.dit) hashes offline using pure-Rust ESE/JET engine"),
    ("esentutl", "Inspect and dump Microsoft Extensible Storage Engine (ESE/JET) database pages, catalogs, and tables"),
    ("dpapi", "Decrypt Windows DPAPI masterkeys, blobs, credentials, and vault entries"),
    ("backupkey", "Retrieve LSA domain backup recovery keys over MS-BKRP for DPAPI recovery"),
    ("Get-GPPPassword", "Decrypt XML Group Policy Preference (GPP) passwords from SYSVOL or offline files"),
    ("ticketConverter", "Convert Kerberos credential caches between Linux MIT .ccache and Windows Mimikatz .kirbi"),
    ("ticketer", "Craft Golden, Silver, and Diamond Kerberos tickets with custom PAC signatures"),
    ("describeTicket", "Inspect and dissect Kerberos ticket ASN.1 structures, flags, and PAC details"),
    ("klist", "Inspect Kerberos credential cache files (.ccache / .kirbi) and list active tickets"),
    ("net", "Remote Windows administrative CLI over MS-SAMR and MS-SRVS (user, group, share, session)"),
    ("wmiquery", "Execute WQL queries against remote Windows Management Instrumentation (WMI) namespaces"),
    ("wmipersist", "WMI persistence and event subscription manager (__EventFilter, EventConsumer, Binding)"),
    ("wspsearch", "Search remote files via Windows Search Protocol (WSP / MS-WSP) SystemIndex catalog"),
    ("rdp_check", "Check remote RDP reachability, NLA support, and TLS certificate details on TCP/3389"),
    ("registry-read", "Quick read of remote registry keys and values over MS-RRP"),
    ("tstool", "Remote Terminal Services / Remote Desktop Session Host inspector and manager"),
    ("ping", "TCP port probe and latency test for target validation"),
    ("tracer", "TCP SYN / connect traceroute network hop probing"),
    ("sniffer", "Pure-Rust offline PCAP packet parser and protocol dissector for SMB, RPC, Kerberos, and LDAP"),
    ("mqtt_check", "Audit MQTT broker authentication and publish/subscribe access"),
    ("getPac", "Extract and inspect Kerberos Privilege Attribute Certificate (PAC) from tickets"),
    ("rbcd", "Configure Resource-Based Constrained Delegation (RBCD) on AD accounts via LDAP"),
    ("findDelegation", "Discover Active Directory unconstrained, constrained, and resource-based delegation"),
    ("trueTree", "Enumerate and display Active Directory forest domain trust trees"),
    ("raiseChild", "Automated child-to-parent domain privilege escalation using SID history injection"),
    ("smbpasswd", "Change user SMB password hashes via SAMR protocol"),
    ("split", "Split and extract Kerberos ticket files"),
    ("ntlmrelayx", "Multi-target NTLM relay server and attack engine across SMB, LDAP, MSSQL, WinRM, and ADCS"),
    ("compat-matrix", "Display Active Directory protocol compatibility matrix across Windows Server editions"),
    ("parse-target", "Parse and validate target connection string syntax"),
    ("ntlm-hash", "Calculate NT and LM hashes for a given password"),
    ("krb5-asreq", "Construct and inspect Kerberos AS-REQ authentication packets"),
    ("smb-negotiate", "Test SMB protocol dialect negotiation against a remote target"),
    ("rpc-interfaces", "List all well-known DCE/RPC interfaces and GUIDs"),
    ("bench-ndr", "Run NDR serialization and deserialization benchmark suite"),
    ("completions", "Generate shell completion scripts for Bash, Zsh, Fish, or PowerShell"),
    ("badsuccessor", "Windows Server 2025 Delegated Managed Service Account (dMSA) exploitation suite"),
    ("keylistattack", "Dump domain user secrets via MS-KILE KERB-KEY-LIST attack with an RODC key"),
];

pub fn generate_bash() -> String {
    let mut subcmd_list = String::new();
    for (name, _) in SUBCOMMANDS {
        subcmd_list.push_str(name);
        subcmd_list.push(' ');
    }
    let subcmd_list = subcmd_list.trim_end();

    format!(
r#"# Bash completion for impacket-rs
# Generated by `impacket-rs completions bash`

_impacket_rs_complete() {{
    local cur prev words cword
    _init_completion -n : 2>/dev/null || {{
        cur="${{COMP_WORDS[COMP_CWORD]}}"
        prev="${{COMP_WORDS[COMP_CWORD-1]}}"
        words=("${{COMP_WORDS[@]}}")
        cword=$COMP_CWORD
    }}

    local subcommands="{subcmd_list}"

    local common_opts="-h --help -proxy --proxy --compat -hashes -no-pass -k -aesKey -dc-ip -target-ip -port -debug"

    # Top-level completion
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$subcommands -h --help --version" -- "$cur"))
        return 0
    fi

    local subcmd="${{words[1]}}"

    case "$subcmd" in
        completions)
            COMPREPLY=($(compgen -W "bash zsh fish powershell" -- "$cur"))
            return 0
            ;;
        bloodhound)
            COMPREPLY=($(compgen -W "$common_opts -zip -json -o -base -dc-ip -port" -- "$cur"))
            return 0
            ;;
        badsuccessor)
            COMPREPLY=($(compgen -W "$common_opts -action -target-ou -dmsa-name -target-account -principals-allowed -dns-hostname -base-dn" -- "$cur"))
            return 0
            ;;
        coerce)
            COMPREPLY=($(compgen -W "$common_opts -listener -method -pipe" -- "$cur"))
            return 0
            ;;
        certipy|adcs)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "find req shadow" -- "$cur"))
                return 0
            fi
            COMPREPLY=($(compgen -W "$common_opts -ca -template -upn -vulnerable -debug -stdout" -- "$cur"))
            return 0
            ;;
        whisker)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "list add clear" -- "$cur"))
                return 0
            fi
            COMPREPLY=($(compgen -W "$common_opts -device-id" -- "$cur"))
            return 0
            ;;
        secretsdump|secretsdump-local|regsecrets)
            COMPREPLY=($(compgen -W "$common_opts -just-dc -just-dc-ntlm -ntds -system -security -sam -history -user-status -pwd-last-set -outputfile" -- "$cur"))
            return 0
            ;;
        GetUserSPNs)
            COMPREPLY=($(compgen -W "$common_opts -request -aes -outputfile -user -spn -etype" -- "$cur"))
            return 0
            ;;
        GetNPUsers)
            COMPREPLY=($(compgen -W "$common_opts -request -outputfile -usersfile -format -fast" -- "$cur"))
            return 0
            ;;
        GetADUsers|GetADComputers)
            COMPREPLY=($(compgen -W "$common_opts -format -json -bloodhound -all -active" -- "$cur"))
            return 0
            ;;
        getTGT)
            COMPREPLY=($(compgen -W "$common_opts -pfx -cert -key -dc-ip -fast" -- "$cur"))
            return 0
            ;;
        getST)
            COMPREPLY=($(compgen -W "$common_opts -spn -impersonate -altservice -dc-ip" -- "$cur"))
            return 0
            ;;
        ntlmrelayx)
            COMPREPLY=($(compgen -W "-tf -t -smb2support -socks -wh -debug -codec" -- "$cur"))
            return 0
            ;;
        net)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "user group localgroup share session" -- "$cur"))
                return 0
            fi
            COMPREPLY=($(compgen -W "$common_opts -name" -- "$cur"))
            return 0
            ;;
        reg)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "query add delete dump export save" -- "$cur"))
                return 0
            fi
            COMPREPLY=($(compgen -W "$common_opts -k -v -o" -- "$cur"))
            return 0
            ;;
        services)
            if [[ $cword -eq 2 ]]; then
                COMPREPLY=($(compgen -W "list status config start stop create delete change" -- "$cur"))
                return 0
            fi
            COMPREPLY=($(compgen -W "$common_opts -name -path -display" -- "$cur"))
            return 0
            ;;
        *)
            COMPREPLY=($(compgen -W "$common_opts" -- "$cur"))
            return 0
            ;;
    esac
}}

complete -F _impacket_rs_complete impacket-rs
complete -F _impacket_rs_complete impacket
"#
    )
}

pub fn generate_zsh() -> String {
    let mut subcmd_entries = String::new();
    for (name, desc) in SUBCOMMANDS {
        let clean_desc = desc.replace('\'', "\\'").replace('"', "\\\"");
        subcmd_entries.push_str(&format!("        '{}:{}'\n", name, clean_desc));
    }

    format!(
r#"#compdef impacket-rs impacket
# Zsh completion for impacket-rs
# Generated by `impacket-rs completions zsh`

_impacket_rs() {{
    local -a subcommands
    subcommands=(
{subcmd_entries}    )

    if (( CURRENT == 2 )); then
        _describe -t commands 'impacket-rs subcommands' subcommands
        return 0
    fi

    local subcmd="${{words[2]}}"

    case "$subcmd" in
        completions)
            local -a shells
            shells=(
                'bash:Generate Bash completion script'
                'zsh:Generate Zsh completion script'
                'fish:Generate Fish completion script'
                'powershell:Generate PowerShell completion script'
            )
            _describe 'shell' shells
            ;;
        bloodhound)
            _arguments \
                '-zip[Package data in standard BloodHound ZIP archive]' \
                '-json[Export raw JSON files]' \
                '-o[Specify output archive or directory]:output:_files' \
                '-base[Custom LDAP search base Distinguished Name]:base:' \
                '-port[Specify LDAP port]:port:' \
                '-dc-ip[Domain Controller IP address]:ip:' \
                '-hashes[LM:NTLM credential hashes]:hashes:' \
                '-no-pass[Do not prompt for password]' \
                '-proxy[Route traffic through SOCKS5 or HTTP proxy]:proxy:' \
                '-h[Show help]' '--help[Show help]'
            ;;
        badsuccessor)
            _arguments \
                '-action[Action to perform (search, add, delete, modify)]:action:(search add delete modify)' \
                '-target-ou[Target OU Distinguished Name]:ou:' \
                '-dmsa-name[Name of dMSA]:name:' \
                '-target-account[Predecessor target account]:account:' \
                '-principals-allowed[Username allowed to retrieve managed password]:user:' \
                '-dns-hostname[DNS hostname for dMSA]:host:' \
                '-base-dn[Custom search base DN]:base:' \
                '-port[LDAP port]:port:' \
                '-proxy[Route traffic through SOCKS5 or HTTP proxy]:proxy:' \
                '-h[Show help]' '--help[Show help]'
            ;;
        coerce)
            _arguments \
                '-listener[Attacker listener IP or hostname]:listener:' \
                '-method[Coercion method (efsr, rprn, fsrvp, dfsnm, all)]:method:(efsr rprn fsrvp dfsnm all)' \
                '-pipe[Specific named pipe for PetitPotam]:pipe:' \
                '-proxy[Route traffic through SOCKS5 or HTTP proxy]:proxy:' \
                '-h[Show help]' '--help[Show help]'
            ;;
        certipy|adcs)
            if (( CURRENT == 3 )); then
                local -a adcs_actions
                adcs_actions=(
                    'find:Audit ADCS certificate templates for vulnerabilities (ESC1-ESC15)'
                    'req:Request certificate issuance from Certificate Authority'
                    'shadow:Manipulate Shadow Credentials msDS-KeyCredentialLink'
                )
                _describe 'action' adcs_actions
            else
                _arguments \
                    '-ca[Certificate Authority name]:ca:' \
                    '-template[Certificate template name]:template:' \
                    '-upn[Alternative Subject Name UPN]:upn:' \
                    '-vulnerable[Only show vulnerable templates]' \
                    '-proxy[Proxy URL]:proxy:' \
                    '-h[Show help]' '--help[Show help]'
            fi
            ;;
        whisker)
            if (( CURRENT == 3 )); then
                local -a whisker_actions
                whisker_actions=(
                    'list:List Key Credentials on target object'
                    'add:Add new Key Credential and generate certificate'
                    'clear:Remove Key Credentials from target object'
                )
                _describe 'action' whisker_actions
            else
                _arguments \
                    '-device-id[Specify device ID GUID]:guid:' \
                    '-proxy[Proxy URL]:proxy:' \
                    '-h[Show help]' '--help[Show help]'
            fi
            ;;
        secretsdump|secretsdump-local|regsecrets)
            _arguments \
                '-just-dc[Extract only NTDS.dit domain credentials]' \
                '-just-dc-ntlm[Extract only NT/LM hashes without Kerberos keys]' \
                '-ntds[Path to offline NTDS.dit database]:ntds:_files' \
                '-system[Path to offline SYSTEM registry hive]:system:_files' \
                '-security[Path to offline SECURITY registry hive]:security:_files' \
                '-sam[Path to offline SAM registry hive]:sam:_files' \
                '-history[Dump password history]' \
                '-user-status[Include disabled/expired account status]' \
                '-pwd-last-set[Include password last set timestamps]' \
                '-outputfile[Save output hashes to base file name]:file:_files' \
                '-hashes[LM:NTLM credential hashes]:hashes:' \
                '-proxy[Proxy URL]:proxy:' \
                '-h[Show help]' '--help[Show help]'
            ;;
        *)
            _arguments \
                '-h[Show help]' '--help[Show help]' \
                '-hashes[LM:NTLM credential hashes]:hashes:' \
                '-no-pass[Do not prompt for password]' \
                '-k[Use Kerberos authentication]' \
                '-aesKey[Kerberos AES key]:key:' \
                '-dc-ip[Domain Controller IP address]:ip:' \
                '-target-ip[Target IP address]:ip:' \
                '-port[Target port]:port:' \
                '-proxy[Route traffic through SOCKS5 or HTTP proxy]:proxy:'
            ;;
    esac
}}

_impacket_rs "$@"
"#
    )
}

pub fn generate_fish() -> String {
    let mut out = String::from(
r#"# Fish completion for impacket-rs
# Generated by `impacket-rs completions fish`

function __fish_impacket_rs_no_subcommand
    for item in (commandline -poc)
        if test "$item" != "impacket-rs" -a "$item" != "impacket"
            if not string match -q -- '-*' "$item"
                return 1
            end
        end
    end
    return 0
end

function __fish_impacket_rs_using_subcommand
    set -l cmd (commandline -poc)
    set -e cmd[1]
    for item in $cmd
        if not string match -q -- '-*' "$item"
            if test "$item" = $argv[1]
                return 0
            end
            return 1
        end
    end
    return 1
end

# Top-level subcommands
"#
    );

    for (name, desc) in SUBCOMMANDS {
        let clean_desc = desc.replace('\'', "\\'").replace('"', "\\\"");
        out.push_str(&format!(
            "complete -c impacket-rs -n '__fish_impacket_rs_no_subcommand' -a '{}' -d \"{}\"\n",
            name, clean_desc
        ));
        out.push_str(&format!(
            "complete -c impacket -n '__fish_impacket_rs_no_subcommand' -a '{}' -d \"{}\"\n",
            name, clean_desc
        ));
    }

    out.push_str(
r#"
# Completions for 'completions' command
complete -c impacket-rs -n '__fish_impacket_rs_using_subcommand completions' -a 'bash zsh fish powershell' -d 'Shell type'
complete -c impacket -n '__fish_impacket_rs_using_subcommand completions' -a 'bash zsh fish powershell' -d 'Shell type'

# Global flags
complete -c impacket-rs -s h -l help -d 'Show help message'
complete -c impacket -s h -l help -d 'Show help message'
complete -c impacket-rs -l proxy -d 'Route traffic through SOCKS5/HTTP proxy'
complete -c impacket -l proxy -d 'Route traffic through SOCKS5/HTTP proxy'
"#
    );

    out
}

pub fn generate_powershell() -> String {
    let mut subcmd_array = String::new();
    for (name, desc) in SUBCOMMANDS {
        let clean_desc = desc.replace('\'', "''");
        subcmd_array.push_str(&format!("        [CompletionResult]::new('{0}', '{0}', [CompletionResultType]::ParameterValue, '{1}')\n", name, clean_desc));
    }

    format!(
r#"# PowerShell completion for impacket-rs
# Generated by `impacket-rs completions powershell`

Register-ArgumentCompleter -Native -CommandName 'impacket-rs', 'impacket' -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)

    $elements = $commandAst.Elements
    if ($elements.Count -le 2) {{
        $subcommands = @(
{subcmd_array}        )
        $subcommands | Where-Object {{ $_.CompletionText -like "$wordToComplete*" }}
        return
    }}

    $subcmd = $elements[1].Extent.Text

    switch ($subcmd) {{
        'completions' {{
            @('bash', 'zsh', 'fish', 'powershell') | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
                [CompletionResult]::new($_, $_, [CompletionResultType]::ParameterValue, "$_ completion script")
            }}
            break
        }}
        'bloodhound' {{
            @('-zip', '-json', '-o', '-base', '-port', '-dc-ip', '-hashes', '-proxy') | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
                [CompletionResult]::new($_, $_, [CompletionResultType]::ParameterName, $_)
            }}
            break
        }}
        'coerce' {{
            @('-listener', '-method', '-pipe', '-hashes', '-proxy') | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
                [CompletionResult]::new($_, $_, [CompletionResultType]::ParameterName, $_)
            }}
            break
        }}
        default {{
            @('-h', '--help', '-hashes', '-no-pass', '-k', '-dc-ip', '-target-ip', '-port', '-proxy') | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
                [CompletionResult]::new($_, $_, [CompletionResultType]::ParameterName, $_)
            }}
            break
        }}
    }}
}}
"#
    )
}
