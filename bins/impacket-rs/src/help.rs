//! Comprehensive Python-Impacket-style help formatter for all 74 tools.

use impacket_core::version;

pub fn print_tool_help(tool_name: &str) {
    print!("{}", version::BANNER);
    if let Some(help) = get_tool_help(tool_name) {
        println!("{}", help);
        println!("global connection options:");
        println!("  -proxy <URL>, --proxy <URL>   Route traffic through SOCKS5 (socks5://host:port) or HTTP (http://host:port) proxy");
        println!("                                (auto-detected from ALL_PROXY, HTTPS_PROXY, HTTP_PROXY env vars)");
        println!("  --compat <PROFILE>            Active Directory dialect: legacy, auto, modern (default: auto)");
        println!();
    } else {
        println!("[-] No detailed help available for tool '{}'", tool_name);
        println!("[*] Run 'impacket-rs' without arguments to see all available tools.");
    }
}

pub fn get_tool_help(tool_name: &str) -> Option<&'static str> {
    let canonical = canonicalize_name(tool_name);
    match canonical {
        "CheckLDAPStatus" => Some(r#"Description: Audits LDAP server RootDSE, supported capabilities, TLS/SSL configuration, and signing enforcement.

usage: impacket-rs CheckLDAPStatus [options] <target>

positional arguments:
  target: [host] or [[domain/]username[:password]@]<host>

options:
  -h, --help            show this help message and exit
  -port <PORT>           LDAP port (default: 389, or 636 for LDAPS)

examples:
  impacket-rs CheckLDAPStatus 192.168.1.10
  impacket-rs CheckLDAPStatus 192.168.1.10 -port 636
"#),
        "DumpNTLMInfo" => Some(r#"Description: Dumps remote host NetBIOS, DNS computer name, domain name, forest, and OS version without authentication via SMB2/3 NTLMSSP challenge.

usage: impacket-rs DumpNTLMInfo [options] <target>

positional arguments:
  target: [host] or [[domain/]username[:password]@]<host>

options:
  -h, --help            show this help message and exit
  -port <PORT>           SMB port (default: 445, or 139)

examples:
  impacket-rs DumpNTLMInfo 192.168.1.20
"#),
        "Get-GPPPassword" => Some(r#"Description: Extracts and decrypts Group Policy Preferences (GPP) passwords from Groups.xml or ScheduledTasks.xml (SYSVOL or offline XML).

usage: impacket-rs Get-GPPPassword [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -xmlfile <FILE>        Offline GPP XML file to parse
  -share <SHARE>         SYSVOL share name (default: SYSVOL)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs Get-GPPPassword corp.local/jdoe:Pass123!@192.168.1.10
  impacket-rs Get-GPPPassword LOCAL -xmlfile /tmp/Groups.xml
"#),
        "GetADComputers" => Some(r#"Description: Queries Active Directory via LDAP for domain computer accounts, operating systems, and SPNs.

usage: impacket-rs GetADComputers [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -all                   Query all computer accounts
  -computer <NAME>       Query metadata for a specific computer name only

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs GetADComputers corp.local/jdoe:Pass123!@192.168.1.10 -all
"#),
        "GetADUsers" => Some(r#"Description: Queries Active Directory via LDAP for domain user accounts, email addresses, and last logon timestamps.

usage: impacket-rs GetADUsers [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -all                   Query all domain users, including disabled and expired accounts
  -user <USER>           Query metadata for a specific user only

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs GetADUsers corp.local/jdoe:Pass123!@192.168.1.10 -all
  impacket-rs GetADUsers corp.local/jdoe@192.168.1.10 -hashes :aad3b435b51404eeaad3b435b51404ee
"#),
        "GetLAPSPassword" => Some(r#"Description: Queries Active Directory via LDAP for legacy LAPS and modern Windows LAPS administrator passwords.

usage: impacket-rs GetLAPSPassword [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -computer <NAME>       Computer account name to retrieve LAPS password for

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs GetLAPSPassword corp.local/admin:Pass123!@192.168.1.10 -computer DC01
"#),
        "GetNPUsers" => Some(r#"Description: Queries Active Directory for accounts with 'Do not require Kerberos preauthentication' (DONT_REQ_PREAUTH) enabled and requests AS-REP ciphertexts to crack offline (AS-REP Roasting).

usage: impacket-rs GetNPUsers [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address> (or domain/ without credentials for anonymous scan)

options:
  -h, --help            show this help message and exit
  -request               Request AS-REP tickets for AS-REP roastable users
  -usersfile <FILE>      File with list of usernames to check (one per line)
  -format <hashcat|john> Output hash format (default: hashcat)
  -outputfile <FILE>     Output filename to write cracked hashes to

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs GetNPUsers corp.local/jdoe:Pass123! -dc-ip 192.168.1.10 -request
  impacket-rs GetNPUsers corp.local/ -usersfile users.txt -no-pass -dc-ip 192.168.1.10 -format hashcat
  impacket-rs GetNPUsers corp.local/admin -hashes :aad3b435b51404eeaad3b435b51404ee -request
"#),
        "GetUserSPNs" => Some(r#"Description: Queries Active Directory for user accounts associated with Service Principal Names (SPNs) and requests Kerberos TGS tickets to crack offline (Kerberoasting).

usage: impacket-rs GetUserSPNs [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -request               Request TGS tickets for all SPN-enabled user accounts (Hashcat mode 13100)
  -spn <SPN>             Request TGS ticket targeting a specific SPN only
  -request-user <USER>   Request TGS tickets targeting a specific user only
  -outputfile <FILE>     Output filename to write captured TGS hashes to

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs GetUserSPNs corp.local/jdoe:Pass123! -dc-ip 192.168.1.10 -request -outputfile kerberoast.hashes
  impacket-rs GetUserSPNs corp.local/jdoe -k -no-pass -dc-ip 192.168.1.10 -request
  impacket-rs GetUserSPNs corp.local/jdoe:Pass123! -spn MSSQLSvc/db01.corp.local:1433 -request
"#),
        "addcomputer" => Some(r#"Description: Provisions a computer account in Active Directory via LDAP with custom password and SPNs.

usage: impacket-rs addcomputer [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -computer-name <NAME>  Name of the new computer account (without trailing $)
  -computer-pass <PASS>  Password for the new computer account

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs addcomputer corp.local/jdoe:Pass123!@192.168.1.10 -computer-name FAKEDC -computer-pass ComputerPass123!
"#),
        "atexec" => Some(r#"Description: Executes remote commands via the Microsoft Task Scheduler service (MS-TSCH over \PIPE\atsvc). Creates, triggers, and deletes a scheduled task, retrieving command output over SMB.

usage: impacket-rs atexec [options] <target> [command]

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>
    command: Command to execute remotely

options:
  -h, --help            show this help message and exit
  -share <SHARE>         SMB share name for output capture (default: ADMIN$)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs atexec corp.local/admin:Pass123@192.168.1.20 "hostname"
  impacket-rs atexec corp.local/admin@192.168.1.20 -hashes :aad3b435b51404eeaad3b435b51404ee "whoami"
"#),
        "atq" => Some(r#"Description: Lists, queries, and deletes scheduled tasks via MS-TSCH (\PIPE\atsvc).

usage: impacket-rs atq [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -jobid <ID>            Specific job ID to query or delete
  -del                   Delete the specified job ID

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs atq corp.local/admin:Pass123@192.168.1.20
"#),
        "attrib" => Some(r#"Description: Queries and modifies remote SMB file attributes (READONLY, HIDDEN, SYSTEM, ARCHIVE).

usage: impacket-rs attrib [options] <target> <share> <path> [attributes]

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>
    share: SMB share name
    path: Path to remote file
    attributes: Attribute modifications (e.g. +R, -H, +S)

options:
  -h, --help            show this help message and exit

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs attrib corp.local/jdoe:Pass123!@192.168.1.20 C$ "test.txt"
  impacket-rs attrib corp.local/jdoe:Pass123!@192.168.1.20 C$ "secret.txt" +H +R
"#),
        "bench-ndr" => Some(r#"Description: Executes high-throughput NDR serialization benchmarks and roundtrip verifications.

usage: impacket-rs bench-ndr [iterations]

positional arguments:
  iterations: Number of benchmark roundtrips (default: 1000000)

options:
  -h, --help            show this help message and exit

examples:
  impacket-rs bench-ndr 1000000
"#),
        "changepasswd" => Some(r#"Description: Changes or resets user passwords remotely via MS-SAMR (TCP/445) or Kerberos kpasswd (TCP/464).

usage: impacket-rs changepasswd [options] <target> -new-pass <NEW>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -new-pass <PASS>       New password to set
  -protocol <samr|kpasswd> Protocol to use (default: samr)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs changepasswd corp.local/jdoe:OldPass123!@192.168.1.20 -new-pass NewPass456!
"#),
        "checkMSSQLStatus" => Some(r#"Description: Audits Microsoft SQL Server TDS protocol version, TLS encryption mode, and channel binding support.

usage: impacket-rs checkMSSQLStatus [options] <target>

positional arguments:
  target: SQL Server hostname or IP address

options:
  -h, --help            show this help message and exit
  -port <PORT>           SQL Server TDS port (default: 1433)

examples:
  impacket-rs checkMSSQLStatus 192.168.1.30
"#),
        "compat-matrix" => Some(r#"Description: Displays the Impacket-RS Active Directory compatibility matrix and profile configurations across Windows 2000 through Server 2025.

usage: impacket-rs compat-matrix

options:
  -h, --help            show this help message and exit

examples:
  impacket-rs compat-matrix
"#),
        "dacledit" => Some(r#"Description: Inspects and modifies Active Directory DACL permissions via LDAP (e.g. GenericAll, WriteDacl).

usage: impacket-rs dacledit [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -target-dn <DN>        Distinguished Name of the target Active Directory object
  -principal <NAME>      Principal account to grant or revoke rights for
  -rights <RIGHTS>       Permissions to apply (e.g. FullControl, WriteDacl, ResetPassword)
  -action <read|write>   Action to perform (default: read)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs dacledit corp.local/jdoe:Pass123!@192.168.1.10 -target-dn "CN=Domain Admins,CN=Users,DC=corp,DC=local" -action read
"#),
        "dcomexec" => Some(r#"Description: Executes remote commands using DCOM objects (MMC20.Application, ShellWindows, ShellBrowserWindow). Bypasses traditional service creation and WMI event logging.

usage: impacket-rs dcomexec [options] <target> [command]

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>
    command: Command to execute remotely

options:
  -h, --help            show this help message and exit
  -object <MMC20|ShellWindows|ShellBrowserWindow> DCOM object to instantiate (default: MMC20)
  -share <SHARE>         SMB share for output retrieval (default: ADMIN$)
  -nooutput              Execute without output redirection

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs dcomexec corp.local/admin:Pass123@192.168.1.20 "whoami"
  impacket-rs dcomexec corp.local/admin@192.168.1.20 -object ShellWindows "calc.exe"
"#),
        "describeTicket" => Some(r#"Description: Parses and describes the internal structures of Kerberos tickets, PAC credentials, client identities, and encryption types.

usage: impacket-rs describeTicket <ticket_file>

positional arguments:
  ticket_file: Path to Kerberos ticket (.ccache or .kirbi)

options:
  -h, --help            show this help message and exit

examples:
  impacket-rs describeTicket admin.ccache
  impacket-rs describeTicket ticket.kirbi
"#),
        "dfsclient" => Some(r#"Description: Active Directory DFS Namespace management and referral query tool ([MS-DFSNM] over \PIPE\netdfs).

usage: impacket-rs dfsclient [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -enum                  Enumerate DFS namespaces
  -info <PATH>           Query referral info for a DFS path

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs dfsclient corp.local/jdoe:Pass123!@192.168.1.10 -enum
"#),
        "dnstool" => Some(r#"Description: Active Directory Integrated DNS record management tool ([MS-DNSP] over LDAP).

usage: impacket-rs dnstool [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -action <query|add|del> Action to perform (default: query)
  -record <NAME>         DNS record name to query or manage
  -data <DATA>           DNS record data (IP address or CNAME target)
  -type <A|CNAME|TXT|PTR> DNS record type (default: A)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs dnstool corp.local/jdoe:Pass123!@192.168.1.10 -action query -record dc01
  impacket-rs dnstool corp.local/jdoe:Pass123!@192.168.1.10 -action add -record evil -data 192.168.1.200
"#),
        "dpapi" => Some(r#"Description: Inspects and decrypts Windows Data Protection API (DPAPI) master keys, credential blobs, and backup keys.

usage: impacket-rs dpapi [options]

options:
  -h, --help            show this help message and exit
  -blob <FILE>           DPAPI protected blob file to parse
  -masterkey <FILE>      DPAPI master key file
  -pvk <FILE>            Domain DPAPI backup key (.pvk)

examples:
  impacket-rs dpapi -blob credential.blob -masterkey masterkey.key
"#),
        "esentutl" => Some(r#"Description: Inspects and dumps Extensible Storage Engine (ESE / JET Blue) database tables and catalog metadata (e.g. NTDS.DIT).

usage: impacket-rs esentutl [options] <database>

positional arguments:
  database: Path to ESE database file (e.g. ntds.dit)

options:
  -h, --help            show this help message and exit
  -table <NAME>          Table name to inspect (e.g. datatable)

examples:
  impacket-rs esentutl ntds.dit -table datatable
"#),
        "eventlog" => Some(r#"Description: Queries and live-streams Windows Event Logs remotely ([MS-EVEN6] over \PIPE\eventlog).

usage: impacket-rs eventlog [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -channel <NAME>        Event channel to query (default: Security)
  -xpath <QUERY>         XPath filter query (e.g. '*[System[(EventID=4624)]]')
  -tail                  Continuously stream new events in real time

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs eventlog corp.local/admin:Pass123@192.168.1.20 -channel Security -xpath "*[System[(EventID=4624)]]"
"#),
        "filetime" => Some(r#"Description: Converts between Windows 64-bit FileTime timestamps and ISO 8601, or modifies remote SMB file timestamps.

usage: impacket-rs filetime <value> | <target> <share> <path> [-set <timestamp>]

positional arguments:
  value: 64-bit FileTime decimal integer (standalone conversion)
    target: Remote SMB target
    share: SMB share name
    path: Remote file path

options:
  -h, --help            show this help message and exit
  -set <TIMESTAMP>       Timestamp to apply (ISO 8601 format)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs filetime 132456789012345678
  impacket-rs filetime corp.local/admin:Pass123@192.168.1.20 C$ "Windows/notepad.exe"
"#),
        "findDelegation" => Some(r#"Description: Queries Active Directory via LDAP for accounts configured with unconstrained, constrained, or resource-based delegation.

usage: impacket-rs findDelegation [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs findDelegation corp.local/jdoe:Pass123!@192.168.1.10
"#),
        "getArch" => Some(r#"Description: Detects remote Windows OS architecture (32-bit x86 vs 64-bit AMD64) via DCE/RPC NDR64 transfer syntax bind negotiation.

usage: impacket-rs getArch [options] <target> [port]

positional arguments:
  target: [host] or [[domain/]username[:password]@]<host>
    port: SMB port to probe (default: 445)

options:
  -h, --help            show this help message and exit

examples:
  impacket-rs getArch 192.168.1.20
"#),
        "getPac" => Some(r#"Description: Extracts, decrypts, and displays the Kerberos Privilege Attribute Certificate (PAC) from a ticket or requests one from KDC.

usage: impacket-rs getPac [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<kdc_ip>

options:
  -h, --help            show this help message and exit
  -target-user <USER>    Target user to extract PAC for
  -dc-ip <IP>            IP Address of the Domain Controller / KDC

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs getPac corp.local/jdoe:Pass123!@192.168.1.10 -target-user Administrator
"#),
        "getST" => Some(r#"Description: Requests a Kerberos Service Ticket (ST/TGS) using a TGT from a .ccache file, with full support for S4U2self and S4U2proxy protocol transition.

usage: impacket-rs getST [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<kdc_ip>

options:
  -h, --help            show this help message and exit
  -spn <SPN>             Service Principal Name to request ticket for (e.g. cifs/fs01.corp.local)
  -impersonate <USER>    Target user to impersonate via S4U2self / S4U2proxy
  -altservice <SERVICE>  Alternate service name to request ticket for
  -dc-ip <IP>            IP Address of the Domain Controller / KDC

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs getST corp.local/jdoe:Pass123! -spn cifs/fs01.corp.local -dc-ip 192.168.1.10
  export KRB5CCNAME=/tmp/websvc.ccache
impacket-rs getST corp.local/websvc$ -k -no-pass -spn cifs/fs01.corp.local -impersonate Administrator -dc-ip 192.168.1.10
"#),
        "getTGT" => Some(r#"Description: Requests a Kerberos Ticket Granting Ticket (TGT) via AS-REQ using password, NTLM hash, or AES key pre-authentication, saving it to a .ccache file.

usage: impacket-rs getTGT [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<kdc_ip>

options:
  -h, --help            show this help message and exit
  -dc-ip <IP>            IP Address of the Domain Controller / KDC
  -outputfile <FILE>     Base name for the output ccache file (default: username.ccache)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs getTGT corp.local/jdoe:Password123! -dc-ip 192.168.1.10
  impacket-rs getTGT corp.local/admin -hashes :aad3b435b51404eeaad3b435b51404ee -dc-ip 192.168.1.10
"#),
        "klist" => Some(r#"Description: Inspects cached Kerberos tickets, encryption types, PAC structures, and validity from .ccache or .kirbi files.

usage: impacket-rs klist [ticket_file]

positional arguments:
  ticket_file: Path to .ccache or .kirbi file (default: $KRB5CCNAME)

options:
  -h, --help            show this help message and exit

examples:
  impacket-rs klist
  impacket-rs klist /tmp/krb5cc_1000
  impacket-rs klist admin.kirbi
"#),
        "krb5-asreq" => Some(r#"Description: Generates a synthetic Kerberos AS-REQ packet for testing and analysis.

usage: impacket-rs krb5-asreq <domain> <user>

positional arguments:
  domain: Kerberos realm / domain name
    user: Username

options:
  -h, --help            show this help message and exit

examples:
  impacket-rs krb5-asreq CORP.LOCAL Administrator
"#),
        "ldapclient" => Some(r#"Description: Interactive Active Directory administrative shell and REPL over LDAP (TCP/389 or LDAPS/636).

usage: impacket-rs ldapclient [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -port <PORT>           LDAP port (default: 389, or 636 for LDAPS)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs ldapclient corp.local/jdoe:Pass123!@192.168.1.10
"#),
        "ldapsearch" => Some(r#"Description: Active Directory generic LDAP directory search tool supporting arbitrary search filters and attributes.

usage: impacket-rs ldapsearch [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -base <DN>             Base DN to start the search from (default: RootDSE defaultNamingContext)
  -filter <FILTER>       LDAP search filter (default: '(objectClass=*)')
  -attributes <A,B,...>  Comma-separated list of attributes to return

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs ldapsearch corp.local/jdoe:Pass123!@192.168.1.10 -filter "(sAMAccountName=admin*)"
"#),
        "lookupsid" => Some(r#"Description: Enumerates local and domain security identifiers (SIDs) and users by brute-forcing relative IDs (RIDs 500..maxRid) over \PIPE\lsarpc (MS-LSAT) or SAMR.

usage: impacket-rs lookupsid [options] <target> [maxRid]

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>
    maxRid: Maximum RID to probe (default: 4000)

options:
  -h, --help            show this help message and exit
  -domain                Query domain SIDs instead of local SIDs
  -rights                Enumerate user system access rights and privileges

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs lookupsid corp.local/jdoe:Pass123!@192.168.1.20
  impacket-rs lookupsid corp.local/guest@192.168.1.20 -no-pass 10000
  impacket-rs lookupsid corp.local/admin@192.168.1.20 -hashes :aad3b435b51404eeaad3b435b51404ee -rights
"#),
        "machine_role" => Some(r#"Description: Queries workstation or server domain-join role, primary domain, and OS version over MS-WKST (\PIPE\wkssvc).

usage: impacket-rs machine_role [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs machine_role corp.local/jdoe:Pass123!@192.168.1.20
"#),
        "mqtt_check" => Some(r#"Description: Audits MQTT broker connection, anonymous access, and topic publishing permissions ([MQTT-3.1.1]).

usage: impacket-rs mqtt_check [options] <host>

positional arguments:
  host: Target MQTT broker hostname or IP address

options:
  -h, --help            show this help message and exit
  -port <PORT>           MQTT port (default: 1883)
  -user <USER>           Username for authentication
  -pass <PASS>           Password for authentication

examples:
  impacket-rs mqtt_check 192.168.1.50 -port 1883
"#),
        "mssqlclient" => Some(r#"Description: Microsoft SQL Server client providing an interactive T-SQL shell, xp_cmdshell execution, linked server navigation, and hash theft over TDS (TCP/1433).

usage: impacket-rs mssqlclient [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -port <PORT>           SQL Server TDS port (default: 1433)
  -db <NAME>             Initial database to connect to (default: master)
  -windows-auth          Use Windows authentication (NTLM/Kerberos)
  -sql-auth              Use native SQL Server authentication

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs mssqlclient corp.local/dbadmin:Pass123!@192.168.1.30 -windows-auth
  impacket-rs mssqlclient sa:SqlPass123@192.168.1.30 -sql-auth
"#),
        "mssqlinstance" => Some(r#"Description: Discovers Microsoft SQL Server instances, TCP ports, and named pipes over UDP port 1434 ([MC-SQLR]).

usage: impacket-rs mssqlinstance [options] <target>

positional arguments:
  target: SQL Server hostname or IP address

options:
  -h, --help            show this help message and exit
  -port <PORT>           SQL Server Browser UDP port (default: 1434)

examples:
  impacket-rs mssqlinstance 192.168.1.30
"#),
        "net" => Some(r#"Description: Remote administrative CLI equivalent to net.exe. Manage users, groups, localgroups, sessions, and shares via SAMR and SRVS.

usage: impacket-rs net [options] <action> <target> [options]

positional arguments:
  action: user | group | localgroup | share | session
    target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -user <NAME>           Username for user operations
  -group <NAME>          Group name for group operations
  -add                   Add a user or group
  -delete                Delete a user or group

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs net user corp.local/admin:Pass123@192.168.1.20
  impacket-rs net localgroup corp.local/admin@192.168.1.20 Administrators -add -user jdoe
"#),
        "netfiles" => Some(r#"Description: Enumerates remote open files and active file locks via MS-SRVS (\PIPE\srvsvc).

usage: impacket-rs netfiles [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs netfiles corp.local/admin:Pass123@192.168.1.20
"#),
        "netview" => Some(r#"Description: Enumerates remote SMB shares, active sessions, and logged-on users across the network using MS-SRVS (\PIPE\srvsvc) and MS-WKST (\PIPE\wkssvc).

usage: impacket-rs netview [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -users                 Enumerate logged-on users over MS-WKST
  -info                  Display OS version, join status, and domain information
  -sessions              Enumerate active SMB client sessions
  -files                 Enumerate opened files and file locks

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs netview corp.local/jdoe:Pass123!@192.168.1.20
  impacket-rs netview corp.local/admin@192.168.1.20 -hashes :aad3b435b51404eeaad3b435b51404ee -users -info
"#),
        "ntdsdump" => Some(r#"Description: Extracts and decrypts Active Directory user credentials, history, and Kerberos keys from offline NTDS.DIT and SYSTEM hives.

usage: impacket-rs ntdsdump -ntds <NTDS> -system <SYS> [options]

options:
  -h, --help            show this help message and exit
  -ntds <FILE>           Path to Active Directory NTDS.DIT database file
  -system <FILE>         Path to SYSTEM registry hive file
  -user <USER>           Extract only data for the specified user

examples:
  impacket-rs ntdsdump -ntds ntds.dit -system SYSTEM
"#),
        "ntlm-hash" => Some(r#"Description: Computes LM and NT hashes for an input password.

usage: impacket-rs ntlm-hash <password>

positional arguments:
  password: Plaintext password to hash

options:
  -h, --help            show this help message and exit

examples:
  impacket-rs ntlm-hash Password123!
"#),
        "ntlmrelayx" => Some(r#"Description: NTLM cross-protocol relay orchestrator supporting HTTP, SMB, and LDAP relay sessions with MIC and EPA channel binding stripping.

usage: impacket-rs ntlmrelayx [options]

options:
  -h, --help            show this help message and exit
  -t <TARGET>            Target URL to relay credentials to (e.g. smb://192.168.1.50 or ldap://dc01)
  -tf <FILE>             File containing targets to relay to (one per line)
  -smb2support           Support SMB2 in relaying
  -socks                 Enable SOCKS proxy server for relayed sessions
  -lootdir <DIR>         Directory to store looted secrets and SAM hashes
  -wh <WPAD_HOST>        Enable rogue WPAD server and proxy requests

examples:
  impacket-rs ntlmrelayx -t smb://192.168.1.50 -smb2support
  impacket-rs ntlmrelayx -t ldap://192.168.1.10 -lootdir /tmp/loot
  impacket-rs ntlmrelayx -tf targets.txt -socks
"#),
        "owneredit" => Some(r#"Description: Queries or changes Active Directory object owner SID via LDAP.

usage: impacket-rs owneredit [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -dn <DN>               Distinguished Name of the target object
  -action <query|set>    Action to perform (query or set)
  -new-owner <SID>       New owner SID to apply (when action is set)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs owneredit corp.local/admin:Pass123!@192.168.1.10 -dn "DC=corp,DC=local" -action query
"#),
        "oxidquery" => Some(r#"Description: DCOM IObjectExporter interface and network binding resolver over TCP/135. Discovers multihomed network interfaces.

usage: impacket-rs oxidquery [options] <target>

positional arguments:
  target: [host] or [[domain/]username[:password]@]<host>

options:
  -h, --help            show this help message and exit
  -port <PORT>           RPC port (default: 135)

examples:
  impacket-rs oxidquery 192.168.1.20
"#),
        "parse-target" => Some(r#"Description: Diagnostic utility for parsing and validating Impacket target strings and credential specifications.

usage: impacket-rs parse-target <target_string>

positional arguments:
  target_string: Target string (e.g. corp.local/admin:password@192.168.1.10)

options:
  -h, --help            show this help message and exit

examples:
  impacket-rs parse-target corp.local/admin:Pass123!@192.168.1.10
"#),
        "ping" => Some(r#"Description: Measures TCP connection reachability and latency statistics against remote network services.

usage: impacket-rs ping [options] <host>

positional arguments:
  host: Target hostname or IP address

options:
  -h, --help            show this help message and exit
  -port <PORT>           Target TCP port (default: 445)
  -count <N>             Number of ping probes to send (default: 4)
  -timeout <MS>          Timeout per probe in milliseconds (default: 2000)

examples:
  impacket-rs ping 192.168.1.20 -port 445 -count 4
"#),
        "psexec" => Some(r#"Description: PSEXEC-like execution using RemCom service trick. Creates an RPC service over \PIPE\svcctl, uploads binary if requested, and redirects stdin/stdout via an SMB named pipe or share.

usage: impacket-rs psexec [options] <target> [command]

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>
    command: Command to execute remotely (default: interactive cmd.exe)

options:
  -h, --help            show this help message and exit
  -share <SHARE>         SMB share name for output redirection (default: ADMIN$)
  -service-name <NAME>   Name of the service to register on the target host
  -remote-binary-name <NAME> Name of the executable binary placed in %SYSTEMROOT%

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs psexec corp.local/admin:Pass123@192.168.1.20 "whoami /all"
  impacket-rs psexec corp.local/admin@192.168.1.20 -hashes :aad3b435b51404eeaad3b435b51404ee
  impacket-rs psexec corp.local/admin@target.corp.local -k -no-pass -share C$
"#),
        "raiseChild" => Some(r#"Description: Child-to-parent domain privilege escalation using SID History injection over LDAP and Kerberos.

usage: impacket-rs raiseChild [options] <target>

positional arguments:
  target: [[child_domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -target-user <USER>    Target user to escalate (default: Administrator)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs raiseChild child.corp.local/admin:Pass123!@192.168.1.10
"#),
        "rbcd" => Some(r#"Description: Manages Resource-Based Constrained Delegation (RBCD) permissions on Active Directory computer objects (msDS-AllowedToActOnBehalfOfOtherIdentity).

usage: impacket-rs rbcd [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -delegate-to <NAME>    Computer account to modify delegation on
  -delegate-from <NAME>  Computer account granted delegation rights
  -action <read|write|flush> Action to perform (default: read)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs rbcd corp.local/jdoe:Pass123!@192.168.1.10 -action read -delegate-to DC01$
  impacket-rs rbcd corp.local/admin:Pass123!@192.168.1.10 -action write -delegate-to DC01$ -delegate-from EVIL$
"#),
        "rdp_check" => Some(r#"Description: Audits remote RDP service for TLS encryption, CredSSP / Network Level Authentication (NLA) enforcement, and account validity.

usage: impacket-rs rdp_check [options] <target>

positional arguments:
  target: [host] or [[domain/]username[:password]@]<host>

options:
  -h, --help            show this help message and exit
  -port <PORT>           RDP port (default: 3389)

examples:
  impacket-rs rdp_check 192.168.1.20
  impacket-rs rdp_check corp.local/jdoe:Pass123!@192.168.1.20
"#),
        "reg" => Some(r#"Description: Remote Windows Registry CLI manipulation tool over MS-RRP (\PIPE\winreg). Query, add, delete, save, and export remote registry keys and values.

usage: impacket-rs reg [options] <target> <action> [key] [options]

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>
    action: query | add | delete | save

options:
  -h, --help            show this help message and exit
  -key <KEY>             Registry key path (e.g. 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa')
  -v <NAME>              Value name to query or set
  -d <DATA>              Data to write to registry value
  -t <TYPE>              Value type (REG_SZ, REG_DWORD, REG_BINARY, REG_MULTI_SZ)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs reg corp.local/admin:Pass123@192.168.1.20 query -key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
  impacket-rs reg corp.local/admin@192.168.1.20 save -key HKLM\SAM -file sam.save
"#),
        "registry-read" => Some(r#"Description: Inspects offline registry hive files or queries remote Windows registry values via MS-RRP.

usage: impacket-rs registry-read [options]

options:
  -h, --help            show this help message and exit
  -hive <FILE>           Local registry hive file to parse
  -key <KEY>             Registry key path to read

examples:
  impacket-rs registry-read -hive SYSTEM -key "ControlSet001\Control\Lsa"
"#),
        "rpc-interfaces" => Some(r#"Description: Lists well-known DCE/RPC interface UUIDs, versions, and named pipes supported by Impacket-RS.

usage: impacket-rs rpc-interfaces

options:
  -h, --help            show this help message and exit

examples:
  impacket-rs rpc-interfaces
"#),
        "rpcdump" => Some(r#"Description: Dumps the list of registered RPC endpoints and interface UUIDs from the Endpoint Mapper (EPM over TCP/135).

usage: impacket-rs rpcdump [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -port <PORT>           DCE/RPC Endpoint Mapper port (default: 135)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs rpcdump 192.168.1.20
  impacket-rs rpcdump corp.local/jdoe:Pass123!@192.168.1.20 -port 135
"#),
        "rpcmap" => Some(r#"Description: Scans and maps RPC endpoints, protocols, and opnums across TCP and SMB named pipes.

usage: impacket-rs rpcmap [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -port <PORT>           Endpoint port (default: 135)
  -pipe <PIPE>           Target named pipe (e.g. \PIPE\srvsvc, \PIPE\samr)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs rpcmap 192.168.1.20
  impacket-rs rpcmap corp.local/jdoe:Pass123!@192.168.1.20 -pipe srvsvc
"#),
        "samedit" => Some(r#"Description: Modifies local user passwords in offline SAM/SYSTEM registry hive files.

usage: impacket-rs samedit -sam <SAM> -system <SYS> -user <U> -pass <P>

options:
  -h, --help            show this help message and exit
  -sam <FILE>            Path to SAM registry hive file
  -system <FILE>         Path to SYSTEM registry hive file
  -user <USER>           Username to modify
  -pass <PASS>           New password to set

examples:
  impacket-rs samedit -sam SAM -system SYSTEM -user Administrator -pass NewPassword123!
"#),
        "samrdump" => Some(r#"Description: Retrieves sensitive security account manager (SAM) and Active Directory user metadata and group memberships over MS-SAMR (\PIPE\samr).

usage: impacket-rs samrdump [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -csv                   Format user and group list as CSV records

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs samrdump corp.local/jdoe:Pass123!@192.168.1.20
  impacket-rs samrdump corp.local/admin@192.168.1.20 -hashes :aad3b435b51404eeaad3b435b51404ee
"#),
        "secretsdump" => Some(r#"Description: Performs various techniques for dumping secrets from remote machine without executing any agent there (DCSync over DRSR, remote registry hive extraction over RRP/SMB, SAM, LSA secrets, DPAPI backup keys).

usage: impacket-rs secretsdump [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address> or LOCAL

options:
  -h, --help            show this help message and exit
  -just-dc               Extract only NTDS.DIT data (NTLM hashes and Kerberos keys) via DCSync
  -just-dc-user <USER>   Extract only NTDS.DIT data for the specified user
  -just-dc-ntlm          Extract only NTDS.DIT data (NTLM hashes only)
  -pwd-last-set          Shows pwdLastSet attribute for each account
  -user-status           Display user status (disabled/enabled/expired)
  -history               Dump password history
  -resumefile <FILE>     Resume file to read/write for interrupted DCSync
  -sam <FILE>            Local SAM hive file to parse (LOCAL mode)
  -system <FILE>         Local SYSTEM hive file to parse (LOCAL mode)
  -security <FILE>       Local SECURITY hive file to parse (LOCAL mode)
  -ntds <FILE>           Local NTDS.DIT file to parse (LOCAL mode)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs secretsdump corp.local/admin:Pass123@192.168.1.10 -just-dc
  impacket-rs secretsdump corp.local/admin@192.168.1.10 -hashes :aad3b435b51404eeaad3b435b51404ee -just-dc-user Administrator
  impacket-rs secretsdump LOCAL -sam SAM -system SYSTEM -security SECURITY
"#),
        "secretsdump-local" => Some(r#"Description: Offline secrets dumper: extracts user hashes, DCC2 cached credentials, and LSA secrets from local SAM, SYSTEM, and SECURITY hive files.

usage: impacket-rs secretsdump-local -sam <SAM> -system <SYS> [-security <SEC>]

options:
  -h, --help            show this help message and exit
  -sam <FILE>            Local SAM registry hive file
  -system <FILE>         Local SYSTEM registry hive file
  -security <FILE>       Local SECURITY registry hive file (optional, dumps LSA secrets & DCC2)

examples:
  impacket-rs secretsdump-local -sam SAM -system SYSTEM -security SECURITY
"#),
        "services" => Some(r#"Description: Manages remote Windows services via the Service Control Manager (MS-SCMR over \PIPE\svcctl). Query, create, start, stop, pause, and delete services.

usage: impacket-rs services [options] <target> <action> [serviceName] [options]

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>
    action: list | create | start | stop | delete | status | config

options:
  -h, --help            show this help message and exit
  -name <NAME>           Service name
  -display <NAME>        Service display name
  -path <PATH>           Binary path for service execution

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs services corp.local/admin:Pass123@192.168.1.20 list
  impacket-rs services corp.local/admin@192.168.1.20 status -name LanmanServer
  impacket-rs services corp.local/admin@192.168.1.20 start -name Spooler
"#),
        "smb-negotiate" => Some(r#"Description: Probes an SMB server's dialect negotiation capabilities and security features.

usage: impacket-rs smb-negotiate <host> [port]

positional arguments:
  host: Target host IP or hostname
    port: Port to connect to (default: 445)

options:
  -h, --help            show this help message and exit

examples:
  impacket-rs smb-negotiate 192.168.1.20
"#),
        "smbclient" => Some(r#"Description: Interactive SMB shell or batch automation tool over SMBv1, SMB2.0.2, and SMB3.1.1 with support for encryption, signing, and full filesystem navigation.

usage: impacket-rs smbclient [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -batch <FILE>          Execute commands sequentially from a batch script file
  -c <COMMANDS>          Execute semicolon-separated commands and exit
  -port <PORT>           SMB port to connect to (default: 445, or 139)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs smbclient corp.local/jdoe:Pass123!@192.168.1.20
  impacket-rs smbclient corp.local/admin@192.168.1.20 -c "use C$; ls; get Windows/win.ini /tmp/win.ini"
  impacket-rs smbclient corp.local/admin@192.168.1.20 -batch commands.txt
"#),
        "smbexec" => Some(r#"Description: A stealthy service execution alternative to psexec. Manipulates the Service Control Manager without uploading a custom binary; runs commands directly through %COMSPEC% and reads output from a temp file.

usage: impacket-rs smbexec [options] <target> [command]

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>
    command: Command to execute remotely

options:
  -h, --help            show this help message and exit
  -share <SHARE>         SMB share name for output capture (default: C$)
  -mode <SHARE|SERVER>   Output capture mode

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs smbexec corp.local/admin:Pass123@192.168.1.20 "ipconfig /all"
  impacket-rs smbexec corp.local/admin@192.168.1.20 -hashes :aad3b435b51404eeaad3b435b51404ee
"#),
        "smbpasswd" => Some(r#"Description: Changes local or domain user passwords over SMB port 445 via SAMR.

usage: impacket-rs smbpasswd [options] <target> [new_password]

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>
    new_password: New password to set

options:
  -h, --help            show this help message and exit

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs smbpasswd corp.local/jdoe:OldPass123!@192.168.1.20 NewPass456!
"#),
        "smbserver" => Some(r#"Description: Pure-Rust multi-threaded SMBv2/SMBv3 file server supporting user authentication, file sharing, and NetNTLM hash capture.

usage: impacket-rs smbserver [options] <shareName> <sharePath>

positional arguments:
  shareName: Name of the SMB share to expose
    sharePath: Local filesystem directory path to serve

options:
  -h, --help            show this help message and exit
  -port <PORT>           Port to bind the SMB server to (default: 445)
  -smb2support           Enable SMB2/SMB3 support (enabled by default)
  -user <USER>           Username required for access (anonymous by default)
  -password <PASS>       Password required for access
  -comment <TEXT>        Share description comment

examples:
  impacket-rs smbserver SHARE /tmp/share
  impacket-rs smbserver -user admin -password secret TOOLS /opt/tools
"#),
        "sniffer" => Some(r#"Description: Network packet sniffer and protocol dissector for offline PCAP captures or live sockets.

usage: impacket-rs sniffer [options]

options:
  -h, --help            show this help message and exit
  -pcap <FILE>           PCAP capture file to dissect
  -filter <PORT>         Port filter for packet dissection
  -test                  Run synthetic packet dissection test suite

examples:
  impacket-rs sniffer -pcap capture.pcap -filter 445
  impacket-rs sniffer -test
"#),
        "split" => Some(r#"Description: Splits a large input wordlist or file into multiple chunks for distributed processing.

usage: impacket-rs split <file> <chunk_size> [output_prefix]

positional arguments:
  file: Input file to split
    chunk_size: Number of lines per chunk
    output_prefix: Prefix for output chunk files (default: chunk_)

options:
  -h, --help            show this help message and exit

examples:
  impacket-rs split wordlist.txt 10000 part_
"#),
        "ticketConverter" => Some(r#"Description: Converts Kerberos credential caches between Linux ccache format and Windows LSA kirbi (.kirbi) format.

usage: impacket-rs ticketConverter <input_file> <output_file>

positional arguments:
  input_file: Source ticket file (.ccache or .kirbi)
    output_file: Destination ticket file (.kirbi or .ccache)

options:
  -h, --help            show this help message and exit

examples:
  impacket-rs ticketConverter ticket.ccache ticket.kirbi
  impacket-rs ticketConverter admin.kirbi admin.ccache
"#),
        "ticketer" => Some(r#"Description: Creates customized Golden, Silver, and Diamond Kerberos tickets from scratch, embedding custom SIDs, group memberships, and PAC signatures.

usage: impacket-rs ticketer [options] <user>

positional arguments:
  user: Target username to issue ticket for

options:
  -h, --help            show this help message and exit
  -domain-sid <SID>      Active Directory Domain SID
  -domain <DOMAIN>       Active Directory Domain FQDN
  -nthash <HASH>         KRBTGT or Service account NTLM hash
  -aesKey <KEY>          KRBTGT or Service account AES key (128 or 256 bits)
  -spn <SPN>             Service Principal Name (omit for Golden Ticket, specify for Silver Ticket)
  -user-id <RID>         User RID to assign (default: 500 for Administrator)
  -groups <G1,G2,...>    Comma-separated group RIDs (default: 513,512,520,518,519)

examples:
  impacket-rs ticketer -domain-sid S-1-5-21-123456789-123456789-123456789 -domain corp.local -nthash aad3b435b51404eeaad3b435b51404ee Administrator
  impacket-rs ticketer -domain-sid S-1-5-21-123456789-123456789-123456789 -domain corp.local -spn cifs/fs01.corp.local -nthash aad3b435b51404eeaad3b435b51404ee Administrator
"#),
        "tracer" => Some(r#"Description: TCP traceroute and network hop prober using TCP SYN/ACK handshakes to trace path to target.

usage: impacket-rs tracer [options] <target>

positional arguments:
  target: Target hostname or IP address

options:
  -h, --help            show this help message and exit
  -port <PORT>           Destination port to probe (default: 445)
  -max-hops <N>          Maximum number of hops (default: 30)

examples:
  impacket-rs tracer 192.168.1.20 -port 445
"#),
        "trueTree" => Some(r#"Description: Maps Active Directory trust relationships, direction, transitivity, and SID filtering across forests.

usage: impacket-rs trueTree [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs trueTree corp.local/jdoe:Pass123!@192.168.1.10
"#),
        "tstool" => Some(r#"Description: Windows Terminal Services and Task Scheduler inspection tool ([MS-TSCH] and [MS-TSTS]).

usage: impacket-rs tstool [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -action <list|info|xml|delete|run> Action to perform (default: list)
  -task <NAME>           Task name to query or manipulate

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs tstool corp.local/admin:Pass123@192.168.1.20 -action list
"#),
        "wmiexec" => Some(r#"Description: Semi-interactive executive shell using Windows Management Instrumentation (WMI / Win32_Process::Create). Executes commands without touching svchost/services, with output retrieved via SMB.

usage: impacket-rs wmiexec [options] <target> [command]

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>
    command: Command to execute remotely (default: interactive shell)

options:
  -h, --help            show this help message and exit
  -share <SHARE>         SMB share name for output capture (default: ADMIN$)
  -nooutput              Execute command stealthily without redirecting or reading output
  -silentcommand         Do not print output retrieval metadata

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs wmiexec corp.local/admin:Pass123@192.168.1.20 "net user"
  impacket-rs wmiexec corp.local/admin@192.168.1.20 -hashes :aad3b435b51404eeaad3b435b51404ee
  impacket-rs wmiexec corp.local/admin@192.168.1.20 -nooutput "powershell -enc ..."
"#),
        "wmipersist" => Some(r#"Description: Manages WMI Event Subscriptions for persistence. List, inspect, add, or remove __EventFilter, __EventConsumer, and __FilterToConsumerBinding.

usage: impacket-rs wmipersist [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -action <list|info|remove> Action to perform (default: list)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs wmipersist corp.local/admin:Pass123@192.168.1.20 -action list
"#),
        "wmiquery" => Some(r#"Description: Executes WMI WQL queries remotely and inspects Windows management instrumentation schemas and classes.

usage: impacket-rs wmiquery [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -query <WQL>           WQL query string (e.g. 'SELECT * FROM Win32_OperatingSystem')
  -namespace <NS>        WMI namespace (default: root\cimv2)

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs wmiquery corp.local/admin:Pass123@192.168.1.20 -query "SELECT Caption, Version FROM Win32_OperatingSystem"
"#),
        "wspsearch" => Some(r#"Description: Windows Search Protocol client ([MS-WSP]). Queries remote indexed catalogs and file systems.

usage: impacket-rs wspsearch [options] <target>

positional arguments:
  target: [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -query <SQL>           Search query expression

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME)
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -dc-ip ip address     IP Address of the domain controller
  -target-ip ip address IP Address of the target machine
  -port port            Destination port to connect to

examples:
  impacket-rs wspsearch corp.local/jdoe:Pass123!@192.168.1.20 -query "SELECT System.ItemName FROM SystemIndex WHERE SCOPE=\'file:\'"
"#),
        _ => None,
    }
}

pub fn canonicalize_name(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    let cleaned = lower.replace('-', "").replace('_', "");
    match cleaned.as_str() {
        "secretsdump" => "secretsdump",
        "getnpusers" => "GetNPUsers",
        "getuserspns" => "GetUserSPNs",
        "psexec" => "psexec",
        "wmiexec" => "wmiexec",
        "smbexec" => "smbexec",
        "atexec" => "atexec",
        "dcomexec" => "dcomexec",
        "smbclient" => "smbclient",
        "smbserver" => "smbserver",
        "ntlmrelayx" => "ntlmrelayx",
        "gettgt" => "getTGT",
        "getst" => "getST",
        "ticketconverter" => "ticketConverter",
        "ticketer" => "ticketer",
        "lookupsid" => "lookupsid",
        "samrdump" => "samrdump",
        "rpcdump" => "rpcdump",
        "rpcmap" => "rpcmap",
        "netview" => "netview",
        "reg" => "reg",
        "services" => "services",
        "mssqlclient" => "mssqlclient",
        "getadusers" => "GetADUsers",
        "getadcomputers" => "GetADComputers",
        "getlapspassword" => "GetLAPSPassword",
        "checkldapstatus" => "CheckLDAPStatus",
        "addcomputer" => "addcomputer",
        "dacledit" => "dacledit",
        "owneredit" => "owneredit",
        "dnstool" => "dnstool",
        "ldapsearch" => "ldapsearch",
        "ldapclient" => "ldapclient",
        "dfsclient" => "dfsclient",
        "getarch" => "getArch",
        "machinerole" => "machine_role",
        "oxidquery" => "oxidquery",
        "samedit" => "samedit",
        "changepasswd" => "changepasswd",
        "getgpppassword" => "Get-GPPPassword",
        "net" => "net",
        "wmiquery" => "wmiquery",
        "wmipersist" => "wmipersist",
        "wspsearch" => "wspsearch",
        "rdpcheck" => "rdp_check",
        "registryread" => "registry-read",
        "tstool" => "tstool",
        "ping" => "ping",
        "tracer" => "tracer",
        "sniffer" => "sniffer",
        "mqttcheck" => "mqtt_check",
        "klist" => "klist",
        "attrib" => "attrib",
        "filetime" => "filetime",
        "mssqlinstance" => "mssqlinstance",
        "checkmssqlstatus" => "checkMSSQLStatus",
        "dumpntlminfo" => "DumpNTLMInfo",
        "ntdsdump" => "ntdsdump",
        "esentutl" => "esentutl",
        "dpapi" => "dpapi",
        "describeticket" => "describeTicket",
        "getpac" => "getPac",
        "rbcd" => "rbcd",
        "finddelegation" => "findDelegation",
        "truetree" => "trueTree",
        "raisechild" => "raiseChild",
        "smbpasswd" => "smbpasswd",
        "split" => "split",
        "atq" => "atq",
        "eventlog" => "eventlog",
        "compatmatrix" => "compat-matrix",
        "parsetarget" => "parse-target",
        "ntlmhash" => "ntlm-hash",
        "krb5asreq" => "krb5-asreq",
        "smbnegotiate" => "smb-negotiate",
        "rpcinterfaces" => "rpc-interfaces",
        "benchndr" => "bench-ndr",
        "secretsdumplocal" => "secretsdump-local",
        "netfiles" => "netfiles",
        "dumpntlm" => "DumpNTLMInfo",
        "ntlm" => "DumpNTLMInfo",
        "secrets" => "secretsdump",
        "getnp" => "GetNPUsers",
        "getuserspn" => "GetUserSPNs",
        "getaduser" => "GetADUsers",
        "getadcomputer" => "GetADComputers",
        "getlaps" => "GetLAPSPassword",
        "checkldap" => "CheckLDAPStatus",
        "checkmssql" => "checkMSSQLStatus",
        "gpppassword" => "Get-GPPPassword",
        "gpp" => "Get-GPPPassword",
        "getuserpac" => "getPac",
        "ldapshell" => "ldapclient",
        "dfssearch" => "dfsclient",
        "tsch" => "atq",
        "ping6" => "ping",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_tools_have_detailed_help() {
        let tools = [
            "secretsdump", "GetNPUsers", "GetUserSPNs", "psexec", "wmiexec",
            "smbclient", "ntlmrelayx", "getTGT", "getST", "ticketConverter",
            "ticketer", "samrdump", "lookupsid", "rpcdump", "rpcmap",
            "netview", "reg", "services", "mssqlclient", "GetADUsers",
            "GetADComputers", "GetLAPSPassword", "CheckLDAPStatus", "addcomputer",
            "dacledit", "owneredit", "dnstool", "ldapsearch", "ldapclient",
            "dfsclient", "getArch", "machine_role", "oxidquery", "samedit",
            "changepasswd", "Get-GPPPassword", "net", "wmiquery", "wmipersist",
            "wspsearch", "rdp_check", "registry-read", "tstool", "ping",
            "tracer", "sniffer", "mqtt_check", "klist", "attrib", "filetime",
            "mssqlinstance", "checkMSSQLStatus", "DumpNTLMInfo", "ntdsdump",
            "esentutl", "dpapi", "describeTicket", "getPac", "rbcd",
            "findDelegation", "trueTree", "raiseChild", "smbpasswd", "split",
            "atq", "eventlog", "compat-matrix", "parse-target", "ntlm-hash",
            "krb5-asreq", "smb-negotiate", "rpc-interfaces", "bench-ndr",
            "secretsdump-local", "netfiles", "smbserver", "smbexec", "dcomexec",
        ];
        for tool in tools {
            let help = get_tool_help(tool);
            assert!(help.is_some(), "Tool '{}' missing detailed help message", tool);
            let text = help.unwrap();
            assert!(text.contains("usage:"), "Help for '{}' missing usage line", tool);
            assert!(text.contains("-h, --help"), "Help for '{}' missing -h flag", tool);
        }
    }

    #[test]
    fn test_case_insensitive_and_hyphen_aliases() {
        assert_eq!(canonicalize_name("get-np-users"), "GetNPUsers");
        assert_eq!(canonicalize_name("getnpusers"), "GetNPUsers");
        assert_eq!(canonicalize_name("SECRETSDUMP"), "secretsdump");
        assert_eq!(canonicalize_name("Get-UserSPNs"), "GetUserSPNs");
        assert_eq!(canonicalize_name("check-ldap-status"), "CheckLDAPStatus");
    }
}
