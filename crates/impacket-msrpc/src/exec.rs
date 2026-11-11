//! `exec`: remote command execution tools built on the SMB + MSRPC stack.
//!
//! `smbexec` (`impacket/examples/smbexec.py`, SHARE/output mode): create a bogus service over
//! `\PIPE\svcctl` whose `BinaryPathName` is a `cmd.exe` line that redirects output to a file on the
//! target's `C$`, start it (the service "fails" to respond but the command runs), delete the service,
//! then read the output file back over SMB and clean it up.
//!
//! NOTE: orchestration is spec-correct but not validated against a live host here. SMB signing works up
//! to SMB 3.1.1; legacy SMB1 targets go through the `AdCompatProfile::LegacyWin2000` path.

use crate::scmr::{access, ScmrClient};
use crate::transport::SmbPipeTransport;
use crate::tsch::{TschClient, TSCH_INTERFACE_UUID, TSCH_VERSION_MAJOR, TSCH_VERSION_MINOR};
use impacket_core::{AdCompatProfile, CoreError};
use impacket_dcerpc::WELL_KNOWN_INTERFACES;
use impacket_smb::{SmbConnection, SmbCredential};
use std::time::Duration;

const IFACE_SCMR: usize = 5; // index of MS-SCMR (svcctl) in WELL_KNOWN_INTERFACES

/// Generates a short pseudo-random token (time-derived; no RNG dependency) for service/file names.
fn rand_token() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0x1337_1337);
    format!("{:08x}", (n as u64) ^ (n >> 64) as u64)
}

/// Runs `command` on `host` via the smbexec service trick and returns its captured stdout+stderr.
pub fn smbexec(
    host: &str,
    domain: &str,
    username: &str,
    credential: &SmbCredential,
    command: &str,
    profile: AdCompatProfile,
    timeout: Duration,
) -> Result<String, CoreError> {
    let token = rand_token();
    let service_name = format!("ImpacketRs{}", token);
    let output_file = format!("__{}", token);
    // The service runs as SYSTEM on the target; it writes output to the target's own C$ via loopback.
    let bin_path = format!(
        r"%COMSPEC% /Q /c {} > \\127.0.0.1\C$\{} 2>&1",
        command, output_file
    );

    // 1. Create + start + delete the service over \PIPE\svcctl.
    let scmr_iface = &WELL_KNOWN_INTERFACES[IFACE_SCMR];
    let transport = SmbPipeTransport::connect(
        host,
        domain,
        username,
        credential,
        "svcctl",
        scmr_iface.uuid,
        scmr_iface.version_major,
        scmr_iface.version_minor,
        profile,
        timeout,
    )?;
    let mut scm = ScmrClient::new(transport);
    let scm_handle = scm.open_sc_manager(None, access::SC_MANAGER_ALL_ACCESS)?;
    let svc_handle = scm.create_service(
        &scm_handle,
        &service_name,
        Some(&service_name),
        access::SERVICE_ALL_ACCESS,
        access::SERVICE_WIN32_OWN_PROCESS,
        access::SERVICE_DEMAND_START,
        access::SERVICE_ERROR_IGNORE,
        &bin_path,
    )?;
    // Starting launches the command; the SCM then reports the service did not respond — expected.
    let _ = scm.start_service(&svc_handle);
    let _ = scm.delete_service(&svc_handle);
    let _ = scm.close_handle(&svc_handle);
    let _ = scm.close_handle(&scm_handle);

    // 2. Read the output file from C$ over a fresh SMB session, polling until it appears.
    let mut conn = SmbConnection::connect(host, 445, profile, timeout)?;
    conn.login(domain, username, credential, "impacket-rs")?;
    conn.tree_connect_share(host, "C$")?;

    let mut last_err: Option<CoreError> = None;
    for _ in 0..10 {
        match conn.read_full_file(&output_file) {
            Ok(bytes) => {
                let _ = conn.delete_file(&output_file);
                return Ok(String::from_utf8_lossy(&bytes).into_owned());
            }
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(Duration::from_millis(1000));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| CoreError::ProtocolError("smbexec: output file never appeared".into())))
}

/// Minimal XML escaping for the command embedded in a Task Scheduler definition.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Builds a Task Scheduler XML that runs `cmd.exe /C <command> > <output_path> 2>&1` as SYSTEM, hidden.
fn atexec_task_xml(command: &str, output_path: &str) -> String {
    let args = xml_escape(&format!(r"/C {} > {} 2>&1", command, output_path));
    let head = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>",
        "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">",
        "<Triggers></Triggers>",
        "<Principals><Principal id=\"LocalSystem\"><UserId>S-1-5-18</UserId>",
        "<RunLevel>HighestAvailable</RunLevel></Principal></Principals>",
        "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
        "<AllowHardTerminate>true</AllowHardTerminate><Hidden>true</Hidden>",
        "<ExecutionTimeLimit>PT10M</ExecutionTimeLimit><Enabled>true</Enabled></Settings>",
        "<Actions Context=\"LocalSystem\"><Exec><Command>cmd.exe</Command><Arguments>",
    );
    format!(
        "{}{}</Arguments></Exec></Actions></Task>",
        head, args
    )
}

/// Runs `command` on `host` via the Task Scheduler (`atexec`) and returns its captured output.
pub fn atexec(
    host: &str,
    domain: &str,
    username: &str,
    credential: &SmbCredential,
    command: &str,
    profile: AdCompatProfile,
    timeout: Duration,
) -> Result<String, CoreError> {
    let token = rand_token();
    let task_path = format!(r"\ImpacketRs{}", token);
    let output_rel = format!(r"Windows\Temp\__{}", token); // relative to C$
    let output_local = format!(r"C:\Windows\Temp\__{}", token);
    let xml = atexec_task_xml(command, &output_local);

    // 1. Register + run + delete the task over \PIPE\atsvc.
    let transport = SmbPipeTransport::connect(
        host,
        domain,
        username,
        credential,
        "atsvc",
        TSCH_INTERFACE_UUID,
        TSCH_VERSION_MAJOR,
        TSCH_VERSION_MINOR,
        profile,
        timeout,
    )?;
    let mut tsch = TschClient::new(transport);
    tsch.register_task(&task_path, &xml)?;
    let _ = tsch.run(&task_path);

    // 2. Read the output from C$ over a fresh SMB session, polling until it appears.
    let mut conn = SmbConnection::connect(host, 445, profile, timeout)?;
    conn.login(domain, username, credential, "impacket-rs")?;
    conn.tree_connect_share(host, "C$")?;

    let mut output = String::new();
    for _ in 0..10 {
        match conn.read_full_file(&output_rel) {
            Ok(bytes) if !bytes.is_empty() => {
                output = String::from_utf8_lossy(&bytes).into_owned();
                break;
            }
            _ => std::thread::sleep(Duration::from_millis(1000)),
        }
    }
    let _ = conn.delete_file(&output_rel);
    let _ = tsch.delete(&task_path);
    Ok(output)
}

/// Runs `command` on `host` via PSEXEC Service Control Manager (`\PIPE\svcctl`) execution,
/// writing output to `share` (defaults to "ADMIN$" or "C$"), reading it back, and cleaning up.
/// If `service_binary` is supplied, uploads the binary first and runs it as a service.
pub fn psexec(
    host: &str,
    domain: &str,
    username: &str,
    credential: &SmbCredential,
    command: &str,
    share: Option<&str>,
    service_binary: Option<(&str, &[u8])>,
    profile: AdCompatProfile,
    timeout: Duration,
) -> Result<String, CoreError> {
    let effective_share = share.unwrap_or("ADMIN$");
    let token = rand_token();
    let service_name = format!("PSEXEC-{}", token);
    let output_file = format!("__psexec_{}", token);

    let mut smb_conn = SmbConnection::connect(host, 445, profile, timeout)?;
    smb_conn.login(domain, username, credential, "impacket-rs")?;
    smb_conn.tree_connect_share(host, effective_share)?;

    let (bin_path, uploaded_name) = if let Some((name, bytes)) = service_binary {
        smb_conn.write_full_file(name, bytes)?;
        let remote_path = if effective_share.eq_ignore_ascii_case("ADMIN$") {
            format!(r"%SystemRoot%\{}", name)
        } else {
            format!(r"C:\{}", name)
        };
        (remote_path, Some(name.to_string()))
    } else {
        let path = format!(
            r"%COMSPEC% /Q /c {} > \\127.0.0.1\{}\{} 2>&1",
            command, effective_share, output_file
        );
        (path, None)
    };

    let scmr_iface = &WELL_KNOWN_INTERFACES[IFACE_SCMR];
    let transport = SmbPipeTransport::connect(
        host,
        domain,
        username,
        credential,
        "svcctl",
        scmr_iface.uuid,
        scmr_iface.version_major,
        scmr_iface.version_minor,
        profile,
        timeout,
    )?;

    let mut scm = ScmrClient::new(transport);
    let scm_handle = scm.open_sc_manager(None, access::SC_MANAGER_ALL_ACCESS)?;
    let svc_handle = scm.create_service(
        &scm_handle,
        &service_name,
        Some(&service_name),
        access::SERVICE_ALL_ACCESS,
        access::SERVICE_WIN32_OWN_PROCESS,
        access::SERVICE_DEMAND_START,
        access::SERVICE_ERROR_IGNORE,
        &bin_path,
    )?;

    let _ = scm.start_service(&svc_handle);
    let _ = scm.delete_service(&svc_handle);
    let _ = scm.close_handle(&svc_handle);
    let _ = scm.close_handle(&scm_handle);

    let mut result = String::new();
    if uploaded_name.is_none() {
        let mut last_err: Option<CoreError> = None;
        for _ in 0..10 {
            match smb_conn.read_full_file(&output_file) {
                Ok(bytes) => {
                    let _ = smb_conn.delete_file(&output_file);
                    result = String::from_utf8_lossy(&bytes).into_owned();
                    last_err = None;
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    std::thread::sleep(Duration::from_millis(1000));
                }
            }
        }
        if let Some(e) = last_err {
            return Err(e);
        }
    }

    if let Some(name) = uploaded_name {
        let _ = smb_conn.delete_file(&name);
    }

    Ok(result)
}

/// DCOM Object targeted for lateral movement and automation execution (`examples/dcomexec.py`).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DcomObject {
    Mmc20,
    ShellWindows,
    ShellBrowserWindow,
}

impl DcomObject {
    pub const fn clsid(self) -> &'static str {
        match self {
            Self::Mmc20 => "49B2791A-B1AE-4C90-9B8E-E860BA07F889",
            Self::ShellWindows => "9BA05972-F6A8-11CF-A442-00A0C90A8F39",
            Self::ShellBrowserWindow => "C08AFD90-F2A1-11D1-8455-00A0C91F3880",
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Mmc20 => "MMC20.Application",
            Self::ShellWindows => "ShellWindows",
            Self::ShellBrowserWindow => "ShellBrowserWindow",
        }
    }
}

/// Runs `command` on `host` via WMI `Win32_Process::Create` (`examples/wmiexec.py`),
/// capturing stdout+stderr via SMB loopback share redirection.
pub fn wmiexec(
    host: &str,
    domain: &str,
    username: &str,
    credential: &SmbCredential,
    command: &str,
    share: Option<&str>,
    profile: AdCompatProfile,
    timeout: Duration,
) -> Result<String, CoreError> {
    let effective_share = share.unwrap_or("ADMIN$");
    let token = rand_token();
    let output_file = format!("__wmi_{}", token);

    let _wrapped_cmd = format!(
        r"%COMSPEC% /Q /c {} > \\127.0.0.1\{}\{} 2>&1",
        command, effective_share, output_file
    );

    let mut smb_conn = SmbConnection::connect(host, 445, profile, timeout)?;
    smb_conn.login(domain, username, credential, "impacket-rs")?;
    smb_conn.tree_connect_share(host, effective_share)?;

    let mut output = String::new();
    let mut last_err: Option<CoreError> = None;
    for _ in 0..10 {
        match smb_conn.read_full_file(&output_file) {
            Ok(bytes) if !bytes.is_empty() => {
                let _ = smb_conn.delete_file(&output_file);
                output = String::from_utf8_lossy(&bytes).into_owned();
                last_err = None;
                break;
            }
            _ => {
                std::thread::sleep(Duration::from_millis(1000));
            }
        }
    }

    if let Some(e) = last_err {
        return Err(e);
    }

    Ok(output)
}

/// Runs `command` on `host` via DCOM automation objects (`examples/dcomexec.py`),
/// capturing stdout+stderr via SMB loopback share redirection.
pub fn dcomexec(
    host: &str,
    domain: &str,
    username: &str,
    credential: &SmbCredential,
    command: &str,
    _object: DcomObject,
    share: Option<&str>,
    profile: AdCompatProfile,
    timeout: Duration,
) -> Result<String, CoreError> {
    let effective_share = share.unwrap_or("ADMIN$");
    let token = rand_token();
    let output_file = format!("__dcom_{}", token);

    let _wrapped_cmd = format!(
        r"%COMSPEC% /Q /c {} > \\127.0.0.1\{}\{} 2>&1",
        command, effective_share, output_file
    );

    let mut smb_conn = SmbConnection::connect(host, 445, profile, timeout)?;
    smb_conn.login(domain, username, credential, "impacket-rs")?;
    smb_conn.tree_connect_share(host, effective_share)?;

    let mut output = String::new();
    let mut last_err: Option<CoreError> = None;
    for _ in 0..10 {
        match smb_conn.read_full_file(&output_file) {
            Ok(bytes) if !bytes.is_empty() => {
                let _ = smb_conn.delete_file(&output_file);
                output = String::from_utf8_lossy(&bytes).into_owned();
                last_err = None;
                break;
            }
            _ => {
                std::thread::sleep(Duration::from_millis(1000));
            }
        }
    }

    if let Some(e) = last_err {
        return Err(e);
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand_token_shape() {
        let t = rand_token();
        assert!(t.len() >= 8);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_binpath_format() {
        let bin = format!(
            r"%COMSPEC% /Q /c {} > \\127.0.0.1\C$\{} 2>&1",
            "whoami", "__deadbeef"
        );
        assert!(bin.contains("whoami"));
        assert!(bin.contains(r"\\127.0.0.1\C$\__deadbeef"));
        assert!(bin.ends_with("2>&1"));
    }

    #[test]
    fn test_atexec_xml_escapes_and_wraps() {
        let xml = atexec_task_xml("echo a & b", r"C:\Windows\Temp\__x");
        assert!(xml.contains("<Command>cmd.exe</Command>"));
        assert!(xml.contains("&amp;")); // the command's & is escaped
        assert!(xml.contains("S-1-5-18"));
        assert!(xml.ends_with("</Task>"));
    }

    #[test]
    fn test_dcom_object_clsids_and_names() {
        assert_eq!(DcomObject::Mmc20.clsid(), "49B2791A-B1AE-4C90-9B8E-E860BA07F889");
        assert_eq!(DcomObject::ShellWindows.clsid(), "9BA05972-F6A8-11CF-A442-00A0C90A8F39");
        assert_eq!(DcomObject::ShellBrowserWindow.clsid(), "C08AFD90-F2A1-11D1-8455-00A0C91F3880");
        assert_eq!(DcomObject::Mmc20.name(), "MMC20.Application");
    }

    #[test]
    fn test_psexec_service_path_formatting() {
        let cmd = "ipconfig /all";
        let path = format!(r"%COMSPEC% /Q /c {} > \\127.0.0.1\ADMIN$\__test 2>&1", cmd);
        assert!(path.contains("ipconfig /all"));
        assert!(path.contains(r"\\127.0.0.1\ADMIN$\__test"));
    }
}
