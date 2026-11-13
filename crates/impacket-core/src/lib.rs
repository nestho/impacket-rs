//! `impacket-core`: Foundational types, memory-safe credential wrappers,
//! classic Impacket target specification parser (`[[domain/]username[:password]@]<target>`),
//! cross-era Active Directory compatibility profiles (`AdCompatProfile`: Windows 2000 through Server 2025),
//! standard SemVer version/banner module (`impacket/version.py`),
//! Windows `FileTime` converter, NTSTATUS error catalog, and UTF-16LE / hexdump utilities.

use std::fmt;
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

/// Standard Semantic Versioning & Banner module matching `impacket/version.py`.
///
/// Follows Cargo / SemVer 2.0.0 (`0.MAJOR_MILESTONE.PATCH-dev` during active development,
/// promoting `[Unreleased]` in `CHANGELOG.md` to `0.1.0`, `0.2.0`, etc. at release boundaries,
/// just as Python Impacket does in `impacket/version.py` and `ChangeLog.md`).
pub mod version {
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");
    pub const BANNER: &str = concat!(
        "Impacket-RS v",
        env!("CARGO_PKG_VERSION"),
        " - High-Performance Active Directory & Protocol Toolkit\n"
    );
}

pub mod der;
pub mod transport;

pub use transport::{ProxyAuth, ProxyConfig, ProxyType, TransportStream};

/// Volatile memory wipe helper (equivalent to `zeroize`) to ensure sensitive
/// keys, passwords, and NTLM hashes are scrubbed from RAM on `Drop`.
#[inline]
pub fn zeroize_slice(slice: &mut [u8]) {
    for byte in slice.iter_mut() {
        unsafe {
            ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

/// Cross-Era Active Directory Compatibility Profile.
///
/// Governs protocol dialect selection, cryptographic cipher suites, authentication levels,
/// and channel binding behavior from Windows 2000/2003 through Windows Server 2025.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AdCompatProfile {
    /// **Legacy Era (Windows NT 4.0 / 2000 / 2003 / XP)**:
    /// - Enables SMBv1 (`NT LM 0.12`) multi-protocol negotiation & NetBIOS TCP/139 framing
    /// - Allows LMv1 / NTLMv1 (DES-56) and NTLMv1 with Extended Session Security (ESS)
    /// - Advertises Kerberos `RC4-HMAC` (`23`), `DES-CBC-MD5` (`3`), and `DES-CBC-CRC` (`1`)
    /// - Uses legacy RPC opnums (`LsarOpenPolicy` opnum 6, `SamrConnect` opnum 0) when v2/v5 opnums fail
    LegacyWin2000,

    /// **Universal Auto-Negotiate (Windows Server 2008 R2 -> 2022 Default)**:
    /// - Negotiates SMB 2.0.2 (`0x0202`) through SMB 3.1.1 (`0x0311`) with SMBv1 fallback
    /// - Uses NTLMv2 (`HMAC-MD5`) with `AV_PAIR` target info and MIC when server timestamp is present
    /// - Advertises Kerberos `[RC4-HMAC (23), AES256 (18), AES128 (17)]`
    /// - Automatically falls back from modern RPC opnums (`SamrConnect5` opnum 64) to legacy (`SamrConnect` opnum 0)
    UniversalAuto,

    /// **Modern Hardened Era (Windows Server 2022 / 2025 Strict Mode)**:
    /// - Requires SMB 3.1.1 (`0x0311`) with SHA-512 preauth integrity and AES-128/256-GCM encryption
    /// - Enforces NTLMv2 with MIC + EPA Channel Binding (`MsvAvChannelBindings`) and `MsvAvTargetName` SPN
    /// - Restricts Kerberos to AES-SHA1 (`18`, `17`) only (zero RC4/DES downgrade exposure)
    /// - Enforces `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` + `PFC_SUPPORT_HEADER_SIGN` on all MSRPC calls
    ModernHardened2025,
}

impl AdCompatProfile {
    pub fn parse(name: &str) -> Result<Self, CoreError> {
        match name.trim().to_ascii_lowercase().as_str() {
            "legacy" | "win2000" | "win2003" | "nt4" => Ok(Self::LegacyWin2000),
            "auto" | "universal" | "default" | "standard" => Ok(Self::UniversalAuto),
            "modern" | "hardened" | "win2025" | "win2022" => Ok(Self::ModernHardened2025),
            other => Err(CoreError::ProtocolError(format!(
                "Unknown AD compatibility profile '{}' (expected: legacy, auto, modern)",
                other
            ))),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::LegacyWin2000 => "Legacy (Win2000/2003/XP - SMBv1/NTLMv1/RC4+DES)",
            Self::UniversalAuto => "Universal Auto (Adaptive Windows 2000 - Server 2025)",
            Self::ModernHardened2025 => "Modern Hardened (Win2022/2025 - SMB3.1.1/AES/EPA/Privacy)",
        }
    }

    pub const fn allows_smbv1(self) -> bool {
        matches!(self, Self::LegacyWin2000 | Self::UniversalAuto)
    }

    pub const fn allows_ntlmv1(self) -> bool {
        matches!(self, Self::LegacyWin2000)
    }

    pub const fn requires_epa_channel_binding(self) -> bool {
        matches!(self, Self::ModernHardened2025)
    }
}

/// Windows `FILETIME` (64-bit count of 100-nanosecond intervals since January 1, 1601 UTC).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FileTime(pub u64);

impl FileTime {
    pub const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn from_unix_secs(secs: u64) -> Self {
        Self(secs * 10_000_000 + Self::EPOCH_DIFF_100NS)
    }

    pub fn now() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self::from_unix_secs(secs)
    }

    pub const fn to_unix_secs(self) -> Option<u64> {
        if self.0 < Self::EPOCH_DIFF_100NS {
            None
        } else {
            Some((self.0 - Self::EPOCH_DIFF_100NS) / 10_000_000)
        }
    }

    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    pub const fn from_le_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_le_bytes(bytes))
    }
}

impl fmt::Debug for FileTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_unix_secs() {
            Some(unix) => write!(f, "FileTime(0x{:016x}, unix={}s)", self.0, unix),
            None => write!(f, "FileTime(0x{:016x})", self.0),
        }
    }
}

/// Memory-safe wrapper for cleartext secrets that wipes its heap buffer on `Drop`.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString {
    inner: Vec<u8>,
}

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        Self {
            inner: s.into().into_bytes(),
        }
    }

    pub fn expose_secret(&self) -> &str {
        std::str::from_utf8(&self.inner).unwrap_or("")
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        zeroize_slice(&mut self.inner);
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString([REDACTED])")
    }
}

/// Represents a 16-byte LM and 16-byte NT hash pair (`LMHASH:NTHASH` or `:NTHASH`).
#[derive(Clone, PartialEq, Eq)]
pub struct NtlmHashes {
    pub lm: [u8; 16],
    pub nt: [u8; 16],
    pub has_lm: bool,
}

pub const EMPTY_LM_HASH: [u8; 16] = [
    0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee,
    0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee,
];

pub const EMPTY_NT_HASH: [u8; 16] = [
    0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
    0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
];

impl NtlmHashes {
    pub fn parse(spec: &str) -> Result<Self, CoreError> {
        let spec = spec.trim();
        let (lm_hex, nt_hex) = if let Some((l, n)) = spec.split_once(':') {
            (l.trim(), n.trim())
        } else {
            ("", spec)
        };

        let nt = decode_hex_16(nt_hex).map_err(|_| {
            CoreError::InvalidHashFormat(format!("NT hash must be 32 hex chars, got '{}'", nt_hex))
        })?;

        let (lm, has_lm) = if lm_hex.is_empty() {
            (EMPTY_LM_HASH, false)
        } else {
            (
                decode_hex_16(lm_hex).map_err(|_| {
                    CoreError::InvalidHashFormat(format!(
                        "LM hash must be 32 hex chars, got '{}'",
                        lm_hex
                    ))
                })?,
                true,
            )
        };

        Ok(Self { lm, nt, has_lm })
    }

    pub fn to_hex_pair(&self) -> String {
        format!("{}:{}", encode_hex(&self.lm), encode_hex(&self.nt))
    }
}

impl Drop for NtlmHashes {
    fn drop(&mut self) {
        zeroize_slice(&mut self.lm);
        zeroize_slice(&mut self.nt);
    }
}

impl fmt::Debug for NtlmHashes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NtlmHashes {{ lm: [REDACTED], nt: [REDACTED], has_lm: {} }}",
            self.has_lm
        )
    }
}

/// Parses the canonical Impacket target string:
/// `[[domain/]username[:password]@]<targetName or address>`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSpec {
    pub domain: String,
    pub username: String,
    pub password: Option<SecretString>,
    pub remote_name: String,
    pub target_port: Option<u16>,
    pub dc_ip: Option<String>,
    pub target_ip: Option<String>,
    pub use_kerberos: bool,
    pub no_pass: bool,
    pub hashes: Option<NtlmHashes>,
    pub aes_key: Option<Vec<u8>>,
    pub compat_profile: AdCompatProfile,
    pub proxy: Option<ProxyConfig>,
}

impl TargetSpec {
    pub fn parse(target: &str) -> Result<Self, CoreError> {
        let target = target.trim();
        if target.is_empty() {
            return Err(CoreError::InvalidTarget("Target string cannot be empty".into()));
        }

        let (credentials_part, host_port_raw) = match target.rsplit_once('@') {
            Some((creds, host)) => (Some(creds), host.trim()),
            None => (None, target),
        };

        if host_port_raw.is_empty() {
            return Err(CoreError::InvalidTarget(
                "Missing target hostname or IP address after '@'".into(),
            ));
        }

        let (remote_name, target_port) = if host_port_raw.starts_with('[') {
            // Bracketed IPv6: [2001:db8::1] or [fe80::1]:445
            if let Some(end) = host_port_raw.find(']') {
                let ipv6_host = &host_port_raw[1..end];
                let rest = &host_port_raw[end + 1..];
                let port = if let Some(p_str) = rest.strip_prefix(':') {
                    Some(
                        p_str
                            .parse::<u16>()
                            .map_err(|e| CoreError::InvalidTarget(format!("Invalid target port: {}", e)))?,
                    )
                } else {
                    None
                };
                (ipv6_host.to_string(), port)
            } else {
                return Err(CoreError::InvalidTarget(
                    "Mismatched bracket in IPv6 address: missing closing ']'".into(),
                ));
            }
        } else if let Some((h, p_str)) = host_port_raw.split_once(':') {
            // Check if it's an unbracketed IPv6 (contains multiple colons)
            if h.contains(':') || p_str.contains(':') {
                (host_port_raw.to_string(), None)
            } else {
                let port = p_str
                    .parse::<u16>()
                    .map_err(|e| CoreError::InvalidTarget(format!("Invalid target port: {}", e)))?;
                (h.to_string(), Some(port))
            }
        } else {
            (host_port_raw.to_string(), None)
        };

        let mut domain = String::new();
        let mut username = String::new();
        let mut password = None;

        if let Some(creds) = credentials_part {
            let (dom_opt, user_pass) = match creds.split_once('/') {
                Some((d, rest)) => (Some(d), rest),
                None => (None, creds),
            };

            if let Some(d) = dom_opt {
                domain = d.to_string();
            }

            if let Some((u, p)) = user_pass.split_once(':') {
                username = u.to_string();
                password = Some(SecretString::new(p));
            } else {
                username = user_pass.to_string();
            }
        }

        Ok(Self {
            domain,
            username,
            password,
            remote_name,
            target_port,
            dc_ip: None,
            target_ip: None,
            use_kerberos: false,
            no_pass: false,
            hashes: None,
            aes_key: None,
            compat_profile: AdCompatProfile::UniversalAuto,
            proxy: ProxyConfig::from_env(),
        })
    }

    pub fn with_hashes(mut self, hashes_str: &str) -> Result<Self, CoreError> {
        self.hashes = Some(NtlmHashes::parse(hashes_str)?);
        Ok(self)
    }

    pub fn with_compat_profile(mut self, profile: AdCompatProfile) -> Self {
        self.compat_profile = profile;
        self
    }

    pub fn with_proxy(mut self, proxy: ProxyConfig) -> Self {
        self.proxy = Some(proxy);
        self
    }

    pub fn with_proxy_url(mut self, proxy_url: &str) -> Result<Self, CoreError> {
        self.proxy = Some(ProxyConfig::parse(proxy_url)?);
        Ok(self)
    }

    pub fn effective_target_ip(&self) -> &str {
        self.target_ip.as_deref().unwrap_or(&self.remote_name)
    }

    pub fn effective_port(&self, default_port: u16) -> u16 {
        self.target_port.unwrap_or(default_port)
    }
}

/// Core error type for `impacket-core` and downstream protocol crates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    InvalidTarget(String),
    InvalidHashFormat(String),
    InvalidHex(String),
    BufferUnderflow { needed: usize, available: usize },
    InvalidUtf16,
    AlignmentError,
    ProtocolError(String),
    NtStatus(NtStatus),
    RpcFault(u32),
    IoError(String),
    ProxyError(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTarget(msg) => write!(f, "Invalid target specification: {}", msg),
            Self::InvalidHashFormat(msg) => write!(f, "Invalid NTLM hash format: {}", msg),
            Self::InvalidHex(msg) => write!(f, "Invalid hex string: {}", msg),
            Self::BufferUnderflow { needed, available } => write!(
                f,
                "Packet buffer underflow: needed {} bytes, but only {} available",
                needed, available
            ),
            Self::InvalidUtf16 => write!(f, "Invalid UTF-16LE byte sequence in packet"),
            Self::AlignmentError => write!(f, "NDR alignment error"),
            Self::ProtocolError(msg) => write!(f, "Protocol error: {}", msg),
            Self::RpcFault(status) => write!(f, "DCE/RPC Fault status: 0x{:08X}", status),
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::ProxyError(msg) => write!(f, "Proxy error: {}", msg),
            Self::NtStatus(status) => write!(
                f,
                "NTSTATUS 0x{:08X} ({}): {}",
                status.0,
                status.name(),
                status.description()
            ),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<std::io::Error> for CoreError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

/// Zero-overhead compile-time NTSTATUS representation replacing the 381 KB `nt_errors.py` dictionary.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct NtStatus(pub u32);

impl NtStatus {
    pub const STATUS_SUCCESS: Self = Self(0x0000_0000);
    pub const STATUS_MORE_ENTRIES: Self = Self(0x0000_0105);
    pub const STATUS_SOME_NOT_MAPPED: Self = Self(0x0000_0107);
    pub const STATUS_NO_MORE_FILES: Self = Self(0x8000_0006);
    pub const STATUS_NO_SUCH_FILE: Self = Self(0xC000_000F);
    pub const STATUS_MORE_PROCESSING_REQUIRED: Self = Self(0xC000_0016);
    pub const STATUS_ACCESS_DENIED: Self = Self(0xC000_0022);
    pub const STATUS_OBJECT_NAME_NOT_FOUND: Self = Self(0xC000_0034);
    pub const STATUS_LOGON_FAILURE: Self = Self(0xC000_006D);
    pub const STATUS_ACCOUNT_RESTRICTION: Self = Self(0xC000_006E);
    pub const STATUS_INVALID_LOGON_HOURS: Self = Self(0xC000_006F);
    pub const STATUS_PASSWORD_EXPIRED: Self = Self(0xC000_0071);
    pub const STATUS_ACCOUNT_DISABLED: Self = Self(0xC000_0072);
    pub const STATUS_NONE_MAPPED: Self = Self(0xC000_0073);
    pub const STATUS_PIPE_NOT_AVAILABLE: Self = Self(0xC000_00AC);
    pub const STATUS_NOT_SUPPORTED: Self = Self(0xC000_00BB);
    pub const STATUS_NETWORK_SESSION_EXPIRED: Self = Self(0xC000_035C);
    pub const STATUS_ACCOUNT_LOCKED_OUT: Self = Self(0xC000_0234);

    pub const fn is_success(self) -> bool {
        (self.0 >> 30) == 0
    }

    pub const fn name(self) -> &'static str {
        match self.0 {
            0x0000_0000 => "STATUS_SUCCESS",
            0x0000_0105 => "STATUS_MORE_ENTRIES",
            0x0000_0107 => "STATUS_SOME_NOT_MAPPED",
            0x8000_0006 => "STATUS_NO_MORE_FILES",
            0xC000_000F => "STATUS_NO_SUCH_FILE",
            0xC000_0016 => "STATUS_MORE_PROCESSING_REQUIRED",
            0xC000_0022 => "STATUS_ACCESS_DENIED",
            0xC000_0034 => "STATUS_OBJECT_NAME_NOT_FOUND",
            0xC000_006D => "STATUS_LOGON_FAILURE",
            0xC000_006E => "STATUS_ACCOUNT_RESTRICTION",
            0xC000_006F => "STATUS_INVALID_LOGON_HOURS",
            0xC000_0071 => "STATUS_PASSWORD_EXPIRED",
            0xC000_0072 => "STATUS_ACCOUNT_DISABLED",
            0xC000_0073 => "STATUS_NONE_MAPPED",
            0xC000_00AC => "STATUS_PIPE_NOT_AVAILABLE",
            0xC000_00BB => "STATUS_NOT_SUPPORTED",
            0xC000_0234 => "STATUS_ACCOUNT_LOCKED_OUT",
            0xC000_035C => "STATUS_NETWORK_SESSION_EXPIRED",
            _ => "STATUS_UNKNOWN",
        }
    }

    pub const fn description(self) -> &'static str {
        match self.0 {
            0x0000_0000 => "The operation completed successfully.",
            0x0000_0105 => "Returned by enumeration APIs to indicate more information is available.",
            0x0000_0107 => "Some of the information to be translated has not been translated.",
            0x8000_0006 => "No more files were found which match the file specification.",
            0xC000_000F => "The specified file does not exist.",
            0xC000_0016 => "The client/server authentication handshake requires another turn.",
            0xC000_0022 => "A process has requested access to an object, but has not been granted those access rights.",
            0xC000_0034 => "Object Name not found.",
            0xC000_006D => "The attempted logon is invalid. This is either due to a bad username or authentication information.",
            0xC000_006E => "Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication.",
            0xC000_006F => "The user account has time restrictions and may not be logged onto at this time.",
            0xC000_0071 => "The user account's password has expired.",
            0xC000_0072 => "The referenced account is currently disabled and may not be logged on to.",
            0xC000_0073 => "None of the information to be translated has been translated.",
            0xC000_00AC => "An instance of a named pipe cannot be found in the listening state.",
            0xC000_00BB => "The request is not supported.",
            0xC000_0234 => "The referenced account is currently locked out and may not be logged on to.",
            0xC000_035C => "The client's session has expired; therefore, the client must re-authenticate.",
            _ => "Unmapped NTSTATUS code.",
        }
    }
}

impl fmt::Debug for NtStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NtStatus(0x{:08X}: {})", self.0, self.name())
    }
}

pub fn encode_utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

pub fn decode_utf16le(bytes: &[u8]) -> Result<String, CoreError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(CoreError::InvalidUtf16);
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16(&units).map_err(|_| CoreError::InvalidUtf16)
}

pub fn decode_hex_16(hex: &str) -> Result<[u8; 16], CoreError> {
    let bytes = decode_hex(hex)?;
    bytes
        .try_into()
        .map_err(|_| CoreError::InvalidHex("Expected 16 bytes (32 hex chars)".into()))
}

pub fn decode_hex(hex: &str) -> Result<Vec<u8>, CoreError> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return Err(CoreError::InvalidHex("Odd number of hex digits".into()));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for chunk in bytes.as_chunks::<2>().0 {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[inline]
fn hex_val(b: u8) -> Result<u8, CoreError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(CoreError::InvalidHex(format!(
            "Invalid hex character '{}'",
            b as char
        ))),
    }
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn encode_base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn decode_base64(input: &str) -> Result<Vec<u8>, CoreError> {
    fn val(c: u8) -> Result<u8, CoreError> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(CoreError::ProtocolError("Invalid base64 character".into())),
        }
    }

    let clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(4) {
        return Err(CoreError::ProtocolError("Invalid base64 length".into()));
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks(4) {
        let c0 = val(chunk[0])?;
        let c1 = val(chunk[1])?;
        let (c2, p2) = if chunk[2] == b'=' { (0, true) } else { (val(chunk[2])?, false) };
        let (c3, p3) = if chunk[3] == b'=' { (0, true) } else { (val(chunk[3])?, false) };

        out.push((c0 << 2) | (c1 >> 4));
        if !p2 {
            out.push(((c1 & 0x0f) << 4) | (c2 >> 2));
        }
        if !p3 {
            out.push(((c2 & 0x03) << 6) | c3);
        }
    }
    Ok(out)
}

pub fn hexdump(data: &[u8]) -> String {
    let mut out = String::new();
    for (row_idx, chunk) in data.chunks(16).enumerate() {
        let offset = row_idx * 16;
        out.push_str(&format!(" {:04x}   ", offset));
        for i in 0..16 {
            if i < chunk.len() {
                out.push_str(&format!("{:02X} ", chunk[i]));
            } else {
                out.push_str("   ");
            }
            if i == 7 {
                out.push(' ');
            }
        }
        out.push_str("  ");
        for &b in chunk {
            if (0x20..=0x7e).contains(&b) {
                out.push(b as char);
            } else {
                out.push('.');
            }
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_impacket_target_full_and_complex_password() {
        let spec = TargetSpec::parse("CONTOSO.LOCAL/Administrator:P@ss:w0rd@123!@10.10.11.200")
            .expect("should parse complex target");
        assert_eq!(spec.domain, "CONTOSO.LOCAL");
        assert_eq!(spec.username, "Administrator");
        assert_eq!(
            spec.password.as_ref().unwrap().expose_secret(),
            "P@ss:w0rd@123!"
        );
        assert_eq!(spec.remote_name, "10.10.11.200");
        assert_eq!(spec.compat_profile, AdCompatProfile::UniversalAuto);
    }

    #[test]
    fn test_parse_target_ipv6_and_port() {
        let spec1 = TargetSpec::parse("DOMAIN/user:pass@[fe80::1]:445").unwrap();
        assert_eq!(spec1.domain, "DOMAIN");
        assert_eq!(spec1.username, "user");
        assert_eq!(spec1.remote_name, "fe80::1");
        assert_eq!(spec1.target_port, Some(445));
        assert_eq!(spec1.effective_port(445), 445);

        let spec2 = TargetSpec::parse("admin:secret@[2001:db8::1]").unwrap();
        assert_eq!(spec2.remote_name, "2001:db8::1");
        assert_eq!(spec2.target_port, None);
        assert_eq!(spec2.effective_port(389), 389);

        let spec3 = TargetSpec::parse("user:pass@2001:db8::1").unwrap();
        assert_eq!(spec3.remote_name, "2001:db8::1");
        assert_eq!(spec3.target_port, None);

        let spec4 = TargetSpec::parse("user:pass@dc.corp.local:8888").unwrap();
        assert_eq!(spec4.remote_name, "dc.corp.local");
        assert_eq!(spec4.target_port, Some(8888));
        assert_eq!(spec4.effective_port(88), 8888);
    }

    #[test]
    fn test_filetime_conversion() {
        let ft = FileTime::from_unix_secs(1_700_000_000);
        assert_eq!(ft.to_unix_secs(), Some(1_700_000_000));
    }

    #[test]
    fn test_ad_compat_profiles() {
        assert!(AdCompatProfile::LegacyWin2000.allows_ntlmv1());
        assert!(!AdCompatProfile::UniversalAuto.allows_ntlmv1());
        assert!(AdCompatProfile::ModernHardened2025.requires_epa_channel_binding());
        assert!(version::BANNER.contains(version::VERSION));
        assert!(version::BANNER.contains("High-Performance Active Directory & Protocol Toolkit"));
    }
}
