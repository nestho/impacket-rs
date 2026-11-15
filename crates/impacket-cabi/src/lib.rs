//! C ABI and FFI bindings for impacket-rs.
//!
//! Exposes pure-Rust Impacket protocol parsers, cryptographic functions, and credential
//! decoders to C/C++ applications, Cobalt Strike BOFs, and foreign languages via C ABI.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::slice;

pub const IMPACKET_OK: i32 = 0;
pub const IMPACKET_ERR_INVALID_PARAM: i32 = -1;
pub const IMPACKET_ERR_BUFFER_TOO_SMALL: i32 = -2;
pub const IMPACKET_ERR_PARSE_FAILED: i32 = -3;
pub const IMPACKET_ERR_CRYPTO_FAILED: i32 = -4;

/// C-compatible target parameters structure.
#[repr(C)]
pub struct impacket_target_t {
    pub domain: [c_char; 256],
    pub username: [c_char; 256],
    pub password: [c_char; 256],
    pub target_host: [c_char; 256],
    pub target_ip: [c_char; 64],
    pub port: u16,
}

impl Default for impacket_target_t {
    fn default() -> Self {
        Self {
            domain: [0; 256],
            username: [0; 256],
            password: [0; 256],
            target_host: [0; 256],
            target_ip: [0; 64],
            port: 0,
        }
    }
}

fn copy_str_to_fixed_c_buf(src: &str, dest: &mut [c_char]) {
    let bytes = src.as_bytes();
    let max = dest.len().saturating_sub(1);
    let len = bytes.len().min(max);
    for (i, &b) in bytes.iter().take(len).enumerate() {
        dest[i] = b as c_char;
    }
    dest[len] = 0;
}

/// Returns a static null-terminated version string.
#[no_mangle]
pub extern "C" fn impacket_version() -> *const c_char {
    static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION.as_ptr() as *const c_char
}

/// Parses target connection specifier.
///
/// # Safety
/// `spec` and `out_target` must be valid, non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn impacket_parse_target(
    spec: *const c_char,
    out_target: *mut impacket_target_t,
) -> i32 {
    if spec.is_null() || out_target.is_null() {
        return IMPACKET_ERR_INVALID_PARAM;
    }

    let spec_str = match CStr::from_ptr(spec).to_str() {
        Ok(s) => s,
        Err(_) => return IMPACKET_ERR_PARSE_FAILED,
    };

    let parsed = match impacket_core::TargetSpec::parse(spec_str) {
        Ok(t) => t,
        Err(_) => return IMPACKET_ERR_PARSE_FAILED,
    };

    let target = &mut *out_target;
    *target = impacket_target_t::default();

    copy_str_to_fixed_c_buf(&parsed.domain, &mut target.domain);
    copy_str_to_fixed_c_buf(&parsed.username, &mut target.username);
    if let Some(ref pass) = parsed.password {
        copy_str_to_fixed_c_buf(pass.expose_secret(), &mut target.password);
    }
    copy_str_to_fixed_c_buf(&parsed.remote_name, &mut target.target_host);
    copy_str_to_fixed_c_buf(parsed.effective_target_ip(), &mut target.target_ip);
    target.port = parsed.target_port.unwrap_or(0);

    IMPACKET_OK
}

/// Computes 16-byte NT hash of a password.
///
/// # Safety
/// `password` and `out_hash` must be valid, non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn impacket_ntlm_hash(
    password: *const c_char,
    out_hash: *mut u8,
) -> i32 {
    if password.is_null() || out_hash.is_null() {
        return IMPACKET_ERR_INVALID_PARAM;
    }

    let pass_str = match CStr::from_ptr(password).to_str() {
        Ok(s) => s,
        Err(_) => return IMPACKET_ERR_PARSE_FAILED,
    };

    let utf16_bytes: Vec<u8> = pass_str
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();

    let digest = impacket_crypto::md4(&utf16_bytes);
    let out = slice::from_raw_parts_mut(out_hash, 16);
    out.copy_from_slice(&digest);

    IMPACKET_OK
}

/// Computes legacy 16-byte LAN Manager (LM) hash.
///
/// # Safety
/// `password` and `out_hash` must be valid, non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn impacket_lm_hash(
    password: *const c_char,
    out_hash: *mut u8,
) -> i32 {
    if password.is_null() || out_hash.is_null() {
        return IMPACKET_ERR_INVALID_PARAM;
    }

    let pass_str = match CStr::from_ptr(password).to_str() {
        Ok(s) => s,
        Err(_) => return IMPACKET_ERR_PARSE_FAILED,
    };

    let digest = impacket_crypto::compute_lm_hash(pass_str);
    let out = slice::from_raw_parts_mut(out_hash, 16);
    out.copy_from_slice(&digest);

    IMPACKET_OK
}

/// Computes 16-byte NTLMv2 hash (NTOWFv2).
///
/// # Safety
/// All pointers must be valid and non-null.
#[no_mangle]
pub unsafe extern "C" fn impacket_ntlmv2_ntowf(
    ntlm_hash: *const u8,
    username: *const c_char,
    domain: *const c_char,
    out_ntowf: *mut u8,
) -> i32 {
    if ntlm_hash.is_null() || username.is_null() || domain.is_null() || out_ntowf.is_null() {
        return IMPACKET_ERR_INVALID_PARAM;
    }

    let user_str = match CStr::from_ptr(username).to_str() {
        Ok(s) => s,
        Err(_) => return IMPACKET_ERR_PARSE_FAILED,
    };

    let domain_str = match CStr::from_ptr(domain).to_str() {
        Ok(s) => s,
        Err(_) => return IMPACKET_ERR_PARSE_FAILED,
    };

    let hash_slice = slice::from_raw_parts(ntlm_hash, 16);
    let user_dom = format!("{}{}", user_str.to_uppercase(), domain_str);
    let user_dom_utf16: Vec<u8> = user_dom
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();

    let ntowf = impacket_crypto::hmac_md5(hash_slice, &user_dom_utf16);
    let out = slice::from_raw_parts_mut(out_ntowf, 16);
    out.copy_from_slice(&ntowf);

    IMPACKET_OK
}

/// Computes MD4 digest.
///
/// # Safety
/// Pointers must be valid and out_digest must hold at least 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn impacket_md4(
    data: *const u8,
    len: usize,
    out_digest: *mut u8,
) -> i32 {
    if data.is_null() || out_digest.is_null() {
        return IMPACKET_ERR_INVALID_PARAM;
    }
    let in_slice = slice::from_raw_parts(data, len);
    let digest = impacket_crypto::md4(in_slice);
    let out = slice::from_raw_parts_mut(out_digest, 16);
    out.copy_from_slice(&digest);
    IMPACKET_OK
}

/// Computes MD5 digest.
///
/// # Safety
/// Pointers must be valid and out_digest must hold at least 16 bytes.
#[no_mangle]
pub unsafe extern "C" fn impacket_md5(
    data: *const u8,
    len: usize,
    out_digest: *mut u8,
) -> i32 {
    if data.is_null() || out_digest.is_null() {
        return IMPACKET_ERR_INVALID_PARAM;
    }
    let in_slice = slice::from_raw_parts(data, len);
    let digest = impacket_crypto::md5(in_slice);
    let out = slice::from_raw_parts_mut(out_digest, 16);
    out.copy_from_slice(&digest);
    IMPACKET_OK
}

/// Computes SHA-1 digest.
///
/// # Safety
/// Pointers must be valid and out_digest must hold at least 20 bytes.
#[no_mangle]
pub unsafe extern "C" fn impacket_sha1(
    data: *const u8,
    len: usize,
    out_digest: *mut u8,
) -> i32 {
    if data.is_null() || out_digest.is_null() {
        return IMPACKET_ERR_INVALID_PARAM;
    }
    let in_slice = slice::from_raw_parts(data, len);
    let digest = impacket_crypto::sha1(in_slice);
    let out = slice::from_raw_parts_mut(out_digest, 20);
    out.copy_from_slice(&digest);
    IMPACKET_OK
}

/// Computes SHA-256 digest.
///
/// # Safety
/// Pointers must be valid and out_digest must hold at least 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn impacket_sha256(
    data: *const u8,
    len: usize,
    out_digest: *mut u8,
) -> i32 {
    if data.is_null() || out_digest.is_null() {
        return IMPACKET_ERR_INVALID_PARAM;
    }
    let in_slice = slice::from_raw_parts(data, len);
    let digest = impacket_crypto::sha256(in_slice);
    let out = slice::from_raw_parts_mut(out_digest, 32);
    out.copy_from_slice(&digest);
    IMPACKET_OK
}

/// Encrypts/decrypts buffer in-place using RC4.
///
/// # Safety
/// Pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn impacket_rc4(
    key: *const u8,
    key_len: usize,
    data: *mut u8,
    data_len: usize,
) -> i32 {
    if key.is_null() || data.is_null() {
        return IMPACKET_ERR_INVALID_PARAM;
    }
    let key_slice = slice::from_raw_parts(key, key_len);
    let data_slice = slice::from_raw_parts_mut(data, data_len);
    let mut rc4 = impacket_crypto::Rc4::new(key_slice);
    rc4.apply_keystream(data_slice);
    IMPACKET_OK
}

/// Encrypts single 8-byte block using DES-ECB with 7-byte raw key.
///
/// # Safety
/// All pointers must hold at least their specified byte count.
#[no_mangle]
pub unsafe extern "C" fn impacket_des_encrypt_block(
    key_7: *const u8,
    in_block: *const u8,
    out_block: *mut u8,
) -> i32 {
    if key_7.is_null() || in_block.is_null() || out_block.is_null() {
        return IMPACKET_ERR_INVALID_PARAM;
    }
    let k_slice = slice::from_raw_parts(key_7, 7);
    let in_slice = slice::from_raw_parts(in_block, 8);
    let mut k_arr = [0u8; 7];
    let mut in_arr = [0u8; 8];
    k_arr.copy_from_slice(k_slice);
    in_arr.copy_from_slice(in_slice);

    let encrypted = impacket_crypto::des_ecb_encrypt_block(&k_arr, &in_arr);
    let out = slice::from_raw_parts_mut(out_block, 8);
    out.copy_from_slice(&encrypted);
    IMPACKET_OK
}

/// Decrypts Group Policy Preferences (GPP) cpassword string.
///
/// # Safety
/// `cpassword` and `out_buf` must be valid, non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn impacket_decrypt_cpassword(
    cpassword: *const c_char,
    out_buf: *mut c_char,
    out_buf_len: usize,
) -> i32 {
    if cpassword.is_null() || out_buf.is_null() || out_buf_len == 0 {
        return IMPACKET_ERR_INVALID_PARAM;
    }

    let cpass_str = match CStr::from_ptr(cpassword).to_str() {
        Ok(s) => s,
        Err(_) => return IMPACKET_ERR_PARSE_FAILED,
    };

    let plaintext = match impacket_sam::gpp::decrypt_cpassword(cpass_str) {
        Ok(p) => p,
        Err(_) => return IMPACKET_ERR_CRYPTO_FAILED,
    };

    let bytes = plaintext.as_bytes();
    if bytes.len() >= out_buf_len {
        return IMPACKET_ERR_BUFFER_TOO_SMALL;
    }

    let out_slice = slice::from_raw_parts_mut(out_buf, out_buf_len);
    for (i, &b) in bytes.iter().enumerate() {
        out_slice[i] = b as c_char;
    }
    out_slice[bytes.len()] = 0;

    IMPACKET_OK
}

/// Formats raw binary SID structure to string ("S-1-5-...").
///
/// # Safety
/// `sid_bytes` and `out_str` must be valid, non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn impacket_sid_to_string(
    sid_bytes: *const u8,
    sid_len: usize,
    out_str: *mut c_char,
    out_str_len: usize,
) -> i32 {
    if sid_bytes.is_null() || out_str.is_null() || out_str_len == 0 {
        return IMPACKET_ERR_INVALID_PARAM;
    }

    let slice = slice::from_raw_parts(sid_bytes, sid_len);
    let sid = match impacket_ndr::RpcSid::from_le_bytes(slice) {
        Ok(s) => s,
        Err(_) => return IMPACKET_ERR_PARSE_FAILED,
    };

    let formatted = sid.to_string();
    let bytes = formatted.as_bytes();
    if bytes.len() >= out_str_len {
        return IMPACKET_ERR_BUFFER_TOO_SMALL;
    }

    let out_slice = slice::from_raw_parts_mut(out_str, out_str_len);
    for (i, &b) in bytes.iter().enumerate() {
        out_slice[i] = b as c_char;
    }
    out_slice[bytes.len()] = 0;

    IMPACKET_OK
}

/// Parses a Kerberos AS-REP DER message and formats a Hashcat roasted hash ($krb5asrep$...).
///
/// # Safety
/// Pointers must be valid and non-null.
#[no_mangle]
pub unsafe extern "C" fn impacket_krb5_parse_asrep_hashcat(
    asrep_der: *const u8,
    asrep_len: usize,
    username: *const c_char,
    realm: *const c_char,
    out_buf: *mut c_char,
    out_buf_len: usize,
) -> i32 {
    if asrep_der.is_null() || username.is_null() || realm.is_null() || out_buf.is_null() || out_buf_len == 0 {
        return IMPACKET_ERR_INVALID_PARAM;
    }

    let user_str = match CStr::from_ptr(username).to_str() {
        Ok(s) => s,
        Err(_) => return IMPACKET_ERR_PARSE_FAILED,
    };
    let realm_str = match CStr::from_ptr(realm).to_str() {
        Ok(s) => s,
        Err(_) => return IMPACKET_ERR_PARSE_FAILED,
    };

    let der_slice = slice::from_raw_parts(asrep_der, asrep_len);
    let asrep = match impacket_krb5::KdcAsResponse::from_der_bytes(der_slice, realm_str, user_str) {
        Ok(a) => a,
        Err(_) => return IMPACKET_ERR_PARSE_FAILED,
    };

    let hashcat_str = match asrep.to_hashcat_format() {
        Some(h) => h,
        None => return IMPACKET_ERR_CRYPTO_FAILED,
    };

    let bytes = hashcat_str.as_bytes();
    if bytes.len() >= out_buf_len {
        return IMPACKET_ERR_BUFFER_TOO_SMALL;
    }

    let out_slice = slice::from_raw_parts_mut(out_buf, out_buf_len);
    for (i, &b) in bytes.iter().enumerate() {
        out_slice[i] = b as c_char;
    }
    out_slice[bytes.len()] = 0;

    IMPACKET_OK
}

/// Frees dynamically allocated string allocated by impacket C ABI.
///
/// # Safety
/// `str` must be a pointer returned by an impacket C ABI allocation, or null.
#[no_mangle]
pub unsafe extern "C" fn impacket_free_string(str: *mut c_char) {
    if !str.is_null() {
        drop(CString::from_raw(str));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_impacket_version() {
        let v = impacket_version();
        assert!(!v.is_null());
        let s = unsafe { CStr::from_ptr(v).to_str().unwrap() };
        assert_eq!(s, "0.3.0");
    }

    #[test]
    fn test_impacket_parse_target() {
        let spec = CString::new("CONTOSO.LOCAL/admin:SecretPassword123!@192.168.1.100:445").unwrap();
        let mut target = impacket_target_t::default();
        let res = unsafe { impacket_parse_target(spec.as_ptr(), &mut target) };
        assert_eq!(res, IMPACKET_OK);

        let domain = unsafe { CStr::from_ptr(target.domain.as_ptr()).to_str().unwrap() };
        let user = unsafe { CStr::from_ptr(target.username.as_ptr()).to_str().unwrap() };
        let pass = unsafe { CStr::from_ptr(target.password.as_ptr()).to_str().unwrap() };
        let ip = unsafe { CStr::from_ptr(target.target_ip.as_ptr()).to_str().unwrap() };

        assert_eq!(domain, "CONTOSO.LOCAL");
        assert_eq!(user, "admin");
        assert_eq!(pass, "SecretPassword123!");
        assert_eq!(ip, "192.168.1.100");
        assert_eq!(target.port, 445);
    }

    #[test]
    fn test_impacket_ntlm_hash() {
        let pass = CString::new("Password").unwrap();
        let mut hash = [0u8; 16];
        let res = unsafe { impacket_ntlm_hash(pass.as_ptr(), hash.as_mut_ptr()) };
        assert_eq!(res, IMPACKET_OK);
        // Known NT hash for "Password": a4f49c406510bdcab6824ee7c30fd852
        let hex = hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert_eq!(hex, "a4f49c406510bdcab6824ee7c30fd852");
    }

    #[test]
    fn test_impacket_lm_hash() {
        let pass = CString::new("Password").unwrap();
        let mut hash = [0u8; 16];
        let res = unsafe { impacket_lm_hash(pass.as_ptr(), hash.as_mut_ptr()) };
        assert_eq!(res, IMPACKET_OK);
        // Known LM hash for "Password": e52cac67419a9a224a3b108f3fa6cb6d
        let hex = hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert_eq!(hex, "e52cac67419a9a224a3b108f3fa6cb6d");
    }

    #[test]
    fn test_impacket_gpp_cpassword_decrypt() {
        let cpass = CString::new("j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw").unwrap();
        let mut out_buf = [0 as c_char; 256];
        let res = unsafe { impacket_decrypt_cpassword(cpass.as_ptr(), out_buf.as_mut_ptr(), out_buf.len()) };
        assert_eq!(res, IMPACKET_OK);
        let plain = unsafe { CStr::from_ptr(out_buf.as_ptr()).to_str().unwrap() };
        assert_eq!(plain, "Local*P4ssword!");
    }

    #[test]
    fn test_impacket_sid_to_string() {
        let sid = impacket_ndr::RpcSid::parse("S-1-5-21-1234-5678-9012-512").unwrap();
        let bytes = sid.to_le_bytes();
        let mut out_buf = [0 as c_char; 128];
        let res = unsafe { impacket_sid_to_string(bytes.as_ptr(), bytes.len(), out_buf.as_mut_ptr(), out_buf.len()) };
        assert_eq!(res, IMPACKET_OK);
        let s = unsafe { CStr::from_ptr(out_buf.as_ptr()).to_str().unwrap() };
        assert_eq!(s, "S-1-5-21-1234-5678-9012-512");
    }

    #[test]
    fn test_impacket_null_safety() {
        assert_eq!(unsafe { impacket_parse_target(std::ptr::null(), std::ptr::null_mut()) }, IMPACKET_ERR_INVALID_PARAM);
        assert_eq!(unsafe { impacket_ntlm_hash(std::ptr::null(), std::ptr::null_mut()) }, IMPACKET_ERR_INVALID_PARAM);
        assert_eq!(unsafe { impacket_lm_hash(std::ptr::null(), std::ptr::null_mut()) }, IMPACKET_ERR_INVALID_PARAM);
        assert_eq!(unsafe { impacket_md4(std::ptr::null(), 0, std::ptr::null_mut()) }, IMPACKET_ERR_INVALID_PARAM);
        assert_eq!(unsafe { impacket_decrypt_cpassword(std::ptr::null(), std::ptr::null_mut(), 0) }, IMPACKET_ERR_INVALID_PARAM);
        assert_eq!(unsafe { impacket_krb5_parse_asrep_hashcat(std::ptr::null(), 0, std::ptr::null(), std::ptr::null(), std::ptr::null_mut(), 0) }, IMPACKET_ERR_INVALID_PARAM);
    }
}
