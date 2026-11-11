//! `http`: HTTP protocol adapter for NTLM authentication relaying (`impacket/examples/ntlmrelayx/servers/httprelayserver.py`).

use impacket_core::{decode_base64, encode_base64, CoreError};

/// Extracts base64-decoded NTLMSSP token from an HTTP `Authorization` or `WWW-Authenticate` header value.
pub fn extract_ntlm_token_from_header(header_val: &str) -> Result<Vec<u8>, CoreError> {
    let trimmed = header_val.trim();
    let b64_str = if let Some(stripped) = trimmed.strip_prefix("NTLM ") {
        stripped.trim()
    } else if let Some(stripped) = trimmed.strip_prefix("Negotiate ") {
        stripped.trim()
    } else {
        trimmed
    };

    decode_base64(b64_str)
}

/// Formats an NTLMSSP challenge token into a `WWW-Authenticate: NTLM <base64>` header value.
pub fn format_ntlm_challenge_header(token: &[u8]) -> String {
    format!("NTLM {}", encode_base64(token))
}

/// Formats an NTLMSSP authenticate token into an `Authorization: NTLM <base64>` header value.
pub fn format_ntlm_authorization_header(token: &[u8]) -> String {
    format!("NTLM {}", encode_base64(token))
}

/// Simple HTTP response builder for NTLM 401 challenge exchanges.
pub fn build_http_401_challenge_response(token: &[u8]) -> Vec<u8> {
    let header_val = format_ntlm_challenge_header(token);
    let body = "<html><body>401 Unauthorized</body></html>";
    format!(
        "HTTP/1.1 401 Unauthorized\r\n\
         WWW-Authenticate: {}\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\r\n{}",
        header_val,
        body.len(),
        body
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_ntlm_header_codec() {
        let raw = b"NTLMSSP\x00\x01\x00\x00\x00";
        let header = format_ntlm_challenge_header(raw);
        assert!(header.starts_with("NTLM "));

        let extracted = extract_ntlm_token_from_header(&header).unwrap();
        assert_eq!(extracted, raw);

        let resp = build_http_401_challenge_response(raw);
        let resp_str = String::from_utf8_lossy(&resp);
        assert!(resp_str.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        assert!(resp_str.contains("WWW-Authenticate: NTLM "));
    }
}
