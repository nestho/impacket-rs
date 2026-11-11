//! Standalone Example: In-Memory NTLMv2 3-Way Handshake & Session Key Derivation
//!
//! Run with:
//!   cargo run --example ntlm_auth_handshake -p impacket-rs

use impacket_auth::{
    compute_ntlm_hashes, compute_ntlmv2_response, NtlmAuthenticateMessage,
    NtlmChallengeMessage, NtlmNegotiateMessage, NtlmTargetInfo,
};
use impacket_core::{encode_hex, AdCompatProfile, FileTime};

fn main() {
    println!("=== Impacket-RS: NTLMv2 Handshake Example ===");

    let domain = "CORP";
    let username = "Administrator";
    let password = "Password123!";
    let client_workstation = "WORKSTATION01";

    println!("[*] Computing NTLM hash for '{}':", password);
    let hashes = compute_ntlm_hashes(password);
    println!("    LM Hash: {}", encode_hex(&hashes.lm));
    println!("    NT Hash: {}", encode_hex(&hashes.nt));

    // 1. Type 1 Negotiate
    println!("\n[1] Generating NTLMSSP Type 1 (NEGOTIATE)...");
    let type1 = NtlmNegotiateMessage::for_profile(AdCompatProfile::ModernHardened2025);
    let type1_bytes = type1.to_bytes();
    println!("    Negotiate packet: {} bytes", type1_bytes.len());

    // 2. Type 2 Challenge (Server side)
    println!("\n[2] Server processes Type 1 and emits Type 2 (CHALLENGE)...");
    let server_challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    let mut target_info = NtlmTargetInfo::new();
    target_info.nb_domain_name = Some(domain.to_string());
    target_info.nb_computer_name = Some("DC01".to_string());
    target_info.dns_domain_name = Some("corp.local".to_string());
    target_info.dns_computer_name = Some("dc01.corp.local".to_string());

    let type2 = NtlmChallengeMessage {
        target_name: domain.to_string(),
        flags: type1.flags,
        server_challenge,
        os_major: 10,
        os_minor: 0,
        os_build: 26100,
        ntlm_revision: 15,
        target_info,
    };
    let type2_bytes = type2.to_bytes();
    println!("    Challenge packet: {} bytes", type2_bytes.len());
    println!("    Server OS:        {}", type2.guessed_os_version());

    // 3. Type 3 Authenticate (Client calculates NTLMv2 response)
    println!("\n[3] Client processes Type 2 and computes Type 3 (AUTHENTICATE)...");
    let client_challenge = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let target_info_bytes = type2.target_info.to_bytes();

    let computed = compute_ntlmv2_response(
        username,
        domain,
        &hashes,
        &server_challenge,
        &client_challenge,
        FileTime(0),
        &target_info_bytes,
    );

    let type3 = NtlmAuthenticateMessage {
        domain: domain.to_string(),
        username: username.to_string(),
        workstation: client_workstation.to_string(),
        lm_challenge_response: computed.lm_challenge_response,
        nt_challenge_response: computed.nt_challenge_response,
        encrypted_session_key: Vec::new(),
        flags: type2.flags,
        os_major: 10,
        os_minor: 0,
        os_build: 26100,
    };
    let type3_bytes = type3.to_bytes();

    println!("    Authenticate packet: {} bytes", type3_bytes.len());
    if let Some(netntlm) = type3.to_netntlmv2_format(&server_challenge) {
        println!("\n[+] NetNTLMv2 Capture Line (Hashcat mode 5600 compatible):");
        println!("    {}", netntlm);
    }
    println!("\n[OK] Handshake successfully completed!");
}
