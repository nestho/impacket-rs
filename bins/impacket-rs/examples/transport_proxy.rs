//! Example: In-Core SOCKS5 & HTTP CONNECT Proxy Tunneling with `impacket-core`
//!
//! Demonstrates how to route Windows Active Directory protocols (SMB2/3, DCE/RPC,
//! Kerberos, LDAP) through SOCKS5 and HTTP proxies in pure Rust without relying on
//! `proxychains4` (which fails on static `musl` binaries due to missing dynamic linker).
//!
//! Run with:
//! ```bash
//! cargo run -p impacket-rs --example transport_proxy
//! ```

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use impacket_core::{ProxyConfig, ProxyType, TargetSpec, TransportStream};

fn main() {
    println!("=== Impacket-RS Transport Proxy & Dual-Stack Demo ===\n");

    // 1. Parsing SOCKS5 and HTTP proxy configurations
    let socks5_cfg = ProxyConfig::parse("socks5://127.0.0.1:1080").unwrap();
    println!("[+] Parsed SOCKS5 Config: {}", socks5_cfg.to_url());
    assert_eq!(socks5_cfg.proxy_type, ProxyType::Socks5);

    let auth_proxy_cfg =
        ProxyConfig::parse("socks5://operator:SecretPass123@10.0.0.1:9050").unwrap();
    println!("[+] Parsed Authenticated SOCKS5: {}", auth_proxy_cfg.to_url());

    let http_proxy_cfg = ProxyConfig::parse("http://proxy.corp.internal:8080").unwrap();
    println!("[+] Parsed HTTP CONNECT Proxy: {}", http_proxy_cfg.to_url());

    // 2. TargetSpec with proxy and IPv6 dual-stack support
    let target = TargetSpec::parse("CORP.LOCAL/admin:Winter2026!@[2001:db8::1]:445")
        .expect("Valid target");
    let target_with_proxy = target.with_proxy(socks5_cfg.clone());
    println!("\n[+] Target Specification:");
    println!("    Domain:      {}", target_with_proxy.domain);
    println!("    User:        {}", target_with_proxy.username);
    println!("    Remote Host: {}", target_with_proxy.remote_name);
    println!(
        "    Target Port: {:?}",
        target_with_proxy.effective_port(445)
    );
    println!(
        "    Proxy URL:   {}",
        target_with_proxy.proxy.as_ref().unwrap().to_url()
    );

    // 3. Live SOCKS5 Handshake Simulation (In-Process Mock Proxy)
    println!("\n[*] Spawning in-process RFC 1928 SOCKS5 mock proxy server...");
    let listener = TcpListener::bind("127.0.0.1:0").expect("Bind local mock proxy");
    let proxy_port = listener.local_addr().unwrap().port();

    let proxy_thread = thread::spawn(move || {
        let (mut client_sock, _) = listener.accept().expect("Accept connection");

        // Step 1: Read greeting (methods)
        let mut greeting = [0u8; 3];
        client_sock.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting[0], 0x05); // SOCKS version 5

        // Respond: No authentication required (0x00)
        client_sock.write_all(&[0x05, 0x00]).unwrap();

        // Step 2: Read CONNECT request
        let mut hdr = [0u8; 4];
        client_sock.read_exact(&mut hdr).unwrap();
        assert_eq!(hdr[1], 0x01); // CMD: CONNECT

        let atyp = hdr[3];
        if atyp == 0x03 {
            // Domain name
            let mut len = [0u8; 1];
            client_sock.read_exact(&mut len).unwrap();
            let mut domain = vec![0u8; len[0] as usize];
            client_sock.read_exact(&mut domain).unwrap();
            let mut port_bytes = [0u8; 2];
            client_sock.read_exact(&mut port_bytes).unwrap();
        }

        // Step 3: Send SOCKS5 success reply (REP = 0x00)
        // Reply with bound address 127.0.0.1:445
        client_sock
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xBD])
            .unwrap();

        // Simulated transparent SMB2 protocol echo
        let mut req = [0u8; 8];
        client_sock.read_exact(&mut req).unwrap();
        assert_eq!(&req, b"\xfeSMBECHO");
        client_sock.write_all(b"\xfeSMBRESP").unwrap();
    });

    let live_proxy = ProxyConfig {
        proxy_type: ProxyType::Socks5,
        host: "127.0.0.1".into(),
        port: proxy_port,
        auth: None,
    };

    println!(
        "[*] Connecting to 'target-dc.corp.local:445' through SOCKS5 proxy 127.0.0.1:{}...",
        proxy_port
    );
    let mut stream = TransportStream::connect(
        "target-dc.corp.local",
        445,
        Duration::from_secs(5),
        Some(&live_proxy),
    )
    .expect("SOCKS5 connection handshake");

    assert!(stream.is_proxied());
    println!(
        "[+] Successfully tunneled to target! Proxied via: {}",
        stream.proxied_via().unwrap()
    );

    // Send payload over the established proxy tunnel
    stream.write_all(b"\xfeSMBECHO").unwrap();
    stream.flush().unwrap();

    let mut response = [0u8; 8];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"\xfeSMBRESP");

    proxy_thread.join().unwrap();
    println!("[+] Tunnel verification complete: wire payload successfully round-tripped through SOCKS5 proxy!");
    println!("\n=== All Tests & Demos Passed Successfully ===");
}
