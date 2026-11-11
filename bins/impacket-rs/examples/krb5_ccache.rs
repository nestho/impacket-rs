//! Standalone Example: Kerberos Credential Cache (CCache / Kirbi) Inspector & Converter
//!
//! Run with:
//!   cargo run --example krb5_ccache -p impacket-rs -- <TICKET_FILE.ccache | .kirbi>

use impacket_krb5::ccache::CCache;
use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <TICKET_FILE>", args[0]);
        eprintln!("Supports standard Kerberos CCache (.ccache) and Mimikatz / Rubeus Kirbi (.kirbi)");
        process::exit(1);
    }

    let file_path = &args[1];
    println!("[*] Loading ticket file: {}", file_path);
    let bytes = match fs::read(file_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[-] Read failed: {}", e);
            process::exit(1);
        }
    };

    // Try parsing as CCache first, then Kirbi
    let ccache = match CCache::parse(&bytes) {
        Ok(c) => {
            println!("[+] Recognized format: Standard CCache v{:04x}", c.version);
            c
        }
        Err(_) => match CCache::from_kirbi(&bytes) {
            Ok(c) => {
                println!("[+] Recognized format: KRB-CRED (Kirbi)");
                c
            }
            Err(e) => {
                eprintln!("[-] Failed to parse as CCache or Kirbi: {}", e);
                process::exit(1);
            }
        },
    };

    println!("[+] Primary Principal: {}", ccache.primary_principal.to_display_string());
    println!("[+] Total Credentials: {}", ccache.credentials.len());

    for (idx, cred) in ccache.credentials.iter().enumerate() {
        println!("\n--- Credential #{idx} ---");
        println!("  Client:   {}", cred.client.to_display_string());
        println!("  Server:   {}", cred.server.to_display_string());
        println!("  Key Type: 0x{:04x} (len: {} bytes)", cred.key.keytype, cred.key.keyvalue.len());
        println!("  AuthTime: {}", cred.times.authtime);
        println!("  EndTime:  {}", cred.times.endtime);
        println!("  Ticket:   {} bytes", cred.ticket.len());
    }

    if let Some(tgt) = ccache.find_tgt_credential() {
        println!("\n[+] Found active TGT for realm: {}", tgt.server.realm);
    }
}
