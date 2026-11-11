//! Standalone Example: Offline SAM & SYSTEM Hive Secrets Dump
//!
//! Run with:
//!   cargo run --example offline_secretsdump -p impacket-rs -- <SAM_FILE> <SYSTEM_FILE>

use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <SAM_HIVE> <SYSTEM_HIVE>", args[0]);
        eprintln!("Example: {} /path/to/SAM /path/to/SYSTEM", args[0]);
        process::exit(1);
    }

    let sam_path = &args[1];
    let system_path = &args[2];

    println!("[*] Reading SAM hive: {}", sam_path);
    let sam_bytes = match fs::read(sam_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[-] Failed to read SAM hive: {}", e);
            process::exit(1);
        }
    };

    println!("[*] Reading SYSTEM hive: {}", system_path);
    let system_bytes = match fs::read(system_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[-] Failed to read SYSTEM hive: {}", e);
            process::exit(1);
        }
    };

    println!("[*] Decrypting SysKey & SAM account hashes...");
    match impacket_sam::secretsdump_local(&sam_bytes, &system_bytes) {
        Ok(accounts) => {
            println!("[+] Successfully extracted {} accounts:\n", accounts.len());
            for account in accounts {
                println!("{}", account.to_secretsdump_line());
            }
        }
        Err(e) => {
            eprintln!("[-] Decryption failed: {}", e);
            process::exit(1);
        }
    }
}
