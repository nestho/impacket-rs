//! Standalone Example: Fast Compile-Time NDR Serialization & Deserialization
//!
//! Demonstrates defining DCE/RPC structures, serializing to NDR wire bytes,
//! and parsing back with zero copy where possible.
//!
//! Run with:
//!   cargo run --example ndr_serialization -p impacket-rs

use impacket_ndr::{ndr_struct, NdrDeserialize, NdrReader, NdrSerialize, NdrWriter, RpcSid, RpcUuid};

ndr_struct! {
    /// Example DCE/RPC operation request packet
    pub struct CustomRpcRequest {
        pub call_id: u32,
        pub context_handle: [u8; 20],
        pub access_mask: u32,
        pub target_sid: RpcSid,
    }
}

fn main() {
    println!("=== Impacket-RS: NDR Serialization Example ===");

    let uuid = RpcUuid::parse("12345678-1234-abcd-ef00-0123456789ab").expect("valid UUID");
    println!("[*] Parsed UUID: {}", uuid);
    println!("[*] Wire bytes:  {:02x?}", uuid.to_le_bytes());

    let sid = RpcSid::parse("S-1-5-21-123456789-987654321-11223344-500").expect("valid SID");
    println!("[*] Parsed SID:  {}", sid);
    println!("[*] Wire bytes ({} bytes): {:02x?}", sid.to_le_bytes().len(), sid.to_le_bytes());

    let req = CustomRpcRequest {
        call_id: 42,
        context_handle: [0xAA; 20],
        access_mask: 0x00020000, // MAXIMUM_ALLOWED
        target_sid: sid,
    };

    // Serialize to NDR format
    let mut writer = NdrWriter::new();
    req.ndr_serialize(&mut writer);
    let wire_bytes = writer.into_bytes();

    println!("[+] Serialized CustomRpcRequest: {} bytes", wire_bytes.len());
    println!("    {:02x?}", wire_bytes);

    // Deserialize back from NDR wire bytes
    let mut reader = NdrReader::new(&wire_bytes);
    let decoded = CustomRpcRequest::ndr_deserialize(&mut reader).expect("NDR deserialization failed");

    println!("[+] Successfully deserialized back:");
    println!("    Call ID:        {}", decoded.call_id);
    println!("    Context Handle: {:02x?}", &decoded.context_handle[..4]);
    println!("    Access Mask:    0x{:08X}", decoded.access_mask);
    println!("    Target SID:     {}", decoded.target_sid);
    assert_eq!(decoded.call_id, 42);
    assert_eq!(decoded.access_mask, 0x00020000);
    println!("\n[OK] NDR Roundtrip verified!");
}
