# Impacket-RS Developer Examples

Standalone examples showing how to use `impacket-rs` modular crates as native Rust libraries in your own projects.

| Example Source | Description | Command |
|---|---|---|
| [`offline_secretsdump.rs`](file:///Users/nestho/impacket-rs/bins/impacket-rs/examples/offline_secretsdump.rs) | Offline extraction of SysKey & SAM password hashes from registry hives | `cargo run -p impacket-rs --example offline_secretsdump -- SAM SYSTEM` |
| [`ndr_serialization.rs`](file:///Users/nestho/impacket-rs/bins/impacket-rs/examples/ndr_serialization.rs) | Fast compile-time NDR DCE/RPC struct serialization & deserialization | `cargo run -p impacket-rs --example ndr_serialization` |
| [`krb5_ccache.rs`](file:///Users/nestho/impacket-rs/bins/impacket-rs/examples/krb5_ccache.rs) | Kerberos CCache / Kirbi ticket inspector, converter & parser | `cargo run -p impacket-rs --example krb5_ccache -- ticket.ccache` |
| [`ntlm_auth_handshake.rs`](file:///Users/nestho/impacket-rs/bins/impacket-rs/examples/ntlm_auth_handshake.rs) | Complete in-memory NTLMv2 3-way handshake & NetNTLMv2 hash generation | `cargo run -p impacket-rs --example ntlm_auth_handshake` |

---

## Standalone Multi-Call CLI Parity

All 74 classic Impacket command-line tools from upstream Python Impacket are compiled into the single high-performance multi-call binary `impacket-rs`:

```bash
# Direct subcommand invocation:
impacket-rs secretsdump target -hashes :aad3b435...
impacket-rs psexec target cmd.exe
impacket-rs getTGT domain/user:password

# Or symlinked drop-in invocation:
ln -s /usr/local/bin/impacket-rs /usr/local/bin/secretsdump
secretsdump target -hashes :aad3b435...
```
