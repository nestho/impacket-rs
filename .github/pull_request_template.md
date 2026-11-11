## Description
Briefly describe the change, motivation, and problem solved.

## Type of Change
- [ ] `feat`: New feature or tool implementation
- [ ] `fix`: Bug fix
- [ ] `docs`: Documentation update
- [ ] `perf`: Performance optimization
- [ ] `refactor`: Code cleanup or restructuring
- [ ] `test`: Unit or integration test coverage

## Affected Crates / Tools
- [ ] `crates/impacket-core`
- [ ] `crates/impacket-crypto`
- [ ] `crates/impacket-ndr`
- [ ] `crates/impacket-auth`
- [ ] `crates/impacket-krb5`
- [ ] `crates/impacket-smb`
- [ ] `crates/impacket-dcerpc`
- [ ] `crates/impacket-msrpc`
- [ ] `crates/impacket-sam`
- [ ] `crates/impacket-ldap`
- [ ] `crates/impacket-dcom`
- [ ] `crates/impacket-mssql`
- [ ] `crates/impacket-relay`
- [ ] `bins/impacket-rs` (CLI / Tool Dispatcher)
- [ ] Documentation (`README.md`, `docs/`)

## Verification Checklist
- [ ] My code adheres to the project's [Contributing Guidelines](CONTRIBUTING.md).
- [ ] `cargo check --workspace --all-targets` passes with no errors.
- [ ] `cargo test --workspace` passes cleanly.
- [ ] `cargo fmt --all -- --check` passes with no formatting diffs.
- [ ] `cargo clippy --workspace --all-targets` produces no warnings.
- [ ] Zero unvetted `unsafe` blocks; any required `unsafe` code contains an explicit `// SAFETY:` rationale.
- [ ] New functionality is covered by unit or integration tests.
- [ ] Documentation has been updated (if applicable).
