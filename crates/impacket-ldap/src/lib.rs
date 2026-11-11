//! `impacket-ldap`: Active Directory LDAP / LDAPS query engine, RFC 4511 ASN.1 BER message codec,
//! and `[MS-DTYP]` Section 2.4.6 Security Descriptor / ACL parser.

pub mod addcomputer;
pub mod asn1;
pub mod client;
pub mod dacledit;
pub mod delegation;
pub mod dnsp;
pub mod rbcd;
pub mod security_descriptor;
pub mod shell;

pub use addcomputer::{add_computer, build_computer_attributes, generate_computer_password};
pub use asn1::{
    filter_and, filter_equality, filter_not, filter_or, filter_present, op_tag, result_code,
    AttributeModification, BindAuth, LdapAttribute, LdapControl, LdapMessage, ModifyOperation,
    ProtocolOp, SearchScope, CONTROL_PAGED_RESULTS,
};
pub use client::{read_ldap_message, LdapClient, LdapEntry};
pub use dacledit::{grant_right, read_dacl, revoke_rights, write_dacl, DaclRight};
pub use delegation::{find_delegation, DelegationRecord, DelegationType};
pub use dnsp::{
    add_dns_node, decode_dns_rpc_name, delete_dns_node, encode_dns_rpc_name,
    format_dns_record_data, list_dns_zones, modify_dns_node, query_dns_node,
    resolve_dns_partitions, tombstone_dns_node, DnsNodeResult, DnsRecordData, DnsRecordType,
    DnsRpcRecord, DNS_RPC_FLAG_AGING_ON, DNS_RPC_RECORD_VERSION, RANK_CACHE_BIT, RANK_ROOT_HINT,
    RANK_ZONE, RANK_ZONE_FILE,
};
pub use rbcd::{
    build_rbcd_security_descriptor, flush_rbcd, parse_rbcd_allowed_sids, read_rbcd, write_rbcd,
    RBCD_ATTR_NAME,
};
pub use security_descriptor::{
    access_mask, ace_flags, ace_type, control_flags, Ace, Acl, SecurityDescriptor,
};
pub use shell::{parse_command_tokens, LdapShellSession, LDAP_MATCHING_RULE_IN_CHAIN};
