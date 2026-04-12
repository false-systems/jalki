use std::net::{Ipv4Addr, Ipv6Addr};

use jalki_common::{AF_INET, AF_INET6};

/// Format an address from the new [u8; 16] + addr_family fields.
///
/// For AF_INET: first 4 bytes are the IPv4 address in network byte order.
/// For AF_INET6: all 16 bytes are the IPv6 address.
pub fn format_addr(raw: &[u8; 16], family: u16) -> String {
    if family == AF_INET6 {
        Ipv6Addr::from(*raw).to_string()
    } else {
        // AF_INET or unknown: treat first 4 bytes as IPv4 in network byte order.
        let v4_bytes: [u8; 4] = [raw[0], raw[1], raw[2], raw[3]];
        Ipv4Addr::from(v4_bytes).to_string()
    }
}
