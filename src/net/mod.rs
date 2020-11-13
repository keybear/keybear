pub mod crypto;

use std::net::{IpAddr, Ipv4Addr};

/// Check if the client trying to connect is valid.
///
/// The client is only allowed to be the Tor hidden service.
pub fn is_valid_client_ip(ip: IpAddr) -> bool {
    if let IpAddr::V4(ipv4) = ip {
        ipv4 == Ipv4Addr::LOCALHOST
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::net;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn valid_client_ips() {
        // Valid
        assert!(net::is_valid_client_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(net::is_valid_client_ip("127.0.0.1".parse().unwrap()));

        // Invalid
        assert!(!net::is_valid_client_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!net::is_valid_client_ip("::1".parse().unwrap()));
        assert!(!net::is_valid_client_ip("192.168.1.1".parse().unwrap()));
        assert!(!net::is_valid_client_ip("127.1.0.1".parse().unwrap()));
        assert!(!net::is_valid_client_ip("127.0.0.0".parse().unwrap()));
    }
}
