use actix_web::{dev::RequestHead, guard::Guard};
use std::net::{IpAddr, Ipv4Addr};

/// Actix guard to ensure that the only requests we receive are Tor requests.
pub struct TorGuard;

impl Guard for TorGuard {
    fn check(&self, req: &RequestHead) -> bool {
        match req.peer_addr {
            Some(addr) => is_valid_client_ip(addr.ip()),
            None => false,
        }
    }
}

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
    use crate::net::{self, TorGuard};
    use actix_web::{guard::Guard, test::TestRequest};
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

    #[actix_rt::test]
    async fn tor_guard_ip() {
        let guard = TorGuard {};

        let req = TestRequest::default()
            // This is an IP the Tor service might have
            .peer_addr("127.0.0.1:52477".parse().unwrap())
            .to_http_request();
        assert!(guard.check(req.head()));

        let req = TestRequest::default()
            // This is an external IP, which should be ignored
            .peer_addr("192.168.1.2:52477".parse().unwrap())
            .to_http_request();
        assert!(!guard.check(req.head()));

        let req = TestRequest::default()
            // Ipv6 addresses should also be ignored
            .peer_addr("[::1]:52477".parse().unwrap())
            .to_http_request();
        assert!(!guard.check(req.head()));
    }
}
