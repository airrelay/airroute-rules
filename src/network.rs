use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NetworkSupport {
    pub ipv4: bool,
    pub ipv6: bool,
}

async fn reachable(address: &str) -> bool {
    tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::TcpStream::connect(address),
    )
    .await
    .is_ok_and(|r| r.is_ok())
}
fn from_checks(peer: SocketAddr, allow_private: bool, v4: &[bool], v6: &[bool]) -> NetworkSupport {
    let public = crate::measure::public_ip(peer.ip());
    NetworkSupport {
        ipv4: v4.iter().any(|v| *v) || (public && peer.is_ipv4()) || allow_private,
        ipv6: v6.iter().any(|v| *v) || (public && peer.is_ipv6()) || allow_private,
    }
}
pub async fn detect(peer: SocketAddr, allow_private: bool) -> NetworkSupport {
    // Diverse destinations: selective blocking of a provider is not absence of a family.
    let (a, b, c, d, e, f) = tokio::join!(
        reachable("1.1.1.1:443"),
        reachable("8.8.8.8:443"),
        reachable("223.5.5.5:53"),
        reachable("[2606:4700:4700::1111]:443"),
        reachable("[2001:4860:4860::8888]:443"),
        reachable("[2400:3200::1]:53")
    );
    from_checks(peer, allow_private, &[a, b, c], &[d, e, f])
}
pub fn supports_target(value: &NetworkSupport, target: &str) -> bool {
    match target.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => value.ipv4,
        Ok(IpAddr::V6(_)) => value.ipv6,
        Err(_) => value.ipv4 || value.ipv6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_reachable_domestic_ipv6_endpoint_prevents_a_provider_block_false_negative() {
        let value = from_checks(
            "192.0.2.10:8788".parse().unwrap(),
            false,
            &[true, false, true],
            &[false, false, true],
        );
        assert!(value.ipv4 && value.ipv6);
        assert!(supports_target(&value, "2400:3200::1"));
        let v4 = from_checks(
            "192.0.2.10:8788".parse().unwrap(),
            false,
            &[true],
            &[false, false, false],
        );
        assert!(!supports_target(&v4, "2400:3200::1"));
        assert!(supports_target(&v4, "example.org"));
    }
    #[test]
    fn private_peer_does_not_claim_public_ipv6_connectivity() {
        assert!(!from_checks("[fd00::1]:8788".parse().unwrap(), false, &[false], &[false]).ipv6);
    }
}
