use std::{collections::HashSet, env, net::Ipv4Addr, process::Command};

use crate::constants::TRUSTED_IPS_ENV;

pub fn normalize_ipv4(candidate: &str) -> Option<String> {
    candidate.parse::<Ipv4Addr>().ok().map(|ip| ip.to_string())
}

pub fn is_blockable_ip(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>().is_ok_and(is_public_routable_ipv4)
}

pub fn get_local_ips() -> HashSet<String> {
    let mut local_ips = HashSet::new();
    local_ips.insert("127.0.0.1".to_owned());

    collect_hostname_ips(&mut local_ips);
    collect_interface_ips(&mut local_ips);
    collect_route_source_ip(&mut local_ips);

    local_ips
}

pub fn trusted_ips_from_env() -> HashSet<String> {
    let Ok(value) = env::var(TRUSTED_IPS_ENV) else {
        return HashSet::new();
    };

    value
        .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
        .filter_map(normalize_ipv4)
        .collect()
}

fn collect_hostname_ips(local_ips: &mut HashSet<String>) {
    if let Ok(output) = Command::new("hostname").arg("-I").output() {
        insert_ipv4s_from_text(local_ips, &String::from_utf8_lossy(&output.stdout));
    }
}

fn collect_interface_ips(local_ips: &mut HashSet<String>) {
    if let Ok(output) = Command::new("ip")
        .args(["-o", "-4", "addr", "show"])
        .output()
    {
        insert_ipv4s_from_text(local_ips, &String::from_utf8_lossy(&output.stdout));
    }
}

fn collect_route_source_ip(local_ips: &mut HashSet<String>) {
    let Ok(output) = Command::new("ip")
        .args(["route", "get", "1.1.1.1"])
        .output()
    else {
        return;
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut tokens = stdout.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "src" {
            if let Some(ip) = tokens.next().and_then(normalize_ipv4) {
                local_ips.insert(ip);
            }
            return;
        }
    }
}

fn insert_ipv4s_from_text(local_ips: &mut HashSet<String>, text: &str) {
    for token in text.split_whitespace() {
        let candidate = token
            .split('/')
            .next()
            .unwrap_or(token)
            .trim_matches(|ch: char| !ch.is_ascii_digit() && ch != '.');

        if let Some(ip) = normalize_ipv4(candidate) {
            local_ips.insert(ip);
        }
    }
}

fn is_public_routable_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
    {
        return false;
    }

    let [first, second, third, _] = ip.octets();

    if first == 0 || first >= 224 {
        return false;
    }

    if first == 100 && (64..=127).contains(&second) {
        return false;
    }

    if first == 198 && (18..=19).contains(&second) {
        return false;
    }

    !matches!(
        (first, second, third),
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
    )
}

#[cfg(test)]
mod tests {
    use super::{is_blockable_ip, normalize_ipv4};

    #[test]
    fn rejects_non_public_ipv4_ranges() {
        assert!(!is_blockable_ip("127.0.0.1"));
        assert!(!is_blockable_ip("10.0.0.1"));
        assert!(!is_blockable_ip("172.16.0.10"));
        assert!(!is_blockable_ip("192.168.1.10"));
        assert!(!is_blockable_ip("100.64.0.1"));
        assert!(!is_blockable_ip("203.0.113.10"));
        assert!(is_blockable_ip("8.8.8.8"));
    }

    #[test]
    fn normalizes_valid_ipv4_only() {
        assert_eq!(normalize_ipv4("001.002.003.004"), None);
        assert_eq!(normalize_ipv4("8.8.8.8").as_deref(), Some("8.8.8.8"));
        assert_eq!(normalize_ipv4("999.8.8.8"), None);
    }
}
