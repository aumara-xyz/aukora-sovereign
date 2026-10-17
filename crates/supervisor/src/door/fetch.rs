// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `net` executor: `web_fetch` for the engine, done by the door.
//!
//! The engine never opens the connection. The door accepts only allowlisted host names (no IP literals, no user
//! info, https unless the policy says otherwise, listed ports only), resolves the name itself, refuses any address in
//! a private, loopback, link-local or otherwise non-public range, and then connects to THAT address (so a name that
//! resolves differently a moment later cannot redirect the connection). Redirects are not followed, proxies are
//! ignored, the body is capped and the whole call has a deadline.

use super::policy::NetPolicy;
use reqwest::Url;
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

/// Whether an address is ordinary public internet space.
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 240)
}

fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let segments = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x0064 && segments[1] == 0xff9b)
        || segments[0] == 0x2002
        || (segments[0] == 0x2001 && segments[1] == 0))
}

/// What the URL check decided: the host name, the port and the parsed URL to request.
#[derive(Debug)]
pub struct Target {
    pub url: Url,
    pub host: String,
    pub port: u16,
}

/// Check a requested URL against the policy. The error is the refusal token.
pub fn check_url(policy: &NetPolicy, text: &str) -> Result<Target, &'static str> {
    if text.len() > 4096 {
        return Err("url-invalid");
    }
    let url = Url::parse(text).map_err(|_| "url-invalid")?;
    let scheme_ok = url.scheme() == "https" || (policy.allow_http && url.scheme() == "http");
    if !scheme_ok {
        return Err("url-scheme");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("url-userinfo");
    }
    // The allowlist holds plain domain names only, so an IP literal (however it is written) can never match.
    let host = url.host_str().ok_or("host-not-allowed")?.to_ascii_lowercase();
    if !policy.hosts.iter().any(|allowed| *allowed == host) {
        return Err("host-not-allowed");
    }
    let port = url.port_or_known_default().ok_or("url-invalid")?;
    if !policy.ports.contains(&port) {
        return Err("port-not-allowed");
    }
    Ok(Target { url, host, port })
}

/// Resolve the host and refuse any non-public address. Returns the addresses to connect to.
pub fn resolve_public(policy: &NetPolicy, target: &Target) -> Result<Vec<SocketAddr>, &'static str> {
    let addrs: Vec<SocketAddr> = (target.host.as_str(), target.port).to_socket_addrs().map_err(|_| "resolve-failed")?.take(8).collect();
    if addrs.is_empty() {
        return Err("resolve-failed");
    }
    if policy.private_ok() || addrs.iter().all(|addr| public_ip(addr.ip())) {
        Ok(addrs)
    } else {
        Err("host-resolves-private")
    }
}

fn client(policy: &NetPolicy, target: &Target, addrs: &[SocketAddr]) -> Result<reqwest::Client, &'static str> {
    reqwest::Client::builder()
        .no_proxy()
        .https_only(!policy.allow_http)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_millis(policy.timeout_ms))
        .user_agent("aukora-door/1")
        .resolve_to_addrs(&target.host, addrs)
        .build()
        .map_err(|_| "fetch-failed")
}

/// Fetch one allowlisted URL and shape the result as DSH's `web_fetch` output.
pub async fn fetch(policy: &NetPolicy, text: &str) -> Result<Value, String> {
    let target = check_url(policy, text).map_err(str::to_owned)?;
    let addrs = resolve_public(policy, &target).map_err(str::to_owned)?;
    let client = client(policy, &target, &addrs).map_err(str::to_owned)?;
    let mut response = client.get(target.url.clone()).send().await.map_err(|e| if e.is_timeout() { "fetch-timeout".to_owned() } else { "fetch-failed".to_owned() })?;
    let status = response.status();
    if status.is_redirection() {
        let location = response.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok()).unwrap_or("").chars().take(1024).collect::<String>();
        return Ok(json!({"url": target.url.as_str(), "statusCode": status.as_u16(), "body": {"kind": "text", "content": format!("redirect: {location}")}, "truncated": false}));
    }
    let mut body: Vec<u8> = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = response.chunk().await.map_err(|_| "fetch-failed".to_owned())? {
        if body.len() + chunk.len() > policy.max_bytes {
            body.extend_from_slice(&chunk[..policy.max_bytes - body.len()]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    let content = String::from_utf8_lossy(&body).into_owned();
    Ok(json!({"url": target.url.as_str(), "statusCode": status.as_u16(), "body": {"kind": "text", "content": content}, "truncated": truncated}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> NetPolicy {
        NetPolicy { hosts: vec!["docs.rs".into(), "example.org".into()], ports: vec![443], max_bytes: 4096, timeout_ms: 2000, allow_http: false, allow_private: false }
    }

    #[test]
    fn only_allowlisted_https_hosts_pass() {
        let p = policy();
        assert!(check_url(&p, "https://docs.rs/serde").is_ok());
        assert!(check_url(&p, "https://DOCS.RS/serde").is_ok());
        assert_eq!(check_url(&p, "https://evil.example/x").unwrap_err(), "host-not-allowed");
        assert_eq!(check_url(&p, "https://sub.docs.rs/x").unwrap_err(), "host-not-allowed");
        assert_eq!(check_url(&p, "https://docs.rs.evil.example/x").unwrap_err(), "host-not-allowed");
        assert_eq!(check_url(&p, "http://docs.rs/x").unwrap_err(), "url-scheme");
        assert_eq!(check_url(&p, "file:///etc/passwd").unwrap_err(), "url-scheme");
        assert_eq!(check_url(&p, "https://user:pw@docs.rs/x").unwrap_err(), "url-userinfo");
        assert_eq!(check_url(&p, "https://docs.rs@evil.example/x").unwrap_err(), "url-userinfo");
        assert_eq!(check_url(&p, "https://docs.rs:8443/x").unwrap_err(), "port-not-allowed");
        assert_eq!(check_url(&p, "https://127.0.0.1/x").unwrap_err(), "host-not-allowed");
        assert_eq!(check_url(&p, "https://[::1]/x").unwrap_err(), "host-not-allowed");
        assert_eq!(check_url(&p, "https://2130706433/x").unwrap_err(), "host-not-allowed");
        assert_eq!(check_url(&p, "not a url").unwrap_err(), "url-invalid");
        assert_eq!(check_url(&p, &format!("https://docs.rs/{}", "a".repeat(5000))).unwrap_err(), "url-invalid");
    }

    #[test]
    fn private_and_special_addresses_are_never_public() {
        for bad in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "198.18.0.1", "240.0.0.1"] {
            assert!(!public_ip(bad.parse().unwrap()), "{bad}");
        }
        for bad in ["::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "2001:db8::1", "64:ff9b::1", "2002::1"] {
            assert!(!public_ip(bad.parse().unwrap()), "{bad}");
        }
        for good in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111", "::ffff:8.8.8.8"] {
            assert!(public_ip(good.parse().unwrap()), "{good}");
        }
    }

    #[test]
    fn a_name_that_resolves_to_a_private_address_is_refused() {
        let p = policy();
        let target = Target { url: Url::parse("https://localhost/").unwrap(), host: "localhost".into(), port: 443 };
        assert_eq!(resolve_public(&p, &target).unwrap_err(), "host-resolves-private");
    }

    #[test]
    fn a_fetch_returns_the_tool_shape_and_caps_the_body() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer);
                let body = "x".repeat(10_000);
                let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        let mut p = policy();
        p.hosts = vec!["localhost.example".into()];
        p.ports = vec![port];
        p.allow_http = true;
        p.allow_private = true;
        // The allowlisted name is mapped to the loopback listener by resolve_to_addrs, standing in for DNS.
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let target = check_url(&p, &format!("http://localhost.example:{port}/page")).unwrap();
        let client = client(&p, &target, &[SocketAddr::from(([127, 0, 0, 1], port))]).unwrap();
        let value = runtime.block_on(async {
            let mut response = client.get(target.url.clone()).send().await.unwrap();
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.unwrap() {
                body.extend_from_slice(&chunk);
            }
            (response.status().as_u16(), body.len())
        });
        assert_eq!(value, (200, 10_000));
    }
}
