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
        // ::/96 (IPv4-compatible, `::a.b.c.d`), fec0::/10 (site-local), 100::/64 (discard-only), 2001::/23 (IETF
        // protocol assignments: Teredo, benchmarking, ORCHID), 3fff::/20 (documentation), 5f00::/16 (SRv6).
        || segments[..6].iter().all(|segment| *segment == 0)
        || (segments[0] & 0xffc0) == 0xfec0
        || (segments[0] == 0x0100 && segments[1..4].iter().all(|segment| *segment == 0))
        || (segments[0] == 0x2001 && segments[1] < 0x0200)
        || (segments[0] == 0x3fff && segments[1] < 0x1000)
        || segments[0] == 0x5f00)
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
    if !policy.hosts.contains(&host) {
        return Err("host-not-allowed");
    }
    let port = url.port_or_known_default().ok_or("url-invalid")?;
    if !policy.ports.contains(&port) {
        return Err("port-not-allowed");
    }
    Ok(Target { url, host, port })
}

/// Resolve the host and refuse any non-public address. Returns the addresses to connect to. The lookup runs on a
/// blocking thread under the policy deadline, so a slow resolver cannot hold the connection slot.
pub async fn resolve_public(policy: &NetPolicy, target: &Target) -> Result<Vec<SocketAddr>, &'static str> {
    let (host, port) = (target.host.clone(), target.port);
    let lookup = tokio::task::spawn_blocking(move || (host.as_str(), port).to_socket_addrs().map(|found| found.take(8).collect::<Vec<_>>()));
    let addrs = tokio::time::timeout(Duration::from_millis(policy.timeout_ms), lookup)
        .await
        .map_err(|_| "resolve-timeout")?
        .map_err(|_| "resolve-failed")?
        .map_err(|_| "resolve-failed")?;
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

/// GET the target with an already pinned client and shape DSH's `web_fetch` output; the body is cut at `max_bytes`.
async fn get(client: &reqwest::Client, target: &Target, max_bytes: usize) -> Result<Value, String> {
    let mut response = client
        .get(target.url.clone())
        .send()
        .await
        .map_err(|e| if e.is_timeout() { "fetch-timeout".to_owned() } else { "fetch-failed".to_owned() })?;
    let status = response.status();
    if status.is_redirection() {
        let location: String = response.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok()).unwrap_or("").chars().take(1024).collect();
        return Ok(json!({"url": target.url.as_str(), "statusCode": status.as_u16(), "body": {"kind": "text", "content": format!("redirect: {location}")}, "truncated": false}));
    }
    let mut body: Vec<u8> = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = response.chunk().await.map_err(|e| if e.is_timeout() { "fetch-timeout".to_owned() } else { "fetch-failed".to_owned() })? {
        if body.len() + chunk.len() > max_bytes {
            body.extend_from_slice(&chunk[..max_bytes - body.len()]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    let content = String::from_utf8_lossy(&body).into_owned();
    Ok(json!({"url": target.url.as_str(), "statusCode": status.as_u16(), "body": {"kind": "text", "content": content}, "truncated": truncated}))
}

/// Cut the body (at a character boundary, setting `truncated`) until the whole value serializes within `limit`, so a
/// full-size page whose JSON escaping grew it is shortened here rather than refused by the client after it ran.
pub fn fit(value: &mut Value, limit: usize) {
    loop {
        if value.to_string().len() <= limit {
            return;
        }
        let Some(content) = value.pointer_mut("/body/content") else { return };
        let Some(text) = content.as_str() else { return };
        if text.is_empty() {
            return;
        }
        let mut cut = text.len() / 2;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        let shorter = text[..cut].to_owned();
        *content = Value::String(shorter);
        value["truncated"] = Value::Bool(true);
    }
}

/// Fetch one allowlisted URL and shape the result as DSH's `web_fetch` output, within `reply_limit` serialized bytes.
pub async fn fetch(policy: &NetPolicy, text: &str, reply_limit: usize) -> Result<Value, String> {
    let target = check_url(policy, text).map_err(str::to_owned)?;
    let addrs = resolve_public(policy, &target).await.map_err(str::to_owned)?;
    let client = client(policy, &target, &addrs).map_err(str::to_owned)?;
    let mut value = get(&client, &target, policy.max_bytes).await?;
    fit(&mut value, reply_limit);
    Ok(value)
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
        for bad in ["::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "2001:db8::1", "64:ff9b::1", "2002::1", "::10.0.0.1", "::8.8.8.8", "fec0::1", "100::1", "2001:2::1", "3fff::1", "5f00::1", "64:ff9b:1::1"] {
            assert!(!public_ip(bad.parse().unwrap()), "{bad}");
        }
        for good in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111", "::ffff:8.8.8.8", "2001:4860:4860::8888", "2a00:1450:4001::1"] {
            assert!(public_ip(good.parse().unwrap()), "{good}");
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    #[test]
    fn a_name_that_resolves_to_a_private_address_is_refused() {
        let p = policy();
        let target = Target { url: Url::parse("https://localhost/").unwrap(), host: "localhost".into(), port: 443 };
        assert_eq!(runtime().block_on(resolve_public(&p, &target)).unwrap_err(), "host-resolves-private");
    }

    /// A one-shot HTTP server on loopback; the allowlisted name `localhost.example` is mapped to it with
    /// `resolve_to_addrs`, exactly as the door pins a checked address.
    fn serve_once(response: String) -> (u16, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer);
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (port, handle)
    }

    fn local_policy(port: u16) -> NetPolicy {
        let mut p = policy();
        p.hosts = vec!["localhost.example".into()];
        p.ports = vec![port];
        p.allow_http = true;
        p.allow_private = true;
        p
    }

    fn run_get(port: u16, max_bytes: usize) -> Value {
        let p = local_policy(port);
        let target = check_url(&p, &format!("http://localhost.example:{port}/page")).unwrap();
        let client = client(&p, &target, &[SocketAddr::from(([127, 0, 0, 1], port))]).unwrap();
        runtime().block_on(get(&client, &target, max_bytes)).unwrap()
    }

    #[test]
    fn a_fetch_returns_the_tool_shape_and_cuts_the_body_at_the_cap() {
        let body = "x".repeat(10_000);
        let (port, server) = serve_once(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}", body.len()));
        let value = run_get(port, 4096);
        server.join().unwrap();
        assert_eq!(value["statusCode"], 200);
        assert_eq!(value["truncated"], true);
        assert_eq!(value["body"]["kind"], "text");
        assert_eq!(value["body"]["content"].as_str().unwrap().len(), 4096);
        assert!(value["url"].as_str().unwrap().starts_with("http://localhost.example:"));
        let small = "hello";
        let (port, server) = serve_once(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{small}", small.len()));
        let value = run_get(port, 4096);
        server.join().unwrap();
        assert_eq!((value["truncated"].clone(), value["body"]["content"].clone()), (json!(false), json!("hello")));
    }

    #[test]
    fn a_redirect_is_reported_not_followed() {
        let (port, server) = serve_once("HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned());
        let value = run_get(port, 4096);
        server.join().unwrap();
        assert_eq!(value["statusCode"], 302);
        assert_eq!(value["body"]["content"], "redirect: https://elsewhere.example/x");
        assert_eq!(value["truncated"], false);
    }

    #[test]
    fn a_body_that_grows_when_escaped_is_cut_to_fit_the_reply_limit() {
        // Control characters serialize to six bytes each: a body within max_bytes can still exceed the reply line.
        let content = "\u{1}".repeat(50_000);
        let mut value = json!({"url": "https://docs.rs/", "statusCode": 200, "body": {"kind": "text", "content": content}, "truncated": false});
        assert!(value.to_string().len() > 300_000);
        fit(&mut value, 100_000);
        assert!(value.to_string().len() <= 100_000);
        assert_eq!(value["truncated"], true);
        assert!(!value["body"]["content"].as_str().unwrap().is_empty());
        // Already small: untouched.
        let mut small = json!({"url": "u", "statusCode": 200, "body": {"kind": "text", "content": "ok"}, "truncated": false});
        fit(&mut small, 100_000);
        assert_eq!(small["truncated"], false);
        // Multi-byte text is cut on a character boundary.
        let mut wide = json!({"body": {"kind": "text", "content": "\u{20ac}".repeat(1000)}, "truncated": false});
        fit(&mut wide, 1500);
        assert!(wide["body"]["content"].as_str().unwrap().chars().all(|c| c == '\u{20ac}'));
    }
}
