// `promptsign proxy` — a local CORS forwarder so the in-browser keyless flow can
// reach Fulcio, Rekor, and the OIDC login service. Same job (and same `?url=`
// contract) as web/workers/keyless-proxy, but a single static binary you run
// under systemd / a container instead of a Cloudflare Worker — no Node, no
// third-party runtime, no account.
//
// It is a narrow forwarder, not an open proxy: only GET/POST/OPTIONS, and only
// an allowlist of https hosts (Sigstore's public hosts by default, plus any
// --allow-host you add).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

const DEFAULT_HOSTS: &[&str] = &[
    "fulcio.sigstore.dev",
    "rekor.sigstore.dev",
    "oauth2.sigstore.dev",
];

#[derive(Clone)]
struct Config {
    allow_origins: Vec<String>, // empty => "*"
    allow_hosts: Vec<String>,   // in addition to DEFAULT_HOSTS
}

pub fn cmd_proxy(rest: &[String]) -> ExitCode {
    let mut host = "127.0.0.1".to_string();
    let mut port = "8787".to_string();
    let mut cfg = Config {
        allow_origins: Vec::new(),
        allow_hosts: Vec::new(),
    };

    let mut i = 0;

    while i < rest.len() {
        match rest[i].as_str() {
            "--host" => {
                i += 1;
                host = rest.get(i).cloned().unwrap_or(host);
            }
            "--port" => {
                i += 1;
                port = rest.get(i).cloned().unwrap_or(port);
            }
            "--allow-origin" => {
                i += 1;
                if let Some(o) = rest.get(i) {
                    cfg.allow_origins.push(o.trim_end_matches('/').to_string());
                }
            }
            "--allow-host" => {
                i += 1;
                if let Some(h) = rest.get(i) {
                    cfg.allow_hosts.push(h.to_ascii_lowercase());
                }
            }
            other => {
                eprintln!("promptsign: proxy: unexpected argument \"{other}\"");
                return ExitCode::from(1);
            }
        }
        i += 1;
    }

    let addr = format!("{host}:{port}");
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("promptsign: proxy: could not bind {addr}: {e}");
            return ExitCode::from(1);
        }
    };

    let origins = if cfg.allow_origins.is_empty() {
        "any (*)".to_string()
    } else {
        cfg.allow_origins.join(", ")
    };
    let hosts: Vec<&str> = DEFAULT_HOSTS
        .iter()
        .copied()
        .chain(cfg.allow_hosts.iter().map(String::as_str))
        .collect();

    eprintln!("promptsign keyless proxy listening on http://{addr}");
    eprintln!("  allowed origins:  {origins}");
    eprintln!("  allowed upstreams: {}", hosts.join(", "));
    eprintln!("  point the web app at it: VITE_KEYLESS_PROXY_URL=http://{addr}");

    for stream in listener.incoming().flatten() {
        let cfg = cfg.clone();

        std::thread::spawn(move || handle(stream, &cfg));
    }
    ExitCode::SUCCESS
}

fn handle(mut stream: TcpStream, cfg: &Config) {
    stream.set_read_timeout(Some(Duration::from_secs(15))).ok();

    let request = match read_request(&mut stream) {
        Some(r) => r,
        None => return,
    };
    let Request {
        method,
        path,
        headers,
        body,
    } = request;

    let cors = cors_headers(cfg, headers.get("origin").map(String::as_str));

    if method == "OPTIONS" {
        write_response(&mut stream, 204, "No Content", None, &[], &cors);
        return;
    }
    if method != "GET" && method != "POST" {
        write_response(
            &mut stream,
            405,
            "Method Not Allowed",
            Some("text/plain"),
            b"method not allowed",
            &cors,
        );
        return;
    }

    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
    let target = match query_param(query, "url") {
        Some(t) => t,
        None => {
            write_response(
                &mut stream,
                400,
                "Bad Request",
                Some("text/plain"),
                b"missing ?url= parameter",
                &cors,
            );
            return;
        }
    };
    let host = match target_host(&target) {
        Some(h) => h,
        None => {
            write_response(
                &mut stream,
                400,
                "Bad Request",
                Some("text/plain"),
                b"only https targets are allowed",
                &cors,
            );
            return;
        }
    };

    if !is_allowed(&host, cfg) {
        let msg = format!("host not allowed: {host}");

        write_response(
            &mut stream,
            403,
            "Forbidden",
            Some("text/plain"),
            msg.as_bytes(),
            &cors,
        );
        return;
    }

    let content_type = headers.get("content-type").map(String::as_str);
    let (status, reason, ct, out) = forward(&method, &target, content_type, &body);

    write_response(&mut stream, status, &reason, ct.as_deref(), &out, &cors);
}

// ---- forwarding (ureq; forwards non-2xx upstream responses verbatim) --------

fn proxy_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("promptsign-proxy/", env!("CARGO_PKG_VERSION")))
        .build()
}

fn forward(
    method: &str,
    url: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> (u16, String, Option<String>, Vec<u8>) {
    let agent = proxy_agent();
    let mut req = if method == "POST" {
        agent.post(url)
    } else {
        agent.get(url)
    };

    if let Some(ct) = content_type {
        req = req.set("Content-Type", ct);
    }

    let result = if method == "POST" {
        req.send_bytes(body)
    } else {
        req.call()
    };

    match result {
        Ok(resp) => read_response(resp),
        Err(ureq::Error::Status(_, resp)) => read_response(resp),
        Err(ureq::Error::Transport(t)) => (
            502,
            "Bad Gateway".to_string(),
            Some("text/plain".to_string()),
            format!("upstream request failed: {t}").into_bytes(),
        ),
    }
}

fn read_response(resp: ureq::Response) -> (u16, String, Option<String>, Vec<u8>) {
    let status = resp.status();
    let reason = resp.status_text().to_string();
    let ct = resp.header("Content-Type").map(str::to_string);
    let mut out = Vec::new();
    let _ = resp
        .into_reader()
        .take(16 * 1024 * 1024)
        .read_to_end(&mut out);

    (status, reason, ct, out)
}

// ---- request parsing --------------------------------------------------------

// Everything `handle` needs off the wire. Named fields rather than a tuple:
// `method` and `path` are both String, so a tuple makes them swappable by
// accident.
struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut tmp).ok()?;

        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            return None; // header block too large
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut parts = lines.next()?.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut headers = HashMap::new();

    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[header_end + 4..].to_vec();

    while body.len() < len {
        let n = stream.read(&mut tmp).ok()?;

        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(len);
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: Option<&str>,
    body: &[u8],
    cors: &[(String, String)],
) {
    let mut head = format!("HTTP/1.1 {status} {reason}\r\n");

    for (k, v) in cors {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));

    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

// ---- pure helpers (unit-tested) --------------------------------------------

fn cors_headers(cfg: &Config, origin: Option<&str>) -> Vec<(String, String)> {
    let allow_origin = if cfg.allow_origins.is_empty() {
        "*".to_string()
    } else if let Some(o) = origin {
        if cfg.allow_origins.iter().any(|a| a == o) {
            o.to_string()
        } else {
            cfg.allow_origins[0].clone()
        }
    } else {
        cfg.allow_origins[0].clone()
    };

    vec![
        ("Access-Control-Allow-Origin".into(), allow_origin),
        (
            "Access-Control-Allow-Methods".into(),
            "GET, POST, OPTIONS".into(),
        ),
        (
            "Access-Control-Allow-Headers".into(),
            "content-type, authorization".into(),
        ),
        ("Access-Control-Max-Age".into(), "86400".into()),
        ("Vary".into(), "Origin".into()),
    ]
}

fn is_allowed(host: &str, cfg: &Config) -> bool {
    DEFAULT_HOSTS.contains(&host) || cfg.allow_hosts.iter().any(|h| h == host)
}

/// Hostname of an https URL, lowercased. `None` for non-https or malformed input.
fn target_host(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?;

    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Value of `name` from a raw query string, percent-decoded.
fn query_param(query: &str, name: &str) -> Option<String> {
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));

        if k == name {
            return Some(pct_decode(v));
        }
    }
    None
}

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);

                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(origins: &[&str], hosts: &[&str]) -> Config {
        Config {
            allow_origins: origins.iter().map(|s| s.to_string()).collect(),
            allow_hosts: hosts.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn target_host_extracts_https_hostname() {
        assert_eq!(
            target_host("https://fulcio.sigstore.dev/api/v2/signingCert").as_deref(),
            Some("fulcio.sigstore.dev")
        );
        assert_eq!(
            target_host("https://oauth2.sigstore.dev:443/token").as_deref(),
            Some("oauth2.sigstore.dev")
        );
        assert_eq!(target_host("http://fulcio.sigstore.dev/x"), None); // not https
        assert_eq!(target_host("ftp://x"), None);
        assert_eq!(target_host("not a url"), None);
    }

    #[test]
    fn allowlist_defaults_and_extras() {
        let base = cfg(&[], &[]);

        assert!(is_allowed("fulcio.sigstore.dev", &base));
        assert!(is_allowed("rekor.sigstore.dev", &base));
        assert!(is_allowed("oauth2.sigstore.dev", &base));
        assert!(!is_allowed("evil.example", &base));

        let ent = cfg(&[], &["dex.acme.example"]);

        assert!(is_allowed("dex.acme.example", &ent));
        assert!(!is_allowed("other.acme.example", &ent));
    }

    #[test]
    fn query_param_percent_decodes() {
        let q = "url=https%3A%2F%2Ffulcio.sigstore.dev%2Fapi%2Fv2%2FsigningCert&x=1";

        assert_eq!(
            query_param(q, "url").as_deref(),
            Some("https://fulcio.sigstore.dev/api/v2/signingCert")
        );
        assert_eq!(query_param(q, "missing"), None);
    }

    #[test]
    fn cors_origin_selection() {
        // no configured origins => wildcard
        let open = cors_headers(&cfg(&[], &[]), Some("https://site.example"));

        assert_eq!(open[0].1, "*");

        // configured + matching origin => echoed
        let locked = cors_headers(
            &cfg(&["https://site.example"], &[]),
            Some("https://site.example"),
        );

        assert_eq!(locked[0].1, "https://site.example");

        // configured + non-matching origin => first allowed (not echoed)
        let denied = cors_headers(
            &cfg(&["https://site.example"], &[]),
            Some("https://evil.example"),
        );

        assert_eq!(denied[0].1, "https://site.example");
    }
}
