// Interactive desktop login: the OAuth 2.0 authorization-code flow with PKCE
// and a loopback (localhost) redirect — the standard way a CLI obtains an OIDC
// identity token from an interactive GitHub/Google/enterprise login (this is
// what cosign does). The token is cached so `promptsign sign` can use it
// without re-prompting.
//
// Public Sigstore federates GitHub/Google/Microsoft behind its Dex issuer; an
// enterprise deployment just overrides PROMPTSIGN_OIDC_ISSUER / _CLIENT_ID.
//
// This is the ONLY interactive/browser code in the CLI; verification stays
// offline in promptsign-core.

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
use promptsign_core::util::promptsign_home;
use promptsign_core::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_ISSUER: &str = "https://oauth2.sigstore.dev/auth";
const DEFAULT_CLIENT_ID: &str = "sigstore";
const DEFAULT_SCOPES: &str = "openid email";
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

fn env_or(var: &str, default: &str) -> String {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => v,
        _ => default.to_string(),
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("promptsign/", env!("CARGO_PKG_VERSION")))
        .build()
}

// ---- PKCE + small URL helpers ---------------------------------------------

fn rand_b64url(nbytes: usize) -> Result<String> {
    let mut b = vec![0u8; nbytes];

    getrandom::getrandom(&mut b).map_err(|e| format!("rng failure: {e}"))?;
    Ok(BASE64_URL_SAFE_NO_PAD.encode(b))
}

fn pkce_challenge(verifier: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());

    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(byte) => {
                    out.push(byte);
                    i += 3;
                }
                Err(_) => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
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

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }

        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));

        map.insert(pct_decode(k), pct_decode(v));
    }
    map
}

// ---- token decoding (for a friendly summary + cache expiry) ---------------

fn jwt_payload(token: &str) -> Option<Value> {
    let raw = BASE64_URL_SAFE_NO_PAD
        .decode(token.split('.').nth(1)?)
        .ok()?;

    serde_json::from_slice(&raw).ok()
}

fn token_identity_exp(token: &str) -> (String, i64) {
    let v = jwt_payload(token).unwrap_or(Value::Null);
    let id = v
        .get("email")
        .and_then(Value::as_str)
        .or_else(|| v.get("sub").and_then(Value::as_str))
        .unwrap_or("(unknown identity)")
        .to_string();
    let exp = v.get("exp").and_then(Value::as_i64).unwrap_or(0);

    (id, exp)
}

// ---- OIDC discovery + browser + loopback listener -------------------------

fn discover(issuer: &str) -> Result<(String, String)> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let v: Value = agent()
        .get(&url)
        .call()
        .map_err(|e| format!("OIDC discovery ({url}): {e}"))?
        .into_json()
        .map_err(|e| format!("OIDC discovery: {e}"))?;
    let auth = v
        .get("authorization_endpoint")
        .and_then(Value::as_str)
        .ok_or("issuer has no authorization_endpoint")?;
    let token = v
        .get("token_endpoint")
        .and_then(Value::as_str)
        .ok_or("issuer has no token_endpoint")?;

    Ok((auth.to_string(), token.to_string()))
}

fn open_browser(url: &str) {
    // Windows: go through rundll32's FileProtocolHandler, NOT `cmd /C start` —
    // cmd treats the `&` in the query string as a command separator and mangles
    // the URL. rundll32 receives the URL as a single argument with no shell.
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", url])
        .spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}

// Branded status page shown in the browser tab after the OAuth redirect.
// Mirrors the web front-end: ink canvas, teal signet seal, gold check, and the
// "PromptSign" wordmark in Schibsted Grotesk (loaded from Google Fonts, falling
// back to system-ui when offline). Matches the site's `.brand__name` wordmark
// (weight 600, -0.01em). `%%MESSAGE%%` is the only substitution point.
const CALLBACK_PAGE: &str = r#"<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PromptSign</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Schibsted+Grotesk:wght@600&family=Hanken+Grotesk:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0b0d;color:#e9e7df;font-family:'Hanken Grotesk',system-ui,sans-serif;-webkit-font-smoothing:antialiased}
.card{max-width:30rem;padding:3rem 2.5rem;text-align:center}
svg{width:76px;height:76px;margin-bottom:1.25rem}
.rim,.ring{fill:none;stroke:#24d1b7}
.rim{stroke-width:3}
.ring{stroke-width:2.5;stroke-dasharray:4.712 4.712;opacity:.7}
.check{fill:none;stroke:#e6b450;stroke-width:7.5;stroke-linecap:round;stroke-linejoin:round}
h1{font-family:'Schibsted Grotesk',system-ui,sans-serif;font-weight:600;letter-spacing:-.01em;font-size:1.75rem;margin:0 0 .5rem}
p{color:#a2a6ad;font-size:1.05rem;line-height:1.55;margin:0}
</style></head>
<body><main class="card">
<svg viewBox="0 0 100 100" aria-hidden="true">
<circle class="rim" cx="50" cy="50" r="45.5"/>
<circle class="ring" cx="50" cy="50" r="36"/>
<path class="check" d="M32.5 51.5L43.5 62.5L67.5 36.5"/>
</svg>
<h1>PromptSign</h1>
<p>%%MESSAGE%%</p>
</main></body></html>"#;

fn respond(stream: &mut TcpStream, message: &str) {
    let body = CALLBACK_PAGE.replace("%%MESSAGE%%", message);
    let http = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(http.as_bytes());
    let _ = stream.flush();
}

// Accept connections until the provider redirects back with ?code=&state=.
fn wait_for_code(listener: &TcpListener, expected_state: &str) -> Result<String> {
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;

    let deadline = Instant::now() + LOGIN_TIMEOUT;

    loop {
        if Instant::now() > deadline {
            return Err("login timed out — no response from the browser".to_string());
        }

        let (mut stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
            Err(e) => return Err(format!("accept failed: {e}")),
        };

        stream.set_nonblocking(false).ok();
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

        let mut buf = [0u8; 8192];
        let n = stream.read(&mut buf).unwrap_or(0);
        let req = String::from_utf8_lossy(&buf[..n]);
        let target = req
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("");
        let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
        let params = parse_query(query);

        if let Some(err) = params.get("error") {
            respond(&mut stream, "Login failed. You can close this tab.");
            return Err(format!("provider returned an error: {err}"));
        }
        match (params.get("code"), params.get("state")) {
            (Some(code), Some(state)) if state == expected_state => {
                respond(
                    &mut stream,
                    "Login complete \u{2014} return to your terminal.",
                );
                return Ok(code.clone());
            }
            (Some(_), Some(_)) => {
                respond(&mut stream, "Login state mismatch. You can close this tab.");
                return Err("OAuth state mismatch (possible CSRF) — aborted".to_string());
            }
            // favicon or other stray requests before the real redirect
            _ => {
                respond(&mut stream, "Waiting for sign-in\u{2026}");
            }
        }
    }
}

/// Run the interactive flow and return an OIDC id_token.
pub fn interactive_login() -> Result<String> {
    let issuer = env_or("PROMPTSIGN_OIDC_ISSUER", DEFAULT_ISSUER);
    let client_id = env_or("PROMPTSIGN_OIDC_CLIENT_ID", DEFAULT_CLIENT_ID);
    let scopes = env_or("PROMPTSIGN_OIDC_SCOPES", DEFAULT_SCOPES);
    let (auth_ep, token_ep) = discover(&issuer)?;

    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("could not open a local port for the login redirect: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let redirect = format!("http://localhost:{port}/auth/callback");

    let verifier = rand_b64url(32)?;
    let challenge = pkce_challenge(&verifier);
    let state = rand_b64url(16)?;
    let nonce = rand_b64url(16)?;

    let auth_url = format!(
        "{auth_ep}?response_type=code&client_id={cid}&scope={scope}&redirect_uri={ru}&state={st}&nonce={no}&code_challenge={ch}&code_challenge_method=S256",
        cid = urlencode(&client_id),
        scope = urlencode(&scopes),
        ru = urlencode(&redirect),
        st = urlencode(&state),
        no = urlencode(&nonce),
        ch = urlencode(&challenge),
    );

    eprintln!("Opening your browser to sign in\u{2026}");
    eprintln!("If it doesn't open, visit this URL:\n  {auth_url}\n");
    open_browser(&auth_url);

    let code = wait_for_code(&listener, &state)?;

    // Exchange the code (+ PKCE verifier) for tokens.
    let secret = std::env::var("PROMPTSIGN_OIDC_CLIENT_SECRET").unwrap_or_default();
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", &redirect),
        ("client_id", &client_id),
        ("code_verifier", &verifier),
    ];

    if !secret.is_empty() {
        form.push(("client_secret", &secret));
    }

    let resp: Value = agent()
        .post(&token_ep)
        .send_form(&form)
        .map_err(|e| format!("token exchange failed: {e}"))?
        .into_json()
        .map_err(|e| format!("token exchange: {e}"))?;

    resp.get("id_token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "token response had no id_token".to_string())
}

// ---- cached session (so `promptsign sign` can reuse a recent login) -------

fn session_path() -> PathBuf {
    promptsign_home().join("session.json")
}

fn store_session(id_token: &str) -> Result<(String, i64)> {
    let (identity, exp) = token_identity_exp(id_token);
    let dir = promptsign_home();

    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;

    let v = json!({ "id_token": id_token, "identity": identity, "exp": exp });
    let path = session_path();

    std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap() + "\n")
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((identity, exp))
}

/// A cached login token if one is present and not (nearly) expired. Used by the
/// keyless signer's token resolution so `promptsign login` then `promptsign sign`
/// works without re-prompting.
pub fn load_session_token() -> Option<String> {
    let raw = std::fs::read_to_string(session_path()).ok()?;
    let v: Value = serde_json::from_str(&raw).ok()?;
    let exp = v.get("exp").and_then(Value::as_i64).unwrap_or(0);

    if exp != 0 && exp <= now_secs() + 10 {
        return None; // expired (or about to)
    }
    v.get("id_token")
        .and_then(Value::as_str)
        .map(str::to_string)
}

pub fn cmd_login(rest: &[String]) -> ExitCode {
    let print_token = rest.iter().any(|a| a == "--print-token");

    match interactive_login() {
        Ok(id_token) => {
            let (identity, exp) = match store_session(&id_token) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("promptsign: {e}");
                    return ExitCode::from(1);
                }
            };

            if print_token {
                // stdout stays clean for `SIGSTORE_ID_TOKEN=$(promptsign login --print-token)`
                println!("{id_token}");
            }

            let mins = if exp > 0 {
                ((exp - now_secs()) / 60).max(0)
            } else {
                0
            };

            eprintln!(
                "Signed in as {identity}. Token valid ~{mins} min; cached for `promptsign sign`."
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("promptsign: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_escapes_reserved_but_not_unreserved() {
        assert_eq!(urlencode("openid email"), "openid%20email");
        assert_eq!(urlencode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(
            urlencode("http://localhost:9/x"),
            "http%3A%2F%2Flocalhost%3A9%2Fx"
        );
    }

    #[test]
    fn parse_query_decodes_pairs() {
        let q = parse_query("code=ab%2Fcd&state=xyz&empty=");

        assert_eq!(q.get("code").unwrap(), "ab/cd");
        assert_eq!(q.get("state").unwrap(), "xyz");
        assert_eq!(q.get("empty").unwrap(), "");
    }

    #[test]
    fn pkce_challenge_is_deterministic_base64url() {
        // RFC 7636 test vector.
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        assert_eq!(
            pkce_challenge(v),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn token_identity_exp_reads_email_and_exp() {
        // {"email":"a@b.com","exp":123}
        let payload = BASE64_URL_SAFE_NO_PAD.encode(br#"{"email":"a@b.com","exp":123}"#);
        let token = format!("h.{payload}.s");

        assert_eq!(token_identity_exp(&token), ("a@b.com".to_string(), 123));
    }
}
