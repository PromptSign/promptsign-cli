// Keyless signing client (spec/05-keyless.md §6) and trust-root management.
// This module is the ONLY place in the workspace that touches the network:
// verification (promptsign-core) is offline by construction.

use base64::prelude::{Engine as _, BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{Signer, SigningKey};
use promptsign_core::bundle::{pae, BUNDLE_SCHEMA};
use promptsign_core::keyless::{chain_leaf_info, pem_chain_to_b64_der, trust_dir, trusted_log_id};
use promptsign_core::revocation::{
    feed_path, load_cached_feed, verify_feed, RevocationEntry, RevocationFeed,
    REVOCATION_PAYLOAD_TYPE, REVOCATION_SCHEMA,
};
use promptsign_core::util::iso8601_now;
use promptsign_core::Result;
use serde_json::{json, Value};
use std::time::Duration;

pub const DEFAULT_FULCIO: &str = "https://fulcio.sigstore.dev";
pub const DEFAULT_REKOR: &str = "https://rekor.sigstore.dev";

fn env_url(var: &str, default: &str) -> String {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => v.trim_end_matches('/').to_string(),
        _ => default.to_string(),
    }
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("promptsign/", env!("CARGO_PKG_VERSION")))
        .build()
}

fn http_err(context: &str, e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let body = resp.into_string().unwrap_or_default();

            format!("{context}: HTTP {code}: {}", body.trim())
        }
        other => format!("{context}: {other}"),
    }
}

/// OIDC token resolution order: explicit flag, $SIGSTORE_ID_TOKEN, a cached
/// `promptsign login` session, then GitHub Actions ambient credentials (the
/// primary CI story — no key to leak).
fn resolve_token(flag: Option<&str>) -> Result<String> {
    if let Some(t) = flag {
        return Ok(t.to_string());
    }
    if let Ok(t) = std::env::var("SIGSTORE_ID_TOKEN") {
        if !t.is_empty() {
            return Ok(t);
        }
    }
    if let Some(t) = crate::login::load_session_token() {
        return Ok(t);
    }
    if let (Ok(url), Ok(bearer)) = (
        std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL"),
        std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
    ) {
        let sep = if url.contains('?') { '&' } else { '?' };
        let resp: Value = agent()
            .get(&format!("{url}{sep}audience=sigstore"))
            .set("Authorization", &format!("bearer {bearer}"))
            .call()
            .map_err(|e| http_err("GitHub Actions OIDC", e))?
            .into_json()
            .map_err(|e| format!("GitHub Actions OIDC: {e}"))?;

        return resp
            .get("value")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| "GitHub Actions OIDC: no token in response".to_string());
    }
    Err(
        "no OIDC identity token — run `promptsign login` first, or pass \
         --identity-token, set SIGSTORE_ID_TOKEN, or run in GitHub Actions with \
         `permissions: id-token: write`"
            .to_string(),
    )
}

fn jwt_claim(token: &str, claim: &str) -> Result<String> {
    let payload = token.split('.').nth(1).ok_or("malformed OIDC token")?;
    let raw = BASE64_URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| "malformed OIDC token payload")?;
    let v: Value = serde_json::from_slice(&raw).map_err(|_| "malformed OIDC token payload")?;

    v.get(claim)
        .and_then(|c| c.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("OIDC token has no \"{claim}\" claim"))
}

pub struct KeylessOutcome {
    pub bundle: Value,
    pub identity: String,
    pub issuer: String,
    pub log_index: i64,
}

/// Ephemeral key → Fulcio cert → sign → Rekor entry → self-contained bundle.
/// The key never leaves this function and is dropped on return. `payload_type`
/// is the DSSE payloadType (manifest for `sign`, revocation for a feed).
pub fn keyless_sign(
    payload: &[u8],
    payload_type: &str,
    token_flag: Option<&str>,
) -> Result<KeylessOutcome> {
    let token = resolve_token(token_flag)?;
    // Fulcio checks the proof-of-possession against the identity it will
    // certify: the `email` claim for email-based tokens (Dex / Google logins),
    // the `sub` claim otherwise (e.g. CI workflow tokens). Mirrors sigstore's
    // SubjectFromToken.
    let subject = jwt_claim(&token, "email").or_else(|_| jwt_claim(&token, "sub"))?;

    let mut secret = [0u8; 32];

    getrandom::getrandom(&mut secret).map_err(|e| format!("rng failure: {e}"))?;

    let key = SigningKey::from_bytes(&secret);
    let pub_pem = key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("public key encoding failed: {e}"))?;
    // Proof of possession: Fulcio requires a signature over the token's
    // subject so a stolen bare token cannot be bound to an attacker's key.
    let pop = BASE64_STANDARD.encode(key.sign(subject.as_bytes()).to_bytes());

    let fulcio = env_url("PROMPTSIGN_FULCIO_URL", DEFAULT_FULCIO);
    let resp: Value = agent()
        .post(&format!("{fulcio}/api/v2/signingCert"))
        .send_json(json!({
            "credentials": { "oidcIdentityToken": token },
            "publicKeyRequest": {
                "publicKey": { "algorithm": "ED25519", "content": pub_pem },
                "proofOfPossession": pop
            }
        }))
        .map_err(|e| http_err("Fulcio", e))?
        .into_json()
        .map_err(|e| format!("Fulcio: {e}"))?;
    let certs = resp
        .get("signedCertificateEmbeddedSct")
        .or_else(|| resp.get("signedCertificateDetachedSct"))
        .and_then(|c| c.get("chain"))
        .and_then(|c| c.get("certificates"))
        .and_then(|c| c.as_array())
        .ok_or("Fulcio: no certificate chain in response")?;
    let chain_pem = certs
        .iter()
        .map(|c| c.as_str().unwrap_or_default().trim().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let chain_b64 = pem_chain_to_b64_der(chain_pem.as_bytes())?;
    let (identity, issuer, leaf_keyid) = chain_leaf_info(&chain_b64)?;
    let leaf_pem = certs[0].as_str().unwrap_or_default().trim().to_string();

    let sig = key.sign(&pae(payload_type, payload));
    let sig_b64 = BASE64_STANDARD.encode(sig.to_bytes());
    let payload_b64 = BASE64_STANDARD.encode(payload);

    // Rekor wants the standard DSSE JSON as a string, verifier = leaf cert.
    let dsse_envelope = serde_json::to_string(&json!({
        "payloadType": payload_type,
        "payload": payload_b64,
        "signatures": [ { "sig": sig_b64 } ]
    }))
    .unwrap();
    let rekor = env_url("PROMPTSIGN_REKOR_URL", DEFAULT_REKOR);
    let resp: Value = agent()
        .post(&format!("{rekor}/api/v1/log/entries"))
        .send_json(json!({
            "apiVersion": "0.0.1",
            "kind": "dsse",
            // verifiers entries are strfmt.Base64 in Rekor's dsse schema: the
            // PEM itself goes in base64-encoded, not raw.
            "spec": { "proposedContent": { "envelope": dsse_envelope, "verifiers": [BASE64_STANDARD.encode(&leaf_pem)] } }
        }))
        .map_err(|e| http_err("Rekor", e))?
        .into_json()
        .map_err(|e| format!("Rekor: {e}"))?;
    // Response is { "<entry-uuid>": { body, integratedTime, logID, logIndex, verification } }
    let entry = resp
        .as_object()
        .and_then(|m| m.values().next())
        .ok_or("Rekor: empty response")?;
    let log_index = entry
        .get("logIndex")
        .and_then(|v| v.as_i64())
        .ok_or("Rekor: no logIndex")?;
    let transparency = json!({
        "logId": entry.get("logID").cloned().unwrap_or(Value::Null),
        "logIndex": log_index,
        "integratedTime": entry.get("integratedTime").cloned().unwrap_or(Value::Null),
        "signedEntryTimestamp": entry
            .get("verification")
            .and_then(|v| v.get("signedEntryTimestamp"))
            .cloned()
            .unwrap_or(Value::Null),
        "body": entry.get("body").cloned().unwrap_or(Value::Null)
    });

    let bundle = json!({
        "schema": BUNDLE_SCHEMA,
        "envelope": {
            "payloadType": payload_type,
            "payload": payload_b64,
            "signatures": [ { "keyid": leaf_keyid, "sig": sig_b64 } ]
        },
        "signer": {
            "scheme": "keyless",
            "identity": identity,
            "issuer": issuer,
            "certChain": chain_b64
        },
        "transparency": transparency
    });

    Ok(KeylessOutcome {
        bundle,
        identity,
        issuer,
        log_index,
    })
}

/// Decoded DER of every PEM block carrying this label. Comparing decoded bytes
/// rather than text makes the clobber check below insensitive to line endings,
/// block order, and re-wrapping.
fn pem_block_ders(pem: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = pem;

    while let Some(start) = rest.find(&begin) {
        let after = &rest[start + begin.len()..];
        let Some(stop) = after.find(&end) else { break };
        let b64: String = after[..stop]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        if let Ok(der) = BASE64_STANDARD.decode(&b64) {
            out.push(der);
        }
        rest = &after[stop + end.len()..];
    }
    out
}

/// Refuse to drop trust material that is already on disk.
///
/// Trust-root files are lists, and rotation appends to them: a signature is
/// verified against the log that witnessed it and the CA that issued its
/// certificate, each selected by name, so retired material has to survive a
/// refresh or everything signed under it stops verifying. These endpoints serve
/// only what is *current*, so writing the response over an appended file is
/// exactly how that loss would happen — silently, on a routine command.
fn ensure_no_loss(path: &std::path::Path, label: &str, fetched: &str) -> Result<()> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Ok(()), // nothing cached yet: nothing to lose
    };
    let incoming = pem_block_ders(fetched, label);
    let dropped = pem_block_ders(&existing, label)
        .into_iter()
        .filter(|der| !incoming.contains(der))
        .count();

    if dropped == 0 {
        return Ok(());
    }

    let file = path.display();
    let name = path.file_name().unwrap_or_default().to_string_lossy();

    Err([
        format!(
            "refusing to overwrite {file}: it holds {dropped} entry(s) the fetched root does not."
        ),
        String::new(),
        "Rotation is append-only. A signature is checked against the log that witnessed it and"
            .to_string(),
        "the CA that issued its certificate, so discarding retired material invalidates every"
            .to_string(),
        "signature made under it. These endpoints only ever serve what is current.".to_string(),
        String::new(),
        "To take the new root and keep the old:".to_string(),
        "    scratch=$(mktemp -d)".to_string(),
        "    PROMPTSIGN_TRUST_DIR=$scratch promptsign trust fetch".to_string(),
        format!("    cat $scratch/{name} >> {file}"),
        String::new(),
        "Or `promptsign trust fetch --force` to overwrite anyway and accept the loss.".to_string(),
    ]
    .join("\n"))
}

/// One-time online step: cache the Fulcio CA chain and Rekor public key so
/// every subsequent keyless verification is offline.
pub fn trust_fetch(force: bool) -> Result<()> {
    let dir = trust_dir();

    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;

    let fulcio = env_url("PROMPTSIGN_FULCIO_URL", DEFAULT_FULCIO);
    let rekor = env_url("PROMPTSIGN_REKOR_URL", DEFAULT_REKOR);

    // Both are fetched and validated before either is written: a half-updated
    // trust dir — new CA, stale log key — verifies nothing, and is worse than
    // never having run the command.
    let ca_pem = agent()
        .get(&format!("{fulcio}/api/v1/rootCert"))
        .call()
        .map_err(|e| http_err("Fulcio", e))?
        .into_string()
        .map_err(|e| format!("Fulcio: {e}"))?;

    pem_chain_to_b64_der(ca_pem.as_bytes())?; // validate before persisting

    let rekor_pem = agent()
        .get(&format!("{rekor}/api/v1/log/publicKey"))
        .call()
        .map_err(|e| http_err("Rekor", e))?
        .into_string()
        .map_err(|e| format!("Rekor: {e}"))?;

    if pem_block_ders(&rekor_pem, "PUBLIC KEY").is_empty() {
        return Err("Rekor: response is not a PEM public key".to_string());
    }

    let fulcio_path = dir.join("fulcio.pem");
    let rekor_path = dir.join("rekor.pub");

    if !force {
        ensure_no_loss(&fulcio_path, "CERTIFICATE", &ca_pem)?;
        ensure_no_loss(&rekor_path, "PUBLIC KEY", &rekor_pem)?;
    }

    std::fs::write(&fulcio_path, &ca_pem).map_err(|e| format!("{}: {e}", fulcio_path.display()))?;
    std::fs::write(&rekor_path, &rekor_pem)
        .map_err(|e| format!("{}: {e}", rekor_path.display()))?;

    println!("wrote {}", fulcio_path.display());
    println!("wrote {}", rekor_path.display());
    println!("rekor log id: {}", trusted_log_id()?);
    Ok(())
}

pub fn trust_show() -> Result<()> {
    let dir = trust_dir();

    println!("trust dir: {}", dir.display());
    println!("rekor log id: {}", trusted_log_id()?);
    Ok(())
}

// ---- Revocation feed (spec/06) ----

fn load_active_policy() -> Result<promptsign_core::policy::Policy> {
    let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
    let (policy, _raw, _src) = promptsign_core::policy::load_policy(None, &cwd)?;

    Ok(policy)
}

/// Opportunistic online refresh: fetch the policy's `revocation_feed`, verify it
/// against the pinned feed identity, and cache it for offline verification. This
/// is the only online step in the revocation path.
pub fn revoke_fetch() -> Result<()> {
    let policy = load_active_policy()?;
    let url = policy
        .revocation_feed
        .clone()
        .ok_or("no revocation_feed in policy — add one (see spec/06) before fetching")?;
    let bundle: Value = agent()
        .get(&url)
        .call()
        .map_err(|e| http_err("revocation feed", e))?
        .into_json()
        .map_err(|e| format!("revocation feed: {e}"))?;
    // Validate before persisting: never cache a feed we would not trust.
    let feed = verify_feed(&bundle, &policy)?;
    let path = feed_path();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }

    let json = serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())?;

    std::fs::write(&path, json + "\n").map_err(|e| format!("{}: {e}", path.display()))?;
    println!("wrote {}", path.display());
    println!(
        "feed generated {} — {} entr{}",
        feed.generated_at,
        feed.entries.len(),
        if feed.entries.len() == 1 { "y" } else { "ies" }
    );
    Ok(())
}

/// Show the cached feed's status (offline).
pub fn revoke_show() -> Result<()> {
    let path = feed_path();
    let bundle = match load_cached_feed()? {
        Some(b) => b,
        None => {
            println!(
                "no revocation feed cached ({}) — run `promptsign revoke fetch`",
                path.display()
            );
            return Ok(());
        }
    };
    let policy = load_active_policy()?;

    println!("feed cache: {}", path.display());
    match verify_feed(&bundle, &policy) {
        Ok(feed) => {
            let stale = promptsign_core::revocation::is_stale(&feed, &policy);

            println!(
                "generated: {}{}",
                feed.generated_at,
                if stale { " (STALE)" } else { "" }
            );
            println!("entries: {}", feed.entries.len());
        }
        Err(e) => println!("NOT TRUSTED: {e}"),
    }
    Ok(())
}

/// Publisher tool: wrap an entries file as a `promptsign/revocation/v1` document,
/// stamp `generatedAt`, and sign it keyless. `entries.json` is either a JSON array
/// of entries or an object with an `entries` array.
pub fn revoke_sign(
    entries_path: &str,
    out_path: Option<&str>,
    token_flag: Option<&str>,
) -> Result<()> {
    let text = std::fs::read_to_string(entries_path).map_err(|e| format!("{entries_path}: {e}"))?;
    let raw: Value = serde_json::from_str(&text).map_err(|e| format!("{entries_path}: {e}"))?;
    let entries_val = match raw {
        Value::Array(_) => raw,
        Value::Object(ref o) => o
            .get("entries")
            .cloned()
            .ok_or("entries file object has no \"entries\" array")?,
        _ => return Err("entries file must be a JSON array or an object with \"entries\"".into()),
    };
    let entries: Vec<RevocationEntry> =
        serde_json::from_value(entries_val).map_err(|e| format!("invalid entries: {e}"))?;
    let feed = RevocationFeed {
        schema: REVOCATION_SCHEMA.to_string(),
        generated_at: iso8601_now(),
        entries,
    };
    let payload = serde_json::to_vec(&feed).map_err(|e| e.to_string())?;

    // The feed must itself verify offline before we publish it (like `sign`).
    promptsign_core::keyless::load_trust_root()?;

    let outcome = keyless_sign(&payload, REVOCATION_PAYLOAD_TYPE, token_flag)?;

    // Self-check: verify the freshly signed feed as a keyless bundle.
    promptsign_core::keyless::verify_keyless(&outcome.bundle)
        .map_err(|e| format!("self-verification of signed feed failed: {e}"))?;

    let out = out_path.unwrap_or("revocation-feed.json");
    let json = serde_json::to_string_pretty(&outcome.bundle).map_err(|e| e.to_string())?;

    std::fs::write(out, json + "\n").map_err(|e| format!("{out}: {e}"))?;
    println!(
        "signed revocation feed ({} entr{}) as {} via {}",
        feed.entries.len(),
        if feed.entries.len() == 1 { "y" } else { "ies" },
        outcome.identity,
        outcome.issuer
    );
    println!("feed: {out}");
    println!("transparency log index: {}", outcome.log_index);
    println!("serve this file at your policy's revocation_feed URL, then `promptsign revoke fetch` on consumers");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ensure_no_loss, pem_block_ders};
    use base64::prelude::{Engine as _, BASE64_STANDARD};

    fn block(label: &str, bytes: &[u8]) -> String {
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            BASE64_STANDARD.encode(bytes)
        )
    }

    fn at(name: &str, contents: Option<&str>) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pstrustguard-{}", std::process::id()));

        std::fs::create_dir_all(&dir).unwrap();

        let p = dir.join(name);

        match contents {
            Some(c) => std::fs::write(&p, c).unwrap(),
            None => {
                let _ = std::fs::remove_file(&p);
            }
        }
        p
    }

    #[test]
    fn reads_every_block_in_a_file() {
        let pem = format!(
            "{}{}",
            block("PUBLIC KEY", b"one"),
            block("PUBLIC KEY", b"two")
        );

        assert_eq!(
            pem_block_ders(&pem, "PUBLIC KEY"),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
        assert!(pem_block_ders(&pem, "CERTIFICATE").is_empty());
    }

    #[test]
    fn nothing_cached_is_never_a_loss() {
        let p = at("absent.pub", None);

        assert!(ensure_no_loss(&p, "PUBLIC KEY", &block("PUBLIC KEY", b"new")).is_ok());
    }

    #[test]
    fn refetching_the_same_root_is_fine() {
        let same = block("PUBLIC KEY", b"current");
        let p = at("same.pub", Some(&same));

        assert!(ensure_no_loss(&p, "PUBLIC KEY", &same).is_ok());
    }

    #[test]
    fn line_endings_and_wrapping_are_not_a_difference() {
        let p = at(
            "crlf.pub",
            Some(&block("PUBLIC KEY", b"current").replace('\n', "\r\n")),
        );

        assert!(ensure_no_loss(&p, "PUBLIC KEY", &block("PUBLIC KEY", b"current")).is_ok());
    }

    #[test]
    fn upstream_serving_more_than_we_have_is_fine() {
        let p = at("subset.pub", Some(&block("PUBLIC KEY", b"current")));
        let fetched = format!(
            "{}{}",
            block("PUBLIC KEY", b"rotated"),
            block("PUBLIC KEY", b"current")
        );

        assert!(ensure_no_loss(&p, "PUBLIC KEY", &fetched).is_ok());
    }

    // The case the guard exists for: rekor.pub was appended to during a
    // rotation, and a later `trust fetch` would drop the retired key.
    #[test]
    fn dropping_an_appended_key_is_refused() {
        let appended = format!(
            "{}{}",
            block("PUBLIC KEY", b"rotated"),
            block("PUBLIC KEY", b"retired")
        );
        let p = at("appended.pub", Some(&appended));
        let err = ensure_no_loss(&p, "PUBLIC KEY", &block("PUBLIC KEY", b"rotated")).unwrap_err();

        assert!(err.contains("refusing to overwrite"), "{err}");
        assert!(err.contains("1 entry(s)"), "{err}");
        assert!(err.contains("--force"), "{err}");
        assert!(err.contains("appended.pub >>"), "{err}");
    }

    #[test]
    fn a_wholly_different_root_is_refused_too() {
        let p = at("replaced.pem", Some(&block("CERTIFICATE", b"ours")));
        let err = ensure_no_loss(&p, "CERTIFICATE", &block("CERTIFICATE", b"theirs")).unwrap_err();

        assert!(err.contains("refusing to overwrite"), "{err}");
    }
}
