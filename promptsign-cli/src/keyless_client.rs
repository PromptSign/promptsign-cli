// Keyless signing client (spec/05-keyless.md §6) and trust-root management.
// This module is the ONLY place in the workspace that touches the network:
// verification (promptsign-core) is offline by construction.

use base64::prelude::{Engine as _, BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{Signer, SigningKey};
use promptsign_core::bundle::{pae, BUNDLE_SCHEMA};
use promptsign_core::keyless::{
    chain_leaf_info, pem_chain_to_b64_der, trust_dir, trusted_log_id, trusted_log_ids,
};
use promptsign_core::revocation::{
    feed_path, load_cached_feed, verify_feed, RevocationEntry, RevocationFeed,
    REVOCATION_PAYLOAD_TYPE, REVOCATION_SCHEMA,
};
use promptsign_core::util::{hex, iso8601_now};
use promptsign_core::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub const DEFAULT_FULCIO: &str = "https://fulcio.sigstore.dev";
pub const DEFAULT_REKOR: &str = "https://rekor.sigstore.dev";

pub(crate) fn env_url(var: &str, default: &str) -> String {
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => v.trim_end_matches('/').to_string(),
        _ => default.to_string(),
    }
}

pub(crate) fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("promptsign/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// A GET of at most 4 MiB, for documents such as trust bundles.
pub(crate) fn http_get(url: &str) -> Result<Vec<u8>> {
    let resp = agent().get(url).call().map_err(|e| http_err(url, e))?;
    let mut body = Vec::new();

    std::io::Read::read_to_end(
        &mut std::io::Read::take(resp.into_reader(), 4 << 20),
        &mut body,
    )
    .map_err(|e| format!("{url}: {e}"))?;
    Ok(body)
}

pub(crate) fn http_err(context: &str, e: ureq::Error) -> String {
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

/// The per-signature key. Rekor v2 accepts only signatures over a prehash, so
/// a signature bound for a v2 log uses ECDSA P-256; otherwise Ed25519.
enum EphemeralKey {
    Ed25519(SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl EphemeralKey {
    fn generate(p256: bool) -> Result<EphemeralKey> {
        let mut secret = [0u8; 32];

        loop {
            getrandom::getrandom(&mut secret).map_err(|e| format!("rng failure: {e}"))?;
            if !p256 {
                return Ok(EphemeralKey::Ed25519(SigningKey::from_bytes(&secret)));
            }
            // Fails only for zero or a value past the group order, which 32
            // random bytes hit with negligible probability.
            if let Ok(k) = p256::ecdsa::SigningKey::from_slice(&secret) {
                return Ok(EphemeralKey::P256(k));
            }
        }
    }

    /// Fulcio's name for the key algorithm.
    fn algorithm(&self) -> &'static str {
        match self {
            EphemeralKey::Ed25519(_) => "ED25519",
            EphemeralKey::P256(_) => "ECDSA",
        }
    }

    fn public_pem(&self) -> Result<String> {
        match self {
            EphemeralKey::Ed25519(k) => k.verifying_key().to_public_key_pem(LineEnding::LF),
            EphemeralKey::P256(k) => k.verifying_key().to_public_key_pem(LineEnding::LF),
        }
        .map_err(|e| format!("public key encoding failed: {e}"))
    }

    /// Ed25519 raw, or ECDSA over SHA-256 of `message`, DER-encoded.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            EphemeralKey::Ed25519(k) => k.sign(message).to_bytes().to_vec(),
            EphemeralKey::P256(k) => {
                let sig: p256::ecdsa::DerSignature = k.sign(message);

                sig.as_bytes().to_vec()
            }
        }
    }
}

/// Ephemeral key → Fulcio cert → sign → timestamps → log entry →
/// self-contained bundle. The key never leaves this function and is dropped
/// on return. `payload_type` is the DSSE payloadType (manifest for `sign`,
/// revocation for a feed). Endpoints come from the signing config.
pub fn keyless_sign(
    payload: &[u8],
    payload_type: &str,
    token_flag: Option<&str>,
) -> Result<KeylessOutcome> {
    let endpoints = crate::signing_config::resolve()?;
    let token = resolve_token(token_flag)?;
    // Fulcio checks the proof-of-possession against the identity it will
    // certify: the `email` claim for email-based tokens (Dex / Google logins),
    // the `sub` claim otherwise (e.g. CI workflow tokens). Mirrors sigstore's
    // SubjectFromToken.
    let subject = jwt_claim(&token, "email").or_else(|_| jwt_claim(&token, "sub"))?;
    let key = EphemeralKey::generate(endpoints.rekor_version == 2)?;
    // Proof of possession: Fulcio requires a signature over the token's
    // subject so a stolen bare token cannot be bound to an attacker's key.
    let pop = BASE64_STANDARD.encode(key.sign(subject.as_bytes()));
    let resp: Value = agent()
        .post(&format!("{}/api/v2/signingCert", endpoints.fulcio))
        .send_json(json!({
            "credentials": { "oidcIdentityToken": token },
            "publicKeyRequest": {
                "publicKey": { "algorithm": key.algorithm(), "content": key.public_pem()? },
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

    let artifact = pae(payload_type, payload);
    let sig = key.sign(&artifact);
    let sig_b64 = BASE64_STANDARD.encode(&sig);
    let payload_b64 = BASE64_STANDARD.encode(payload);

    // Timestamps first: a timestamp authority that fails leaves nothing in
    // the log.
    let timestamps = endpoints
        .tsas
        .iter()
        .map(|url| request_timestamp(url, &sig).map(|t| BASE64_STANDARD.encode(t)))
        .collect::<Result<Vec<_>>>()?;
    let (transparency, log_index) = if endpoints.rekor_version == 2 {
        let leaf_der = BASE64_STANDARD
            .decode(&chain_b64[0])
            .map_err(|_| "invalid base64 in certChain")?;

        log_v2(&endpoints.rekor, &artifact, &sig, &leaf_der)?
    } else {
        log_v1(
            &endpoints.rekor,
            payload_type,
            &payload_b64,
            &sig_b64,
            &leaf_pem,
        )?
    };

    let mut bundle = json!({
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

    if !timestamps.is_empty() {
        bundle["timestamps"] = json!(timestamps);
    }

    Ok(KeylessOutcome {
        bundle,
        identity,
        issuer,
        log_index,
    })
}

/// A Rekor v1 `dsse` entry, and the transparency block with its signed entry
/// timestamp (spec/05 §3.1).
fn log_v1(
    rekor: &str,
    payload_type: &str,
    payload_b64: &str,
    sig_b64: &str,
    leaf_pem: &str,
) -> Result<(Value, i64)> {
    // Rekor wants the standard DSSE JSON as a string, verifier = leaf cert.
    let dsse_envelope = serde_json::to_string(&json!({
        "payloadType": payload_type,
        "payload": payload_b64,
        "signatures": [ { "sig": sig_b64 } ]
    }))
    .unwrap();
    let resp: Value = agent()
        .post(&format!("{rekor}/api/v1/log/entries"))
        .send_json(json!({
            "apiVersion": "0.0.1",
            "kind": "dsse",
            // verifiers entries are strfmt.Base64 in Rekor's dsse schema: the
            // PEM itself goes in base64-encoded, not raw.
            "spec": { "proposedContent": { "envelope": dsse_envelope, "verifiers": [BASE64_STANDARD.encode(leaf_pem)] } }
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

    Ok((transparency, log_index))
}

/// A Rekor v2 `hashedrekord` 0.0.2 entry, and the transparency block with
/// its inclusion proof and checkpoint (spec/05 §3.2).
fn log_v2(rekor: &str, artifact: &[u8], sig: &[u8], leaf_der: &[u8]) -> Result<(Value, i64)> {
    let resp: Value = agent()
        .post(&format!("{rekor}/api/v2/log/entries"))
        .send_json(json!({
            "hashedRekordRequestV002": {
                "digest": BASE64_STANDARD.encode(Sha256::digest(artifact)),
                "signature": {
                    "content": BASE64_STANDARD.encode(sig),
                    "verifier": {
                        "x509Certificate": { "rawBytes": BASE64_STANDARD.encode(leaf_der) },
                        "keyDetails": "PKIX_ECDSA_P256_SHA_256"
                    }
                }
            }
        }))
        .map_err(|e| http_err("Rekor", e))?
        .into_json()
        .map_err(|e| format!("Rekor: {e}"))?;
    // A TransparencyLogEntry in protobuf JSON, where int64 fields are strings.
    let int = |v: &Value, what: &str| -> Result<i64> {
        v.as_i64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
            .ok_or_else(|| format!("Rekor: no {what} in response"))
    };
    let log_index = int(&resp["logIndex"], "logIndex")?;
    let key_id = BASE64_STANDARD
        .decode(
            resp["logId"]["keyId"]
                .as_str()
                .ok_or("Rekor: no logId in response")?,
        )
        .map_err(|_| "Rekor: invalid base64 in logId")?;
    let proof = &resp["inclusionProof"];
    let transparency = json!({
        "logId": hex(&key_id),
        "logIndex": log_index,
        "body": resp["canonicalizedBody"]
            .as_str()
            .ok_or("Rekor: no canonicalizedBody in response")?,
        "inclusionProof": {
            "treeSize": int(&proof["treeSize"], "inclusion proof treeSize")?,
            "rootHash": proof["rootHash"]
                .as_str()
                .ok_or("Rekor: no inclusion proof rootHash in response")?,
            "hashes": proof["hashes"].as_array().cloned().unwrap_or_default(),
            "checkpoint": proof["checkpoint"]["envelope"]
                .as_str()
                .ok_or("Rekor: no checkpoint in response")?
        }
    });

    Ok((transparency, log_index))
}

/// A DER TimeStampReq (RFC 3161 §2.4.1) for SHA-256 of `signature`, asking
/// for the authority's certificate in the token.
fn timestamp_request(signature: &[u8]) -> Vec<u8> {
    const SHA256_ALG: [u8; 15] = [
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    ];
    let mut req = vec![0x30, 0x39, 0x02, 0x01, 0x01, 0x30, 0x31];

    req.extend(SHA256_ALG);
    req.extend([0x04, 0x20]);
    req.extend(Sha256::digest(signature));
    req.extend([0x01, 0x01, 0xff]); // certReq TRUE
    req
}

/// The tag and contents of the DER TLV at the start of `buf`.
fn der_tlv(buf: &[u8]) -> Option<(u8, &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;

        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        (
            rest[..n]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | *b as usize),
            &rest[n..],
        )
    };

    Some((tag, rest.get(..len)?))
}

/// An RFC 3161 timestamp over `signature` from the authority at `url`, as the
/// DER TimeStampResp the bundle stores (spec/05 §3.3).
fn request_timestamp(url: &str, signature: &[u8]) -> Result<Vec<u8>> {
    let context = format!("timestamp authority {url}");
    let resp = agent()
        .post(url)
        .set("Content-Type", "application/timestamp-query")
        .send_bytes(&timestamp_request(signature))
        .map_err(|e| http_err(&context, e))?;
    let mut body = Vec::new();

    std::io::Read::read_to_end(
        &mut std::io::Read::take(resp.into_reader(), 1 << 20),
        &mut body,
    )
    .map_err(|e| format!("{context}: {e}"))?;

    // TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken },
    // and PKIStatusInfo opens with the status: 0 granted, 1 granted with
    // modifications, anything else a refusal.
    let status = der_tlv(&body)
        .filter(|(tag, _)| *tag == 0x30)
        .and_then(|(_, resp)| der_tlv(resp))
        .filter(|(tag, _)| *tag == 0x30)
        .and_then(|(_, info)| der_tlv(info))
        .filter(|(tag, v)| *tag == 0x02 && v.len() == 1)
        .map(|(_, v)| v[0])
        .ok_or_else(|| format!("{context}: response is not a TimeStampResp"))?;

    if status > 1 {
        return Err(format!("{context}: request refused (status {status})"));
    }
    Ok(body)
}

/// A keyless root to verify against: the built-in one or one the user added,
/// such as their organization's own Fulcio and Rekor (spec/07). Signing checks
/// this before any network call, since its self-check could not pass without.
pub fn require_keyless_root() -> Result<()> {
    if promptsign_core::trustroot::load_registry()?
        .iter()
        .any(|r| !r.is_ca_only())
    {
        return Ok(());
    }
    Err(format!(
        "no Sigstore trust root in {}: run \"promptsign trust fetch\" first",
        trust_dir().display()
    ))
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

/// One-time online step: cache the Fulcio CA chain and Rekor public key,
/// and the public trusted_root.json and signing config, so every later
/// keyless verification is offline.
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

    let documents = tuf_documents()?;
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

    // The TUF documents replace what is there without the check above.
    // Sigstore signs them with its root keys and keeps retired logs and CAs in
    // them with closed windows, so an entry that disappears is one Sigstore
    // removed on purpose, such as a revoked key.
    for (name, bytes) in documents {
        let path = dir.join(name);

        std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        println!("wrote {}", path.display());
    }
    println!("rekor log id: {}", trusted_log_id()?);
    Ok(())
}

/// The public trusted_root.json, which adds the Rekor v2 log and the
/// timestamp authority to the pinned pair, and the public signing config,
/// both from Sigstore's TUF repository. A private deployment named by
/// PROMPTSIGN_FULCIO_URL or PROMPTSIGN_REKOR_URL skips them unless
/// PROMPTSIGN_TUF_URL names its own repository.
fn tuf_documents() -> Result<Vec<(&'static str, Vec<u8>)>> {
    let set = |var: &str| std::env::var(var).is_ok_and(|v| !v.is_empty());

    if (set("PROMPTSIGN_FULCIO_URL") || set("PROMPTSIGN_REKOR_URL")) && !set("PROMPTSIGN_TUF_URL") {
        return Ok(Vec::new());
    }

    let mut targets = crate::tuf::Repo::from_env()?
        .fetch_targets(&["trusted_root.json", "signing_config.v0.2.json"])?
        .into_iter();
    let (Some(trusted_root), Some(signing_config)) = (targets.next(), targets.next()) else {
        return Err("TUF: missing target".into());
    };
    // Validated before anything is written, like the pair above.
    let doc: Value =
        serde_json::from_slice(&trusted_root).map_err(|e| format!("trusted_root.json: {e}"))?;

    promptsign_core::trustroot::Root::from_trusted_root(
        promptsign_core::trustroot::DEFAULT_ROOT,
        &doc,
    )
    .map_err(|e| format!("trusted_root.json: {e}"))?;

    let config: Value = serde_json::from_slice(&signing_config)
        .map_err(|e| format!("signing_config.v0.2.json: {e}"))?;

    crate::signing_config::select(&config, now())
        .map_err(|e| format!("signing_config.v0.2.json: {e}"))?;
    Ok(vec![
        ("trusted_root.json", trusted_root),
        (crate::signing_config::FILE, signing_config),
    ])
}

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

pub fn trust_show() -> Result<()> {
    let dir = trust_dir();

    println!("trust dir: {}", dir.display());
    // This lists every pinned log, not just the current one. After a rotation,
    // the retired keys are what keep older signatures verifying, so an operator
    // needs to see that they are still present.
    for (i, id) in trusted_log_ids()?.iter().enumerate() {
        if i == 0 {
            println!("rekor log id: {id}");
        } else {
            println!("  also trusted: {id}");
        }
    }
    Ok(())
}

// ---- Revocation feed (spec/06) ----

fn load_active_policy() -> Result<promptsign_core::policy::Policy> {
    // Revocation settings come from the user's policy only (spec/04).
    let (policy, _raw, _src) = promptsign_core::policy::load_policy(None)?;

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
    require_keyless_root()?;

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
