// End-to-end keyless flow against a mock Fulcio/Rekor on localhost:
// `promptsign sign` (keyless by default; real HTTP, real certs issued for the
// CLI's ephemeral key) followed by fully offline `promptsign verify`.

use base64::prelude::{Engine as _, BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::pkcs8::EncodePublicKey as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::{Ia5String, Utf8StringRef};
use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::der::{Decode, Encode, EncodePem, Length, Writer};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::AsExtension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

const IDENTITY: &str =
    "https://github.com/acme/skills/.github/workflows/release.yml@refs/heads/main";
const ISSUER: &str = "https://token.actions.githubusercontent.com";

struct IssuerExt(String);
impl AssociatedOid for IssuerExt {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.8");
}
impl Encode for IssuerExt {
    fn encoded_len(&self) -> x509_cert::der::Result<Length> {
        Utf8StringRef::new(&self.0)?.encoded_len()
    }
    fn encode(&self, w: &mut impl Writer) -> x509_cert::der::Result<()> {
        Utf8StringRef::new(&self.0)?.encode(w)
    }
}
impl AsExtension for IssuerExt {
    fn critical(&self, _: &Name, _: &[x509_cert::ext::Extension]) -> bool {
        false
    }
}

fn read_http_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end;

    loop {
        let n = stream.read(&mut tmp).unwrap();

        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = i + 4;
            break;
        }
    }

    let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let content_length: usize = headers
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let mut body = buf[header_end..].to_vec();

    while body.len() < content_length {
        let n = stream.read(&mut tmp).unwrap();

        body.extend_from_slice(&tmp[..n]);
    }
    (headers.lines().next().unwrap_or_default().to_string(), body)
}

fn respond_json(stream: &mut std::net::TcpStream, status: &str, body: &Value) {
    let payload = serde_json::to_vec(body).unwrap();
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );

    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(&payload).unwrap();
}

fn pem_spki_body(pem: &str) -> Vec<u8> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    BASE64_STANDARD.decode(b64).unwrap()
}

#[test]
fn keyless_sign_then_offline_verify() {
    let bin = env!("CARGO_BIN_EXE_promptsign");
    let work = std::env::temp_dir().join(format!("pske2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let home = work.join("home");
    let trust = work.join("trust");
    let skill = work.join("skill");

    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&trust).unwrap();
    std::fs::create_dir_all(skill.join("scripts")).unwrap();
    std::fs::write(skill.join("SKILL.md"), "# e2e-skill\nDoes things.\n").unwrap();
    std::fs::write(skill.join("scripts").join("run.py"), "print(1)\n").unwrap();

    // --- CA, Rekor key, trust dir ---
    let ca_key = p256::ecdsa::SigningKey::from_slice(&[51u8; 32]).unwrap();
    let ca_name = Name::from_str("CN=mock fulcio root").unwrap();
    let ca_spki = SubjectPublicKeyInfoOwned::from_der(
        ca_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let ca_cert: Certificate = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        Validity::from_now(Duration::from_secs(3600 * 24)).unwrap(),
        ca_name.clone(),
        ca_spki,
        &ca_key,
    )
    .unwrap()
    .build::<p256::ecdsa::DerSignature>()
    .unwrap();
    let ca_pem = ca_cert.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap();
    let rekor_key = p256::ecdsa::SigningKey::from_slice(&[52u8; 32]).unwrap();
    let log_id = {
        let der = rekor_key.verifying_key().to_public_key_der().unwrap();
        let mut s = String::new();

        for b in Sha256::digest(der.as_bytes()) {
            s.push_str(&format!("{b:02x}"));
        }
        s
    };

    std::fs::write(trust.join("fulcio.pem"), &ca_pem).unwrap();
    std::fs::write(
        trust.join("rekor.pub"),
        rekor_key
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap(),
    )
    .unwrap();

    // --- mock Fulcio + Rekor on one listener ---
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let ca_key2 = ca_key.clone();
    let ca_name2 = ca_name.clone();
    let ca_pem2 = ca_pem.clone();
    let log_id2 = log_id.clone();
    // The mock also serves whatever `revoke sign` has most recently written, at
    // /feed, so `revoke fetch` exercises the real HTTP + verify-before-persist path.
    let feed_file2 = work.join("feed.json");

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let (request_line, body) = read_http_request(&mut stream);
            let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            if request_line.contains("/api/v2/signingCert") {
                let pem = req["publicKeyRequest"]["publicKey"]["content"]
                    .as_str()
                    .unwrap();
                let leaf_spki = SubjectPublicKeyInfoOwned::from_der(&pem_spki_body(pem)).unwrap();
                let mut b = CertificateBuilder::new(
                    Profile::Leaf {
                        issuer: ca_name2.clone(),
                        enable_key_agreement: false,
                        enable_key_encipherment: false,
                    },
                    SerialNumber::from(7u32),
                    Validity::from_now(Duration::from_secs(600)).unwrap(),
                    Name::from_str("CN=mock-leaf").unwrap(),
                    leaf_spki,
                    &ca_key2,
                )
                .unwrap();
                b.add_extension(&SubjectAltName(vec![
                    GeneralName::UniformResourceIdentifier(Ia5String::new(IDENTITY).unwrap()),
                ]))
                .unwrap();
                b.add_extension(&IssuerExt(ISSUER.to_string())).unwrap();
                let leaf: Certificate = b.build::<p256::ecdsa::DerSignature>().unwrap();
                let leaf_pem = leaf.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap();
                respond_json(
                    &mut stream,
                    "200 OK",
                    &json!({ "signedCertificateEmbeddedSct": { "chain": { "certificates": [leaf_pem, ca_pem2] } } }),
                );
            } else if request_line.contains("/api/v1/log/entries") {
                // Like the real Rekor: verifiers are strfmt.Base64 (the PEM is
                // sent base64-encoded); a raw PEM must be rejected.
                let verifier_b64 = req["spec"]["proposedContent"]["verifiers"][0]
                    .as_str()
                    .unwrap();
                match BASE64_STANDARD.decode(verifier_b64) {
                    Ok(pem) if pem.starts_with(b"-----BEGIN CERTIFICATE-----") => {}
                    _ => {
                        respond_json(
                            &mut stream,
                            "400 Bad Request",
                            &json!({"code": 400, "message": "error processing entry: failed parsing base64 data for verifier"}),
                        );
                        continue;
                    }
                }
                let envelope: Value = serde_json::from_str(
                    req["spec"]["proposedContent"]["envelope"].as_str().unwrap(),
                )
                .unwrap();
                let payload = BASE64_STANDARD
                    .decode(envelope["payload"].as_str().unwrap())
                    .unwrap();
                let payload_hash = {
                    let mut s = String::new();
                    for b in Sha256::digest(&payload) {
                        s.push_str(&format!("{b:02x}"));
                    }
                    s
                };
                let entry_body = json!({
                    "apiVersion": "0.0.1",
                    "kind": "dsse",
                    "spec": {
                        "payloadHash": { "algorithm": "sha256", "value": payload_hash },
                        "signatures": [ {
                            "signature": envelope["signatures"][0]["sig"],
                            "verifier": req["spec"]["proposedContent"]["verifiers"][0]
                        } ]
                    }
                });
                let body_b64 = BASE64_STANDARD.encode(serde_json::to_vec(&entry_body).unwrap());
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                let canonical = format!(
                    "{{\"body\":{},\"integratedTime\":{t},\"logID\":{},\"logIndex\":77}}",
                    serde_json::to_string(&body_b64).unwrap(),
                    serde_json::to_string(&log_id2).unwrap()
                );
                let set: p256::ecdsa::Signature = rekor_key
                    .sign_prehash(&Sha256::digest(canonical.as_bytes()))
                    .unwrap();
                respond_json(
                    &mut stream,
                    "201 Created",
                    &json!({ "e2e-uuid": {
                        "body": body_b64,
                        "integratedTime": t,
                        "logID": log_id2,
                        "logIndex": 77,
                        "verification": { "signedEntryTimestamp": BASE64_STANDARD.encode(set.to_der()) }
                    } }),
                );
            } else if request_line.contains("/feed") {
                match std::fs::read(&feed_file2) {
                    Ok(bytes) => {
                        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                        respond_json(&mut stream, "200 OK", &v);
                    }
                    Err(_) => {
                        respond_json(&mut stream, "404 Not Found", &json!({"error": "no feed"}))
                    }
                }
            }
        }
    });

    // --- fake OIDC token (mock Fulcio does not validate it) ---
    let jwt = format!(
        "{}.{}.sig",
        BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
        BASE64_URL_SAFE_NO_PAD.encode(format!("{{\"sub\":\"{IDENTITY}\"}}").as_bytes())
    );

    let run = |args: &[&str], dir: &Path| {
        Command::new(bin)
            .args(args)
            .current_dir(dir)
            .env("PROMPTSIGN_HOME", &home)
            .env("PROMPTSIGN_TRUST_DIR", &trust)
            .env("PROMPTSIGN_FULCIO_URL", format!("http://127.0.0.1:{port}"))
            .env("PROMPTSIGN_REKOR_URL", format!("http://127.0.0.1:{port}"))
            .output()
            .unwrap()
    };

    // keyless sign is the default — no flag (includes offline self-verification)
    let skill_str = skill.to_string_lossy().to_string();
    let out = run(
        &[
            "sign",
            &skill_str,
            "--identity-token",
            &jwt,
            "--name",
            "acme/e2e",
            "--version",
            "1.0.0",
        ],
        &work,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        out.status.success(),
        "keyless sign failed: {stdout} {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains(&format!("as {IDENTITY} via {ISSUER}")),
        "{stdout}"
    );
    assert!(stdout.contains("transparency log index: 77"), "{stdout}");

    // offline verify: pass + TOFU pin on identity+issuer
    let out = run(&["verify", &skill_str], &work);
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(out.status.success(), "verify failed: {stdout}");
    assert!(
        stdout.contains(&format!("signed by {IDENTITY} via {ISSUER}")),
        "{stdout}"
    );

    let pins = std::fs::read_to_string(home.join("pins.json")).unwrap();

    assert!(pins.contains(ISSUER), "pin should record issuer: {pins}");

    // tamper -> block
    std::fs::write(skill.join("scripts").join("run.py"), "print(2)\n").unwrap();

    let out = run(&["verify", &skill_str], &work);

    assert_eq!(
        out.status.code(),
        Some(2),
        "tampered keyless bundle must fail"
    );
    std::fs::write(skill.join("scripts").join("run.py"), "print(1)\n").unwrap();

    // --- Revocation feed (spec/06): publish -> fetch -> revoked verify fails ---
    let entries_path = work.join("entries.json").to_string_lossy().to_string();
    let feed_out = work.join("feed.json").to_string_lossy().to_string();
    let feed_url = format!("http://127.0.0.1:{port}/feed");
    let rev_policy = |on_stale: &str| {
        json!({
            "schema": "promptsign/policy/v1",
            "default": "warn",
            "rules": [ { "pattern": "*", "action": "warn", "tofu": true } ],
            "revocation_feed": feed_url,
            "revocation_feed_identity": IDENTITY,
            "revocation_feed_issuer": ISSUER,
            "max_feed_staleness": "72h",
            "on_feed_stale": on_stale
        })
        .to_string()
    };

    // Publish a feed revoking this identity, then cache it via the real HTTP path.
    std::fs::write(
        &entries_path,
        json!([{ "type": "identity", "identity": IDENTITY, "issuer": ISSUER, "reason": "test-revoke" }]).to_string(),
    )
    .unwrap();

    let out = run(
        &[
            "revoke",
            "sign",
            &entries_path,
            "--out",
            &feed_out,
            "--identity-token",
            &jwt,
        ],
        &work,
    );

    assert!(
        out.status.success(),
        "revoke sign failed: {} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::write(home.join("policy.json"), rev_policy("warn")).unwrap();

    let out = run(&["revoke", "fetch"], &work);

    assert!(
        out.status.success(),
        "revoke fetch failed: {} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The signing identity is now revoked -> verify blocks.
    let out = run(&["verify", &skill_str], &work);

    assert_eq!(
        out.status.code(),
        Some(2),
        "revoked identity must fail verify"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("revoked"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Republish a feed that does NOT name this artifact -> verify passes again.
    std::fs::write(
        &entries_path,
        json!([{ "type": "digest", "payloadDigest": "sha256:deadbeef", "reason": "unrelated" }])
            .to_string(),
    )
    .unwrap();

    let out = run(
        &[
            "revoke",
            "sign",
            &entries_path,
            "--out",
            &feed_out,
            "--identity-token",
            &jwt,
        ],
        &work,
    );

    assert!(
        out.status.success(),
        "revoke sign (2) failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run(&["revoke", "fetch"], &work);

    assert!(
        out.status.success(),
        "revoke fetch (2) failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run(&["verify", &skill_str], &work);

    assert!(
        out.status.success(),
        "non-revoking feed should verify: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Missing cache with on_feed_stale=fail -> verify blocks (freshness required).
    std::fs::remove_file(home.join("revocation.json")).ok();
    std::fs::write(home.join("policy.json"), rev_policy("fail")).unwrap();

    let out = run(&["verify", &skill_str], &work);

    assert_eq!(
        out.status.code(),
        Some(2),
        "missing feed with on_feed_stale=fail must block"
    );
    std::fs::remove_file(home.join("policy.json")).ok();

    // issuer policy rule: wrong issuer glob -> enforce fail
    std::fs::write(
        home.join("policy.json"),
        json!({
            "schema": "promptsign/policy/v1",
            "default": "warn",
            "rules": [ { "pattern": "acme/*", "identity": "*", "issuer": "https://accounts.google.com", "action": "enforce" } ]
        })
        .to_string(),
    )
    .unwrap();

    let out = run(&["verify", &skill_str], &work);

    assert_eq!(out.status.code(), Some(2), "issuer rule mismatch must fail");

    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(stdout.contains("issuer"), "{stdout}");

    let _ = std::fs::remove_dir_all(&work);
}
