// Keyless signing through a signing config (spec/05 §6) over real HTTP: a
// Rekor v2 entry with an RFC 3161 timestamp, Rekor v1 with one, the
// PROMPTSIGN_TSA_URL override, and the ways a v2 signature fails before a
// bundle is written.

mod common;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use common::v2::{signing_config, V2Services};
use common::{token, Deployment};
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output};

const SIGNER: &str =
    "https://github.com/acme/skills/.github/workflows/release.yml@refs/tags/v1.0.0";

struct Setup {
    work: PathBuf,
    fulcio: Deployment,
    v2: V2Services,
    trust: PathBuf,
    home: PathBuf,
}

/// A deployment whose trust directory holds the pinned pair and a
/// trusted_root.json with the v2 log, and the timestamp authority when
/// `tsa_in_root`.
fn setup(name: &str, seed: u8, tsa_in_root: bool) -> Setup {
    let work = std::env::temp_dir().join(format!("ps-v2-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let fulcio = Deployment::start(seed, SIGNER, &work.join("files"));
    let v2 = V2Services::start(seed);
    let trust = fulcio.trust_dir(&work.join("trust"));
    let home = work.join("home");
    let mut doc = fulcio.trusted_root();

    v2.add_to(&mut doc, tsa_in_root);
    std::fs::write(
        trust.join("trusted_root.json"),
        serde_json::to_vec_pretty(&doc).unwrap(),
    )
    .unwrap();
    std::fs::create_dir_all(&home).unwrap();

    Setup {
        work,
        fulcio,
        v2,
        trust,
        home,
    }
}

impl Setup {
    fn config(&self, rekor_version: u64, tsa: Option<&str>) -> String {
        let rekor = if rekor_version == 2 {
            self.v2.url()
        } else {
            self.fulcio.url()
        };

        serde_json::to_string_pretty(&signing_config(
            &self.fulcio.url(),
            &rekor,
            rekor_version,
            tsa,
        ))
        .unwrap()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_promptsign"));

        c.args(args)
            .current_dir(&self.work)
            .env("PROMPTSIGN_HOME", &self.home)
            .env("PROMPTSIGN_TRUST_DIR", &self.trust)
            .env_remove("PROMPTSIGN_FULCIO_URL")
            .env_remove("PROMPTSIGN_REKOR_URL")
            .env_remove("PROMPTSIGN_TSA_URL")
            .env_remove("PROMPTSIGN_SIGNING_CONFIG")
            .env_remove("PROMPTSIGN_POLICY");
        c
    }

    /// Sign a new file named `name`; the output, and the bundle if one was
    /// left behind.
    fn sign(&self, name: &str, env: &[(&str, String)]) -> (Output, Option<Value>) {
        let file = self.work.join(name);

        std::fs::write(&file, format!("{{\"name\":\"{name}\"}}\n")).unwrap();

        let out = self
            .command(&[
                "sign",
                file.to_str().unwrap(),
                "--identity-token",
                &token(SIGNER),
            ])
            .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
            .output()
            .unwrap();
        let bundle = std::fs::read(self.work.join(format!("{name}.psig.json")))
            .ok()
            .map(|b| serde_json::from_slice(&b).unwrap());

        (out, bundle)
    }

    fn verify(&self, name: &str) -> Output {
        let file = self.work.join(name);

        self.command(&["verify", file.to_str().unwrap()])
            .output()
            .unwrap()
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn envelope_sig(bundle: &Value) -> Vec<u8> {
    BASE64_STANDARD
        .decode(bundle["envelope"]["signatures"][0]["sig"].as_str().unwrap())
        .unwrap()
}

#[test]
fn rekor_v2_with_a_timestamp_from_the_trust_directory_config() {
    let s = setup("v2", 91, true);

    std::fs::write(
        s.trust.join("signing_config.json"),
        s.config(2, Some(&s.v2.tsa_url())),
    )
    .unwrap();

    let (out, bundle) = s.sign("a.json", &[]);

    assert!(out.status.success(), "sign: {}", text(&out));

    let bundle = bundle.unwrap();
    let t = &bundle["transparency"];

    assert!(t["signedEntryTimestamp"].is_null(), "{t}");
    assert!(t["inclusionProof"]["checkpoint"]
        .as_str()
        .unwrap()
        .starts_with(&s.v2.origin()));
    assert_eq!(t["inclusionProof"]["treeSize"], 3);
    assert_eq!(t["logIndex"], 2);
    assert_eq!(bundle["timestamps"].as_array().unwrap().len(), 1);

    // ECDSA P-256 for the v2 log: a DER signature, not 64 raw Ed25519 bytes.
    let sig = envelope_sig(&bundle);

    assert!(sig[0] == 0x30 && sig.len() != 64, "{sig:?}");

    let out = s.verify("a.json");

    assert!(out.status.success(), "verify: {}", text(&out));
    assert!(text(&out).contains(SIGNER), "{}", text(&out));

    // The log keeps growing: a second signature is entry 3 of 4.
    let (out, bundle) = s.sign("b.json", &[]);

    assert!(out.status.success(), "second sign: {}", text(&out));
    assert_eq!(
        bundle.unwrap()["transparency"]["inclusionProof"]["treeSize"],
        4
    );
}

#[test]
fn rekor_v1_with_a_timestamp_from_promptsign_signing_config() {
    let s = setup("v1", 92, true);
    let config = s.work.join("config.json");

    std::fs::write(&config, s.config(1, Some(&s.v2.tsa_url()))).unwrap();

    let (out, bundle) = s.sign(
        "a.json",
        &[("PROMPTSIGN_SIGNING_CONFIG", config.display().to_string())],
    );

    assert!(out.status.success(), "sign: {}", text(&out));

    let bundle = bundle.unwrap();

    assert!(bundle["transparency"]["signedEntryTimestamp"].is_string());
    assert!(bundle["transparency"]["inclusionProof"].is_null());
    assert_eq!(bundle["timestamps"].as_array().unwrap().len(), 1);
    assert_eq!(envelope_sig(&bundle).len(), 64, "Ed25519 for a v1 log");
    assert!(s.verify("a.json").status.success());
}

#[test]
fn env_endpoints_skip_the_trust_directory_config_and_take_a_tsa_override() {
    let s = setup("env", 93, true);

    // A v2 config in the trust directory describes the public instance, so
    // it must not apply once PROMPTSIGN_FULCIO_URL points elsewhere.
    std::fs::write(
        s.trust.join("signing_config.json"),
        s.config(2, Some(&s.v2.tsa_url())),
    )
    .unwrap();

    let endpoints = [
        ("PROMPTSIGN_FULCIO_URL", s.fulcio.url()),
        ("PROMPTSIGN_REKOR_URL", s.fulcio.url()),
    ];
    let (out, bundle) = s.sign("plain.json", &endpoints);

    assert!(out.status.success(), "sign: {}", text(&out));

    let bundle = bundle.unwrap();

    assert!(bundle["transparency"]["signedEntryTimestamp"].is_string());
    assert!(bundle.get("timestamps").is_none(), "{bundle}");

    let mut with_tsa = endpoints.to_vec();

    with_tsa.push(("PROMPTSIGN_TSA_URL", s.v2.tsa_url()));

    let (out, bundle) = s.sign("stamped.json", &with_tsa);

    assert!(out.status.success(), "sign with a TSA: {}", text(&out));
    assert_eq!(bundle.unwrap()["timestamps"].as_array().unwrap().len(), 1);
}

#[test]
fn a_v2_signature_fails_without_a_timestamp_the_root_accepts() {
    let s = setup("no-tsa", 94, false);
    let config = s.work.join("config.json");

    std::fs::write(&config, s.config(2, Some(&s.v2.tsa_url()))).unwrap();

    let (out, bundle) = s.sign(
        "a.json",
        &[("PROMPTSIGN_SIGNING_CONFIG", config.display().to_string())],
    );

    assert!(!out.status.success());
    assert!(
        text(&out).contains("no verified signing time"),
        "{}",
        text(&out)
    );
    assert!(bundle.is_none(), "the self-check removes the bundle");
}

#[test]
fn a_refusing_timestamp_authority_stops_the_signature() {
    let s = setup("refuse", 95, true);
    let config = s.work.join("config.json");
    let refuse = format!("{}/refuse", s.v2.url());

    std::fs::write(&config, s.config(2, Some(&refuse))).unwrap();

    let (out, bundle) = s.sign(
        "a.json",
        &[("PROMPTSIGN_SIGNING_CONFIG", config.display().to_string())],
    );

    assert!(!out.status.success());
    assert!(
        text(&out).contains(&format!(
            "timestamp authority {refuse}: request refused (status 2)"
        )),
        "{}",
        text(&out)
    );
    assert!(bundle.is_none());
}
