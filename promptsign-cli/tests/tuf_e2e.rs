// `trust fetch` through a TUF repository over real HTTP: the root rotates,
// the public trusted_root.json and signing config land in the trust
// directory, and the client refuses a tampered target, a root its
// predecessor did not sign, an expired timestamp and a rolled-back timestamp.

mod common;

use common::v2::{publish, root, sign_metadata, signing_config, TufKey};
use common::Deployment;
use std::path::PathBuf;
use std::process::Output;

const SIGNER: &str =
    "https://github.com/acme/skills/.github/workflows/release.yml@refs/tags/v1.0.0";
const FAR: &str = "2099-01-01T00:00:00Z";

struct Repo {
    work: PathBuf,
    deployment: Deployment,
    tuf: PathBuf,
    trust: PathBuf,
    trusted_root: Vec<u8>,
    signing_config: Vec<u8>,
}

/// A repository whose root rotates from key 1 to key 2, with version 1 of
/// the targets published under key 2.
fn repo(name: &str, seed: u8, second_root_signers: &[&TufKey]) -> Repo {
    let work = std::env::temp_dir().join(format!("ps-tuf-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let deployment = Deployment::start(seed, SIGNER, &work.join("files"));
    let tuf = work.join("files").join("tuf");
    let (k1, k2) = (TufKey::new(1), TufKey::new(2));
    let trusted_root = serde_json::to_vec_pretty(&deployment.trusted_root()).unwrap();
    let signing_config = serde_json::to_vec_pretty(&signing_config(
        &deployment.url(),
        &deployment.url(),
        1,
        None,
    ))
    .unwrap();

    std::fs::create_dir_all(&tuf).unwrap();
    std::fs::write(
        work.join("initial-root.json"),
        sign_metadata(root(1, &k1, FAR), &[&k1]),
    )
    .unwrap();
    std::fs::write(
        tuf.join("2.root.json"),
        sign_metadata(root(2, &k2, FAR), second_root_signers),
    )
    .unwrap();
    publish(
        &tuf,
        &k2,
        1,
        FAR,
        &[
            ("trusted_root.json", &trusted_root),
            ("signing_config.v0.2.json", &signing_config),
        ],
    );

    Repo {
        trust: work.join("trust"),
        work,
        deployment,
        tuf,
        trusted_root,
        signing_config,
    }
}

impl Repo {
    fn fetch(&self) -> Output {
        std::process::Command::new(env!("CARGO_BIN_EXE_promptsign"))
            .args(["trust", "fetch"])
            .current_dir(&self.work)
            .env("PROMPTSIGN_HOME", self.work.join("home"))
            .env("PROMPTSIGN_TRUST_DIR", &self.trust)
            .env("PROMPTSIGN_FULCIO_URL", self.deployment.url())
            .env("PROMPTSIGN_REKOR_URL", self.deployment.url())
            .env(
                "PROMPTSIGN_TUF_URL",
                format!("{}/files/tuf", self.deployment.url()),
            )
            .env("PROMPTSIGN_TUF_ROOT", self.work.join("initial-root.json"))
            .output()
            .unwrap()
    }

    fn cache(&self) -> PathBuf {
        self.trust
            .join("tuf")
            .join(format!("127.0.0.1_{}_files_tuf", self.deployment.port))
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn fetch_follows_a_root_rotation_and_refuses_a_rollback() {
    let (k1, k2) = (TufKey::new(1), TufKey::new(2));
    let r = repo("ok", 101, &[&k1, &k2]);
    let out = r.fetch();

    assert!(out.status.success(), "fetch: {}", text(&out));
    assert!(text(&out).contains("trusted_root.json"), "{}", text(&out));
    assert_eq!(
        std::fs::read(r.trust.join("trusted_root.json")).unwrap(),
        r.trusted_root
    );
    assert_eq!(
        std::fs::read(r.trust.join("signing_config.json")).unwrap(),
        r.signing_config
    );
    assert!(r.trust.join("fulcio.pem").exists());

    let cached: serde_json::Value =
        serde_json::from_slice(&std::fs::read(r.cache().join("root.json")).unwrap()).unwrap();

    assert_eq!(cached["signed"]["version"], 2);

    // Version 2 of the targets, then the version 1 timestamp served again.
    let old_timestamp = std::fs::read(r.tuf.join("timestamp.json")).unwrap();

    publish(
        &r.tuf,
        &k2,
        2,
        FAR,
        &[
            ("trusted_root.json", &r.trusted_root),
            ("signing_config.v0.2.json", &r.signing_config),
        ],
    );
    assert!(r.fetch().status.success());
    std::fs::write(r.tuf.join("timestamp.json"), old_timestamp).unwrap();

    let out = r.fetch();

    assert!(!out.status.success());
    assert!(
        text(&out).contains("timestamp.json: version is older than the one already seen"),
        "{}",
        text(&out)
    );
}

#[test]
fn a_tampered_target_is_refused_and_nothing_is_written() {
    let (k1, k2) = (TufKey::new(1), TufKey::new(2));
    let r = repo("tampered", 102, &[&k1, &k2]);
    let served = std::fs::read_dir(r.tuf.join("targets"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.to_string_lossy().ends_with(".trusted_root.json"))
        .unwrap();
    let mut bytes = std::fs::read(&served).unwrap();
    let last = bytes.len() - 2;

    bytes[last] ^= 1; // same length, different content
    std::fs::write(&served, bytes).unwrap();

    let out = r.fetch();

    assert!(!out.status.success());
    assert!(
        text(&out).contains("trusted_root.json: sha256 hash does not match"),
        "{}",
        text(&out)
    );
    assert!(!r.trust.join("trusted_root.json").exists());
    assert!(!r.trust.join("fulcio.pem").exists(), "all or nothing");
}

#[test]
fn a_root_its_predecessor_did_not_sign_is_refused() {
    let k2 = TufKey::new(2);
    let r = repo("unsigned-root", 103, &[&k2]);
    let out = r.fetch();

    assert!(!out.status.success());
    assert!(
        text(&out).contains("2.root.json: 0 of the 1 required signatures verify"),
        "{}",
        text(&out)
    );
}

#[test]
fn an_expired_timestamp_is_refused() {
    let (k1, k2) = (TufKey::new(1), TufKey::new(2));
    let r = repo("expired", 104, &[&k1, &k2]);

    publish(
        &r.tuf,
        &k2,
        1,
        "2020-01-01T00:00:00Z",
        &[("trusted_root.json", &r.trusted_root)],
    );

    let out = r.fetch();

    assert!(!out.status.success());
    assert!(
        text(&out).contains("timestamp.json expired at 2020-01-01T00:00:00Z"),
        "{}",
        text(&out)
    );
}
