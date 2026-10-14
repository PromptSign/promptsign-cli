// A revocation feed named by a trust bundle (spec/06 §3, spec/07 §5.1), over
// real HTTP: an organization's bundle points at its feed, which a developer
// signs through the organization's own Fulcio and Rekor. A user whose policy
// says `revocation_feed: "trust-bundle:acme"` fetches it and sees a revoked
// artifact fail.

mod common;

use common::{rfc3339, token, Deployment, GH};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PUBLISH: &str = "https://github.com/acme/trust/.github/workflows/publish.yml@refs/heads/main";
const DEVELOPER: &str =
    "https://github.com/acme/skills/.github/workflows/release.yml@refs/heads/main";

struct Env {
    home: PathBuf,
    trust: PathBuf,
    fulcio: String,
}

fn run(env: &Env, args: &[&str], dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_promptsign"))
        .args(args)
        .current_dir(dir)
        .env("PROMPTSIGN_HOME", &env.home)
        .env("PROMPTSIGN_TRUST_DIR", &env.trust)
        .env("PROMPTSIGN_FULCIO_URL", &env.fulcio)
        .env("PROMPTSIGN_REKOR_URL", &env.fulcio)
        .env_remove("PROMPTSIGN_POLICY")
        .env_remove("PROMPTSIGN_REVOCATION_FILE")
        .output()
        .unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_trust_bundle_feed_revokes_an_artifact_signed_through_the_organization() {
    let work = std::env::temp_dir().join(format!("ps-revoke-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let public = Deployment::start(62, PUBLISH, &work.join("public-files"));
    let org = Deployment::start(72, DEVELOPER, &work.join("org-files"));
    let user = Env {
        home: work.join("home"),
        trust: public.trust_dir(&work.join("trust-public")),
        fulcio: public.url(),
    };
    let developer = Env {
        home: work.join("dev-home"),
        trust: org.trust_dir(&work.join("trust-org")),
        fulcio: org.url(),
    };
    let publisher = Env {
        home: work.join("pub-home"),
        trust: user.trust.clone(),
        fulcio: public.url(),
    };

    for d in [&user.home, &developer.home, &publisher.home] {
        std::fs::create_dir_all(d).unwrap();
    }

    // --- the organization publishes a bundle that names its feed ---
    let feed_url = format!("{}/files/revocation.json", public.url());
    let published = public.files.join("trust-bundle.json");

    std::fs::write(
        &published,
        serde_json::to_vec_pretty(&json!({
            "schema": "promptsign/trust-bundle/v1",
            "name": "acme",
            "version": 1,
            "issued": rfc3339(-3600),
            "expires": rfc3339(86400),
            "roots": { "prod": org.trusted_root() },
            "signers": [{ "identity": PUBLISH, "issuer": GH, "root": "sigstore-public" }],
            "revocationFeed": { "url": feed_url, "identity": DEVELOPER, "issuer": GH, "root": "prod" },
        }))
        .unwrap(),
    )
    .unwrap();

    let out = run(
        &publisher,
        &[
            "sign",
            published.to_str().unwrap(),
            "--identity-token",
            &token(PUBLISH),
        ],
        &work,
    );

    assert!(out.status.success(), "publish: {}", text(&out));

    // --- a developer signs an artifact, then revokes their own identity ---
    let notes = work.join("notes.txt");

    std::fs::write(&notes, "org-signed notes\n").unwrap();

    let out = run(
        &developer,
        &[
            "sign",
            notes.to_str().unwrap(),
            "--identity-token",
            &token(DEVELOPER),
        ],
        &work,
    );

    assert!(out.status.success(), "developer sign: {}", text(&out));

    let entries = work.join("entries.json");

    std::fs::write(
        &entries,
        json!([{ "type": "identity", "identity": DEVELOPER, "reason": "key compromise" }])
            .to_string(),
    )
    .unwrap();

    let out = run(
        &developer,
        &[
            "revoke",
            "sign",
            entries.to_str().unwrap(),
            "--out",
            public.files.join("revocation.json").to_str().unwrap(),
            "--identity-token",
            &token(DEVELOPER),
        ],
        &work,
    );

    assert!(out.status.success(), "revoke sign: {}", text(&out));

    // --- the user installs the bundle and points the policy at its feed ---
    let bundle_url = format!("{}/files/trust-bundle.json", public.url());
    let out = run(
        &user,
        &[
            "trust",
            "add",
            "acme",
            &bundle_url,
            "--signer",
            PUBLISH,
            "--yes",
        ],
        &work,
    );

    assert!(out.status.success(), "trust add: {}", text(&out));

    let notes_arg = notes.to_str().unwrap();
    let out = run(&user, &["verify", notes_arg, "--no-pin-updates"], &work);

    assert!(out.status.success(), "verify before: {}", text(&out));

    std::fs::write(
        user.home.join("policy.json"),
        json!({
            "schema": "promptsign/policy/v1",
            "default": "warn",
            "rules": [],
            "revocation_feed": "trust-bundle:acme",
            "on_feed_stale": "fail"
        })
        .to_string(),
    )
    .unwrap();

    let out = run(&user, &["verify", notes_arg, "--no-pin-updates"], &work);

    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(
        text(&out).contains("revocation feed not cached"),
        "{}",
        text(&out)
    );

    let out = run(&user, &["revoke", "fetch"], &work);

    assert!(out.status.success(), "revoke fetch: {}", text(&out));

    let out = run(&user, &["verify", notes_arg, "--no-pin-updates"], &work);

    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(text(&out).contains(": key compromise"), "{}", text(&out));

    // A policy that pins another root refuses the cached feed.
    std::fs::write(
        user.home.join("policy.json"),
        json!({
            "schema": "promptsign/policy/v1",
            "default": "warn",
            "rules": [],
            "revocation_feed": "trust-bundle:acme",
            "revocation_feed_trust_root": "sigstore-public",
        })
        .to_string(),
    )
    .unwrap();

    let out = run(&user, &["verify", notes_arg, "--no-pin-updates"], &work);

    assert!(
        text(&out).contains("revocation feed not trusted: certificate chain does not terminate"),
        "{}",
        text(&out)
    );

    let _ = std::fs::remove_dir_all(&work);
}
