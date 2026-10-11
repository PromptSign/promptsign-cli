// Trust bundles end to end (spec/07 §5) over real HTTP: an organization
// publishes its root in a bundle signed with plain `promptsign sign`, a user
// installs it with `trust add <url>`, verifies an artifact signed through the
// organization's own Fulcio and Rekor, and `trust fetch` applies an update and
// refuses a rollback.

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

fn bundle(version: u64, org: &Deployment) -> Vec<u8> {
    serde_json::to_vec_pretty(&json!({
        "schema": "promptsign/trust-bundle/v1",
        "name": "acme",
        "version": version,
        "issued": rfc3339(-3600),
        "expires": rfc3339(86400),
        "roots": { "prod": org.trusted_root() },
        "signers": [{ "identity": PUBLISH, "issuer": GH, "root": "sigstore-public" }],
    }))
    .unwrap()
}

#[test]
fn install_verify_update_and_refuse_a_rollback() {
    let work = std::env::temp_dir().join(format!("ps-bundle-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let public = Deployment::start(61, PUBLISH, &work.join("public-files"));
    let org = Deployment::start(71, DEVELOPER, &work.join("org-files"));
    let user = Env {
        home: work.join("home"),
        trust: public.trust_dir(&work.join("trust-public")),
        fulcio: public.url(),
    };
    // The organization's developers sign through its own deployment, so their
    // signing self-check runs against its root.
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

    // --- the organization publishes v1 of its bundle ---
    let published = public.files.join("trust-bundle.json");
    let publish = |version: u64| {
        std::fs::write(&published, bundle(version, &org)).unwrap();

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

        assert!(
            out.status.success(),
            "publishing v{version}: {}",
            text(&out)
        );
    };

    publish(1);
    assert!(public.files.join("trust-bundle.json.psig.json").exists());

    // --- a developer signs an artifact through the organization's Fulcio ---
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

    let notes_arg = notes.to_str().unwrap();
    let out = run(&user, &["verify", notes_arg], &work);

    assert_eq!(
        out.status.code(),
        Some(2),
        "untrusted before the bundle: {}",
        text(&out)
    );

    // --- the user installs the bundle ---
    let url = format!("{}/files/trust-bundle.json", public.url());
    let out = run(&user, &["trust", "add", "acme", &url], &work);

    assert!(!out.status.success(), "installing needs confirmation");
    assert!(text(&out).contains("--yes"), "{}", text(&out));

    let out = run(
        &user,
        &[
            "trust",
            "add",
            "acme",
            &url,
            "--signer",
            "https://github.com/other/*",
            "--yes",
        ],
        &work,
    );

    assert!(
        !out.status.success(),
        "a --signer that does not match must refuse"
    );

    let out = run(
        &user,
        &[
            "trust",
            "add",
            "acme",
            &url,
            "--signer",
            "https://github.com/acme/*",
            "--yes",
        ],
        &work,
    );
    let shown = text(&out);

    assert!(out.status.success(), "{shown}");
    assert!(shown.contains("version 1"), "{shown}");
    assert!(shown.contains("acme/prod"), "{shown}");
    assert!(shown.contains(PUBLISH), "{shown}");

    let out = run(&user, &["verify", notes_arg], &work);

    assert!(
        out.status.success(),
        "trusted through the bundle: {}",
        text(&out)
    );
    assert!(text(&out).contains("root acme/prod"), "{}", text(&out));

    let listed = text(&run(&user, &["trust", "list"], &work));

    assert!(listed.contains("acme/prod"), "{listed}");
    assert!(listed.contains("bundle acme v1"), "{listed}");

    // --- an update is applied, a rollback refused ---
    publish(2);

    let out = run(&user, &["trust", "fetch", "acme"], &work);

    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("version 1 -> 2"), "{}", text(&out));

    publish(1);

    let out = run(&user, &["trust", "fetch", "acme"], &work);

    assert!(
        !out.status.success(),
        "a rollback must fail: {}",
        text(&out)
    );
    assert!(text(&out).contains("rollback"), "{}", text(&out));
    assert!(
        text(&run(&user, &["trust", "list"], &work)).contains("bundle acme v2"),
        "the installed version stays"
    );

    // --- removing the bundle removes its roots ---
    let out = run(&user, &["trust", "rm", "acme"], &work);

    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        run(&user, &["verify", notes_arg], &work).status.code(),
        Some(2)
    );

    let _ = std::fs::remove_dir_all(&work);
}

/// A developer who keeps the public root and adds the organization's own as a
/// named root signs through the organization's Fulcio: signing needs a keyless
/// root to self-check against, not the built-in one in particular.
#[test]
fn signing_through_an_organizations_fulcio_needs_only_its_named_root() {
    let work = std::env::temp_dir().join(format!("ps-org-sign-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let org = Deployment::start(81, DEVELOPER, &work.join("org-files"));
    let dev = Env {
        home: work.join("home"),
        trust: work.join("trust-empty"),
        fulcio: org.url(),
    };
    let root = work.join("trusted_root.json");
    let notes = work.join("notes.md");

    for d in [&dev.home, &dev.trust] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(&root, serde_json::to_vec(&org.trusted_root()).unwrap()).unwrap();
    std::fs::write(&notes, "# notes\n").unwrap();

    let sign = || {
        run(
            &dev,
            &[
                "sign",
                notes.to_str().unwrap(),
                "--identity-token",
                &token(DEVELOPER),
            ],
            &work,
        )
    };
    let refused = sign();

    assert!(!refused.status.success(), "{}", text(&refused));
    assert!(
        text(&refused).contains("no Sigstore trust root"),
        "{}",
        text(&refused)
    );

    let added = run(
        &dev,
        &[
            "trust",
            "add",
            "acme-prod",
            "--trusted-root",
            root.to_str().unwrap(),
            "--yes",
        ],
        &work,
    );

    assert!(added.status.success(), "{}", text(&added));

    let signed = sign();

    assert!(signed.status.success(), "{}", text(&signed));

    let verified = run(&dev, &["verify", notes.to_str().unwrap()], &work);

    assert!(verified.status.success(), "{}", text(&verified));
    assert!(
        text(&verified).contains("(root acme-prod)"),
        "{}",
        text(&verified)
    );
    let _ = std::fs::remove_dir_all(&work);
}
