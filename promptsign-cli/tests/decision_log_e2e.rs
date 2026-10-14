// The decision log on the command line (spec/08): a managed policy turns it on
// for the hook, a user policy for its own directory, `--decision-log` for one
// command, and a project policy cannot turn it on. $PROMPTSIGN_MANAGED_DIR
// stands in for the platform directory, so these tests skip on a machine that
// has one.

use serde_json::Value;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const POLICY: &str = r#""schema":"promptsign/policy/v1","default":"warn","rules":[]"#;

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());

        if entry.path().is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), dest).unwrap();
        }
    }
}

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/oms/test-ca")
}

fn platform_dir_exists() -> bool {
    let dir = if cfg!(windows) {
        r"C:\ProgramData\PromptSign"
    } else if cfg!(target_os = "macos") {
        "/Library/Application Support/PromptSign"
    } else {
        "/etc/promptsign"
    };

    Path::new(dir).exists()
}

/// A home with the OMS test plugin installed the way Claude Code records it,
/// a managed directory that trusts its CA, and a fixed user name.
struct Env {
    base: PathBuf,
    home: PathBuf,
    managed: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Env {
        let base = std::env::temp_dir().join(format!("ps-dlog-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&base);

        let home = base.join("home");
        let plugins = home.join(".claude").join("plugins");
        let install = plugins.join("cache").join("demo").join("1.0.0");

        copy_dir(&fixtures().join("plugin"), &install);
        fs::copy(fixtures().join("plugin.sig"), install.join("model.sig")).unwrap();
        fs::write(
            plugins.join("installed_plugins.json"),
            serde_json::json!({
                "version": 2,
                "plugins": { "demo@mkt": [{ "installPath": install.to_string_lossy() }] }
            })
            .to_string(),
        )
        .unwrap();
        fs::create_dir_all(base.join("project")).unwrap();
        fs::create_dir_all(base.join("managed")).unwrap();

        let env = Env {
            managed: base.join("managed"),
            base,
            home,
        };
        let pem = fixtures().join("test-ca.pem");
        let added = env.run(
            &[
                "trust",
                "add",
                "test-ca",
                "--ca",
                pem.to_str().unwrap(),
                "--yes",
                "--managed",
            ],
            "",
        );

        assert!(added.status.success(), "{}", text(&added));
        env
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_promptsign"))
            .args(args)
            .current_dir(self.base.join("project"))
            .env("PROMPTSIGN_HOME", self.base.join("ps"))
            .env("PROMPTSIGN_MANAGED_DIR", &self.managed)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env("USER", "tester")
            .env("USERNAME", "tester")
            .env_remove("PROMPTSIGN_TRUST_DIR")
            .env_remove("PROMPTSIGN_POLICY")
            .env_remove("PROMPTSIGN_SKILL_ROOTS")
            .env_remove("PROMPTSIGN_STRICT")
            .env_remove("CLAUDE_PROJECT_DIR")
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn invoke(&self, skill: &str) -> Output {
        let event = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Skill",
            "tool_input": { "skill": skill },
            "cwd": self.base.join("project").to_string_lossy(),
        });

        self.run(&["hook"], &event.to_string())
    }

    fn managed_policy(&self, extra: &str) {
        fs::write(
            self.managed.join("managed-policy.json"),
            format!("{{{POLICY}{extra}}}"),
        )
        .unwrap();
    }

    fn plugin(&self) -> PathBuf {
        self.home
            .join(".claude")
            .join("plugins")
            .join("cache")
            .join("demo")
            .join("1.0.0")
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn records(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn a_managed_policy_logs_every_hook_decision() {
    if platform_dir_exists() {
        return;
    }

    let env = Env::new("managed");
    let log = env.managed.join("log").join("decisions-tester.jsonl");

    env.managed_policy(r#","decision_log":true,"strict":true"#);
    assert_eq!(env.invoke("demo:hello").status.code(), Some(0));
    assert_eq!(env.invoke("nobody:missing").status.code(), Some(2));

    let r = records(&log);

    assert_eq!(r.len(), 2, "{r:?}");
    assert_eq!(r[0]["schema"], "promptsign/decision-log/v1");
    assert_eq!(r[0]["user"], "tester");
    assert_eq!(r[0]["harness"], "claude");
    assert_eq!(r[0]["event"], "PreToolUse");
    assert_eq!(r[0]["format"], "oms");
    assert_eq!(r[0]["root"], "test-ca");
    assert_eq!(r[0]["result"], "pass");
    assert_eq!(r[0]["decision"], "allow");
    assert_eq!(r[0]["revocation"], "unchecked");
    assert_eq!(
        r[0]["rule"],
        serde_json::json!({ "layer": "managed", "pattern": "*", "action": "warn" })
    );
    assert!(r[0]["payload_digest"]
        .as_str()
        .is_some_and(|d| d.starts_with("sha256:")));
    assert!(r[0]["verifier"]
        .as_str()
        .is_some_and(|v| v.starts_with("promptsign-cli/")));

    assert_eq!(r[1]["name"], "nobody:missing");
    assert_eq!(r[1]["result"], "unresolved");
    assert_eq!(r[1]["decision"], "block");
    assert!(r[1].get("target").is_none());
}

#[test]
fn a_user_policy_logs_to_its_own_directory_and_a_project_one_cannot() {
    if platform_dir_exists() {
        return;
    }

    let env = Env::new("user");
    let log = env.base.join("ps/log/decisions-tester.jsonl");

    fs::create_dir_all(env.base.join("project/.promptsign")).unwrap();
    fs::write(
        env.base.join("project/.promptsign/policy.json"),
        format!(r#"{{{POLICY},"decision_log":true}}"#),
    )
    .unwrap();
    assert_eq!(env.invoke("demo:hello").status.code(), Some(0));
    assert!(!log.exists());
    assert!(!env.managed.join("log").exists());

    fs::create_dir_all(env.base.join("ps")).unwrap();
    fs::write(
        env.base.join("ps/policy.json"),
        format!(r#"{{{POLICY},"decision_log":true}}"#),
    )
    .unwrap();
    assert_eq!(env.invoke("demo:hello").status.code(), Some(0));

    let r = records(&log);

    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!(r[0]["result"], "pass");
    assert_eq!(r[0]["rule"]["layer"], "user");
}

#[test]
fn the_flag_logs_one_command_without_a_decision() {
    if platform_dir_exists() {
        return;
    }

    let env = Env::new("flag");
    let log = env.base.join("verify.jsonl");
    let plugin = env.plugin();
    let out = env.run(
        &[
            "verify",
            plugin.to_str().unwrap(),
            "--no-pin-updates",
            "--decision-log",
            log.to_str().unwrap(),
        ],
        "",
    );

    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    fs::write(plugin.join("extra.md"), "added after signing\n").unwrap();

    let out = env.run(
        &[
            "verify-tree",
            plugin.to_str().unwrap(),
            "--decision-log",
            log.to_str().unwrap(),
        ],
        "",
    );

    assert_eq!(out.status.code(), Some(2), "{}", text(&out));

    let r = records(&log);

    assert_eq!(r.len(), 2, "{r:?}");
    assert_eq!(r[0]["event"], "verify");
    assert_eq!(r[0]["result"], "pass");
    assert!(r[0].get("harness").is_none() && r[0].get("decision").is_none());
    assert_eq!(r[1]["event"], "verify-tree");
    assert_eq!(r[1]["result"], "fail");
    assert_eq!(r[1]["target"], plugin.to_string_lossy().as_ref());
    assert!(r[1]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["level"] == "error"));
}
