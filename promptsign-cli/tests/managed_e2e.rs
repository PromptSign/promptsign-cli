// The managed layer on the command line (spec/04 "Managed policy", spec/07
// §2.4): `trust add --managed`, `trust list`, `policy show`, and the hook's
// strict mode from a managed policy. $PROMPTSIGN_MANAGED_DIR stands in for the
// platform directory, so these tests skip on a machine that has one.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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
/// and an empty managed directory.
struct Env {
    base: PathBuf,
    home: PathBuf,
    managed: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Env {
        let base = std::env::temp_dir().join(format!("ps-managed-{}-{tag}", std::process::id()));
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

        Env {
            managed: base.join("managed"),
            base,
            home,
        }
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_promptsign"))
            .args(args)
            .current_dir(self.base.join("project"))
            .env("PROMPTSIGN_HOME", self.base.join("ps"))
            .env("PROMPTSIGN_MANAGED_DIR", &self.managed)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
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

    fn add_ca(&self, managed: bool) -> Output {
        let pem = fixtures().join("test-ca.pem");
        let mut args = vec![
            "trust",
            "add",
            "test-ca",
            "--ca",
            pem.to_str().unwrap(),
            "--yes",
        ];

        if managed {
            args.push("--managed");
        }
        self.run(&args, "")
    }

    fn managed_policy(&self, json: &str) {
        fs::write(self.managed.join("managed-policy.json"), json).unwrap();
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

#[test]
fn a_managed_root_verifies_for_every_user_and_cannot_be_shadowed() {
    if platform_dir_exists() {
        return;
    }

    let env = Env::new("root");
    let added = env.add_ca(true);

    assert!(added.status.success(), "{}", text(&added));
    assert!(env.managed.join("trust/roots/test-ca.json").exists());
    assert!(!env.base.join("ps/trust/roots").exists());

    let out = env.invoke("demo:hello");

    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    let list = text(&env.run(&["trust", "list"], ""));

    assert!(
        list.lines()
            .any(|l| l.starts_with("test-ca ") && l.ends_with("(managed)")),
        "{list}"
    );

    // A user root may not take the managed name.
    let clash = env.add_ca(false);

    assert_eq!(clash.status.code(), Some(1), "{}", text(&clash));
    assert!(
        text(&clash).contains("is the name of a managed trust root"),
        "{}",
        text(&clash)
    );

    // The registry ignores a hand-written user root of that name, and trust
    // list reports it.
    fs::create_dir_all(env.base.join("ps/trust/roots")).unwrap();
    fs::copy(
        env.managed.join("trust/roots/test-ca.json"),
        env.base.join("ps/trust/roots/test-ca.json"),
    )
    .unwrap();

    let list = text(&env.run(&["trust", "list"], ""));

    assert!(
        list.contains("trust root \"test-ca\" in ") && list.contains("ignored"),
        "{list}"
    );

    let removed = env.run(&["trust", "rm", "test-ca", "--managed"], "");

    assert!(removed.status.success(), "{}", text(&removed));
    assert!(!env.managed.join("trust/roots/test-ca.json").exists());
}

#[test]
fn user_roots_false_drops_the_users_own_roots() {
    if platform_dir_exists() {
        return;
    }

    let env = Env::new("user-roots");
    let added = env.add_ca(false);

    assert!(added.status.success(), "{}", text(&added));
    assert_eq!(env.invoke("demo:hello").status.code(), Some(0));

    env.managed_policy(
        r#"{"schema":"promptsign/policy/v1","default":"warn","rules":[],"user_roots":false}"#,
    );

    let out = env.invoke("demo:hello");

    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(
        text(&out).contains("signature did not verify"),
        "{}",
        text(&out)
    );
}

#[test]
fn a_managed_strict_policy_blocks_what_the_environment_would_allow() {
    if platform_dir_exists() {
        return;
    }

    let env = Env::new("strict");

    // Not strict: the hook lets through a skill it cannot resolve.
    assert_eq!(env.invoke("nobody:missing").status.code(), Some(0));

    env.managed_policy(
        r#"{"schema":"promptsign/policy/v1","default":"warn","rules":[],"strict":true}"#,
    );

    let out = env.invoke("nobody:missing");

    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
}

#[test]
fn policy_show_names_every_layer_and_the_settings_they_decide() {
    if platform_dir_exists() {
        return;
    }

    let env = Env::new("show");
    let show = text(&env.run(&["policy", "show"], ""));

    assert!(show.starts_with("# source: (built-in default)"), "{show}");
    assert!(show.ends_with("# strict: off\n"), "{show}");

    env.managed_policy(
        r#"{"schema":"promptsign/policy/v1","default":"enforce","rules":[],"lock_env":true,"strict":true}"#,
    );
    fs::create_dir_all(env.base.join("project/.promptsign")).unwrap();
    fs::write(
        env.base.join("project/.promptsign/policy.json"),
        r#"{"schema":"promptsign/policy/v1","default":"off","rules":[]}"#,
    )
    .unwrap();

    let show = text(&env.run(&["policy", "show"], ""));
    let headers: Vec<&str> = show.lines().filter(|l| l.starts_with("# ")).collect();

    assert!(headers[0].starts_with("# managed policy: "), "{show}");
    assert!(
        headers[1].starts_with("# project policy (tighten only): "),
        "{show}"
    );
    assert_eq!(
        &headers[2..],
        [
            "# user policy: none (the built-in default does not apply under a managed policy)",
            "# lock_env: on (PROMPTSIGN_POLICY, PROMPTSIGN_HOME, PROMPTSIGN_TRUST_DIR and PROMPTSIGN_REVOCATION_FILE are ignored)",
            "# user_roots: on",
            "# strict: on (managed policy)",
        ],
        "{show}"
    );
}
