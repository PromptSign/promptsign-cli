// `promptsign hook` on a plugin signed with OMS at its root (model.sig), so no
// skills/<name>/ directory carries a signature of its own. The skill has to be
// verified through the plugin's signature: a tampered or planted skill must
// block, not read as unsigned.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/oms/test-ca")
}

/// A home with the test plugin installed the way Claude Code records it: a
/// cache copy listed in installed_plugins.json. `trusted` adds the test CA.
struct Env {
    base: PathBuf,
    home: PathBuf,
    install: PathBuf,
}

impl Env {
    fn new(tag: &str, trusted: bool) -> Env {
        let base = std::env::temp_dir().join(format!("ps-hook-oms-{}-{tag}", std::process::id()));
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

        let env = Env {
            base,
            home,
            install,
        };

        if trusted {
            let pem = fixtures().join("test-ca.pem");
            let added = env.run(
                &[
                    "trust",
                    "add",
                    "test-ca",
                    "--ca",
                    pem.to_str().unwrap(),
                    "--yes",
                ],
                "",
            );

            assert!(added.status.success(), "{}", text(&added));
        }
        env
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_promptsign"))
            .args(args)
            .current_dir(self.base.join("project"))
            .env("PROMPTSIGN_HOME", self.base.join("ps"))
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
fn an_untouched_skill_in_a_root_signed_plugin_runs() {
    let env = Env::new("clean", true);
    let out = env.invoke("demo:hello");

    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}

#[test]
fn a_tampered_skill_in_a_root_signed_plugin_is_blocked() {
    let env = Env::new("tampered", true);
    let skill_md = env.install.join("skills").join("hello").join("SKILL.md");

    fs::write(
        &skill_md,
        "---\nname: hello\ndescription: hi\n---\n\necho tampered\n",
    )
    .unwrap();

    let out = env.invoke("demo:hello");

    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(
        text(&out).contains("modified: skills/hello/SKILL.md"),
        "{}",
        text(&out)
    );
    assert!(text(&out).contains("signed as part of"), "{}", text(&out));
}

#[test]
fn a_skill_planted_into_a_root_signed_plugin_is_blocked() {
    let env = Env::new("planted", true);
    let planted = env.install.join("skills").join("planted");

    fs::create_dir_all(&planted).unwrap();
    fs::write(
        planted.join("SKILL.md"),
        "---\nname: planted\ndescription: x\n---\n\nbody\n",
    )
    .unwrap();

    let out = env.invoke("demo:planted");

    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(
        text(&out).contains("uncovered: skills/planted/SKILL.md is not covered by the signature"),
        "{}",
        text(&out)
    );
}

#[test]
fn an_uncovered_data_file_in_the_skill_warns_without_blocking() {
    let env = Env::new("data-file", true);

    fs::write(
        env.install.join("skills").join("hello").join("notes.txt"),
        "notes\n",
    )
    .unwrap();

    let out = env.invoke("demo:hello");

    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}

#[test]
fn an_uncovered_script_in_the_skill_is_blocked() {
    let env = Env::new("script", true);
    let scripts = env.install.join("skills").join("hello").join("scripts");

    fs::write(scripts.join("extra.sh"), "echo tampered\n").unwrap();

    let out = env.invoke("demo:hello");

    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(
        text(&out).contains("uncovered: skills/hello/scripts/extra.sh"),
        "{}",
        text(&out)
    );
}

#[test]
fn a_signature_under_an_untrusted_ca_is_blocked_and_not_called_unsigned() {
    let env = Env::new("untrusted", false);
    let out = env.invoke("demo:hello");

    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(!text(&out).contains("(unsigned)"), "{}", text(&out));
    assert!(
        text(&out).contains("signature did not verify"),
        "{}",
        text(&out)
    );

    let verified = env.run(&["verify", env.install.to_str().unwrap()], "");

    assert!(!verified.status.success(), "{}", text(&verified));
    assert!(
        !text(&verified).contains("(unsigned)"),
        "{}",
        text(&verified)
    );
    assert!(
        text(&verified).contains("signature did not verify"),
        "{}",
        text(&verified)
    );
}
