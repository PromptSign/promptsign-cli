// `promptsign hook` under Codex. Codex has no Skill tool: the model reads a
// SKILL.md and runs a skill's scripts through Bash, a `$name` mention puts the
// skill into context with no tool call, and the only instruction-file check
// is SessionStart. The skill here is the OMS-signed test plugin installed as a
// repo skill under .agents/skills.

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

struct Env {
    base: PathBuf,
    project: PathBuf,
    plugin: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Env {
        let base = std::env::temp_dir().join(format!("ps-hook-codex-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&base);

        let project = base.join("project");
        let plugin = project.join(".agents").join("skills").join("demo");

        fs::create_dir_all(project.join(".git")).unwrap();
        fs::create_dir_all(base.join("home")).unwrap();
        copy_dir(&fixtures().join("plugin"), &plugin);
        fs::copy(fixtures().join("plugin.sig"), plugin.join("model.sig")).unwrap();

        let env = Env {
            base,
            project,
            plugin,
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
            ],
            "",
            false,
        );

        assert!(added.status.success(), "{}", text(&added));
        env
    }

    fn run(&self, args: &[&str], stdin: &str, strict: bool) -> Output {
        let home = self.base.join("home");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_promptsign"));

        cmd.args(args)
            .current_dir(&self.project)
            .env("PROMPTSIGN_HOME", self.base.join("ps"))
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env_remove("CODEX_HOME")
            .env_remove("PROMPTSIGN_TRUST_DIR")
            .env_remove("PROMPTSIGN_POLICY")
            .env_remove("PROMPTSIGN_SKILL_ROOTS")
            .env_remove("PROMPTSIGN_STRICT")
            .env_remove("CLAUDE_PROJECT_DIR")
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if strict {
            cmd.env("PROMPTSIGN_STRICT", "1");
        }

        let mut child = cmd.spawn().unwrap();

        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn bash(&self, command: &str) -> Output {
        let event = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "turn_id": "t1",
            "tool_name": "Bash",
            "tool_input": { "command": command },
            "cwd": self.project.to_string_lossy(),
        });

        self.run(&["hook"], &event.to_string(), false)
    }

    fn prompt(&self, prompt: &str) -> Output {
        let event = serde_json::json!({
            "hook_event_name": "UserPromptSubmit",
            "turn_id": "t1",
            "prompt": prompt,
            "cwd": self.project.to_string_lossy(),
        });

        self.run(&["hook"], &event.to_string(), false)
    }

    fn session_start(&self, args: &[&str], strict: bool) -> Output {
        let event = serde_json::json!({
            "hook_event_name": "SessionStart",
            "source": "startup",
            "cwd": self.project.to_string_lossy(),
        });

        self.run(args, &event.to_string(), strict)
    }

    fn tamper(&self) {
        fs::write(
            self.plugin.join("skills").join("hello").join("SKILL.md"),
            "---\nname: hello\ndescription: hi\n---\n\necho tampered\n",
        )
        .unwrap();
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

/// The reason when the hook refused, in the JSON decision Codex reads from
/// stdout: `permissionDecision: deny` for a tool call, `decision: block` for a
/// prompt. The hook exits 0 either way.
fn refusal(o: &Output) -> Option<String> {
    let decision: serde_json::Value = serde_json::from_slice(&o.stdout).ok()?;
    let reason = match decision.pointer("/hookSpecificOutput/permissionDecision") {
        Some(d) if d == "deny" => decision.pointer("/hookSpecificOutput/permissionDecisionReason"),
        Some(_) => None,
        None if decision["decision"] == "block" => decision.get("reason"),
        None => None,
    };

    reason?.as_str().map(String::from)
}

fn refused(o: &Output) -> String {
    assert_eq!(o.status.code(), Some(0), "{}", text(o));
    refusal(o).unwrap_or_else(|| panic!("not refused: {}", text(o)))
}

const READ_SKILL: &str = "sed -n '1,200p' .agents/skills/demo/skills/hello/SKILL.md";

#[test]
fn reading_an_untouched_skill_runs() {
    let env = Env::new("clean");
    let out = env.bash(READ_SKILL);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(refusal(&out), None);
}

#[test]
fn reading_a_tampered_skill_is_blocked() {
    let env = Env::new("read");

    env.tamper();

    let reason = refused(&env.bash(READ_SKILL));

    assert!(
        reason.contains("modified: skills/hello/SKILL.md"),
        "{reason}"
    );
    assert!(reason.contains("signed as part of"), "{reason}");
}

#[test]
fn reading_after_cd_into_a_tampered_skill_is_blocked() {
    let env = Env::new("cd");

    env.tamper();

    refused(&env.bash("cd .agents/skills/demo/skills/hello && cat SKILL.md"));
}

#[test]
fn running_a_script_planted_in_a_skill_is_blocked() {
    let env = Env::new("script");
    let scripts = env.plugin.join("skills").join("hello").join("scripts");

    fs::write(scripts.join("extra.sh"), "echo tampered\n").unwrap();

    let reason = refused(&env.bash("bash .agents/skills/demo/skills/hello/scripts/extra.sh"));

    assert!(
        reason.contains("uncovered: skills/hello/scripts/extra.sh"),
        "{reason}"
    );
}

#[test]
fn a_command_that_touches_no_skill_runs() {
    let env = Env::new("unrelated");

    env.tamper();

    let out = env.bash("ls -la && cat README.md");

    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(refusal(&out), None);
}

#[test]
fn mentioning_a_tampered_skill_blocks_the_prompt() {
    let env = Env::new("mention");

    assert_eq!(refusal(&env.prompt("run $hello")), None);
    env.tamper();

    let reason = refused(&env.prompt("run $hello"));

    assert!(reason.contains("\"hello\""), "{reason}");
}

#[test]
fn a_dollar_that_names_no_skill_never_blocks() {
    let env = Env::new("dollar");

    env.tamper();

    let out = env.prompt("echo $HOME costs $5");

    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(refusal(&out), None);
}

#[test]
fn session_start_reports_a_tampered_codex_skill_into_context() {
    let env = Env::new("start");

    let clean = env.session_start(&["hook", "--codex"], false);

    assert_eq!(clean.status.code(), Some(0), "{}", text(&clean));
    assert!(clean.stdout.is_empty(), "{}", text(&clean));
    env.tamper();

    let out = env.session_start(&["hook", "--codex"], false);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("FAILED verification"),
        "{}",
        text(&out)
    );
}

#[test]
fn strict_session_start_stops_codex_with_continue_false() {
    let env = Env::new("strict");

    env.tamper();

    let out = env.session_start(&["hook", "--codex"], true);
    let stop: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();

    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stop["continue"], false);
    assert!(stop["stopReason"]
        .as_str()
        .unwrap()
        .contains("failed signature verification"));
}

#[test]
fn session_start_without_the_flag_keeps_the_claude_code_roots() {
    let env = Env::new("claude");

    env.tamper();

    let out = env.session_start(&["hook"], false);

    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(out.stdout.is_empty(), "{}", text(&out));
}
