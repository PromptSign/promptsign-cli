// promptsign — sign and verify AI instruction files (SKILL.md, AGENTS.md,
// CLAUDE.md, agent definitions). Single static binary, no runtime deps:
// built to be invoked from Claude Code / Codex hooks with ~zero startup cost.
// Exit codes: 0 = ok (possibly with warnings), 1 = usage/internal error,
// 2 = enforcement failure (hook-friendly: Claude Code/Codex block on exit 2).

mod args;
mod hook;
mod keyless_client;
mod login;
mod proxy;

#[cfg(feature = "local-key")]
use promptsign_core::bundle::{sign_manifest, write_bundle};
#[cfg(feature = "local-key")]
use promptsign_core::keys::{default_identity, default_key_path, keygen, load_private_key};
use promptsign_core::manifest::{build_manifest, BuildOptions};
use promptsign_core::policy::{default_policy, load_pins, load_policy, save_pins, Action};
use promptsign_core::util::{promptsign_home, short16};
use promptsign_core::verify::{verify_target, VerifyOptions, VerifyResult};
use promptsign_core::verifytree::verify_tree;
use std::fmt::Write as _;
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const VERSION: &str = env!("CARGO_PKG_VERSION");

// Signing is keyless by default: log in once, sign as that verified identity.
// The local-key path (keygen + `sign --local-key`) is compiled in only with
// the `local-key` cargo feature; release binaries ship without it.
#[cfg(not(feature = "local-key"))]
const USAGE: &str = "promptsign VERSION — identity-verified signing for AI instruction files

Usage:
  promptsign login [--print-token]   (interactive browser sign-in; caches a token for signing)
  promptsign sign <dir|file> [--identity-token <jwt>] [--embed] [--name n] [--version v] [--kind k]
  promptsign verify <dir|file> [--policy path] [--json] [--no-pin-updates]
  promptsign verify-tree <root>... [--policy path] [--json] [--quiet] [--no-pin-updates]
  promptsign policy init [--global] | policy show  (the effective policy and its source)
  promptsign pin list | pin rm <name>
  promptsign trust fetch [--force] | trust show   (cache Sigstore roots for offline verify)
  promptsign revoke fetch | revoke show  (refresh/inspect the cached revocation feed)
  promptsign revoke sign <entries.json> [--out path]   (publish a signed revocation feed)
  promptsign hook [event]     (Claude Code / Codex / OpenClaw hook: reads event JSON on stdin)
  promptsign proxy [--host h] [--port p] [--allow-origin o] [--allow-host h]
                              (local CORS proxy for in-browser keyless signing)

Signing is keyless: sign in with GitHub, Google, or your company account
(promptsign login), and bundles carry that verified identity. In CI, a token
is picked up automatically (e.g. GitHub Actions with id-token: write).

Signing unit is a bundle manifest: for a directory, every file in it (skills
include the scripts they run); for a single file, a sidecar <file>.psig.json.
With --embed, a single Markdown file's signature is written into its own YAML
frontmatter (x-promptsign:) instead of a sidecar, so it travels with the file
(not allowed for CLAUDE.md/AGENTS.md — those keep the sidecar).
Verification = signature + integrity against disk + trust policy + TOFU pins.";

#[cfg(feature = "local-key")]
const USAGE: &str = "promptsign VERSION — identity-verified signing for AI instruction files

Usage:
  promptsign login [--print-token]   (interactive browser sign-in; caches a token for signing)
  promptsign sign <dir|file> [--identity-token <jwt>] [--embed] [--name n] [--version v] [--kind k]
  promptsign sign <dir|file> --local-key [--identity id] [--key path] [--embed] [--name n] [--version v] [--kind k]
  promptsign keygen [--identity <id>] [--force]
  promptsign verify <dir|file> [--policy path] [--json] [--no-pin-updates]
  promptsign verify-tree <root>... [--policy path] [--json] [--quiet] [--no-pin-updates]
  promptsign policy init [--global] | policy show  (the effective policy and its source)
  promptsign pin list | pin rm <name>
  promptsign trust fetch [--force] | trust show   (cache Sigstore roots for offline verify)
  promptsign revoke fetch | revoke show  (refresh/inspect the cached revocation feed)
  promptsign revoke sign <entries.json> [--out path]   (publish a signed revocation feed)
  promptsign hook [event]     (Claude Code / Codex / OpenClaw hook: reads event JSON on stdin)
  promptsign proxy [--host h] [--port p] [--allow-origin o] [--allow-host h]
                              (local CORS proxy for in-browser keyless signing)

Signing is keyless by default: sign in with GitHub, Google, or your company
account (promptsign login), and bundles carry that verified identity. This
build also includes local-key signing (--local-key) for offline/private use.

Signing unit is a bundle manifest: for a directory, every file in it (skills
include the scripts they run); for a single file, a sidecar <file>.psig.json.
With --embed, a single Markdown file's signature is written into its own YAML
frontmatter (x-promptsign:) instead of a sidecar, so it travels with the file
(not allowed for CLAUDE.md/AGENTS.md — those keep the sidecar).
Verification = signature + integrity against disk + trust policy + TOFU pins.";

fn fail(msg: &str) -> ! {
    eprintln!("promptsign: {msg}");
    std::process::exit(1);
}

// ANSI color helpers. Colorizing is opt-in per call (see `use_color`) so the
// TTY-facing `verify`/`verify-tree` output is color-coded while the same
// formatters, when reused for hook/JSON/piped output, stay plain text.
mod color {
    pub const RESET: &str = "\x1b[0m";
    pub const DIM: &str = "\x1b[2m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const CYAN: &str = "\x1b[36m";
}

/// Wrap `s` in `codes` (reset at the end) only when `on`; otherwise return it
/// unchanged. Keeps callers free of `if on { .. } else { .. }` noise.
fn paint(s: &str, codes: &str, on: bool) -> String {
    if on {
        format!("{codes}{s}{}", color::RESET)
    } else {
        s.to_string()
    }
}

/// Color output for an interactive stdout, unless the caller opted out with
/// NO_COLOR. FORCE_COLOR overrides both (handy for `| less -R` and CI logs).
/// Both are the de-facto standards; presence — not value — is what counts.
fn use_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::env::var_os("FORCE_COLOR").is_some() || std::io::stdout().is_terminal()
}

/// Runtime bookkeeping a harness writes into an artifact directory *after* it
/// has installed and pinned it. Naming it in the report is explanation only:
/// the finding stands and the verdict is unchanged.
///
/// This deliberately does not live in the manifest's skip list. A stale name
/// here degrades to the plain message, while a stale name in the skip list
/// degrades to hiding a genuinely added file, and "the manifest lists every
/// file" is the property that makes a deleted one detectable. Explanation is
/// the safe place to put knowledge of another product's internal filenames.
fn harness_note(rel_path: &str) -> Option<&'static str> {
    let first = rel_path.split('/').next().unwrap_or(rel_path);

    match (first, rel_path) {
        (".in_use", _) | (_, ".orphaned_at") => Some(
            "Claude Code plugin bookkeeping, written into this directory after install.",
        ),
        _ => None,
    }
}

pub fn format_result(r: &VerifyResult, color: bool) -> String {
    let (label, codes) = if r.signed {
        match r.action {
            Action::Pass => ("[ OK ]", concat!("\x1b[1m", "\x1b[32m")),
            Action::Warn => ("[WARN]", concat!("\x1b[1m", "\x1b[33m")),
            Action::Fail => ("[FAIL]", concat!("\x1b[1m", "\x1b[31m")),
        }
    } else {
        ("[----]", color::DIM)
    };
    let icon = paint(label, codes, color);
    let version = r
        .version
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(|v| format!("@{v}"))
        .unwrap_or_default();
    let who = match (&r.identity, &r.issuer) {
        (Some(i), Some(iss)) => format!(" signed by {i} via {iss}"),
        (Some(i), None) => format!(" signed by {i}"),
        (None, _) => " (unsigned)".to_string(),
    };
    let target = paint(&r.target, color::DIM, color);
    let mut out = format!("{icon} {}{version}{who} — {target}\n", r.name);

    for f in &r.findings {
        let codes = match f.level.as_str() {
            "error" => color::RED,
            "warn" => color::YELLOW,
            _ => color::CYAN,
        };
        let level = paint(&f.level.to_uppercase(), codes, color);
        let _ = writeln!(out, "       {level}: {}", f.message);

        if let Some(note) = f
            .message
            .strip_prefix("unlisted file present: ")
            .and_then(harness_note)
        {
            let note = paint(&format!("note: {note}"), color::DIM, color);
            let _ = writeln!(out, "              {note}");
        }
    }
    out
}

pub fn format_tree_report(results: &[VerifyResult], quiet: bool, color: bool) -> String {
    let mut out = String::new();

    for r in results {
        if quiet && r.action == Action::Pass {
            continue;
        }
        out.push_str(&format_result(r, color));
    }

    let (mut pass, mut warn, mut failed) = (0, 0, 0);

    for r in results {
        match r.action {
            Action::Pass => pass += 1,
            Action::Warn => warn += 1,
            Action::Fail => failed += 1,
        }
    }

    // Only emphasize a count when it's nonzero, so a clean run reads calmly.
    let hue = |n: usize, codes: &str| paint(&n.to_string(), codes, color && n > 0);
    let _ = write!(
        out,
        "\n{} artifact(s): {} ok, {} warning, {} failed\n",
        results.len(),
        hue(pass, color::GREEN),
        hue(warn, color::YELLOW),
        hue(failed, color::RED),
    );

    out
}

fn exit_for(results: &[VerifyResult]) -> ExitCode {
    if results.iter().any(|r| r.action == Action::Fail) {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(not(feature = "local-key"))]
fn cmd_keygen(_rest: &[String]) -> ExitCode {
    fail(
        "keygen: local-key signing is not included in this build — sign with your login instead \
         (promptsign login, then promptsign sign <dir|file>)",
    );
}

#[cfg(feature = "local-key")]
fn cmd_keygen(rest: &[String]) -> ExitCode {
    let p = args::parse(rest, &["identity", "dir"], &["force"]).unwrap_or_else(|e| fail(&e));
    let dir = p.values.get("dir").map(PathBuf::from);
    let res = keygen(
        dir.as_deref(),
        p.flags.contains("force"),
        p.values.get("identity").map(String::as_str),
    )
    .unwrap_or_else(|e| fail(&e));

    println!("generated ed25519 key: {}", res.key_path.display());
    println!("keyid: {}", res.keyid);
    match p.values.get("identity") {
        Some(id) => println!("identity: {id}"),
        None => println!(
            "identity defaults to key:{} (set one with --identity)",
            short16(&res.keyid)
        ),
    }
    ExitCode::SUCCESS
}

// Self-check: verify the freshly written bundle end-to-end (catches
// canonicalization drift immediately, at the signer, not at consumers).
fn self_check_or_remove(abs: &Path, out: &Path) {
    let check = verify_target(
        &abs.to_string_lossy(),
        &VerifyOptions {
            policy_path: None,
            no_pin_updates: true,
            skip_policy: true,
        },
    );
    let failed_msgs: Option<String> = match &check {
        Ok(r) if r.action == Action::Fail => Some(
            r.findings
                .iter()
                .map(|f| f.message.clone())
                .collect::<Vec<_>>()
                .join("\n  "),
        ),
        Err(e) => Some(e.clone()),
        _ => None,
    };

    if let Some(msgs) = failed_msgs {
        let _ = std::fs::remove_file(out);

        fail(&format!(
            "self-verification of freshly signed bundle failed:\n  {msgs}"
        ));
    }
}

// --embed is only valid for a single Markdown file that already has YAML
// frontmatter and is not a context-injected instruction file. Validated before
// signing so a keyless network round-trip is never wasted.
fn check_embed_eligible(abs: &Path, is_dir: bool) -> std::result::Result<(), String> {
    if is_dir {
        return Err("--embed is only for a single Markdown file; a directory is signed via .promptsign/bundle.json (omit --embed)".to_string());
    }

    let name = abs
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    if !promptsign_core::canonicalize::is_markdown(&name) {
        return Err(format!("--embed requires a Markdown file; {name} is not .md/.markdown — use the sidecar (omit --embed)"));
    }
    if promptsign_core::manifest::CONTEXT_INJECTED.contains(&name.as_str()) {
        return Err(format!(
            "refusing to embed in {name}: it is injected into model context verbatim, so an \
             embedded signature would be unsigned noise the model reads — sign it with the sidecar (omit --embed)"
        ));
    }

    let text = std::fs::read_to_string(abs).map_err(|e| format!("{}: {e}", abs.display()))?;
    let body = text.strip_prefix('\u{feff}').unwrap_or(&text);

    if !(body.starts_with("---\n") || body.starts_with("---\r\n")) {
        return Err(format!(
            "cannot embed in {name}: it has no YAML frontmatter (a leading '---' block); add one or use the sidecar (omit --embed)"
        ));
    }
    Ok(())
}

// Embed the bundle into the file's frontmatter, then self-verify. On failure the
// original file bytes are restored (the embedded counterpart of removing a bad
// sidecar in self_check_or_remove).
fn embed_and_write(abs: &Path, bundle_json: &[u8]) {
    let original = std::fs::read(abs).unwrap_or_else(|e| fail(&format!("{}: {e}", abs.display())));
    let text = String::from_utf8_lossy(&original).into_owned();
    let embedded = promptsign_core::bundle::embed_bundle_in_markdown(&text, bundle_json)
        .unwrap_or_else(|e| fail(&e));

    std::fs::write(abs, embedded).unwrap_or_else(|e| fail(&format!("{}: {e}", abs.display())));
    self_check_or_restore(abs, &original);
}

fn self_check_or_restore(abs: &Path, original: &[u8]) {
    let check = verify_target(
        &abs.to_string_lossy(),
        &VerifyOptions {
            policy_path: None,
            no_pin_updates: true,
            skip_policy: true,
        },
    );
    let failed_msgs: Option<String> = match &check {
        Ok(r) if r.action == Action::Fail => Some(
            r.findings
                .iter()
                .map(|f| f.message.clone())
                .collect::<Vec<_>>()
                .join("\n  "),
        ),
        Err(e) => Some(e.clone()),
        _ => None,
    };

    if let Some(msgs) = failed_msgs {
        let _ = std::fs::write(abs, original);

        fail(&format!(
            "self-verification of freshly embedded signature failed:\n  {msgs}"
        ));
    }
}

fn cmd_sign(rest: &[String]) -> ExitCode {
    #[cfg(feature = "local-key")]
    let p = args::parse(
        rest,
        &[
            "name",
            "version",
            "kind",
            "identity",
            "key",
            "identity-token",
        ],
        &["local-key", "embed"],
    )
    .unwrap_or_else(|e| fail(&e));
    #[cfg(not(feature = "local-key"))]
    let p = args::parse(
        rest,
        &["name", "version", "kind", "identity-token"],
        &["embed"],
    )
    .unwrap_or_else(|e| fail(&e));

    let target = p
        .positionals
        .first()
        .unwrap_or_else(|| fail("sign: missing <dir|file>"));

    if !Path::new(target).exists() {
        fail(&format!("sign: no such path: {target}"));
    }

    let abs = std::path::absolute(target).unwrap_or_else(|e| fail(&e.to_string()));
    let is_dir = abs.is_dir();
    let root = if is_dir {
        abs.clone()
    } else {
        abs.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    // Validate --embed eligibility before signing so we never spend a keyless
    // signature (a network round-trip) on a file we cannot embed into.
    let embed = p.flags.contains("embed");

    if embed {
        check_embed_eligible(&abs, is_dir).unwrap_or_else(|e| fail(&e));
    }

    let manifest = build_manifest(
        &root,
        if is_dir { None } else { Some(&abs) },
        &BuildOptions {
            name: p.values.get("name").map(String::as_str),
            version: p.values.get("version").map(String::as_str),
            kind: p.values.get("kind").map(String::as_str),
        },
    )
    .unwrap_or_else(|e| fail(&e));
    let n = manifest.files.len();
    let (kind, name) = (
        manifest.kind.clone().unwrap_or_else(|| "file".to_string()),
        manifest.name.clone(),
    );

    #[cfg(feature = "local-key")]
    {
        if p.flags.contains("local-key") {
            let key_path = p
                .values
                .get("key")
                .map(PathBuf::from)
                .unwrap_or_else(default_key_path);
            let private_key = load_private_key(&key_path).unwrap_or_else(|e| fail(&e));
            let identity = match p.values.get("identity") {
                Some(id) => id.clone(),
                None => default_identity(&private_key.verifying_key()).unwrap_or_else(|e| fail(&e)),
            };
            let bundle =
                sign_manifest(&manifest, &private_key, &identity).unwrap_or_else(|e| fail(&e));

            if embed {
                let bundle_json =
                    serde_json::to_vec(&bundle).unwrap_or_else(|e| fail(&e.to_string()));

                embed_and_write(&abs, &bundle_json);
                println!(
                    "signed {kind} \"{name}\" ({n} file{}) as {identity}",
                    if n == 1 { "" } else { "s" }
                );
                println!("embedded signature into {}", abs.display());
                return ExitCode::SUCCESS;
            }

            let out = write_bundle(&abs, &bundle).unwrap_or_else(|e| fail(&e));

            self_check_or_remove(&abs, &out);
            println!(
                "signed {kind} \"{name}\" ({n} file{}) as {identity}",
                if n == 1 { "" } else { "s" }
            );
            println!("bundle: {}", out.display());
            return ExitCode::SUCCESS;
        }
        if p.values.contains_key("identity") || p.values.contains_key("key") {
            fail("sign: --identity/--key need --local-key (a keyless identity comes from your login)");
        }
    }

    // Default: keyless. Fail before any network call if offline verification
    // could not succeed anyway — the self-check needs the cached trust root.
    promptsign_core::keyless::load_trust_root().unwrap_or_else(|e| fail(&e));

    let payload = serde_json::to_vec(&manifest).unwrap_or_else(|e| fail(&e.to_string()));
    let outcome = keyless_client::keyless_sign(
        &payload,
        promptsign_core::bundle::PAYLOAD_TYPE,
        p.values.get("identity-token").map(String::as_str),
    )
    .unwrap_or_else(|e| fail(&e));

    if embed {
        let bundle_json =
            serde_json::to_vec(&outcome.bundle).unwrap_or_else(|e| fail(&e.to_string()));

        embed_and_write(&abs, &bundle_json);
        println!(
            "signed {kind} \"{name}\" ({n} file{}) as {} via {}",
            if n == 1 { "" } else { "s" },
            outcome.identity,
            outcome.issuer
        );
        println!("embedded signature into {}", abs.display());
        println!("transparency log index: {}", outcome.log_index);
        return ExitCode::SUCCESS;
    }

    let out = promptsign_core::bundle::write_bundle_value(&abs, &outcome.bundle)
        .unwrap_or_else(|e| fail(&e));

    self_check_or_remove(&abs, &out);
    println!(
        "signed {kind} \"{name}\" ({n} file{}) as {} via {}",
        if n == 1 { "" } else { "s" },
        outcome.identity,
        outcome.issuer
    );
    println!("bundle: {}", out.display());
    println!("transparency log index: {}", outcome.log_index);
    ExitCode::SUCCESS
}

fn cmd_trust(rest: &[String]) -> ExitCode {
    match rest.first().map(String::as_str) {
        Some("fetch") => {
            let p = args::parse(&rest[1..], &[], &["force"]).unwrap_or_else(|e| fail(&e));

            keyless_client::trust_fetch(p.flags.contains("force"))
                .map(|_| ExitCode::SUCCESS)
                .unwrap_or_else(|e| fail(&e))
        }
        Some("show") => keyless_client::trust_show()
            .map(|_| ExitCode::SUCCESS)
            .unwrap_or_else(|e| fail(&e)),
        _ => fail("trust: expected \"fetch\" or \"show\""),
    }
}

fn cmd_revoke(rest: &[String]) -> ExitCode {
    match rest.first().map(String::as_str) {
        Some("fetch") => keyless_client::revoke_fetch()
            .map(|_| ExitCode::SUCCESS)
            .unwrap_or_else(|e| fail(&e)),
        Some("show") => keyless_client::revoke_show()
            .map(|_| ExitCode::SUCCESS)
            .unwrap_or_else(|e| fail(&e)),
        Some("sign") => {
            let p = args::parse(&rest[1..], &["out", "identity-token"], &[])
                .unwrap_or_else(|e| fail(&e));
            let entries = p
                .positionals
                .first()
                .unwrap_or_else(|| fail("revoke sign: missing <entries.json>"));

            keyless_client::revoke_sign(
                entries,
                p.values.get("out").map(String::as_str),
                p.values.get("identity-token").map(String::as_str),
            )
            .map(|_| ExitCode::SUCCESS)
            .unwrap_or_else(|e| fail(&e))
        }
        _ => fail("revoke: expected \"fetch\", \"show\", or \"sign <entries.json>\""),
    }
}

fn cmd_verify(rest: &[String]) -> ExitCode {
    let p =
        args::parse(rest, &["policy"], &["json", "no-pin-updates"]).unwrap_or_else(|e| fail(&e));
    let target = p
        .positionals
        .first()
        .unwrap_or_else(|| fail("verify: missing <dir|file>"));

    if !Path::new(target).exists() {
        fail(&format!("verify: no such path: {target}"));
    }

    let r = verify_target(
        target,
        &VerifyOptions {
            policy_path: p.values.get("policy").map(PathBuf::from),
            no_pin_updates: p.flags.contains("no-pin-updates"),
            skip_policy: false,
        },
    )
    .unwrap_or_else(|e| fail(&e));

    if p.flags.contains("json") {
        println!("{}", serde_json::to_string_pretty(&r).unwrap());
    } else {
        print!("{}", format_result(&r, use_color()));
    }
    exit_for(std::slice::from_ref(&r))
}

fn cmd_verify_tree(rest: &[String]) -> ExitCode {
    let p = args::parse(rest, &["policy"], &["json", "quiet", "no-pin-updates"])
        .unwrap_or_else(|e| fail(&e));

    if p.positionals.is_empty() {
        fail("verify-tree: missing <root>...");
    }

    let results = verify_tree(
        &p.positionals,
        &VerifyOptions {
            policy_path: p.values.get("policy").map(PathBuf::from),
            no_pin_updates: p.flags.contains("no-pin-updates"),
            skip_policy: false,
        },
    )
    .unwrap_or_else(|e| fail(&e));

    if p.flags.contains("json") {
        println!("{}", serde_json::to_string_pretty(&results).unwrap());
    } else {
        print!(
            "{}",
            format_tree_report(&results, p.flags.contains("quiet"), use_color())
        );
    }
    exit_for(&results)
}

fn cmd_policy(rest: &[String]) -> ExitCode {
    match rest.first().map(String::as_str) {
        Some("init") => {
            let p = args::parse(&rest[1..], &[], &["global"]).unwrap_or_else(|e| fail(&e));
            let dir = if p.flags.contains("global") {
                promptsign_home()
            } else {
                std::env::current_dir()
                    .unwrap_or_else(|e| fail(&e.to_string()))
                    .join(".promptsign")
            };
            let path = dir.join("policy.json");

            if path.exists() {
                fail(&format!("policy already exists: {}", path.display()));
            }
            std::fs::create_dir_all(&dir).unwrap_or_else(|e| fail(&e.to_string()));

            let json = serde_json::to_string_pretty(&default_policy()).unwrap();

            std::fs::write(&path, json + "\n").unwrap_or_else(|e| fail(&e.to_string()));
            println!("wrote {}", path.display());
            ExitCode::SUCCESS
        }
        Some("show") => {
            let cwd = std::env::current_dir().unwrap_or_else(|e| fail(&e.to_string()));
            let (_policy, raw, source) = load_policy(None, &cwd).unwrap_or_else(|e| fail(&e));

            println!("# source: {source}");
            println!("{}", serde_json::to_string_pretty(&raw).unwrap());
            ExitCode::SUCCESS
        }
        _ => fail("policy: expected \"init\" or \"show\""),
    }
}

fn cmd_pin(rest: &[String]) -> ExitCode {
    let pins = load_pins().unwrap_or_else(|e| fail(&e));

    match rest.first().map(String::as_str) {
        Some("list") | None => {
            if pins.is_empty() {
                println!("no pins recorded");
            }
            for (name, pin) in &pins {
                println!(
                    "{name} -> {} (key {}…, since {})",
                    pin.identity,
                    short16(&pin.keyid),
                    pin.first_seen
                );
            }
            ExitCode::SUCCESS
        }
        Some("rm") => {
            let name = rest
                .get(1)
                .unwrap_or_else(|| fail("pin rm: missing <name>"));
            let mut pins = pins;

            if pins.remove(name).is_none() {
                fail(&format!("no pin for \"{name}\""));
            }
            save_pins(&pins).unwrap_or_else(|e| fail(&e));
            println!("removed pin for \"{name}\"");
            ExitCode::SUCCESS
        }
        _ => fail("pin: expected \"list\" or \"rm <name>\""),
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = match argv.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => ("help", &[] as &[String]),
    };

    match cmd {
        "keygen" => cmd_keygen(rest),
        "login" => login::cmd_login(rest),
        "sign" => cmd_sign(rest),
        "verify" => cmd_verify(rest),
        "verify-tree" => cmd_verify_tree(rest),
        "policy" => cmd_policy(rest),
        "pin" => cmd_pin(rest),
        "trust" => cmd_trust(rest),
        "revoke" => cmd_revoke(rest),
        "hook" => hook::cmd_hook(rest),
        "proxy" => proxy::cmd_proxy(rest),
        "version" | "--version" | "-v" => {
            println!("{VERSION}");
            ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            println!("{}", USAGE.replacen("VERSION", VERSION, 1));
            ExitCode::SUCCESS
        }
        other => fail(&format!(
            "unknown command \"{other}\" (try: promptsign help)"
        )),
    }
}

#[cfg(test)]
mod report_tests {
    use super::*;
    use promptsign_core::policy::Finding;

    fn finding(message: &str) -> Finding {
        Finding {
            level: "error".to_string(),
            message: message.to_string(),
        }
    }

    fn failing_result(findings: Vec<Finding>) -> VerifyResult {
        VerifyResult {
            target: "/plugins/cache/promptsign/promptsign/0.3.0".to_string(),
            policy_source: "built-in".to_string(),
            name: "promptsign".to_string(),
            version: None,
            kind: None,
            identity: None,
            issuer: None,
            keyid: None,
            integrated_time: None,
            signed: true,
            action: Action::Fail,
            findings,
        }
    }

    #[test]
    fn harness_bookkeeping_is_explained_but_still_reported_as_an_error() {
        let out = format_result(
            &failing_result(vec![finding("unlisted file present: .in_use/37960")]),
            false,
        );

        assert!(out.contains("ERROR: unlisted file present: .in_use/37960"));
        assert!(out.contains("note: Claude Code plugin bookkeeping"));
    }

    #[test]
    fn the_orphan_marker_is_explained_too() {
        let out = format_result(
            &failing_result(vec![finding("unlisted file present: .orphaned_at")]),
            false,
        );

        assert!(out.contains("note: Claude Code plugin bookkeeping"));
    }

    /// The note must never attach to an ordinary added file, which is the case
    /// the unlisted-file check exists for in the first place.
    #[test]
    fn an_ordinary_added_file_gets_no_note() {
        let out = format_result(
            &failing_result(vec![finding("unlisted file present: skills/evil.md")]),
            false,
        );

        assert!(out.contains("unlisted file present: skills/evil.md"));
        assert!(!out.contains("note:"));
    }

    /// A path that merely contains the name is not the bookkeeping directory.
    #[test]
    fn a_lookalike_path_gets_no_note() {
        let out = format_result(
            &failing_result(vec![finding("unlisted file present: skills/.in_use.md")]),
            false,
        );

        assert!(!out.contains("note:"));
    }

    /// Every other finding kind is untouched: only the unlisted-file message
    /// carries a path this can reason about.
    #[test]
    fn a_modified_file_gets_no_note() {
        let out = format_result(&failing_result(vec![finding("modified: .in_use/37960")]), false);

        assert!(!out.contains("note:"));
    }
}
