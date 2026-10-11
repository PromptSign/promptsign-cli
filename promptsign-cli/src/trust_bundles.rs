// Trust bundles on the command line (spec/07 §5): `trust add <name>
// <url|file>` installs one, `trust fetch [<name>]` keeps installed ones
// current. This only consumes bundles. Publishing one is `promptsign sign
// trust-bundle.json`, an ordinary sidecar signature.

use crate::keyless_client::http_get;
use promptsign_core::trustbundle::{
    check_user_trust_bundle, installed_user_bundles, store_trust_bundle, Check,
};
use promptsign_core::trustroot::user_trust_dir;
use promptsign_core::util::{format_iso8601, glob_match};
use promptsign_core::Result;
use serde_json::Value;
use std::io::IsTerminal as _;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// Plain HTTP only reaches this machine, which is what tests and a local
/// mirror need. Anything else is fetched over https.
fn is_loopback_http(url: &str) -> bool {
    [
        "http://127.0.0.1:",
        "http://127.0.0.1/",
        "http://localhost:",
        "http://localhost/",
    ]
    .iter()
    .any(|p| url.starts_with(p))
}

/// The bundle bytes and its sidecar from a URL (`<url>` and
/// `<url>.psig.json`) or a file (`<file>` and `<file>.psig.json`), plus the
/// URL to refresh from.
fn read_source(src: &str) -> Result<(Vec<u8>, Vec<u8>, Option<String>)> {
    if src.starts_with("https://") || is_loopback_http(src) {
        let bytes = http_get(src)?;
        let sidecar = http_get(&format!("{src}.psig.json"))?;

        return Ok((bytes, sidecar, Some(src.to_string())));
    }
    if src.starts_with("http://") {
        return Err(format!("{src}: trust bundles are fetched over https only"));
    }

    let read = |p: &str| std::fs::read(p).map_err(|e| format!("{p}: {e}"));

    Ok((read(src)?, read(&format!("{src}.psig.json"))?, None))
}

fn check(name: &str, bytes: &[u8], sidecar: &[u8]) -> Result<Check> {
    let sidecar: Value =
        serde_json::from_slice(sidecar).map_err(|e| format!("trust bundle signature: {e}"))?;

    check_user_trust_bundle(name, bytes, &sidecar, now())
}

fn describe(c: &Check) {
    let b = &c.bundle;

    println!("trust bundle: {}, version {}", b.name, b.version);
    if !b.suggested_name.is_empty() && b.suggested_name != b.name {
        println!("publisher name: {}", b.suggested_name);
    }
    println!(
        "valid:        issued {}, expires {}",
        format_iso8601(b.issued),
        format_iso8601(b.expires)
    );
    println!(
        "signed by:    {} (issuer {}, root {})",
        c.signer.identity, c.signer.issuer, c.signer.root
    );
    for r in &b.roots {
        let kind = if r.is_ca_only() {
            "certificate"
        } else {
            "keyless"
        };

        println!(
            "root:         {} ({kind}) {}  sha256:{}",
            r.name, r.subject, r.fingerprint
        );
    }
}

/// Ask on the terminal, or require --yes when there is none.
pub fn confirm(question: &str, yes: bool, command: &str) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "{command}: confirm with --yes when not running interactively"
        ));
    }
    print!("{question} [y/N] ");

    let _ = std::io::Write::flush(&mut std::io::stdout());
    let mut answer = String::new();

    std::io::stdin().read_line(&mut answer).unwrap_or_default();
    if matches!(answer.trim(), "y" | "Y" | "yes") {
        Ok(())
    } else {
        Err(format!("{command}: not added"))
    }
}

/// `trust add <name> <url|file> [--signer <glob>] [--yes]`. A first install
/// trusts the bundle's own signers, so it needs the user's consent. An update
/// signed by a signer the installed version names does not.
pub fn add(name: &str, src: &str, signer: Option<&str>, yes: bool) -> Result<()> {
    let (bytes, sidecar, url) = read_source(src)?;
    let c = check(name, &bytes, &sidecar)?;

    describe(&c);
    if c.unchanged {
        println!(
            "trust bundle \"{name}\" is already at version {}",
            c.bundle.version
        );
        return Ok(());
    }
    if !c.update {
        if let Some(glob) = signer {
            if !glob_match(glob, &c.signer.identity) {
                return Err(format!(
                    "trust add: the bundle is signed by \"{}\", which does not match --signer {glob}",
                    c.signer.identity
                ));
            }
        }
        confirm(
            &format!(
                "Trust every signature that chains to these roots, and future versions from this signer, as \"{name}\"?"
            ),
            yes,
            "trust add",
        )?;
    }
    store_trust_bundle(&user_trust_dir(), name, &bytes, &sidecar, url.as_deref())?;
    println!(
        "{} trust bundle \"{name}\" version {} in {}",
        if c.update { "updated" } else { "installed" },
        c.bundle.version,
        user_trust_dir().join("bundles").join(name).display()
    );
    Ok(())
}

/// `trust fetch <name>`, or every installed bundle when `only` is None.
/// Reports each bundle and errors if any could not be refreshed, leaving that
/// one at its installed version.
pub fn fetch(only: Option<&str>) -> Result<()> {
    let installed = installed_user_bundles(now())?;
    let mut failed = Vec::new();
    let mut seen = false;

    for i in installed {
        let name = i.bundle.name.clone();

        if only.is_some_and(|o| o != name) {
            continue;
        }
        seen = true;

        let Some(url) = i.source.as_deref() else {
            println!("{name}: installed from a file, nothing to fetch");
            continue;
        };
        let outcome = read_source(url).and_then(|(bytes, sidecar, _)| {
            let c = check(&name, &bytes, &sidecar)?;

            if !c.unchanged {
                store_trust_bundle(&user_trust_dir(), &name, &bytes, &sidecar, Some(url))?;
            }
            Ok(c)
        });

        match outcome {
            Ok(c) if c.unchanged => println!("{name}: up to date (version {})", c.bundle.version),
            Ok(c) => println!(
                "{name}: version {} -> {}",
                i.bundle.version, c.bundle.version
            ),
            Err(e) => {
                println!("{name}: {e}");
                failed.push(name);
            }
        }
    }
    if let (Some(o), false) = (only, seen) {
        return Err(format!("no trust bundle named \"{o}\""));
    }
    if !failed.is_empty() {
        return Err(format!(
            "trust fetch: could not refresh {}; the installed version stays",
            failed.join(", ")
        ));
    }
    Ok(())
}
