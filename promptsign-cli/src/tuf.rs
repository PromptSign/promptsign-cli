// A TUF client (TUF 1.0, "detailed client workflow") for the documents
// `trust fetch` takes from Sigstore's TUF repository: the public
// trusted_root.json and signing config. The chain of root metadata starts at a
// root compiled into this binary, so the client checks what the CDN serves
// against keys the root's signers hold offline, and TLS carries none of the
// trust. It looks up top-level targets and does not follow delegations.

use crate::keyless_client::agent;
use promptsign_core::util::{format_iso8601, hex, parse_iso8601};
use promptsign_core::Result;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use std::path::PathBuf;

pub const DEFAULT_TUF_URL: &str = "https://tuf-repo-cdn.sigstore.dev";

/// Sigstore's root metadata, version 15. The client reaches a newer root by
/// fetching and verifying each version after it, so this needs to be a root
/// Sigstore signed at some point.
const EMBEDDED_ROOT: &str = include_str!("tuf-root.json");

/// The client stops after this many root versions in one update.
const MAX_ROOT_ROTATIONS: u64 = 1024;

/// Response size caps, from the TUF reference client's defaults.
const MAX_ROOT_BYTES: u64 = 512 * 1024;
const MAX_TIMESTAMP_BYTES: u64 = 16 * 1024;
const MAX_METADATA_BYTES: u64 = 4 << 20;

pub struct Repo {
    url: String,
    /// Verified metadata from earlier runs, for rollback checks.
    cache: PathBuf,
    initial_root: Vec<u8>,
    now: i64,
}

impl Repo {
    /// The repository `$PROMPTSIGN_TUF_URL` names (Sigstore's by default),
    /// trusting `$PROMPTSIGN_TUF_ROOT` as its initial root when set, else the
    /// embedded Sigstore root. It keeps verified metadata under
    /// `<trust_dir>/tuf/`.
    pub fn from_env(trust_dir: &std::path::Path) -> Result<Repo> {
        let url = crate::keyless_client::env_url("PROMPTSIGN_TUF_URL", DEFAULT_TUF_URL);
        let initial_root = match std::env::var("PROMPTSIGN_TUF_ROOT") {
            Ok(p) if !p.is_empty() => std::fs::read(&p).map_err(|e| format!("{p}: {e}"))?,
            _ => EMBEDDED_ROOT.as_bytes().to_vec(),
        };
        let cache = trust_dir.join("tuf").join(cache_name(&url));

        Ok(Repo {
            url,
            cache,
            initial_root,
            now: crate::keyless_client::now(),
        })
    }

    /// The named top-level targets, each checked against the length and
    /// hashes the current targets metadata gives for it.
    pub fn fetch_targets(&self, names: &[&str]) -> Result<Vec<Vec<u8>>> {
        let root = self.update_root()?;
        let keys = &root["signed"]["keys"];
        let roles = &root["signed"]["roles"];
        let consistent = root["signed"]["consistent_snapshot"].as_bool() == Some(true);

        // Timestamp: the freshest metadata, naming the current snapshot.
        let timestamp_bytes =
            self.get(&format!("{}/timestamp.json", self.url), MAX_TIMESTAMP_BYTES)?;
        let timestamp = parse(&timestamp_bytes, "timestamp.json")?;

        verify_role(&timestamp, keys, &roles["timestamp"], "timestamp.json")?;
        check_signed(&timestamp, "timestamp", None)?;
        self.check_expiry(&timestamp, "timestamp.json")?;

        let snapshot_meta = &timestamp["signed"]["meta"]["snapshot.json"];
        let snapshot_version = version_of(snapshot_meta, "timestamp.json snapshot.json")?;

        if let Some(old) = self.cached("timestamp.json", keys, &roles["timestamp"]) {
            if version(&timestamp)? < version(&old)? {
                return Err("timestamp.json: version is older than the one already seen".into());
            }
            if snapshot_version
                < version_of(&old["signed"]["meta"]["snapshot.json"], "snapshot.json")?
            {
                return Err(
                    "timestamp.json: names an older snapshot than the one already seen".into(),
                );
            }
        }

        // Snapshot: the version of every targets metadata file.
        let snapshot_bytes = self.get(
            &self.metadata_url("snapshot.json", snapshot_version, consistent),
            MAX_METADATA_BYTES,
        )?;

        check_file(snapshot_meta, &snapshot_bytes, "snapshot.json", false)?;

        let snapshot = parse(&snapshot_bytes, "snapshot.json")?;

        verify_role(&snapshot, keys, &roles["snapshot"], "snapshot.json")?;
        check_signed(&snapshot, "snapshot", Some(snapshot_version))?;
        self.check_expiry(&snapshot, "snapshot.json")?;

        if let Some(old) = self.cached("snapshot.json", keys, &roles["snapshot"]) {
            for (name, meta) in old["signed"]["meta"].as_object().into_iter().flatten() {
                let now = &snapshot["signed"]["meta"][name];

                if now.is_null() {
                    return Err(format!("snapshot.json: {name} was removed"));
                }
                if version_of(now, name)? < version_of(meta, name)? {
                    return Err(format!("snapshot.json: {name} went back a version"));
                }
            }
        }

        // Targets: the length and hashes of every target file.
        let targets_meta = &snapshot["signed"]["meta"]["targets.json"];
        let targets_version = version_of(targets_meta, "snapshot.json targets.json")?;
        let targets_bytes = self.get(
            &self.metadata_url("targets.json", targets_version, consistent),
            MAX_METADATA_BYTES,
        )?;

        check_file(targets_meta, &targets_bytes, "targets.json", false)?;

        let targets = parse(&targets_bytes, "targets.json")?;

        verify_role(&targets, keys, &roles["targets"], "targets.json")?;
        check_signed(&targets, "targets", Some(targets_version))?;
        self.check_expiry(&targets, "targets.json")?;

        let mut out = Vec::with_capacity(names.len());

        for name in names {
            let meta = &targets["signed"]["targets"][*name];

            if meta.is_null() {
                return Err(format!("{name} is not a target of {}", self.url));
            }

            let length = meta["length"]
                .as_u64()
                .ok_or_else(|| format!("targets.json: {name} has no length"))?;
            let url = match (consistent, meta["hashes"]["sha256"].as_str()) {
                (true, Some(h)) => format!("{}/targets/{h}.{name}", self.url),
                (true, None) => return Err(format!("targets.json: {name} has no sha256 hash")),
                (false, _) => format!("{}/targets/{name}", self.url),
            };
            let bytes = self.get(&url, length)?;

            check_file(meta, &bytes, name, true)?;
            out.push(bytes);
        }

        self.store("timestamp.json", &timestamp_bytes)?;
        self.store("snapshot.json", &snapshot_bytes)?;
        self.store("targets.json", &targets_bytes)?;
        Ok(out)
    }

    /// The newest root: the trusted one, then each next version the
    /// repository has. Each must carry a threshold of signatures from the
    /// previous root's keys and from its own.
    fn update_root(&self) -> Result<Value> {
        let mut root = parse(&self.initial_root, "initial root.json")?;

        verify_role(
            &root,
            &root["signed"]["keys"],
            &root["signed"]["roles"]["root"],
            "initial root.json",
        )?;
        check_signed(&root, "root", None)?;

        // A root stored by an earlier run moves the start forward, so a
        // repository cannot roll this client back to an older root.
        if let Some(cached) = self.cached_root(&root)? {
            root = cached;
        }

        let start = version(&root)?;

        for _ in 0..MAX_ROOT_ROTATIONS {
            let next = version(&root)? + 1;
            let Some(bytes) =
                self.get_optional(&format!("{}/{next}.root.json", self.url), MAX_ROOT_BYTES)?
            else {
                break;
            };
            let candidate = parse(&bytes, &format!("{next}.root.json"))?;
            let what = format!("{next}.root.json");

            verify_role(
                &candidate,
                &root["signed"]["keys"],
                &root["signed"]["roles"]["root"],
                &what,
            )?;
            verify_role(
                &candidate,
                &candidate["signed"]["keys"],
                &candidate["signed"]["roles"]["root"],
                &what,
            )?;
            check_signed(&candidate, "root", Some(next))?;
            self.store("root.json", &bytes)?;
            root = candidate;
        }

        self.check_expiry(&root, "root.json")?;

        // New root keys can mean new timestamp and snapshot keys, which the
        // stored copies were not signed with.
        if version(&root)? != start {
            for name in ["timestamp.json", "snapshot.json", "targets.json"] {
                let _ = std::fs::remove_file(self.cache.join(name));
            }
        }
        Ok(root)
    }

    /// The root an earlier run stored, when it is newer than `trusted` and
    /// still signed by a threshold of its own keys.
    fn cached_root(&self, trusted: &Value) -> Result<Option<Value>> {
        let Ok(bytes) = std::fs::read(self.cache.join("root.json")) else {
            return Ok(None);
        };
        let Ok(cached) = parse(&bytes, "root.json") else {
            return Ok(None);
        };
        let signed = &cached["signed"];

        if check_signed(&cached, "root", None).is_err()
            || verify_role(
                &cached,
                &signed["keys"],
                &signed["roles"]["root"],
                "root.json",
            )
            .is_err()
        {
            return Ok(None);
        }
        Ok((version(&cached)? > version(trusted)?).then_some(cached))
    }

    /// Stored metadata that still verifies under the current root's keys.
    fn cached(&self, name: &str, keys: &Value, role: &Value) -> Option<Value> {
        let bytes = std::fs::read(self.cache.join(name)).ok()?;
        let meta = parse(&bytes, name).ok()?;

        verify_role(&meta, keys, role, name).ok().map(|_| meta)
    }

    fn store(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let path = self.cache.join(name);

        std::fs::create_dir_all(&self.cache)
            .map_err(|e| format!("{}: {e}", self.cache.display()))?;
        std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn metadata_url(&self, name: &str, version: u64, consistent: bool) -> String {
        if consistent {
            format!("{}/{version}.{name}", self.url)
        } else {
            format!("{}/{name}", self.url)
        }
    }

    fn check_expiry(&self, meta: &Value, what: &str) -> Result<()> {
        let expires = meta["signed"]["expires"]
            .as_str()
            .and_then(parse_iso8601)
            .ok_or_else(|| format!("{what}: expires is not an RFC 3339 time"))?;

        if self.now >= expires {
            return Err(format!("{what} expired at {}", format_iso8601(expires)));
        }
        Ok(())
    }

    fn get(&self, url: &str, max: u64) -> Result<Vec<u8>> {
        self.get_optional(url, max)?
            .ok_or_else(|| format!("{url}: not found"))
    }

    /// A GET where a missing file is `None`. Object stores answer 403 as well
    /// as 404 for a key that does not exist.
    fn get_optional(&self, url: &str, max: u64) -> Result<Option<Vec<u8>>> {
        let resp = match agent().get(url).call() {
            Ok(r) => r,
            Err(ureq::Error::Status(403 | 404, _)) => return Ok(None),
            Err(e) => return Err(crate::keyless_client::http_err(url, e)),
        };
        let mut body = Vec::new();

        std::io::Read::read_to_end(
            &mut std::io::Read::take(resp.into_reader(), max + 1),
            &mut body,
        )
        .map_err(|e| format!("{url}: {e}"))?;
        if body.len() as u64 > max {
            return Err(format!("{url}: larger than {max} bytes"));
        }
        Ok(Some(body))
    }
}

/// A cache directory name for a repository URL: its host and path, with
/// anything outside a conservative character set replaced.
fn cache_name(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);

    rest.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn parse(bytes: &[u8], what: &str) -> Result<Value> {
    serde_json::from_slice(bytes).map_err(|e| format!("{what}: {e}"))
}

fn version(meta: &Value) -> Result<u64> {
    meta["signed"]["version"]
        .as_u64()
        .ok_or_else(|| "metadata has no version".to_string())
}

fn version_of(meta: &Value, what: &str) -> Result<u64> {
    meta["version"]
        .as_u64()
        .ok_or_else(|| format!("{what}: no version"))
}

/// The checks every metadata file gets besides its signatures: its type, a
/// 1.x spec version, and, when the referring metadata names one, its version.
fn check_signed(meta: &Value, ty: &str, expected: Option<u64>) -> Result<()> {
    let signed = &meta["signed"];

    if signed["_type"].as_str() != Some(ty) {
        return Err(format!("{ty}.json: _type is not \"{ty}\""));
    }
    if !signed["spec_version"]
        .as_str()
        .is_some_and(|v| v == "1" || v.starts_with("1."))
    {
        return Err(format!("{ty}.json: unsupported spec_version"));
    }

    let v = version(meta)?;

    if v == 0 {
        return Err(format!("{ty}.json: version 0"));
    }
    if let Some(want) = expected {
        if v != want {
            return Err(format!("{ty}.json: version {v}, expected {want}"));
        }
    }
    Ok(())
}

/// A downloaded file against the `length` and `hashes` its referrer gives.
/// Target files must carry a hash this client knows; metadata files may omit
/// both.
fn check_file(meta: &Value, bytes: &[u8], what: &str, need_hash: bool) -> Result<()> {
    if let Some(len) = meta["length"].as_u64() {
        if bytes.len() as u64 != len {
            return Err(format!("{what}: length {}, expected {len}", bytes.len()));
        }
    }

    let mut checked = 0;

    for (alg, want) in meta["hashes"].as_object().into_iter().flatten() {
        let got = match alg.as_str() {
            "sha256" => hex(&Sha256::digest(bytes)),
            "sha512" => hex(&Sha512::digest(bytes)),
            _ => continue,
        };

        if Some(got.as_str()) != want.as_str() {
            return Err(format!("{what}: {alg} hash does not match"));
        }
        checked += 1;
    }
    if need_hash && checked == 0 {
        return Err(format!("{what}: no sha256 or sha512 hash to check"));
    }
    Ok(())
}

/// At least `threshold` distinct keys of `role` signed the canonical form of
/// `meta.signed`.
fn verify_role(meta: &Value, keys: &Value, role: &Value, what: &str) -> Result<()> {
    let threshold = role["threshold"]
        .as_u64()
        .filter(|t| *t >= 1)
        .ok_or_else(|| format!("{what}: role has no threshold"))?;
    let keyids: Vec<&str> = role["keyids"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let mut message = String::new();

    canonical_json(&meta["signed"], &mut message)?;

    // Counted by key material as well as by id, so one key listed under two
    // ids still counts once.
    let mut counted: Vec<&str> = Vec::new();

    for sig in meta["signatures"].as_array().into_iter().flatten() {
        let (Some(keyid), Some(sig)) = (sig["keyid"].as_str(), sig["sig"].as_str()) else {
            continue;
        };
        let key = &keys[keyid];
        let public = key["keyval"]["public"].as_str().unwrap_or_default();

        if !keyids.contains(&keyid) || counted.contains(&public) {
            continue;
        }
        if verify_signature(key, message.as_bytes(), sig) {
            counted.push(public);
        }
    }
    if (counted.len() as u64) < threshold {
        return Err(format!(
            "{what}: {} of the {threshold} required signatures verify",
            counted.len()
        ));
    }
    Ok(())
}

fn verify_signature(key: &Value, message: &[u8], sig_hex: &str) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    use p256::pkcs8::DecodePublicKey as _;

    let Some(sig) = unhex(sig_hex) else {
        return false;
    };
    let public = key["keyval"]["public"].as_str().unwrap_or_default();

    match key["scheme"].as_str() {
        Some("ecdsa-sha2-nistp256") => {
            let vk = if public.contains("-----BEGIN") {
                p256::ecdsa::VerifyingKey::from_public_key_pem(public).ok()
            } else {
                unhex(public).and_then(|b| p256::ecdsa::VerifyingKey::from_sec1_bytes(&b).ok())
            };

            match (vk, p256::ecdsa::Signature::from_der(&sig)) {
                (Some(vk), Ok(sig)) => vk.verify(message, &sig).is_ok(),
                _ => false,
            }
        }
        Some("ed25519") => {
            let Some(pk) = unhex(public).and_then(|b| <[u8; 32]>::try_from(b).ok()) else {
                return false;
            };
            let Ok(sig) = <[u8; 64]>::try_from(sig) else {
                return false;
            };

            ed25519_dalek::VerifyingKey::from_bytes(&pk).is_ok_and(|vk| {
                vk.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&sig))
                    .is_ok()
            })
        }
        _ => false,
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The canonical JSON TUF signs (OLPC canonical JSON, as securesystemslib
/// writes it): keys sorted, no whitespace, only `"` and `\` escaped, and
/// integers only.
fn canonical_json(v: &Value, out: &mut String) -> Result<()> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) if n.is_i64() || n.is_u64() => out.push_str(&n.to_string()),
        Value::Number(_) => return Err("TUF metadata holds a non-integer number".into()),
        Value::String(s) => canonical_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();

            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_string(k, out);
                out.push(':');
                canonical_json(&map[k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn canonical_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_keys_and_escapes_only_quote_and_backslash() {
        let mut out = String::new();

        canonical_json(
            &json!({ "b": [1, true, null], "a": "x\"y\\z\n", "_t": { "z": 0, "y": -2 } }),
            &mut out,
        )
        .unwrap();
        assert_eq!(
            out,
            "{\"_t\":{\"y\":-2,\"z\":0},\"a\":\"x\\\"y\\\\z\n\",\"b\":[1,true,null]}"
        );
    }

    #[test]
    fn canonical_json_refuses_floats() {
        assert!(canonical_json(&json!({ "a": 1.5 }), &mut String::new()).is_err());
    }

    #[test]
    fn the_embedded_root_is_signed_by_its_own_threshold() {
        let root: Value = serde_json::from_str(EMBEDDED_ROOT).unwrap();

        verify_role(
            &root,
            &root["signed"]["keys"],
            &root["signed"]["roles"]["root"],
            "root",
        )
        .unwrap();
        check_signed(&root, "root", Some(15)).unwrap();
    }

    #[test]
    fn a_changed_root_no_longer_verifies() {
        let mut root: Value = serde_json::from_str(EMBEDDED_ROOT).unwrap();

        root["signed"]["expires"] = json!("2099-01-01T00:00:00Z");

        let err = verify_role(
            &root,
            &root["signed"]["keys"],
            &root["signed"]["roles"]["root"],
            "root",
        )
        .unwrap_err();

        assert!(
            err.contains("0 of the 3 required signatures verify"),
            "{err}"
        );
    }

    #[test]
    fn cache_names_keep_hosts_readable() {
        assert_eq!(
            cache_name("https://tuf-repo-cdn.sigstore.dev"),
            "tuf-repo-cdn.sigstore.dev"
        );
        assert_eq!(
            cache_name("http://127.0.0.1:8080/tuf"),
            "127.0.0.1_8080_tuf"
        );
    }
}
