// Which certificate authority, transparency log and timestamp authorities a
// keyless signature goes through (spec/05 §6): a Sigstore SigningConfig v0.2
// document, read from $PROMPTSIGN_SIGNING_CONFIG or the trust directory, with
// each service picked by its validity window and API version.

use crate::keyless_client::{DEFAULT_FULCIO, DEFAULT_REKOR};
use promptsign_core::keyless::trust_dir;
use promptsign_core::util::parse_iso8601;
use promptsign_core::Result;
use serde_json::Value;

pub const MEDIA_TYPE: &str = "application/vnd.dev.sigstore.signingconfig.v0.2+json";

/// The trust-directory file `trust fetch` writes the public config to.
pub const FILE: &str = "signing_config.json";

/// Timestamps a bundle may carry (spec/05 §1).
const MAX_TIMESTAMPS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoints {
    pub fulcio: String,
    pub rekor: String,
    /// The log's major API version: 1 takes `dsse` entries and returns a
    /// signed entry timestamp, 2 takes `hashedrekord` 0.0.2 entries and
    /// returns an inclusion proof.
    pub rekor_version: u64,
    pub tsas: Vec<String>,
}

struct Service<'a> {
    url: &'a str,
    version: u64,
    start: i64,
    operator: &'a str,
}

/// The services of one list that are valid at `now` and speak a supported
/// API version: for each operator, the one with the highest version, then
/// the latest start. Operators keep document order.
fn per_operator<'a>(
    doc: &'a Value,
    list: &str,
    supported: &[u64],
    now: i64,
) -> Result<Vec<Service<'a>>> {
    let mut best: Vec<Service<'a>> = Vec::new();

    for s in doc[list].as_array().into_iter().flatten() {
        let url = s["url"]
            .as_str()
            .filter(|u| !u.is_empty())
            .ok_or_else(|| format!("signing config: {list} entry has no url"))?;
        let version = s["majorApiVersion"].as_u64().unwrap_or(1);
        let time = |key: &str| -> Result<Option<i64>> {
            match &s["validFor"][key] {
                Value::Null => Ok(None),
                t => t.as_str().and_then(parse_iso8601).map(Some).ok_or_else(|| {
                    format!("signing config: {url}: validFor.{key} is not an RFC 3339 time")
                }),
            }
        };
        let start =
            time("start")?.ok_or_else(|| format!("signing config: {url} has no validFor.start"))?;
        let end = time("end")?;

        if now < start || end.is_some_and(|e| now >= e) || !supported.contains(&version) {
            continue;
        }

        let candidate = Service {
            url: url.trim_end_matches('/'),
            version,
            start,
            operator: s["operator"].as_str().unwrap_or_default(),
        };

        match best.iter_mut().find(|b| b.operator == candidate.operator) {
            Some(b) if (candidate.version, candidate.start) > (b.version, b.start) => {
                *b = candidate
            }
            Some(_) => {}
            None => best.push(candidate),
        }
    }
    Ok(best)
}

/// How many services a selector asks for, out of `available` operators.
fn wanted(config: &Value, available: usize, what: &str) -> Result<usize> {
    match config["selector"].as_str().unwrap_or("ANY") {
        "ANY" => Ok(available.min(1)),
        "ALL" => Ok(available),
        "EXACT" => {
            let count = config["count"]
                .as_u64()
                .filter(|c| *c >= 1)
                .ok_or_else(|| {
                    format!("signing config: the EXACT selector for {what} needs a count")
                })? as usize;

            if count > available {
                return Err(format!(
                    "signing config asks for {count} {what}, and {available} are valid now"
                ));
            }
            Ok(count)
        }
        other => Err(format!(
            "signing config: unknown selector \"{other}\" for {what}"
        )),
    }
}

/// Pick the endpoints a signature made at `now` uses.
pub fn select(doc: &Value, now: i64) -> Result<Endpoints> {
    if doc["mediaType"].as_str() != Some(MEDIA_TYPE) {
        return Err(format!("signing config: mediaType is not {MEDIA_TYPE}"));
    }

    let ca = per_operator(doc, "caUrls", &[1], now)?
        .into_iter()
        .max_by_key(|s| (s.version, s.start))
        .ok_or("signing config: no certificate authority is valid now")?;
    let logs = per_operator(doc, "rekorTlogUrls", &[1, 2], now)?;
    let log_count = wanted(&doc["rekorTlogConfig"], logs.len(), "transparency logs")?;

    // A PromptSign bundle staples one log entry (spec/05 §1). Logging to one
    // log when the config asks for more would weaken it without telling you.
    if log_count > 1 {
        return Err(format!(
            "signing config asks for {log_count} transparency log entries; a PromptSign bundle carries one"
        ));
    }

    let log = logs
        .into_iter()
        .max_by_key(|s| (s.version, s.start))
        .ok_or("signing config: no transparency log is valid now")?;
    let tsas = per_operator(doc, "tsaUrls", &[1], now)?;
    let tsa_count = wanted(&doc["tsaConfig"], tsas.len(), "timestamp authorities")?;

    if tsa_count > MAX_TIMESTAMPS {
        return Err(format!(
            "signing config asks for {tsa_count} timestamps; a bundle carries at most {MAX_TIMESTAMPS}"
        ));
    }

    let mut tsas = tsas;

    tsas.sort_by_key(|s| std::cmp::Reverse((s.version, s.start)));

    Ok(Endpoints {
        fulcio: ca.url.to_string(),
        rekor: log.url.to_string(),
        rekor_version: log.version,
        tsas: tsas
            .iter()
            .take(tsa_count)
            .map(|s| s.url.to_string())
            .collect(),
    })
}

fn env(var: &str) -> Option<String> {
    std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .map(|v| v.trim_end_matches('/').to_string())
}

/// The endpoints for a signature made now. The config is
/// `$PROMPTSIGN_SIGNING_CONFIG` when set, else the trust directory's
/// `signing_config.json`, else public Fulcio and Rekor v1 with no timestamp
/// authority. The trust-directory file describes the public instance, so
/// this skips it when PROMPTSIGN_FULCIO_URL or PROMPTSIGN_REKOR_URL points
/// elsewhere. Those two and PROMPTSIGN_TSA_URL then replace the picked URLs.
pub fn resolve() -> Result<Endpoints> {
    let fulcio = env("PROMPTSIGN_FULCIO_URL");
    let rekor = env("PROMPTSIGN_REKOR_URL");
    let path = match env("PROMPTSIGN_SIGNING_CONFIG") {
        Some(p) => Some(std::path::PathBuf::from(p)),
        None if fulcio.is_none() && rekor.is_none() => {
            Some(trust_dir().join(FILE)).filter(|p| p.exists())
        }
        None => None,
    };
    let mut endpoints = match path {
        Some(p) => {
            let doc: Value = serde_json::from_slice(
                &std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?,
            )
            .map_err(|e| format!("{}: {e}", p.display()))?;
            select(&doc, crate::keyless_client::now())
                .map_err(|e| format!("{}: {e}", p.display()))?
        }
        None => Endpoints {
            fulcio: DEFAULT_FULCIO.to_string(),
            rekor: DEFAULT_REKOR.to_string(),
            rekor_version: 1,
            tsas: Vec::new(),
        },
    };

    if let Some(u) = fulcio {
        endpoints.fulcio = u;
    }
    if let Some(u) = rekor {
        endpoints.rekor = u;
    }
    if let Some(u) = env("PROMPTSIGN_TSA_URL") {
        endpoints.tsas = vec![u];
    }
    Ok(endpoints)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: i64 = 1_790_000_000; // 2026-09-21

    fn service(url: &str, version: u64, start: &str, operator: &str) -> Value {
        json!({ "url": url, "majorApiVersion": version, "validFor": { "start": start }, "operator": operator })
    }

    fn config(logs: Vec<Value>, tsas: Vec<Value>) -> Value {
        json!({
            "mediaType": MEDIA_TYPE,
            "caUrls": [service("https://fulcio.example", 1, "2022-04-13T20:06:15.000Z", "a")],
            "rekorTlogUrls": logs,
            "tsaUrls": tsas,
            "rekorTlogConfig": { "selector": "ANY" },
            "tsaConfig": { "selector": "ANY" }
        })
    }

    #[test]
    fn the_public_default_config_signs_to_rekor_v1_with_a_timestamp() {
        let doc = config(
            vec![service(
                "https://rekor.example",
                1,
                "2021-01-12T11:53:27.000Z",
                "a",
            )],
            vec![service(
                "https://tsa.example/api/v1/timestamp",
                1,
                "2025-07-04T00:00:00Z",
                "a",
            )],
        );

        assert_eq!(
            select(&doc, NOW).unwrap(),
            Endpoints {
                fulcio: "https://fulcio.example".into(),
                rekor: "https://rekor.example".into(),
                rekor_version: 1,
                tsas: vec!["https://tsa.example/api/v1/timestamp".into()],
            }
        );
    }

    #[test]
    fn a_v2_log_wins_once_its_window_opens() {
        let doc = config(
            vec![
                service("https://log2.example", 2, "2026-01-01T00:00:00Z", "a"),
                service("https://rekor.example", 1, "2021-01-12T11:53:27.000Z", "a"),
            ],
            vec![],
        );
        let before = parse_iso8601("2025-12-31T23:59:59Z").unwrap();

        assert_eq!(select(&doc, before).unwrap().rekor, "https://rekor.example");

        let after = select(&doc, NOW).unwrap();

        assert_eq!(
            (after.rekor.as_str(), after.rekor_version),
            ("https://log2.example", 2)
        );
        assert!(after.tsas.is_empty());
    }

    #[test]
    fn closed_windows_and_unknown_versions_are_skipped() {
        let mut old = service("https://old.example", 1, "2020-01-01T00:00:00Z", "a");

        old["validFor"]["end"] = json!("2021-01-01T00:00:00Z");

        let doc = config(
            vec![
                old,
                service("https://v3.example", 3, "2025-01-01T00:00:00Z", "a"),
                service("https://rekor.example", 1, "2021-01-12T11:53:27Z", "a"),
            ],
            vec![],
        );

        assert_eq!(select(&doc, NOW).unwrap().rekor, "https://rekor.example");
    }

    #[test]
    fn a_config_that_needs_two_log_entries_is_refused() {
        let mut doc = config(
            vec![
                service("https://one.example", 1, "2021-01-01T00:00:00Z", "a"),
                service("https://two.example", 1, "2021-01-01T00:00:00Z", "b"),
            ],
            vec![],
        );

        doc["rekorTlogConfig"] = json!({ "selector": "ALL" });

        let err = select(&doc, NOW).unwrap_err();

        assert!(err.contains("asks for 2 transparency log entries"), "{err}");
    }

    #[test]
    fn exact_takes_that_many_timestamp_authorities() {
        let mut doc = config(
            vec![service(
                "https://rekor.example",
                1,
                "2021-01-01T00:00:00Z",
                "a",
            )],
            vec![
                service("https://t1.example", 1, "2025-01-01T00:00:00Z", "a"),
                service("https://t2.example", 1, "2025-02-01T00:00:00Z", "b"),
            ],
        );

        doc["tsaConfig"] = json!({ "selector": "EXACT", "count": 2 });
        assert_eq!(select(&doc, NOW).unwrap().tsas.len(), 2);

        doc["tsaConfig"] = json!({ "selector": "EXACT", "count": 3 });
        assert!(select(&doc, NOW)
            .unwrap_err()
            .contains("asks for 3 timestamp authorities"));
    }

    #[test]
    fn a_document_of_another_type_is_refused() {
        let mut doc = config(vec![], vec![]);

        doc["mediaType"] = json!("application/vnd.dev.sigstore.trustedroot+json;version=0.1");
        assert!(select(&doc, NOW).unwrap_err().contains("mediaType"));
    }
}
