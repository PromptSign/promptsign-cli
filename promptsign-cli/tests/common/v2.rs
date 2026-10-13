// A mock Rekor v2 log (`/api/v2/log/entries`, returning a real inclusion
// proof and a checkpoint signed with an Ed25519 key) and a mock RFC 3161
// timestamp authority (`/tsa`), plus a TUF repository builder. Together with
// the Deployment in mod.rs they cover every service a v2 signature uses.

use base64::prelude::{Engine as _, BASE64_STANDARD};
use ed25519_dalek::Signer as _;
use promptsign_core::util::{format_iso8601, hex};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::TcpListener;
use std::path::Path;
use std::str::FromStr;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
const CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";
const MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
const TSA_POLICY: &str = "1.3.6.1.4.1.57264.2";

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];

    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();

        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn set(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

fn oid(s: &str) -> Vec<u8> {
    ObjectIdentifier::new_unwrap(s).to_der().unwrap()
}

fn int(v: u64) -> Vec<u8> {
    let mut bytes: Vec<u8> = v
        .to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect();

    if bytes.first().is_none_or(|b| b & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    tlv(0x02, &bytes)
}

fn generalized_time(t: i64) -> Vec<u8> {
    let s: String = format_iso8601(t)
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == 'Z')
        .collect();

    tlv(0x18, s.as_bytes())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn validity(not_before: i64, not_after: i64) -> Validity {
    use x509_cert::der::asn1::GeneralizedTime;
    use x509_cert::time::Time;

    let t = |s: i64| {
        Time::GeneralTime(
            GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(s as u64)).unwrap(),
        )
    };

    Validity {
        not_before: t(not_before),
        not_after: t(not_after),
    }
}

fn p256_spki(key: &p256::ecdsa::SigningKey) -> SubjectPublicKeyInfoOwned {
    use p256::pkcs8::EncodePublicKey;

    SubjectPublicKeyInfoOwned::from_der(key.verifying_key().to_public_key_der().unwrap().as_bytes())
        .unwrap()
}

fn leaf_hash(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();

    h.update([0u8]);
    h.update(data);
    h.finalize().to_vec()
}

fn node_hash(l: &[u8], r: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();

    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().to_vec()
}

fn mth(leaves: &[Vec<u8>]) -> Vec<u8> {
    if leaves.len() == 1 {
        return leaves[0].clone();
    }

    let k = leaves.len().next_power_of_two() / 2;

    node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
}

fn audit_path(m: usize, leaves: &[Vec<u8>]) -> Vec<Vec<u8>> {
    if leaves.len() == 1 {
        return Vec::new();
    }

    let k = leaves.len().next_power_of_two() / 2;

    if m < k {
        let mut p = audit_path(m, &leaves[..k]);

        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = audit_path(m - k, &leaves[k..]);

        p.push(mth(&leaves[..k]));
        p
    }
}

/// The signed-note key hash of an Ed25519 log key under `origin`, which is
/// also the log's id.
fn note_key_hash(origin: &str, key: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
    let mut h = Sha256::new();

    h.update(origin.as_bytes());
    h.update(b"\n\x01");
    h.update(key.as_bytes());
    h.finalize().to_vec()
}

fn checkpoint(origin: &str, key: &ed25519_dalek::SigningKey, size: u64, root: &[u8]) -> String {
    let text = format!("{origin}\n{size}\n{}\n", BASE64_STANDARD.encode(root));
    let mut sig = note_key_hash(origin, &key.verifying_key())[..4].to_vec();

    sig.extend(key.sign(text.as_bytes()).to_bytes());
    format!(
        "{text}\n\u{2014} {origin} {}\n",
        BASE64_STANDARD.encode(sig)
    )
}

struct Tsa {
    root: Certificate,
    cert: Certificate,
    key: p256::ecdsa::SigningKey,
}

impl Tsa {
    fn new(seed: u8) -> Tsa {
        let root_key = p256::ecdsa::SigningKey::from_slice(&[seed.wrapping_add(3); 32]).unwrap();
        let root_name = Name::from_str("CN=mock TSA root,O=promptsign tests").unwrap();
        let (from, to) = (now() - 3600, now() + 86400);
        let root = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            validity(from, to),
            root_name.clone(),
            p256_spki(&root_key),
            &root_key,
        )
        .unwrap()
        .build::<p256::ecdsa::DerSignature>()
        .unwrap();
        let key = p256::ecdsa::SigningKey::from_slice(&[seed.wrapping_add(4); 32]).unwrap();
        let mut leaf = CertificateBuilder::new(
            Profile::Leaf {
                issuer: root_name,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(2u32),
            validity(from, to),
            Name::from_str("CN=mock TSA,O=promptsign tests").unwrap(),
            p256_spki(&key),
            &root_key,
        )
        .unwrap();

        leaf.add_extension(&ExtendedKeyUsage(vec![ObjectIdentifier::new_unwrap(
            TIME_STAMPING,
        )]))
        .unwrap();

        Tsa {
            root,
            cert: leaf.build::<p256::ecdsa::DerSignature>().unwrap(),
            key,
        }
    }

    /// A granted TimeStampResp over a SHA-256 `digest`, dated now, with the
    /// timestamping certificate embedded.
    fn respond(&self, digest: &[u8]) -> Vec<u8> {
        let at = now();
        let imprint = seq(&[seq(&[oid(SHA256_OID), tlv(0x05, &[])]), tlv(0x04, digest)]);
        let tst_info = seq(&[
            int(1),
            oid(TSA_POLICY),
            imprint,
            int(at as u64),
            generalized_time(at),
        ]);
        let attrs = [
            seq(&[oid(CONTENT_TYPE), set(&[oid(TST_INFO)])]),
            seq(&[
                oid(MESSAGE_DIGEST),
                set(&[tlv(0x04, &Sha256::digest(&tst_info))]),
            ]),
        ]
        .concat();
        let signature: p256::ecdsa::DerSignature = self.key.sign(&tlv(0x31, &attrs));
        let signer_info = seq(&[
            int(1),
            seq(&[
                self.cert.tbs_certificate.issuer.to_der().unwrap(),
                self.cert.tbs_certificate.serial_number.to_der().unwrap(),
            ]),
            seq(&[oid(SHA256_OID)]),
            tlv(0xa0, &attrs),
            seq(&[oid(ECDSA_SHA256)]),
            tlv(0x04, signature.as_bytes()),
        ]);
        let signed_data = seq(&[
            int(3),
            set(&[seq(&[oid(SHA256_OID)])]),
            seq(&[oid(TST_INFO), tlv(0xa0, &tlv(0x04, &tst_info))]),
            tlv(0xa0, &self.cert.to_der().unwrap()),
            set(&[signer_info]),
        ]);

        seq(&[
            seq(&[int(0)]),
            seq(&[oid(SIGNED_DATA), tlv(0xa0, &signed_data)]),
        ])
    }
}

/// The SHA-256 hashedMessage of a TimeStampReq: the 32 bytes after the
/// OCTET STRING header that follows the SHA-256 AlgorithmIdentifier.
fn requested_digest(req: &[u8]) -> Option<Vec<u8>> {
    let alg = seq(&[oid(SHA256_OID), tlv(0x05, &[])]);
    let at = req.windows(alg.len()).position(|w| w == alg.as_slice())? + alg.len();

    (req.get(at..at + 2)? == [0x04, 0x20]).then(|| req.get(at + 2..at + 34).map(<[u8]>::to_vec))?
}

/// A Rekor v2 log and a timestamp authority on one localhost port.
pub struct V2Services {
    pub port: u16,
    log_key: ed25519_dalek::SigningKey,
    tsa_root: Certificate,
    tsa_cert: Certificate,
}

impl V2Services {
    pub fn start(seed: u8) -> V2Services {
        let log_key = ed25519_dalek::SigningKey::from_bytes(&[seed.wrapping_add(9); 32]);
        let tsa = Tsa::new(seed);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let services = V2Services {
            port,
            log_key: log_key.clone(),
            tsa_root: tsa.root.clone(),
            tsa_cert: tsa.cert.clone(),
        };
        let origin = services.origin();
        let log_id = note_key_hash(&origin, &log_key.verifying_key());

        std::thread::spawn(move || {
            // Two entries before the first real one, so proofs have hashes.
            let mut leaves = vec![leaf_hash(b"entry 0"), leaf_hash(b"entry 1")];

            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (line, body) = super::read_request(&mut stream);

                if line.contains("/api/v2/log/entries") {
                    let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    let r = &req["hashedRekordRequestV002"];
                    let entry = json!({
                        "apiVersion": "0.0.2",
                        "kind": "hashedrekord",
                        "spec": { "hashedRekordV002": {
                            "data": { "algorithm": "SHA2_256", "digest": r["digest"] },
                            "signature": {
                                "content": r["signature"]["content"],
                                "verifier": r["signature"]["verifier"]
                            }
                        } }
                    });
                    let entry_bytes = serde_json::to_vec(&entry).unwrap();

                    leaves.push(leaf_hash(&entry_bytes));

                    let index = leaves.len() - 1;
                    let root = mth(&leaves);
                    let out = json!({
                        "logIndex": index.to_string(),
                        "logId": { "keyId": BASE64_STANDARD.encode(&log_id) },
                        "kindVersion": { "kind": "hashedrekord", "version": "0.0.2" },
                        "integratedTime": "0",
                        "inclusionProof": {
                            "logIndex": index.to_string(),
                            "rootHash": BASE64_STANDARD.encode(&root),
                            "treeSize": leaves.len().to_string(),
                            "hashes": audit_path(index, &leaves)
                                .iter()
                                .map(|h| BASE64_STANDARD.encode(h))
                                .collect::<Vec<_>>(),
                            "checkpoint": { "envelope": checkpoint(&origin, &log_key, leaves.len() as u64, &root) }
                        },
                        "canonicalizedBody": BASE64_STANDARD.encode(&entry_bytes)
                    });

                    super::respond(
                        &mut stream,
                        "201 Created",
                        &serde_json::to_vec(&out).unwrap(),
                    );
                } else if line.contains("/tsa") {
                    match requested_digest(&body) {
                        Some(d) => super::respond(&mut stream, "200 OK", &tsa.respond(&d)),
                        None => super::respond(&mut stream, "400 Bad Request", b"{}"),
                    }
                } else if line.contains("/refuse") {
                    // A TimeStampResp with status 2, rejection.
                    super::respond(&mut stream, "200 OK", &seq(&[seq(&[int(2)])]));
                } else {
                    super::respond(&mut stream, "404 Not Found", b"{}");
                }
            }
        });
        services
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn tsa_url(&self) -> String {
        format!("{}/tsa", self.url())
    }

    /// The log's origin: the host of the base URL the trusted root lists,
    /// which can differ from the address the client posts to.
    pub fn origin(&self) -> String {
        format!(
            "rekor-{}.test",
            hex(&self.log_key.verifying_key().as_bytes()[..4])
        )
    }

    /// `doc` (a deployment's trusted_root.json) with this log and timestamp
    /// authority added, as `trust fetch` would write it.
    pub fn add_to(&self, doc: &mut Value, with_tsa: bool) {
        use ed25519_dalek::pkcs8::EncodePublicKey;

        let key = self.log_key.verifying_key();
        let raw =
            |c: &Certificate| json!({ "rawBytes": BASE64_STANDARD.encode(c.to_der().unwrap()) });

        doc["tlogs"].as_array_mut().unwrap().push(json!({
            "baseUrl": format!("https://{}", self.origin()),
            "hashAlgorithm": "SHA2_256",
            "publicKey": {
                "rawBytes": BASE64_STANDARD.encode(key.to_public_key_der().unwrap().as_bytes()),
                "keyDetails": "PKIX_ED25519"
            },
            "logId": { "keyId": BASE64_STANDARD.encode(note_key_hash(&self.origin(), &key)) }
        }));
        if with_tsa {
            doc["timestampAuthorities"] = json!([{
                "subject": { "commonName": "mock TSA" },
                "uri": self.tsa_url(),
                "certChain": { "certificates": [raw(&self.tsa_cert), raw(&self.tsa_root)] }
            }]);
        }
    }
}

/// A Sigstore SigningConfig v0.2 with one service of each kind.
pub fn signing_config(fulcio: &str, rekor: &str, rekor_version: u64, tsa: Option<&str>) -> Value {
    let service = |url: &str, version: u64| json!({ "url": url, "majorApiVersion": version, "validFor": { "start": "2021-01-01T00:00:00Z" }, "operator": "test" });

    json!({
        "mediaType": "application/vnd.dev.sigstore.signingconfig.v0.2+json",
        "caUrls": [service(fulcio, 1)],
        "oidcUrls": [],
        "rekorTlogUrls": [service(rekor, rekor_version)],
        "tsaUrls": tsa.map(|t| vec![service(t, 1)]).unwrap_or_default(),
        "rekorTlogConfig": { "selector": "ANY" },
        "tsaConfig": { "selector": "ANY" }
    })
}

// ---- TUF ----

fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();

            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(&Value::String(k.clone()), out);
                out.push(':');
                canonical(&map[k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(item, out);
            }
            out.push(']');
        }
        Value::String(s) => {
            out.push('"');
            for c in s.chars() {
                if c == '"' || c == '\\' {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('"');
        }
        other => out.push_str(&other.to_string()),
    }
}

pub struct TufKey(p256::ecdsa::SigningKey);

impl TufKey {
    pub fn new(seed: u8) -> TufKey {
        TufKey(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap())
    }

    fn public(&self) -> Value {
        use p256::pkcs8::EncodePublicKey;

        json!({
            "keytype": "ecdsa",
            "scheme": "ecdsa-sha2-nistp256",
            "keyval": { "public": self.0.verifying_key().to_public_key_pem(Default::default()).unwrap() }
        })
    }

    pub fn id(&self) -> String {
        let mut c = String::new();

        canonical(&self.public(), &mut c);
        hex(&Sha256::digest(c.as_bytes()))
    }
}

/// `signed`, wrapped with a signature by each of `keys`.
pub fn sign_metadata(signed: Value, keys: &[&TufKey]) -> Vec<u8> {
    let mut c = String::new();

    canonical(&signed, &mut c);

    let signatures: Vec<Value> = keys
        .iter()
        .map(|k| {
            let sig: p256::ecdsa::DerSignature = k.0.sign(c.as_bytes());

            json!({ "keyid": k.id(), "sig": hex(sig.as_bytes()) })
        })
        .collect();

    serde_json::to_vec_pretty(&json!({ "signatures": signatures, "signed": signed })).unwrap()
}

/// Root metadata where `key` holds every role.
pub fn root(version: u64, key: &TufKey, expires: &str) -> Value {
    let role = json!({ "keyids": [key.id()], "threshold": 1 });

    json!({
        "_type": "root",
        "spec_version": "1.0",
        "version": version,
        "expires": expires,
        "consistent_snapshot": true,
        "keys": { key.id(): key.public() },
        "roles": { "root": role, "targets": role, "snapshot": role, "timestamp": role }
    })
}

fn file_meta(bytes: &[u8]) -> Value {
    json!({ "length": bytes.len(), "hashes": { "sha256": hex(&Sha256::digest(bytes)) } })
}

/// Timestamp, snapshot and targets metadata for `targets`, all signed by
/// `key`, and the target files at their consistent-snapshot paths, under
/// `dir`. `version` numbers all three.
pub fn publish(dir: &Path, key: &TufKey, version: u64, expires: &str, targets: &[(&str, &[u8])]) {
    std::fs::create_dir_all(dir.join("targets")).unwrap();

    let mut listed = serde_json::Map::new();

    for (name, bytes) in targets {
        let meta = file_meta(bytes);

        std::fs::write(
            dir.join("targets").join(format!(
                "{}.{name}",
                meta["hashes"]["sha256"].as_str().unwrap()
            )),
            bytes,
        )
        .unwrap();
        listed.insert(name.to_string(), meta);
    }

    let targets_json = sign_metadata(
        json!({ "_type": "targets", "spec_version": "1.0", "version": version, "expires": expires, "targets": listed }),
        &[key],
    );
    let snapshot_json = sign_metadata(
        json!({ "_type": "snapshot", "spec_version": "1.0", "version": version, "expires": expires,
                "meta": { "targets.json": { "version": version } } }),
        &[key],
    );
    let mut snapshot_meta = file_meta(&snapshot_json);

    snapshot_meta["version"] = json!(version);

    let timestamp_json = sign_metadata(
        json!({ "_type": "timestamp", "spec_version": "1.0", "version": version, "expires": expires,
                "meta": { "snapshot.json": snapshot_meta } }),
        &[key],
    );

    std::fs::write(dir.join(format!("{version}.targets.json")), targets_json).unwrap();
    std::fs::write(dir.join(format!("{version}.snapshot.json")), snapshot_json).unwrap();
    std::fs::write(dir.join("timestamp.json"), timestamp_json).unwrap();
}
