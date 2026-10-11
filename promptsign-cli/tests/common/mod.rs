// A mock Sigstore deployment on localhost for end-to-end tests: Fulcio
// (`/api/v2/signingCert`, issuing real certificates for the CLI's ephemeral
// key under one fixed identity) and Rekor (`/api/v1/log/entries`, returning a
// real signed entry timestamp), plus `/files/<name>`, which serves a directory
// byte for byte so `trust add <url>` and `trust fetch` run over real HTTP.

#![allow(dead_code)]

use base64::prelude::{Engine as _, BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::pkcs8::EncodePublicKey as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::{Ia5String, Utf8StringRef};
use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::der::{Decode, Encode, EncodePem, Length, Writer};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::AsExtension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

pub const GH: &str = "https://token.actions.githubusercontent.com";

struct IssuerExt(String);

impl AssociatedOid for IssuerExt {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57264.1.8");
}
impl Encode for IssuerExt {
    fn encoded_len(&self) -> x509_cert::der::Result<Length> {
        Utf8StringRef::new(&self.0)?.encoded_len()
    }
    fn encode(&self, w: &mut impl Writer) -> x509_cert::der::Result<()> {
        Utf8StringRef::new(&self.0)?.encode(w)
    }
}
impl AsExtension for IssuerExt {
    fn critical(&self, _: &Name, _: &[x509_cert::ext::Extension]) -> bool {
        false
    }
}

fn read_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end;

    loop {
        let n = stream.read(&mut tmp).unwrap();

        if n == 0 {
            return (String::new(), Vec::new());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = i + 4;
            break;
        }
    }

    let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let content_length: usize = headers
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let mut body = buf[header_end..].to_vec();

    while body.len() < content_length {
        let n = stream.read(&mut tmp).unwrap();

        body.extend_from_slice(&tmp[..n]);
    }
    (headers.lines().next().unwrap_or_default().to_string(), body)
}

fn respond(stream: &mut TcpStream, status: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );

    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
}

fn pem_body(pem: &str) -> Vec<u8> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();

    BASE64_STANDARD.decode(b64).unwrap()
}

pub struct Deployment {
    pub port: u16,
    pub ca_pem: String,
    pub rekor_pem: String,
    ca_der: Vec<u8>,
    rekor_der: Vec<u8>,
    /// Served at `/files/<name>`.
    pub files: PathBuf,
}

impl Deployment {
    /// A deployment whose keys derive from `seed`, issuing every certificate
    /// for `identity` under the GitHub Actions issuer.
    pub fn start(seed: u8, identity: &str, files: &Path) -> Deployment {
        let ca_key = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let ca_name = Name::from_str(&format!("CN=mock fulcio {seed}")).unwrap();
        let ca_spki = SubjectPublicKeyInfoOwned::from_der(
            ca_key
                .verifying_key()
                .to_public_key_der()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let ca_cert: Certificate = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            Validity::from_now(Duration::from_secs(3600 * 24)).unwrap(),
            ca_name.clone(),
            ca_spki,
            &ca_key,
        )
        .unwrap()
        .build::<p256::ecdsa::DerSignature>()
        .unwrap();
        let ca_pem = ca_cert.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap();
        let rekor_key = p256::ecdsa::SigningKey::from_slice(&[seed.wrapping_add(1); 32]).unwrap();
        let rekor_der = rekor_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let rekor_pem = rekor_key
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        let log_id: String = Sha256::digest(&rekor_der)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = files.to_path_buf();
        let identity = identity.to_string();
        let chain_ca = ca_pem.clone();

        std::fs::create_dir_all(files).unwrap();
        std::thread::spawn(move || {
            let mut serial = 7u32;

            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let (line, body) = read_request(&mut stream);
                let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);

                if line.contains("/api/v2/signingCert") {
                    let pem = req["publicKeyRequest"]["publicKey"]["content"]
                        .as_str()
                        .unwrap();
                    let leaf_spki = SubjectPublicKeyInfoOwned::from_der(&pem_body(pem)).unwrap();

                    serial += 1;

                    let mut b = CertificateBuilder::new(
                        Profile::Leaf {
                            issuer: ca_name.clone(),
                            enable_key_agreement: false,
                            enable_key_encipherment: false,
                        },
                        SerialNumber::from(serial),
                        Validity::from_now(Duration::from_secs(600)).unwrap(),
                        Name::from_str("CN=mock-leaf").unwrap(),
                        leaf_spki,
                        &ca_key,
                    )
                    .unwrap();

                    b.add_extension(&SubjectAltName(vec![
                        GeneralName::UniformResourceIdentifier(Ia5String::new(&identity).unwrap()),
                    ]))
                    .unwrap();
                    b.add_extension(&IssuerExt(GH.to_string())).unwrap();

                    let leaf: Certificate = b.build::<p256::ecdsa::DerSignature>().unwrap();
                    let leaf_pem = leaf.to_pem(x509_cert::der::pem::LineEnding::LF).unwrap();
                    let out = json!({ "signedCertificateEmbeddedSct": { "chain": { "certificates": [leaf_pem, chain_ca] } } });

                    respond(&mut stream, "200 OK", &serde_json::to_vec(&out).unwrap());
                } else if line.contains("/api/v1/log/entries") {
                    let verifier = &req["spec"]["proposedContent"]["verifiers"][0];
                    let envelope: Value = serde_json::from_str(
                        req["spec"]["proposedContent"]["envelope"].as_str().unwrap(),
                    )
                    .unwrap();
                    let payload = BASE64_STANDARD
                        .decode(envelope["payload"].as_str().unwrap())
                        .unwrap();
                    let payload_hash: String = Sha256::digest(&payload)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    let entry = json!({
                        "apiVersion": "0.0.1",
                        "kind": "dsse",
                        "spec": {
                            "payloadHash": { "algorithm": "sha256", "value": payload_hash },
                            "signatures": [{ "signature": envelope["signatures"][0]["sig"], "verifier": verifier }]
                        }
                    });
                    let body_b64 = BASE64_STANDARD.encode(serde_json::to_vec(&entry).unwrap());
                    let t = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;

                    serial += 1;

                    let canonical = format!(
                        "{{\"body\":{},\"integratedTime\":{t},\"logID\":{},\"logIndex\":{serial}}}",
                        serde_json::to_string(&body_b64).unwrap(),
                        serde_json::to_string(&log_id).unwrap()
                    );
                    let set: p256::ecdsa::Signature = rekor_key
                        .sign_prehash(&Sha256::digest(canonical.as_bytes()))
                        .unwrap();
                    let out = json!({ "e2e-uuid": {
                        "body": body_b64,
                        "integratedTime": t,
                        "logID": log_id,
                        "logIndex": serial,
                        "verification": { "signedEntryTimestamp": BASE64_STANDARD.encode(set.to_der()) }
                    } });

                    respond(
                        &mut stream,
                        "201 Created",
                        &serde_json::to_vec(&out).unwrap(),
                    );
                } else if let Some(name) = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|p| p.strip_prefix("/files/"))
                {
                    match std::fs::read(served.join(name)) {
                        Ok(bytes) => respond(&mut stream, "200 OK", &bytes),
                        Err(_) => respond(&mut stream, "404 Not Found", b"{}"),
                    }
                } else {
                    respond(&mut stream, "404 Not Found", b"{}");
                }
            }
        });

        Deployment {
            port,
            ca_pem,
            rekor_pem,
            ca_der: ca_cert.to_der().unwrap(),
            rekor_der,
            files: files.to_path_buf(),
        }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// A trust directory pinning this deployment as the built-in root.
    pub fn trust_dir(&self, dir: &Path) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("fulcio.pem"), &self.ca_pem).unwrap();
        std::fs::write(dir.join("rekor.pub"), &self.rekor_pem).unwrap();
        dir.to_path_buf()
    }

    pub fn trusted_root(&self) -> Value {
        json!({
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": [{
                "hashAlgorithm": "SHA2_256",
                "publicKey": {
                    "rawBytes": BASE64_STANDARD.encode(&self.rekor_der),
                    "keyDetails": "PKIX_ECDSA_P256_SHA_256"
                },
                "logId": { "keyId": BASE64_STANDARD.encode(Sha256::digest(&self.rekor_der)) }
            }],
            "certificateAuthorities": [{
                "subject": { "commonName": "mock" },
                "certChain": { "certificates": [{ "rawBytes": BASE64_STANDARD.encode(&self.ca_der) }] }
            }],
            "ctlogs": [],
            "timestampAuthorities": []
        })
    }
}

/// An unsigned OIDC token for `subject`. The mock Fulcio does not check it.
pub fn token(subject: &str) -> String {
    format!(
        "{}.{}.sig",
        BASE64_URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
        BASE64_URL_SAFE_NO_PAD.encode(format!("{{\"sub\":\"{subject}\"}}").as_bytes())
    )
}

pub fn rfc3339(offset_secs: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    promptsign_core::util::format_iso8601(now + offset_secs)
}
