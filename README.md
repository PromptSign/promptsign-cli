# promptsign (CLI)

The `promptsign` command signs and verifies AI instruction files—including skills,
agent definitions, `CLAUDE.md`, and `AGENTS.md`—along with their accompanying
script payloads.

### Architectural Constraints

It ships as a **single static binary** because it runs inside `SessionStart` and
`PreToolUse` hooks on every agent session and skill invocation. 

* **Zero Dependencies** – Consumer machines require nothing preinstalled.
* **Instant Execution** – Startup time directly impacts perceived user latency,
not build time.

### Quick Reference

* **Usage** – Run `promptsign --help` for the authoritative, feature-flag-aware CLI
documentation.
This file does not duplicate it.
* **Wire Formats** – Formats are strictly defined in [PromptSign/spec](https://github.com/PromptSign/spec).
* **Verification Logic** – Core verification architecture lives exclusively inside
[`promptsign-core`](https://github.com/PromptSign/promptsign-core).

## Building

```bash
cargo build --release      # target/release/promptsign
```

A clone of this repo alone is enough. `promptsign-core` is a **git dependency**
on its own public repository, pinned by tag in `promptsign-cli/Cargo.toml` and
by commit in the committed `Cargo.lock`, so the only requirement is network
access to github.com on the first build. Cargo caches the checkout afterwards,
and `--offline` works from then on.

To develop against a local core rather than the pinned tag, override the
dependency in `.cargo/config.toml` (untracked) rather than editing
`Cargo.toml`:

```toml
[patch."https://github.com/PromptSign/promptsign-core"]
promptsign-core = { path = "../promptsign-core/promptsign-core" }
```

The path is relative to this repo's root — the parent of `.cargo/`, not the
config file itself — so it assumes a sibling checkout:

```
<parent>/
  promptsign-cli/     <- this repo
  promptsign-core/
```

While that patch is active, cargo rewrites `Cargo.lock` to drop core's
`source` line. Don't commit that: releases must build from the pinned tag.

### Feature flags

| Feature | Default | Effect |
|---|---|---|
| `local-key` | **off** | Adds `keygen` and `sign --local-key` (Ed25519 signing with a long-lived local key). |

Release binaries are built **without** it, so they are keyless-only: signing
means an identity, never a key file sitting on a laptop. *Verifying* local-key
bundles is always compiled in, regardless of the flag — old bundles keep
working. Note that `--help` output differs between the two builds.

```bash
cargo build --release --features local-key
```

### Release profile

`lto = true`, `strip = true`, `codegen-units = 1` — set at the workspace root
and deliberate: this binary's startup time is a tax on every agent session.

`Cargo.lock` **is** committed. It is a binary crate and builds should be
reproducible.

## Where the network lives

All network access in PromptSign is in this crate, and that is an architectural
invariant rather than an accident:

- `keyless_client.rs` — Fulcio certificate request, Rekor log submission
- `login.rs` — interactive browser sign-in, token cache
- `proxy.rs` — local CORS proxy for in-browser signing
- `trust fetch` / `revoke fetch` — one-time and opportunistic cache refreshes

`ureq` is a dependency **here only**. `promptsign-core` has no HTTP client and
no TLS stack anywhere in its tree, which is what makes the verify path offline
*by construction* instead of by promise. Verification must work on a plane and
in a sealed CI sandbox, and must never be able to phone home.

Adding a network call to a verify path — or a network crate to core — breaks
this. Keep new online behavior in this crate, behind an explicit subcommand.

## Testing

```bash
cargo test                          # Unit + E2E tests
cargo test --features local-key     # Covers local-key code paths
```

### Keyless E2E Suite
`tests/keyless_e2e.rs` executes the full keyless flow (token exchange, certificate issuance, log entry, stapled bundle creation, and offline verification) locally.

* **Hermetic & CI-Safe** – Runs against mock Fulcio and Rekor servers started in-process. It never touches public Sigstore infrastructure.
* **Environment Overrides** – Sigstore endpoints are redirected using:
  * `PROMPTSIGN_FULCIO_URL`
  * `PROMPTSIGN_REKOR_URL`

### Component Coverage
* **`login.rs`** – Unit tests covering the browser login flow.
* **`proxy.rs`** – Unit tests covering the CORS proxy functionality.

### Cross-implementation conformance

`cargo test` only proves this implementation agrees with itself. The wire
format belongs to the spec, so the suite that checks two implementations still
agree on it lives there — `spec/test/conformance.sh` — and CI runs it against
the Node reference on every push (the `conformance` job in
`.github/workflows/ci.yml`).

This is the one workflow where the repos' on-disk layout matters. The suite
looks for them as siblings:

```
<parent>/
  promptsign-cli/     <- this repo
  promptsign-node/
  spec/
```

Half the suite needs this implementation to *sign*, so it needs a `local-key`
build. Name that binary explicitly — the suite's own search prefers
`target/release` over `target/debug`, and the release profile is keyless-only,
so a stale release binary wins and every signing check is silently **skipped**
rather than failed:

```bash
cargo build --features local-key
cd ../spec/test
IMPL_B="$(cd ../../promptsign-cli && pwd)/target/debug/promptsign" ./conformance.sh
```

A full run is `33 passed, 0 failed, 0 skipped`. Treat a nonzero skip count as a
failed run: it means the suite quietly stopped exercising the interop,
digest-equivalence, TOFU, policy, verify-tree, and fail-closed sections.

`IMPL_A` names the other implementation the same way, which is how CI runs the
suite from checkout paths of its own choosing. `IMPL_B_SIGN_ARGS` defaults to
`--local-key`, correct for this CLI and empty for implementations that sign
with a local key by default.

## Releases

Pushing a `v*` tag runs `.github/workflows/release.yml`, which builds five
targets and attaches the archives — plus a combined `SHA256SUMS` — to a GitHub
Release:

| Target | Notes |
|---|---|
| `x86_64-unknown-linux-musl` | static, built with `cross` |
| `aarch64-unknown-linux-musl` | static, built with `cross` |
| `x86_64-apple-darwin` | |
| `aarch64-apple-darwin` | |
| `x86_64-pc-windows-msvc` | |

musl rather than glibc: this runs inside hooks on machines where nothing is
preinstalled, and a binary bound to the host's glibc version is a binary that
fails on someone's LTS distro. Release builds use default features, so they are
keyless-only — see [Feature flags](#feature-flags). End users get these
prebuilt binaries from the product website; the download page is fed from these
release assets.

### Bootstrapping trust

This binary is a trust root. It decides whether everything else is authentic,
and nothing in the system can vouch for it in turn — so it must not be
distributed unverified. The release job therefore publishes two independent
things alongside each archive:

1. **A PromptSign signature** (`<archive>.psig.json`), made by the binary this
   same workflow just built, under the workflow's own Sigstore identity. No key
   exists anywhere; the certificate binds the identity, and the signature is
   recorded in Rekor, so an unexpected release is publicly discoverable after
   the fact. The job verifies every sidecar before publishing.
2. **A GitHub build provenance attestation**, verifiable with
   `gh attestation verify`.

Both are needed, because they answer different questions. A checksum only
proves an archive arrived intact from wherever it was fetched — an attacker who
can swap the download can swap the checksum beside it. A signature proves *who
built it*, which is the property that survives a compromised download channel.

**Verifying with `promptsign` itself is circular on first install**: an
attacker who swapped the download swapped the verifier too, and it will report
OK. So the two cases differ:

```bash
# First install — no trusted promptsign yet. `gh` is trusted independently.
gh attestation verify promptsign-x86_64-unknown-linux-musl.tar.gz \
  --repo PromptSign/promptsign-cli

# Upgrades — an already-trusted promptsign checks the next one.
promptsign trust fetch      # once per machine; caches the Sigstore roots
promptsign verify promptsign-x86_64-unknown-linux-musl.tar.gz --policy release.json
```

`trust fetch` is safe to re-run, and it will refuse rather than discard. The
cached files are lists: `fulcio.pem` contains a chain of CAs, while `rekor.pub`
contains one block per transparency log. A signature is checked against the CA
that issued its certificate and the log that witnessed its entry, with each
selected by name.

When Sigstore rotates, the retired material has to stay because dropping it
invalidates every signature made under it. Fulcio and Rekor serve only what is
*current*, so if the cache holds anything the response does not, `trust fetch`
stops and tells you how to append instead. `--force` overwrites anyway and
accepts that loss.

Keep the `.psig.json` sidecar next to the archive under its original name; that
pairing is how `verify` finds it. Bare `promptsign verify` pins the signer on
first use (TOFU) and holds across releases, since archive names carry the
target but not the version. To assert *which* identity up front instead, name
it in policy:

```json
{ "pattern": "promptsign-*",
  "identity": "https://github.com/PromptSign/promptsign-cli/.github/workflows/release.yml@refs/tags/*",
  "issuer": "https://token.actions.githubusercontent.com",
  "action": "enforce" }
```

Platform-level packaging signatures (macOS notarization, Windows Authenticode)
are a separate track from the signing described here.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
