# OMS fixture

Copied from promptsign-core `tests/fixtures/foreign/oms/` (provenance in its
README): `NVIDIA/skills` @ `0e0d506`, `skills/earth2studio-discover`
(Apache-2.0), and its trust anchor `nv-agent-root-cert.pem`.

## test-ca/

Copied from promptsign-plugin `test/fixtures/oms/` (provenance in its README):
OMS signatures made with `model_signing` 1.1.1 in certificate mode under a test
CA (`test-ca.pem`, keys discarded). `plugin.sig` signs `plugin/` at its root.
It is stored beside the directory it signs, and `tests/hook_oms_e2e.rs` puts it
back under its real name (`model.sig`) in a temp copy.
