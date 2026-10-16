# VIPER Master Integration v1.5

Evidence-gated release control plane. Fail-closed by design.

## Current Truth (matches CI)

| Item | Status |
|:---|:---|
| CI_PIPELINE | PASS |
| SECURITY_F01_F05 | TESTED_PASS |
| SECURITY_SCAN | TESTED_PASS |
| DSL_COMPILE | TESTED_PASS |
| OPA_CHECK | TESTED_PASS |
| OPA_EVAL | TESTED_PASS |
| STAGING_VERIFICATION | TESTED_PASS (Mock Sandbox) |
| INDEPENDENT_VERIFICATION | NOT_RUN |
| RELEASE_AUTHORIZATION | DENY |

Rule: NO_EVIDENCE -> NO_CLAIM -> NO_TRUST -> NO_RELEASE

## Run locally

pip install -r requirements.txt
pytest -q

## Security

See docs/KNOWN_RISKS.md. Ed25519 proves key possession, not person identity.
