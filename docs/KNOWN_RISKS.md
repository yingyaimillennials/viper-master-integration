# Known Risks — VIPER Master Integration v1.6

| ID | Risk | Mitigation | Status |
|---|---|---|---|
| R-01 | Staging deploy is mock, not real infrastructure | Label all staging evidence as MOCK SANDBOX; no production claim | MITIGATED |
| R-02 | Independent verification not run | INDEPENDENT_VERIFICATION=NOT_RUN; RELEASE_AUTHORIZATION=DENY | OPEN |
| R-03 | Ed25519 proves key possession, not person identity | Require email challenge attestation before trust | MITIGATED |
| R-04 | All 4 emails may belong to one person | Multi-party requires 2+ distinct humans | OPEN |
| R-05 | OPA_SHA256 is placeholder | Pin and verify OPA checksum before production | OPEN |
| R-06 | Attestations stored in env vars, not persistent store | Move to persistent trusted store + audit ledger | OPEN |
| R-07 | No hash-chained audit ledger for link events | Implement append-only ledger with hash chain | OPEN |
| R-08 | Private key leakage | Secrets only in GitHub Secrets / hardware key; rotate on leak | MITIGATED |
