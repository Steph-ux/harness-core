---
name: harness-secret-scan
description: "Search files already collected in an engagement for secrets, record the location and hash, and leave the secret value out of the ledger."
---

# Secrets — Gitleaks + Trufflehog, dedup by hash, no raw secret in ledger

Source: `implementing-secret-scanning-with-gitleaks` + supply-chain (2024: Trufflehog verification via OOB is a second opinion, not a replacement).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Scan only `<evidence-dir>` or an approved repo already cloned into evidence (never a live service, never a customer repo outside scope). Do not `pip install` during the scan.

## Steps

1. Two scans on the same evidence, each its own observation:
```text
gitleaks detect --source <evidence-dir> --report-format json --report-path <evidence-dir>/gitleaks.json --no-banner --exit-code 0
trufflehog filesystem <evidence-dir> --json --no-verification > <evidence-dir>/trufflehog.json
```
Record both run observations. Dedup findings by `(file, rule, SHA256(secret))`.

2. For each match, create a candidate citing the engine observation + `file:line:rule` + `SHA256(secret)`. `cyber_source` ingest the file chunk (no secret bytes).
3. A match in `tests/`, `examples/`, `fixtures/`, or `*.md` doc is a candidate until the same value authenticates — mark it `likely-false-positive` with the path reason.
4. Auth is a separate approved `cyber_process` `argv` check: one request with the found credential (`Authorization: Bearer …`), then stop. Record success/failure as its own observation. If auth is not attempted or fails, state it explicitly in the finding limitation.
5. Visual proof (e.g. `aws sts get-caller-identity` `Account: …` screen) via `cyber_capture` linked to the auth observation id.

6. `cyber_finding` with `evidence` = Gitleaks and/or Trufflehog observation + auth-attempt observation (or explicit `not-attempted`), `sources` = file chunk, `checks` = `gitleaks.json:positive-control` / fixture path:negative-control. Never copy the secret value into the finding, prompt, or report.

### Secret lifecycle matrix

Classify each match as active credential, revoked credential, test fixture,
example/documentation, high-entropy non-secret, private key, webhook token or
personal data. Search current files, history and generated artifacts only when
that source is explicitly in scope. Deduplicate by secret hash while retaining
every location; one secret in two files is one secret candidate with two source
locations.

### Validation and containment

Authentication is opt-in and one bounded request. Prefer a harmless identity
endpoint and stop on success; never enumerate data or rotate/revoke a key from
the scanner. If exposure is confirmed, record the minimum identity metadata,
request operator remediation through the engagement workflow, and keep the raw
value out of stdout, observations, reports and prompts.

## Done

Each secret finding has a scan observation, a `SHA256(secret)`, a source chunk, and an auth observation or an explicit `not-attempted` limitation.
