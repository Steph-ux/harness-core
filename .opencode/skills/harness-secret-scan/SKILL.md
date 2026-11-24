---
name: harness-secret-scan
description: "Scan collected evidence with Gitleaks and Trufflehog, dedupe by SHA256(secret), fixture path as control, optional one-shot identity check; never put the secret in the ledger."
---

# Secrets — two engines, hash only, no raw value

Source: Gitleaks, Trufflehog. Verification is a second opinion, not a replacement.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Scan only the evidence directory or an approved clone **already** in evidence. Never a live customer repo outside scope. Do not `pip install` during the scan. Do not print the secret.

## Steps

### 1. Two scans, two observations

```
cyber_process argv=["gitleaks","detect","--source","<evidence-dir>","--report-format","json","--report-path","<evidence-dir>/gitleaks.json","--no-banner","--exit-code","0"]
cyber_process argv=["trufflehog","filesystem","<evidence-dir>","--json","--no-verification"]
```

No shell `>`. Dedup by `(file, rule, SHA256(secret))`. One secret in two files = one candidate, two locations.

### 2. Classify

active / revoked / fixture / example / high-entropy junk / private key / webhook / PII. `tests/`, `examples/`, `fixtures/`, `*.md` → `likely-false-positive` until auth proves otherwise.

`cyber_source` the file chunk **without** secret bytes.

### 3. Negative control

A known fixture file that contains an example key must match as fixture, not as a finding. If Gitleaks flags it as live, the rule is too wide — record that, do not open a critical finding.

### 4. Optional one-shot auth

Only if the operator approved: one harmless identity call (`sts get-caller-identity`, `/user`). Stop on success. Never enumerate data, never rotate. `cyber_capture` linked to that observation if visual.

If not attempted: limitation `not-attempted`.

### 5. Finding contract

`cyber_finding` evidence = scan obs + auth or `not-attempted`, sources = chunk, checks = gitleaks positive / fixture negative. SHA256 in the finding, **never** the value in prompt, report, or observation text.

## Proof contract

A live credential needs the scan observation, SHA256, fixture-path control, and either a one-shot identity observation or `not-attempted`. The raw secret never enters the ledger.

## Done

Each secret finding has a scan observation, `SHA256(secret)`, a source chunk, and auth or explicit `not-attempted`.
