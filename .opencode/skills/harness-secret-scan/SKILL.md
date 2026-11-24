---
name: harness-secret-scan
description: "Scan collected evidence with Gitleaks and Trufflehog, dedupe by SHA256(secret), fixture path as control, optional one-shot identity check; never put the secret in the ledger."
---

# Secrets — two engines, hash only, no raw value

Source: Gitleaks, Trufflehog. Verification is a second opinion, not a replacement.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Scan only the evidence directory or an approved clone **already** in evidence. Never a live customer repo outside scope. Do not `pip install` during the scan. Do not print the secret.

## Steps

### 1. Redacted scan, optional independent engine

```
cyber_process argv=["gitleaks","detect","--source","<evidence-dir>","--redact=100","--report-format","json","--report-path","<restricted-output-dir>/gitleaks.json","--no-banner","--exit-code","0"]
cyber_process argv=["trufflehog","filesystem","<synthetic-fixture-dir>","--json","--no-verification"]
```

TruffleHog JSON can contain raw secrets: the example is for synthetic fixtures only.
For real files use a reviewed adapter that redacts before durable process tracing;
if unavailable, mark that engine not-tested. Keep scanner outputs outside scan inputs.
No shell `>`. Compute fingerprints locally through a protected redactor, never by printing values.

### 2. Classify

active / revoked / fixture / example / high-entropy junk / private key / webhook / PII.
File paths are hints, not proof: real secrets can occur in tests, examples and Markdown.

`cyber_source` the file chunk **without** secret bytes.

### 3. Negative control

A proven inert fixture may match the detector but must not become a live-credential
finding. Gitleaks detects patterns; it does not establish current credential validity.

### 4. Optional one-shot auth

Only if the operator approved: one harmless identity call (`sts get-caller-identity`, `/user`). Stop on success. Never enumerate data, never rotate. `cyber_capture` linked to that observation if visual.

If not attempted: limitation `not-attempted`.

### 5. Finding contract

`cyber_finding` evidence = scan obs + auth or `not-attempted`, sources = chunk, checks = gitleaks positive / fixture negative. SHA256 in the finding, **never** the value in prompt, report, or observation text.

## Proof contract

A credential-exposure claim needs scan observation, protected fingerprint, actual fixture control,
and one-shot identity proof or explicit validity `not-attempted`. The raw value stays out of the ledger.

### Engines

```
cyber_process argv=["gitleaks","detect","--source","<evidence-dir>","--redact=100","--report-format","json","--report-path","<restricted-output-dir>/gitleaks.json","--no-banner","--exit-code","0"]
cyber_process argv=["trufflehog","filesystem","<synthetic-fixture-dir>","--json","--no-verification"]
```

Dedup `(file, rule, SHA256(secret))`. Proven inert fixture contents are the negative control.
One-shot auth only if approved. Raw secret never in the ledger.

### Classification

| Class | Finding? |
|---|---|
| proven inert fixture | no — classifier negative control |
| high-entropy junk | no |
| live key + identity obs | yes |
| exposed candidate + not-attempted | validity unknown; assess source exposure only |

Do not `pip install` during the scan. Do not print the secret. One identity call max if approved (`sts get-caller-identity`). Stop on success. Never rotate/revoke from the scanner.

### Stop

Live customer repo outside evidence, dumping the secret into the finding title, enumerating after a hit.

### Evidence ids

Gitleaks and/or Trufflehog, actual inert-fixture control, SHA256, auth or `not-attempted`, file chunk without secret bytes.

### Dedup

`(file, rule, SHA256(secret))`. Same secret two files = one candidate, two locations.
Use a proven inert fixture as the negative control, not a directory name.

```
cyber_process argv=["gitleaks","detect","--source","<evidence-dir>","--redact=100","--report-format","json","--report-path","<restricted-output-dir>/gitleaks.json","--no-banner","--exit-code","0"]
```

No `pip install` during scan. No print. Identity call once if approved, then stop.

### Stop

Live repo outside evidence, secret in the finding title, enumerating after a hit.

## Verification scenarios

Validate redaction with an inert synthetic credential before scanning real artifacts.
Verification disabled means a detector match has unknown validity, not “live”.
Keep source exposure and successful authentication as separate claims.

| Scenario | Observation | Expected classification |
|---|---|---|
| Inert example token triggers an entropy rule | fixture provenance and redacted output | classifier negative control |
| Real-looking key appears in an example file | issuer format and exposure context | investigate; path is not an exemption |
| Public client identifier matches a secret rule | issuer's credential classification | not a private secret |
| Approved one-shot identity request is rejected | status and issuer error | invalid/revoked/insufficient context, not automatically revoked |
| No live check is approved | source and detector observations | exposed candidate with validity not-attempted |

Never let scanner verification contact providers implicitly.
Record engine version, rule id, source location and the protected fingerprint.
No raw key may enter argv, logs, finding titles or promoted lessons.

## Done

Each secret finding has a scan observation, `SHA256(secret)`, a source chunk, and auth or explicit `not-attempted`.
