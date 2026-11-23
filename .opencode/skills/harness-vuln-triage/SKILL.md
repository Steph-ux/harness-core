---
name: harness-vuln-triage
description: "Decide whether a scanner hit or HTTP 200 is a confirmed finding by requiring a reproducible observation and a negative control."
---

# Triage — 200 ≠ finding

Source: `performing-web-application-vulnerability-triage` (2024: error page `200` is #1 FP).

## Gate

One reproduction only (single `dalfox`/`trivy`/`nuclei` probe counts as one when target already in scope) of an already approved request. Every command via `cyber_process` `argv` when repro needed.

## Steps

1. One-sentence claim + offered observation ids. `cyber_memory evidence` them — body must show claimed data/state change, not only status (`gate` rule 7).
2. Name negative control: `unauth 401/403`, `wrong id 404`, `tampered JWT 401`, `recomputed price 400`. None recorded → candidate, no finding.
3. Repro once `cyber_process` `argv`, fresh `request-id` only. Same relevant field must appear. New observation id.
4. If visual (stored XSS rendering, receipt total, state banner), `cyber_capture` linked to reproduction observation. No id = refused.
5. `cyber_finding` only when `original+control+reproduction` agree, with `checks`={original:reproduction, control:negative-control, baseline:positive-control} each `observationId`+`contains` (leaked field/persisted state, not status) + `purpose`, plus `sources` chunks via `cyber_source`. Otherwise limitation + stop.

### Decision matrix

Classify the report as confirmed, candidate, false positive, or not-tested.
Confirmed requires the claimed effect in the body, state, callback or capture;
candidate means the signal exists but a control or runtime proof is missing;
false positive means the control explains it; not-tested means scope or tooling
blocked the reproduction. Never promote a scanner severity, status code or
response time by itself.

### Reproduction quality

Use one fresh correlation id and preserve the exact request shape, status,
content type, body hash and relevant field. Compare the positive baseline and
negative control under the same authentication and environment. Redact tokens,
cookies, secrets and unrelated personal data before recording `contains`.

### Reporting contract

The finding links every observation id and source chunk, names the limitation,
maps OWASP and MITRE only when the behavior supports it, and states what was
not proven. A visual capture is supplementary; it never replaces the CLI or
HTTP observation that demonstrates the effect.

## Done

Ledger is either finding (3 citations+captures) or explicit candidate with missing control named.
