---
name: harness-learned-0day
description: "Capitalize each source-deep / logic-cve / component-cve run into reusable abstract patterns via the hunter lesson prompt and the ranked memory, without leaking target data."
---

# Learned 0-day — from one CVE to the next

This skill turns the current session's 0-day work into durable, abstract knowledge. It uses the hunter lesson prompt, the store's `cyber_memory` / `cyber_lessons`, and the ranked memory — never a raw host or secret.

## Gate

Every fact needs successful evidence. No finding from a scanner claim alone. Every command goes through `cyber_process` with `argv`. Do not build a shell string.

## Steps

1. List the current session's 0-day artefacts already in `<evidence-dir>`: `taint-inventory.json`, `endpoints.json`, `semgrep-*.json`, `logic-cve` persistence read, `component-cve` lab `Dockerfile`/`composer.json` + patch. Each is its own observation (already recorded by the three hunter skills).
2. Run `cyber_lessons pending` — check if a previous session awaits extraction. If `pending` is non-empty, ask the operator once via `harness_operator` before `cyber_lessons run --sessionId <id>`.
3. Propose at most one abstract knowledge fact, e.g.:
   - `price-client-computed-checkout-js-amount-field-persisted` (workflow)
   - `postmessage-innerhtml-taint-harness-source-deep` (environment)
   - `plesk-18.0.81-api-v2-swagger-unauth-candidate` (false-positive until second DC)

   Each fact's `evidence` must include the `semgrep` hit observation + the `taint/endpoints` JSON observation + the live persistence or lab proof observation. No target hostname in the `content`; use `file:line` + `method+path template` only.

4. Propose at most one reusable skill when the same pattern succeeded twice (two sessions, `minimumSkillSessions: 2`): e.g. `js-price-tamper-persistence-read` with `procedure` = the three hunter steps, `validation` = the marker `contains` excerpt from the persistence read observation, `evidence` = the two session observation ids. Confidence is computed by the store (`0.75` threshold).
5. Verify via `cyber_memory facts` and `cyber_method list` — the fact/skill must appear. If rejected, read `rejected` in the lesson outcome and fix the evidence. Injection: the fact ranks via `memory-ranking.ts` (TF-IDF + FR/EN synonyms) and is injected within `memoryMaxChars: 12000` / `operatorModelChars: 5000` on every turn, without crowding operator rules.
6. When the method is general enough to serve the next engagement, share it: `cyber_method {action:"promote", name}`. The promotion needs an **active** method and survives only if the text names no host, URL, IP, email, hash or token — the evidence stays in the project, so nothing from this target reaches another.

### Abstraction test

Before saving a lesson, remove hostnames, product identifiers, credentials,
target paths and raw payloads. Keep only precondition, observable signal,
negative control, failure mode and reusable procedure. A lesson that cannot be
validated from two distinct sessions remains a candidate and is not promoted.

### Quality controls

Run a leakage scan over the proposed fact and method for URL, IP, email, token,
hash and secret patterns. Compare the abstract procedure against the original
positive and negative observations; if either is absent, record the gap instead
of manufacturing validation.

### Finding contract

This method does not promote a scanner result into a `cyber_finding`. It only
capitalizes already confirmed evidence into an abstract lesson; the original
project finding and its observations remain the source of truth.

### Leakage scan before promote

Strip host, URL, IP, email, hash, token from the proposed fact. If `cyber_method promote` would refuse identifiers, fix the text — do not file a `cyber_finding` from the lesson itself.

Two sessions, confidence ≥ 0.75. A lesson without positive and negative observations stays a candidate.

### Session budget

| Item | Max |
|---|---|
| abstract facts | 1 |
| reusable skill | 1 per two sessions |
| host/URL/IP in text | 0 |

```
cyber_process argv=["sha256sum","<evidence-dir>/taint-inventory.json"]
```

Use `cyber_lessons pending` then operator once before `run`. Evidence = semgrep + taint/endpoints + lab/persistence. Leakage scan before `cyber_method promote`. This method does not create a `cyber_finding` from a scanner; it capitalizes confirmed evidence. Negative control: lesson without both pos/neg observations stays candidate.

### Stop

Promoting with a hostname, skipping operator on lessons run, manufacturing validation.

### Evidence ids

Hunter artefacts already recorded, lesson outcome, memory list check.

### Promote gate

`cyber_method promote` refuses host/URL/IP/email/hash/token. Fix the text. Two sessions, ≥0.75. Lesson without pos+neg observations stays candidate.

```
cyber_process argv=["sha256sum","<evidence-dir>/lab-reproduction.json"]
```

`cyber_lessons pending` then operator once before `run`. This method does not turn a scanner into a `cyber_finding`.

### Stop

Hostname in the fact, skipping operator, manufacturing validation.

## Verification scenarios

Hashing artifacts identifies inputs; it does not validate a reusable method.
Reuse existing observations rather than generating placeholder successes.
Inspect current tool schemas for lesson/session arguments before invoking extraction.

| Scenario | Store observation | Expected outcome |
|---|---|---|
| One successful session proposes a reusable method | one distinct supporting session | remains candidate |
| Same evidence id is repeated under two labels | evidence provenance | not independent support |
| Two sessions include reproduction and different-output control | method status and computed confidence | eligible only if store gates pass |
| Proposed global text contains a target URL | rejected promotion reason | negative control for leakage guard |
| Local fact is valid but source was later invalidated | source status and lesson review | revise or deprecate, not silent reuse |

Store the precondition, observation, failure mode and boundary of applicability.
A lesson about a known defect is not evidence of a novel vulnerability or CVE assignment.
Verify status through `cyber_method list`, not merely the proposal acknowledgement.
Keep project evidence local when promoting an identifier-free global procedure.
Report extraction failures and rejected reasons rather than fabricating validation markers.

## Done

One hunter session yields at most one abstract fact and, every second success, one reusable skill. Raw target data, hostnames, and secrets are never preserved.
