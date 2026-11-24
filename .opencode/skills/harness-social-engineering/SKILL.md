---
name: harness-social-engineering
description: "Authorized phishing/pretext simulation on an approved recipient-list hash: canary endpoint stores only sha256+timestamp, aggregate rates, stop at first real secret, never name an individual."
---

# Social engineering — authorized simulation, canary only

Source: phishing simulation as a **control test**, not an attack on a person. Deliverable is a rate and a gap.

## Gate

Written authorization, approved recipient list, informed HR/legal owner. Every command goes through `cyber_process` with `argv`. Do not build a shell string. No external third-party kit, no malware attachment, no availability impact, no pretext from personal data of a named individual. Collect only a campaign-specific canary fingerprint + timestamp, never a password.

**Stop** at the first real credential: halt collection, notify the owner and follow the incident procedure. **Stop** if any recipient is outside the list.

## Steps

### 1. Freeze approval

Record approval reference, **hash of the recipient list**, campaign window, control recipient (must not receive). One `cyber_source` chunk names all four.

### 2. Canary endpoint proof

Build so a submission accepts the synthetic campaign token and records only its fingerprint and timestamp. Prove with a test submission:

```
cyber_process argv=["curl","-sS","-X","POST","--data-binary","@canary-test.json","<canary-url>"]
```

Observation must show the store has no secret fields. Empty or invalid canary submission is not counted (negative control).

### 3. One campaign, one pretext class

No personalization from outside the list. Record send count **per recipient hash**, not per name.

### 4. Three separate counts

Delivery, click, canary submission — three observations. An open is not a click. A click is not a secret.

### 5. Negative controls

- control recipient never receives
- address outside the window is discarded
- empty or invalid campaign token not counted

### 6. Quiesce and plan cleanup

Halt collection at the approved deadline. Preserve aggregate evidence through restitution.
Record the cleanup command and execute it only after the mission's restitution gate allows it.
Unexpected secrets follow the owner's incident procedure, not automatic unrecorded destruction.

### 7. Finding contract

`cyber_finding` states the control that failed, the aggregate rate, approved remediation. No individual named. One click without its control stays a candidate.

### Counts (three observations)

| Metric | Is not |
|---|---|
| delivery | a click |
| click | a secret |
| canary submit | a named person |

```
cyber_process argv=["curl","-sS","-X","POST","--data-binary","@canary-test.json","<canary-url>"]
```

Store is canary fingerprint+timestamp only. Invalid canary is not counted.
Control recipient never receives. First real secret → halt collection and notify.

### Stop

Malware attachment, personal pretext, recipient off-list, third-party kit, continuing after a real secret.

### Evidence ids

Approval chunk, canary-store proof, three counts, control misses and cleanup status.
Finding is the **rate**, never a name. One click without its control stays a candidate.

Recipient list is stored as a hash, never as a roster in the finding.

### Reproduction recipe

Canary fingerprint+timestamp only. Three counts. Retain aggregate proof through restitution. Rate not names.

## Verification scenarios

Validate the campaign against synthetic recipients before sending to the approved list.
Prefer a campaign-specific canary token rather than requesting a real password.
Hashing a submitted real password is still handling a secret; avoid that collection.

| Scenario | Test observation | Expected result |
|---|---|---|
| Canary recipient submits a campaign token | token id and timestamp only | count one synthetic submission |
| Same recipient refreshes the confirmation page | repeated event id | no duplicate success |
| Mail security scanner prefetches a link | known scanner event | separate from human clicks |
| Request arrives after campaign expiry | server rejection | negative control |
| Unlisted recipient requests a campaign URL | allowlist decision | no message or collection |

Record delivered, bounced, unique clicks and synthetic submissions separately.
Define the denominator before calculating rates; exclude failed deliveries explicitly.
Report uncertainty caused by proxies, link scanners and incomplete telemetry.
Campaign simulation must not attribute intent or competence to a named employee.

### Finding packet

Attach authorization, list fingerprint, event schema and synthetic preflight controls.
Retain aggregate proof through restitution; purge event data through approved cleanup.
If real credentials appear, halt collection and follow the owner's incident procedure.
Do not silently delete mission evidence merely to make a report appear clean.

## Done

Evidence holds approval, canary-store proof, three counts, control misses and
explicit cleanup status. No name or plaintext password; removal proof is added after approved cleanup.
