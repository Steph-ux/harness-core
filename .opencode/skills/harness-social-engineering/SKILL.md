---
name: harness-social-engineering
description: "Authorized phishing/pretext simulation on an approved recipient-list hash: canary endpoint stores only sha256+timestamp, aggregate rates, stop at first real secret, never name an individual."
---

# Social engineering — authorized simulation, canary only

Source: phishing simulation as a **control test**, not an attack on a person. Deliverable is a rate and a gap.

## Gate

Written authorization, approved recipient list, informed HR/legal owner. Every command goes through `cyber_process` with `argv`. Do not build a shell string. No external third-party kit, no malware attachment, no availability impact, no pretext from personal data of a named individual. The capture endpoint stores **only** `sha256(password)` + timestamp, never the secret.

**Stop** at the first real credential: destroy capture, notify owner, halt campaign. **Stop** if any recipient is outside the list.

## Steps

### 1. Freeze approval

Record approval reference, **hash of the recipient list**, campaign window, control recipient (must not receive). One `cyber_source` chunk names all four.

### 2. Canary endpoint proof

Build so a submission records hash+timestamp only. Prove with a test submission:

```
cyber_process argv=["curl","-sS","-X","POST","--data-binary","@canary-test.json","<canary-url>"]
```

Observation must show the store has no plaintext. Empty-password submission is not counted (negative control).

### 3. One campaign, one pretext class

No personalization from outside the list. Record send count **per recipient hash**, not per name.

### 4. Three separate counts

Delivery, click, canary submission — three observations. An open is not a click. A click is not a secret.

### 5. Negative controls

- control recipient never receives
- address outside the window is discarded
- empty password not counted

### 6. Destroy

Destruction command recorded; store empty observation. If a real secret appeared, it was destroyed in the stop path — the finding is the **control failure rate**, not the secret.

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

Store is hash+timestamp only. Empty password not counted. Control recipient never receives. Destroy before any `cyber_finding`. First real secret → halt, destroy, notify.

### Stop

Malware attachment, personal pretext, recipient off-list, third-party kit, continuing after a real secret.

### Evidence ids

Approval chunk, canary-store proof, three counts, control misses, destruction. Finding is the **rate**, never a name. One click without its control stays a candidate.

## Done

Evidence holds approval, canary-store proof, three counts, control misses, destruction proof. No name, no plaintext password.
