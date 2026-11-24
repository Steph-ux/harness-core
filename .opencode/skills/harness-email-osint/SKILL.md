---
name: harness-email-osint
description: "Correlate an approved email with Holehe plus a second source; unused-address control; never send mail, never reset, never treat one hit as ownership."
---

# Email OSINT — two-source, no contact

Source: Holehe, theHarvester. Breach correlation only from approved corpora.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Email named in scope. Do not send mail, do not contact, do not trigger password reset, do not log in, do not buy premium APIs unless approved.

## Steps

### 1. Holehe (used sites only)

```
cyber_process argv=["holehe","<email>","--only-used"]
```

Own observation. No full-site spam.

### 2. Domain harvest if the domain is in scope

```
cyber_process argv=["theHarvester","-d","<domain>","-b","all","-l","100","-f","<evidence-dir>/theharvester"]
```

Separate observation. Limit 100. The address under test must appear or this is not a second source **for that email**.

### 3. Confirm with a second attribute

Exactly one pair:
- email + public name already in evidence
- email + approved username (`harness-maigret`)
- email + approved breach row (`harness-breach-osint`)

A provider-registration hit alone does not prove ownership or compromise. Normalize the address (plus-tag, dots on Gmail) and record that normalization as its own note, not a new identity.

### 4. Negative control

A syntactically valid **known-unused** address and a **near-match** must not yield the same owner graph. Record both.

### 5. Finding contract

`cyber_finding` with ≥2 observations, `cyber_source` chunk, unused-address control. No plaintext secret. New usernames stay leads until scoped.

## Done

Evidence holds Holehe and the second source. Confirmed cites two observations + chunk + control.
