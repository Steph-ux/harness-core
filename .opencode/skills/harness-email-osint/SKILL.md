---
name: harness-email-osint
description: "Correlate an approved email with Holehe and a second source; never send mail, never reset a password, never treat one hit as ownership."
---

# Email OSINT — two-source, no contact

Source: Holehe, theHarvester. Hunter/breach correlation only from approved corpora.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. The email is named in the approved scope. Do not send an email, do not contact the target, do not trigger password reset, do not log in, do not pay for premium APIs unless explicitly approved.

## Steps

### 1. First tool

```
cyber_process argv=["holehe","<email>","--only-used"]
```

Own observation. `--only-used` only — no site spam.

### 2. Domain harvest (if the domain is in scope)

```
cyber_process argv=["theHarvester","-d","<domain>","-b","all","-l","100","-f","<evidence-dir>/theharvester"]
```

Separate observation. Limit 100. The email under test must appear or this is not a second source for **that** address.

### 3. Confirm with a second independent attribute

Same email + public name, or same email + approved username, or same email + approved breach source (`harness-breach-osint`). A provider-registration hit alone does not prove ownership or compromise.

### 4. Negative control

A syntactically valid **known-unused** address and a **near-match** must not yield the same "confirmed owner" graph. Record both.

### 5. Finding contract

`cyber_finding` only with ≥2 observations (tool + second source), a `cyber_source` chunk, and the unused-address control. Unconfirmed stays candidate. No plaintext secret. New usernames stay leads until `harness-maigret` is scoped.

## Done

Evidence holds Holehe and the second source. Confirmed findings cite two observations + a source chunk + control.
