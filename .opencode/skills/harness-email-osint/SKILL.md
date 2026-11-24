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

### Pairing (pick one)

email + public name | email + approved username | email + approved breach row

```
cyber_process argv=["holehe","<email>","--only-used"]
```

Provider-registration alone is not ownership. Unused-address negative control required. No mail, no reset, no login.

### Normalize

Apply dot/plus normalization only where the provider documents those rules.
Preserve the exact supplied address; custom domains need not follow Gmail behavior.

```
cyber_process argv=["theHarvester","-d","<domain>","-b","all","-l","100","-f","<evidence-dir>/theharvester"]
```

Domain harvest is a second source only if **this** address appears. New usernames → `harness-maigret` after scope. No mail, no reset, no login.

### Stop

Contacting the target, premium API without cost approval, treating one Holehe hit as ownership.

### Evidence ids

Holehe, second source, unused-address negative control, source chunk.

### Harvest limit

theHarvester `-l 100` max. The address under test must appear or it is not a second source for **that** email.

```
cyber_process argv=["holehe","<email>","--only-used"]
```

Plus-tags/Gmail dots: record normalization, do not split identities. Unused-address negative control required.

### Stop

Mail, reset, login, premium API without cost approval, one Holehe hit as ownership.

## Verification scenarios

Inspect enabled registration-check modules before running them.
Skip any module that sends mail, initiates a reset, or violates the mission's no-contact gate.
Use an operator-owned unused address or offline fixtures, not a random third party.

| Scenario | Comparison | Expected classification |
|---|---|---|
| Exact address appears in an approved directory | original source and collection time | public association supported |
| Provider blocks or rate-limits enumeration | module error and status | unavailable, not registered |
| Catch-all domain answers equally for every address | owned unused-address twin | enumeration signal rejected |
| Same local part appears on another domain | exact identifiers differ | no identity merge |
| Search result repeats another source verbatim | provenance and timestamps | not independent corroboration |

A registration signal does not prove that a particular person owns the account.
Current ownership needs a current approved association; old directories can be stale.
Email exposure, registration and compromise are different claim types.
Keep domain-wide harvesting separate from consent to investigate every discovered address.
Attach the exact match, second attribute, executed control and normalization decisions.

## Done

Evidence holds Holehe and the second source. Confirmed cites two observations + chunk + control.
