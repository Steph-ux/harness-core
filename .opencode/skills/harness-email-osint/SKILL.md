---
name: harness-email-osint
description: "Correlate an approved email address with Holehe and theHarvester, recording the source and the result."
---

# Email OSINT — two-source, no contact

Source: Holehe 1.61, theHarvester 5.0.0, `osint-deep` (2025: hunter breach correlation).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. The email is named in the approved scope. Do not send an email, do not contact the target, do not pay for premium APIs unless explicitly approved.

## Steps

1. Run as `cyber_process` `argv`:
```text
holehe <email> --only-used
theHarvester -d <domain> -b all -l 100 -f <evidence-dir>/theharvester.html
# optional: Mes-outils/_lib waymore-style second source already in evidence
```
Each is its own observation in `<evidence-dir>`.

2. A found account / leak reference is a candidate. Record the source breach/site and hash any sensitive token.
3. Confirm with a second independent source already allowed by `osint-deep`: same email + known name/username/phone or a second breach corpus. One hit is not confirmation.
4. Extracted usernames stay leads — each new search needs its own scope coverage before `harness-maigret`.
5. `cyber_finding` only with at least two observations (tool + second source) and a `cyber_source` chunk for the breach listing. Unconfirmed stays candidate. No plaintext secret in the ledger.

### Correlation matrix

Normalize the address and record provider, domain, source date and result type.
Require two independent attributes before confirming ownership: email + public
name, email + approved username, or email + approved breach/domain source. A
provider-registration hit alone does not prove account ownership or compromise.

### Controls and privacy

Use a syntactically valid but known-unused address and a near-match as
`negative-control` cases. Do not send mail, trigger password reset, log in, scrape private
profiles, or retain passwords. New identifiers discovered during the run stay
leads until separately approved and scoped.

## Done

Evidence holds the Holehe + theHarvester reports. Confirmed findings cite two observations + a source chunk.
