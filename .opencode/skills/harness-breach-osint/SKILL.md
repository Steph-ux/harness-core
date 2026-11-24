---
name: harness-breach-osint
description: "Check approved identifiers against breach and paste sources with a second-source confirmation before calling a credential confirmed."
---

# Breach OSINT

Source: `osint-deep` breach module. This does not replace `harness-email-osint` / `harness-maigret` / `harness-phone-osint`.

## Gate

The identifier (email, username, or domain) must be named in the approved scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. Do not pay for premium breach APIs unless the engagement explicitly allows it and the cost is approved.

## Steps

1. Run one breach check at a time against the approved identifier:

```
cyber_process argv=["holehe","<email>","--only-used"]
cyber_process argv=["theHarvester","-d","<domain>","-b","all","-l","100","-f","<evidence-dir>/theharvester.html"]
```

When a breach-search binary is on PATH and the scope allows it (e.g. local `haveibeenpwned` wrapper, `dehashed` file), run it as `cyber_process` with `argv` and write into `<evidence-dir>/breach-<identifier>.json`. Record one observation per tool.

2. A breach hit is a candidate. Record the source breach name, the identifier, and the observation. Do not store the plaintext password — hash only.

3. Confirm with a second independent source already allowed by `osint-deep`: the same identifier plus a known name, username, or phone hit. One breach-source hit is not confirmation.

4. Extracted credentials stay leads. Testing a credential against a live service is a separate approved check:

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"email\":\"<email>\",\"password\":\"<hash-only-ref>\"}","<approved-login-url>"]
```

Then stop. Record that attempt as its own observation.

5. Second-source confirmation — use a different tool:

```
cyber_process argv=["maigret","<username>","--json","simple","--timeout","10","-o","<evidence-dir>/maigret-<username>.json"]
```

Or domain-level email harvest:

```
cyber_process argv=["emailfinder","-d","<domain>","-o","<evidence-dir>/emailfinder.json"]
```

6. Negative control — query an address known NOT to be in scope:

```
cyber_process argv=["holehe","unused-control-address@example.com","--only-used"]
```

This must return zero breach hits. If it returns hits, the tool's noise floor is too high.

Every confirmed credential is `cyber_finding` with its breach observation, the second-source observation, and the auth-attempt observation (or the explicit statement that auth was not attempted). Unconfirmed hits stay candidates.

### Correlation matrix

Normalize email case, username spelling, domain and breach date, but preserve
the original source. Correlate at least two independent attributes (identifier
+ name, identifier + username, or identifier + domain) before confirming an
identity. A similar-looking email, reused avatar or search-engine snippet is a
lead, not proof.

### Privacy and controls

Do not download bulk dumps, contact the person, test passwords on third-party
services, or retain plaintext credentials. A known-clean identifier and a
near-match are negative controls for parser/correlation errors. Redact personal
data in sources and retain only the minimum evidence needed for the approved
finding.

### Confirmation

Two independent sources before "this email is in that breach". One dump hit is a candidate.

```
cyber_process argv=["h8mail","-t","<email>","-o","<evidence-dir>/h8mail.json"]
```

Missing tool → `not-tested`. Do not log in with a found password unless the operator approved a one-shot identity check (`harness-secret-scan`). Unused-address control must not share the same dump rows.

### Pairing

One dump hit is a candidate. Confirmed = dump + (public name | approved username | second corpus).

Do not log in with a found password unless the operator approved a one-shot identity check. Then stop. Unused-address negative control must not share the same rows.

### Stop

Credential stuffing, contacting the person, paying a dump site without approval, putting a plaintext password in the ledger.

### Evidence ids

Breach tool, second source, unused-address control, optional auth. Hash any token.

One dump row without a second attribute stays a candidate, never a confirmed owner.

Do not paste a full dump into the finding. Redact to the minimum row.

### Auth

One-shot identity check only if the operator approved. Then stop. No stuffing. Unused-address negative control must not share dump rows.

```
cyber_process argv=["h8mail","-t","<email>","-o","<evidence-dir>/h8mail.json"]
```

Missing tool → `not-tested`. Do not paste a full dump. Hash tokens.

### Stop

Contacting the person, paying a dump without approval, plaintext password in the ledger.

## Verification scenarios

Use synthetic breach-search fixtures for near-match and parser controls.
Holehe tests registration, and theHarvester collects public references; neither is a breach corpus.
Two providers mirroring one dump are one underlying source.

| Scenario | Evidence compared | Expected classification |
|---|---|---|
| Exact scoped address appears in a named corpus | source, breach date and exact match | exposure candidate |
| Address differs by one character | raw source identifiers | reject identity match |
| Two mirrors return the same row | underlying corpus fingerprint | duplicate provenance |
| Authorized fixture address has no corpus row | successful query with zero matches | negative control |
| Provider returns auth/quota error | error body and status | unavailable, not “no breach” |

A public profile may corroborate identity but cannot prove breach membership.
Record collection date separately from incident date and data publication date.
Do not describe an old disclosed password as currently valid without a separate check.
The finding packet distinguishes historical exposure, identity correlation and live validity.
Retain only redacted rows and restricted artifact fingerprints, not bulk credential data.

## Done

Evidence holds the breach outputs (JSON/HTML). Confirmed findings cite the breach tool and a second source; tested credentials cite the auth observation.
