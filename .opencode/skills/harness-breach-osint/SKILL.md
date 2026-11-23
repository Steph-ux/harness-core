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

```text
holehe <email> --only-used
theHarvester -d <domain> -b all -l 100 -f <evidence-dir>/theharvester.html
```

When a breach-search binary is on PATH and the scope allows it (e.g. local `haveibeenpwned` wrapper, `dehashed` file), run it as `cyber_process` with `argv` and write into `<evidence-dir>/breach-<identifier>.json`. Record one observation per tool.

2. A breach hit is a candidate. Record the source breach name, the identifier, and the observation. Do not store the plaintext password — hash only.

3. Confirm with a second independent source already allowed by `osint-deep`: the same identifier plus a known name, username, or phone hit. One breach-source hit is not confirmation.

4. Extracted credentials stay leads. Testing a credential against a live service is a separate approved check: one request with the found credential via `cyber_process` `argv`, then stop. Record that attempt as its own observation.

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

## Done

Evidence holds the breach outputs (JSON/HTML). Confirmed findings cite the breach tool and a second source; tested credentials cite the auth observation.
