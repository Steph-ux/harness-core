---
name: harness-phone-osint
description: "Gather public metadata on an approved E.164 number with PhoneInfoga plus a second source; never dial, SMS, or expand wildcards."
---

# Phone — PhoneInfoga + second source, no scrape

Source: PhoneInfoga, HLR/public lookup. No `*` expansion, no OTP trigger.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Number in canonical `+<cc><nsn>`, named in scope. No carrier scrape, no brute, no premium API unless cost is approved. No auto-dialer, no SMS oracle.

## Steps

### 1. Normalize

Record E.164, country, and line-type **hypothesis** from the scope, not from a guess.
Convert national format only with documented country context.

### 2. First source

```
cyber_process argv=["phoneinfoga","scan","-n","+<cc><nsn>"]
```

Own observation. If the binary is missing: `not-tested`, do not scrape HTML "instead".

### 3. Second independent source

Only if step 2 produced a **derived** email/name already in evidence:

```
cyber_process argv=["holehe","<derived-email>","--only-used"]
```

Or a breach corpus already allowed by `harness-breach-osint`. Same number + a second attribute (email/name/address) = candidate for confirmation. One lookup is never confirmation.

### 4. Negative control

A **known-unused** number in the same country, and a **near-match** (one digit off, in scope as a control only if the operator listed it) must not yield the same carrier+listing pair. Do not dial either.

### 5. Finding contract

`cyber_finding` only with:
- PhoneInfoga observation
- second-source observation
- `cyber_source` chunk (public listing, not a paid dump)
- negative-control observation

Hash any token. Never raw MSISDN in a global skill. Extracted emails/names stay leads — each needs its own scope before `harness-email-osint` / `harness-maigret`.

### Claim types (separate)

| Claim | Needs |
|---|---|
| carrier/country/line | PhoneInfoga obs |
| public listing | source chunk |
| same person | second attribute |
| credential | not this method |

```
cyber_process argv=["phoneinfoga","scan","-n","+<cc><nsn>"]
```

Known-unused number in the same country is the negative control. Derived emails stay leads until scoped.

### Stop

Dial, SMS, OTP, `*` expansion, premium API without cost approval.

### Evidence ids

PhoneInfoga, second source, unused-number control, listing chunk. Hash tokens. Never raw MSISDN in a promoted global skill.

Missing phoneinfoga → `not-tested`, do not scrape HTML instead.

### E.164

Canonical `+cc+nsn` in scope. National format needs documented country context.
Missing phoneinfoga → `not-tested`, no HTML scrape.

```
cyber_process argv=["phoneinfoga","scan","-n","+<cc><nsn>"]
```

Second source only if a derived email/name is already in evidence. Known-unused same-country number is the negative control.

### Stop

Dial, SMS, OTP, `*` expansion, premium API without cost approval.

## Verification scenarios

PhoneInfoga v2 scan writes console output; its process trace is the evidence artifact.
Check the installed `scan --help` before using version-dependent flags or scanner plugins.
Preserve the supplied number and the documented country-aware normalization.

| Scenario | Evidence compared | Expected classification |
|---|---|---|
| National-format number has an explicit country context | normalized E.164 and country rule | same number if conversion is valid |
| Historic listing names an earlier subscriber | publication and collection dates | no current ownership conclusion |
| Ported number differs from prefix-assigned carrier | source type and timestamp | distinguish original from current carrier |
| Search-link generator provides no retrieved page | generated URL only | lead, not an independent source |
| Unused fixture yields a generic country description | same-country fixture comparison | no individual attribution |

Use operator-owned fixtures; a one-digit near-match can belong to another person.
Carrier/country metadata is not a precise personal location.
Subscriber identity, account ownership and credential validity are separate claims.
Attach exact identifier match, source provenance, date limitations and executed control.
Reference: sundowndev/phoneinfoga v2 `cmd/scan.go` has no active `-o` output flag.

## Done

Evidence holds PhoneInfoga output. Confirmed cites two observations + source + control. No call, no SMS, no OTP, no wildcard.
