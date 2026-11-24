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

Record E.164, country, and line-type **hypothesis** from the scope, not from a guess. A national format without `+` is not the same number.

### 2. First source

```
cyber_process argv=["phoneinfoga","scan","-n","+<cc><nsn>","-o","<evidence-dir>/phoneinfoga.txt"]
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
cyber_process argv=["phoneinfoga","scan","-n","+<cc><nsn>","-o","<evidence-dir>/phoneinfoga.txt"]
```

Known-unused number in the same country is the negative control. Derived emails stay leads until scoped.

### Stop

Dial, SMS, OTP, `*` expansion, premium API without cost approval.

### Evidence ids

PhoneInfoga, second source, unused-number control, listing chunk. Hash tokens. Never raw MSISDN in a promoted global skill.

## Done

Evidence holds PhoneInfoga output. Confirmed cites two observations + source + control. No call, no SMS, no OTP, no wildcard.
