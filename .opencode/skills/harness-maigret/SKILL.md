---
name: harness-maigret
description: "Correlate one approved username with Maigret or Sherlock, using a bounded site set and a second source before calling a profile confirmed."
---

# Maigret+Sherlock — bounded, two-source

Source: Maigret 0.6.6, Sherlock 0.16.2 (top-sites 100 then expand, 2025).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string.
Username in approved scope. No `--permute/--all-sites/--enrich/--with-domains` first pass.

## Steps

1. `cyber_process` `argv`:
```text
maigret <username> --no-autoupdate --no-recursion --top-sites 100 --timeout 15 -n 20 -J simple -fo <evidence-dir>
sherlock <username> --timeout 15 --print-found --output <evidence-dir>/sherlock.txt
```
Each own observation.

2. Site claim = candidate. Record URL + `200` + marker (profile is searched username, not generic search page). `cyber_source` JSON/HTML chunk.
3. Confirm via second independent `osint-deep` source: same username + `email/name/photo` hash. One hit not confirmation.
4. Extracted emails/usernames stay leads — each new identifier needs its own scope before second run.
5. `cyber_finding` only with two observations (Maigret/Sherlock + second source) + source chunk. Unconfirmed = candidate.

### Identity confidence

Classify each result as unavailable, claimed, found, or confirmed. Check the
final URL, HTTP body marker, profile title and account creation clues; a 200
status or generic login page is not a profile. Correlate a second attribute only
after the username result and keep each discovered username/email separately
scoped.

### Controls and privacy

Use a known-unused username and a near-match as negative controls. Do not
permute names, enrich profiles, contact accounts, bypass rate limits, or
collect private content. Store URLs and public result markers, not scraped
private messages, tokens or unnecessary personal data.

## Done

Evidence holds Maigret JSON + Sherlock text. Confirmed cites two observations + chunk.
