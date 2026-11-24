---
name: harness-maigret
description: "Bounded Maigret/Sherlock on one approved username: top-sites only, classify 200 vs profile, second attribute, unused-username control. Never permute or contact."
---

# Maigret+Sherlock — bounded, two-source

Source: Maigret, Sherlock. First pass is top-sites 100. A login page is not a profile.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Username in approved scope. No `--permute`, `--all-sites`, `--enrich`, `--with-domains` on the first pass. Do not contact accounts, do not bypass rate limits, do not scrape DMs.

## Steps

### 1. Bounded scan

```
cyber_process argv=["maigret","<username>","--no-autoupdate","--no-recursion","--top-sites","100","--timeout","15","-n","20","-J","simple","-fo","<evidence-dir>"]
cyber_process argv=["sherlock","<username>","--timeout","15","--print-found","--output","<evidence-dir>/sherlock.txt"]
```

Each own observation. Missing binary → `not-tested`.

### 2. Classify each URL

unavailable / claimed / found / confirmed.

A **found** profile needs: final URL after redirects, HTTP body marker, profile title. The searched username must be the **account**, not a search hit. Generic `/login` 200 = claimed at most.

`cyber_source` JSON/HTML for found URLs only.

### 3. Second independent attribute

Same username + email, public name, or photo hash from `harness-email-osint` / `harness-breach-osint`. One site hit is not confirmation. Extra usernames discovered here are **new scope items**.

### 4. Negative control

A **known-unused** username (operator-listed) and a **near-match** must not produce the same found-set. Record both. If the unused name "exists" on the same 40 sites, the tool is matching search pages — not profiles.

### 5. Finding contract

`cyber_finding` only with Maigret/Sherlock observation + second source + source chunk + unused-username control. Store URLs and public markers. No tokens, no private messages.

Expand to more sites only in a **second** pass after the operator approves, still without permute.

### Result classes

| Class | Meaning |
|---|---|
| unavailable | timeout / 5xx |
| claimed | 200 login/search page |
| found | username is the account in title/body |
| confirmed | found + second attribute |

```
cyber_process argv=["maigret","<username>","--no-autoupdate","--no-recursion","--top-sites","100","--timeout","15","-n","20","-J","simple","-fo","<evidence-dir>"]
```

Unused-username control must not share the same found-set.

## Done

Evidence holds Maigret JSON and/or Sherlock text. Confirmed cites two observations + chunk + control.
