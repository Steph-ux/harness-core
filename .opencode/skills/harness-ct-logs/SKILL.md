---
name: harness-ct-logs
description: "Extract in-scope hostnames from certificate transparency; a logged name is not alive and not authorization to probe it."
---

# CT — logged ≠ alive ≠ authorized

Source: crt.sh, CertSpotter, bbot crt. Wildcard certs hide members.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Read CT already collected, or passive CT for the **approved apex** only. Do not browse a name because a cert mentions it.

## Steps

### 1. Collect

Prefer evidence already on disk. If absent:

```
cyber_process argv=["bbot","-t","<apex>","-m","crt","certspotter","-rf","passive","--no-deps","-y","--json","-o","<evidence-dir>"]
```

Each CT source = own observation. Deduplicate by **certificate fingerprint**, not hostname.

### 2. Scope filter

Extract SAN+CN. Keep names under the approved apex. `*.apex` is a parent signal, not a license to brute. Out-of-apex names are out of scope.

### 3. Liveness is another observation

Only after scope filter:

```
cyber_process argv=["dnsx","-silent","-resp","-l","<candidates.txt>"]
cyber_process argv=["httpx","-silent","-tls-probe","-l","<live-dns.txt>"]
```

Liveness = DNS answer + httpx 200/3xx + tlsx valid. A CT row alone is never a finding.

### 4. Negative control

Keep: wildcard-only name, expired cert, CT hostname that **fails** DNS. Those are controls. Do not fetch them "to see".

Takeover hypothesis → current DNS + provider evidence (`harness-dns-enum` / `harness-subdomain-enum`), not this method.

### 5. Finding contract

CT creates **asset candidates**, not `cyber_finding`. Certificate/takeover/exposure claims go to the owning method with live observation, source chunk, and controls.

### Name fate

| CT name | Next |
|---|---|
| under apex | candidates.txt |
| wildcard only | control, not brute |
| expired cert | control |
| NXDOMAIN | control, not live |
| out of apex | drop |

```
cyber_process argv=["bbot","-t","<apex>","-m","crt","certspotter","-rf","passive","--no-deps","-y","--json","-o","<evidence-dir>"]
cyber_process argv=["dnsx","-silent","-resp","-l","<candidates.txt>"]
```

Dedup by certificate fingerprint. Logged ≠ alive ≠ authorized. Takeover → `harness-dns-enum`.

### Stop

Browsing a CT name before scope+dnsx. This method does not file `cyber_finding` for a log row alone.

### Evidence ids

Each CT source, merge, dnsx. Finding only via owning method with live obs. A log row is never a `cyber_finding` by itself.

Wildcard members are not a license to brute in this method.

## Done

Ledger separates in-scope vs out-of-scope, each tied to a CT observation. Reused in attack-surface merge.
