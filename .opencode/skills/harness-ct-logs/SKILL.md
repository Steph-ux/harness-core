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

### Reproduction recipe

CT is candidates not findings. dnsx before live. Wildcard/NXDOMAIN are controls.

## Verification scenarios

Use recorded CT responses to test normalization before resolving any new name.
Suffix matching must accept `api.example.test` but reject `example.test.evil.test`.
Preserve the original SAN and the normalized hostname as separate fields.

| Scenario | Expected result | Evidence retained |
|---|---|---|
| Same certificate in two CT feeds | one certificate, two provenance entries | fingerprint and feed timestamps |
| Certificate contains `*.example.test` only | wildcard candidate, no invented members | original SAN |
| Valid certificate for a dead DNS name | historical asset candidate, not live | CT row and DNS response |
| Expired certificate, live HTTPS now | inspect current certificate separately | two distinct fingerprints |
| CT provider rate-limits | source unavailable, not empty inventory | 429 and retry limit |

Two feeds repeating the same certificate are not two independent ownership proofs.
A successful DNS answer is liveness evidence even when HTTPS returns 401 or 404.
An expired historical certificate does not prove the current endpoint has expired TLS.
Keep certificate observations, hostname observations and authorization scope distinct.

### Coverage record

Record feed, collection time, fingerprint, SAN, validity interval and scope decision.
Record DNS resolver, response code and collection time for permitted resolutions.
Do not use an out-of-scope hostname as an active negative-control destination.
Hand any current TLS weakness to `harness-crypto-tls` with its own controls.

## Done

Ledger separates in-scope vs out-of-scope, each tied to a CT observation. Reused in attack-surface merge.
