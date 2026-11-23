---
name: harness-ct-logs
description: "Extract in-scope hostnames from certificate transparency evidence without treating a logged name as authorization to probe it."
---

# CT — logged ≠ alive ≠ authorized

Source: `analyzing-tls-certificate-transparency-logs` (2024: crt.sh 502s, wildcard blindness).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string.
Read CT already collected, or `bbot -m crt` passive for approved apex. Do not browse a name because cert mentions it.

## Steps

1. Prefer `<evidence-dir>`: `bbot -m crt` events, `httpx/tlsx` SANs, `gau/waymore` + `Mes-outils/01-enumeration/ct-union.py` (5 plugins: `ct_certspotter` double `domain=`/`q=`, `ct_crtname`, `ct_crtsh`, `ct_hackertarget`, `ct_sourcegraph`). Run if absent:
```text
bbot -t <apex> -m crt certspotter -rf passive --no-deps -y --json -o <evidence-dir>
_ lib: 01-enumeration/ct-union.py --apex <apex> --check <host> --only-uniq
```
Each source = own observation.

2. Extract SAN+CN, keep `*.apex` parent only; rest out-of-scope. Generic `*.apex` certs signal invisible members → schedule `dns-convention.py`.
3. Feed kept names into `candidates.txt` merge + `dnsx -resp` + `httpx -tls-probe` before live. Liveness = `httpx 200/3xx` + `tlsx` valid, own observation. Cert alone never finding.

### Certificate correlation

Record certificate fingerprint, issuer, validity window, SAN/CN, wildcard
relationship and source timestamp. Deduplicate by fingerprint, not hostname.
Issuance is evidence—not ownership, liveness, authorization or a vulnerability.

### Negative controls and limits

Keep a wildcard-only name, an expired certificate and a CT hostname that fails
DNS resolution as controls. Do not fetch a CT-listed host until it passes scope
and liveness gates. A takeover hypothesis needs current DNS, provider evidence
and an approved non-destructive ownership check.

### Finding contract

CT logs create asset candidates, not a `cyber_finding`. Any certificate,
takeover or exposure claim must be handed to the owning method with live
observation, source chunk and positive/negative controls.

## Done

Ledger separates in-scope vs out-of-scope, each tied to CT observation. Reused in attack-surface merge.
