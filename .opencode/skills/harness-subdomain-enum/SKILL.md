---
name: harness-subdomain-enum
description: "Enumerate subdomains of an approved domain with the installed passive inventory (BBOT, Amass, subfinder, dnsx, ct-logs) and keep out-of-scope names out of the ledger."
---

# Subdomain — passive-only, dedup + re-resolve

Source: `performing-subdomain-enumeration-with-subfinder` (2024: overlaps via `candidates.txt`).

## Gate

Approved scope must include the apex and its subdomains, otherwise stop. Every command goes through `cyber_process` with `argv`. `BBOT --no-deps`. No `dnsbrute`/`dnsbrute_mutations`/`naabu`/`ffuf` in this pass.

## Steps

1. Three passive sources, each its own observation:
```text
bbot -t <apex> -p subdomain-enum -rf passive -em dnsbrute dnsbrute_mutations --no-deps -y --json -o <evidence-dir>
amass enum -d <apex> -passive -o <evidence-dir>/amass.txt
subfinder -d <apex> -all -o <evidence-dir>/subfinder.txt
```
2. Merge → `candidates.txt` (unique, only `*.apex` parent kept; rest = out-of-scope, blacklisted, not requested).
3. Re-resolve the kept names:
```text
dnsx -l <evidence-dir>/candidates.txt -resp -o <evidence-dir>/dnsx.json
```
Only `dnsx`-resolved names advance. Unresolved = stays candidate.

4. Cross-check with CT already collected by `harness-attack-surface` A / `harness-ct-logs` (including `Mes-outils/01-enumeration/ct-union.py --only-uniq`). A name seen in CT but absent from `dnsx` is not live — not an asset.
5. One observation per tool + one for `candidates.txt` + one for `dnsx.json`. Two independent passive sources must agree before calling a name confirmed.

### Candidate states

Store each name as `candidate`, `in-scope`, `resolved`, `live`, or `not-tested`,
with source and reason. Normalize trailing dots, wildcard labels, IDN/punycode
and case before deduplication. A CNAME to a provider is a pivot lead only; do
not register or claim the provider resource.

### Negative controls and limits

Retain an out-of-scope name, an NXDOMAIN name and a name seen in only one source
as controls. Do not brute-force, resolve arbitrary CT names, or probe names
absent from the approved apex. A passive hit is never proof of an active host.

### Finding contract

Subdomain enumeration does not create a `cyber_finding`. A takeover, exposure
or vulnerable service claim requires the live observation and controls from the
owning DNS, web or triage method.

## Done

Subdomain list cites the three tool observations + `dnsx.json`. One-source or non-apex names stay candidates.
