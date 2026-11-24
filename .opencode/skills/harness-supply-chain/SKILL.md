---
name: harness-supply-chain
description: "Review an approved lockfile, SBOM or registry pin, confirm a vulnerable dependency with a lookup plus a negative control, and keep reachability separate."
---

# Supply chain — lockfile and lookup

Source: CycloneDX/SPDX, OSV, NVD, `trivy fs` / `osv-scanner`. A public advisory is a lead until the lookup matches the **pinned** version.

## Gate

The repository, image, or SBOM must already be in evidence or named in scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. Do not install the dependency. Do not `npm install` / `pip install` to "get a tree". Do not reach production registries with write credentials.

## Steps

### 1. Hash the pin file

Hash the lockfile, SBOM, or image reference before parsing:

```
cyber_process argv=["sha256sum","<lockfile>"]
```

Record ecosystem, name, and version **exactly as written** (`==`, `~=`, git URL, digest). A range without a lockfile is `not-tested`, not "latest is vulnerable".

### 2. One lookup per ecosystem

Run **one** of:
```
cyber_cve lookup   (ecosystem, package, version)
cyber_process argv=["trivy","fs","--scanners","vuln","<dir>"]
cyber_process argv=["osv-scanner","-L","<lockfile>"]
```

One observation per ecosystem (PyPI, npm, Go, Debian, Maven). Mixing five ecosystems in one paste is not a lookup.

### 3. Negative control

A dependency at a version the lookup does **not** flag, or a name that is **not** in the lockfile, must not be reported. Run the same lookup on that pin or on a truncated lockfile that omits the claimed package. Same CVE on the control pin rejects the claim.

### 4. Reachability is another method

A vulnerable pin that no code imports stays a **candidate**. Do not open `harness-source-deep` inside this pass unless the mission already asked for reachability. `affected-by` on the entity graph links `technology:<eco>:<name>:<version>` to `vulnerability:CVE-…` only after the lookup observation exists.

### 5. Finding contract

`cyber_finding` cites:
- lockfile / SBOM chunk (`cyber_source`)
- lookup observation (`cyber_cve` or trivy/osv)
- negative-control observation (unflagged pin or absent name)

Transitive vs direct: say which. A GHSA without a matching version is not a finding.

## Done

Each reported dependency has a pin, a lookup, and a control. An unscanned ecosystem stays `not-tested`. The lockfile hash is in evidence.
