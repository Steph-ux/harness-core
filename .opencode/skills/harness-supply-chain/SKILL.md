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

### Ecosystem budget (one lookup each)

| Eco | Pin file | Lookup |
|---|---|---|
| npm | package-lock.json | cyber_cve / osv-scanner |
| PyPI | poetry.lock / pip freeze | cyber_cve |
| Go | go.sum | cyber_cve |
| Debian | dpkg list | cyber_cve |
| Maven | pom lock | cyber_cve |

```
cyber_process argv=["sha256sum","<lockfile>"]
cyber_process argv=["trivy","fs","--scanners","vuln","<dir>"]
```

Range without a lockfile is `not-tested`. Do not `npm install` to grow a tree. Unflagged pin or absent name is the negative control. Transitive vs direct: say which. Reachability is `harness-source-deep`, not this pass.

### Stop

Installing the dep, write to a production registry, reporting a GHSA that does not match the pinned version.

### Evidence ids

Lockfile hash, one lookup per eco, unflagged-pin control, `affected-by` only after lookup.

### Reproduction recipe

Hash the pin file before parse. Lookup the exact version. Unflagged pin or absent name is the negative control. Do not install. Reachability is another method. GHSA without matching pin is not a finding.

## Done

Each reported dependency has a pin, a lookup, and a control. An unscanned ecosystem stays `not-tested`. The lockfile hash is in evidence.
