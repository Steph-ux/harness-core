---
name: harness-supply-chain
description: "Review an approved lockfile, SBOM, or registry reference already collected, and confirm a vulnerable dependency with a lookup plus a negative control."
---

# Supply chain — lockfile and lookup

## Gate

The repository, image, or SBOM must already be in evidence or named in scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. Do not install the dependency. A public advisory is a lead until the lookup matches the pinned version.

## Steps

1. Hash the lockfile, SBOM, or image reference. Record ecosystem, name, and version exactly as written.
2. Run `cyber_cve lookup` or `trivy fs` on that pin. One observation per ecosystem.
3. Negative control: a dependency at a version the lookup does not flag, or a name that is not in the lockfile, must not be reported.
4. Reachability is a separate method. A vulnerable pin that no code calls stays a candidate.
5. `cyber_finding` cites the lockfile chunk, the lookup observation, and the negative control. Link `affected-by` in the entity graph.

## Done

Each reported dependency has a pin, a lookup, and a control. An unscanned ecosystem stays `not-tested`.
