---
name: harness-container
description: "Assess an approved container image, Dockerfile, or Kubernetes manifest already in scope, read-only, and record exposure, identity, and supply-chain gaps."
---

# Container — image and manifest, read-only

## Gate

The image, registry, cluster, or manifest must be named in the approved scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. Read-only: no image push, no pod create, no privilege change, no container escape attempt.

## Steps

1. Hash the collected image, Dockerfile, or manifest and record one identity observation. Completion: SHA256 is in evidence.
2. Inventory with the tools present: `trivy image`, `trivy config`, or `kubectl auth can-i --list` and `kubectl get pods,sa,roles -o json` on the approved context. A missing binary is `not-tested`, not a guessed result.
3. Record privileged, hostPath, hostNetwork, hostPID, mounted docker socket, default service account token, and a registry pull that is public. Each is a candidate until a second read agrees.
4. Negative control: a known-private image or a non-privileged workload in the same scope must not show the same exposure. A scanner hit alone is not a finding.
5. `cyber_finding` only with the inventory observation, the second read, the negative control, and the manifest or image source chunk via `cyber_source`.

## Done

Evidence holds the hash, the read-only inventory, and the negative control. An unscanned image stays `not-tested` with the missing tool named.
