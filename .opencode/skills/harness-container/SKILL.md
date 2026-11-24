---
name: harness-container
description: "Assess an approved container image, Dockerfile or Kubernetes manifest read-only: identity, privileges, supply-chain pins, and a negative control."
---

# Container — image and manifest, read-only

Source: CIS Kubernetes, NSA/CISA K8s hardening, OCI image config, Trivy. Escape, pod create, and registry write are out of this method.

## Gate

The image, registry, cluster, or manifest must be named in the approved scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. Read-only: no image push, no `kubectl apply`, no privilege change, no container escape, no docker.sock exploit, no `nsenter` into a node.

## Steps

### 1. Identity first

Hash the collected image, Dockerfile, or manifest:

```
cyber_process argv=["sha256sum","<file>"]
cyber_process argv=["crane","digest","<approved-image>"]
```

Completion: one identity observation (digest or SHA256). A tag without a digest is not identity.

### 2. Inventory with the tools that exist

Use what is present; a missing binary is `not-tested`, not a guessed result:

```
cyber_process argv=["trivy","image","--scanners","vuln,misconfig,secret","<image>"]
cyber_process argv=["trivy","config","<manifest-dir>"]
cyber_process argv=["kubectl","auth","can-i","--list"]
cyber_process argv=["kubectl","get","pods,sa,roles,rolebindings","-o","json"]
```

Do not create a pod "to see". Do not `docker run --privileged` to confirm.

### 3. Record exposure candidates

Each of these is a **candidate** until a second read agrees:
- privileged, hostPID, hostNetwork, hostIPC
- hostPath, docker.sock, `/var/run/crio.sock`
- default service account token mounted
- runAsUser 0 / no runAsNonRoot
- capabilities ADD beyond a documented set
- public registry pull (no auth) for an image that should be private
- `latest` tag in a production manifest

Quote the JSON path or Dockerfile line. A Trivy FAIL without the snippet is not enough.

### 4. Negative control

A known-private image or a non-privileged workload **in the same scope** must not show the same exposure. Compare:
- privileged candidate vs a `securityContext` that drops ALL
- public pull vs a digest that 401s without creds

Same finding text on both is refused.

### 5. Finding contract

`cyber_finding` only with:
- inventory observation
- second agreeing read
- negative control
- manifest or image source chunk via `cyber_source`

Link `technology:container:<digest>` in the entity graph. CVEs on the image go through `cyber_cve` / `harness-supply-chain`, not this method's privilege claims.

## Done

Evidence holds the hash, the read-only inventory, and the negative control. An unscanned image stays `not-tested` with the missing tool named.
