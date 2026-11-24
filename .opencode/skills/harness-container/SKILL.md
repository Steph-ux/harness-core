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

### Candidate table

| Signal | Second read | Control |
|---|---|---|
| privileged | same in live pod json | drop-ALL pod |
| hostPath / docker.sock | volumeMounts snippet | volume absent |
| SA token default | automount true | automount false |
| runAsUser 0 | securityContext | non-root |
| public pull | crane/skopeo 200 anon | 401 without creds |
| `:latest` in prod | digest pin missing | tagged digest |

Escape, `nsenter`, `docker run --privileged` are out. Image CVEs → `harness-supply-chain`.

### Reproduction recipe

Digest identity, read-only trivy/kubectl, drop-ALL pod as control. No escape.

## Verification scenarios

Record Kubernetes context, namespace and workload UID before each live read.
Distinguish image defaults, rendered manifests, admission changes and actual pod state.
Evaluate effective capabilities and uid, not only one manifest key.

| Scenario | Evidence compared | Expected classification |
|---|---|---|
| Root image overridden by non-root pod context | image user and live securityContext | runtime override accounted for |
| Token automount omitted but inherited as false | service account and pod settings | not an exposed-token finding |
| Role grants `get` but not `list` on one resource | exact can-i action and namespace | bounded permission |
| Hardened twin denies the same requested privilege | manifest and authorization response | negative control |
| Registry pull works with cached credentials | credential configuration | anonymous access not established |

Pin the digest and cluster API resourceVersion to bound state drift.
Drop-ALL capabilities do not by themselves disable privileged or host namespace settings.
An unpinned tag is a reproducibility issue, not proof that malicious code ran.
Attach policy requirement, effective state, matching control and scope limitation.

## Done

Evidence holds the hash, the read-only inventory, and the negative control. An unscanned image stays `not-tested` with the missing tool named.
