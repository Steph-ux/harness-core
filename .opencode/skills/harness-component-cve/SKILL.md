---
name: harness-component-cve
description: "Forge a CVE on a public component already in evidence: inventory the pin, reproduce in an isolated lab, one sink class, patched-lab negative control. Never fuzz the live host."
---

# Component CVE — lab only, one sink, patched control

Source: patch diff, white-box reachability, black-box canary. A NVD row is a lead.

## Gate

The component (plugin, theme, WHMCS/Plesk/XenForo module, service binary, container image) must already be in evidence or on an approved public registry. Every command goes through `cyber_process` with `argv`. Do not build a shell string. **Lab only.** Never fuzz the live engagement host. No proprietary source outside boundaries. No public exploit PoC against production.

## Steps

### 1. Inventory the exact pin

From bundles, `httpx` tech, `tlsx`, or:

```
cyber_process argv=["trivy","fs","<evidence-dir>"]
```

Record name + version as written (`Plesk 18.0.81`, `XenForo 2.1.10 P2`). One inventory observation. If Trivy flagged a CVE, cite it; otherwise `no NVD CVE at this version`.

### 2. Lab of the same public version

```
cyber_process argv=["docker","pull","<public-image>:<tag>"]
```

or a vendor tarball hashed into `/tmp/cve-lab-<name>`. Record image digest / commit. The lab is the only fuzz target. Network-isolate it.

### 3. White-box — one sink class

Same discipline as `harness-source-deep`, **one** class: deserialize, SSRF, auth bypass, or file write.

```
cyber_process argv=["semgrep","--config","p/<lang>","<lab-src>"]
```

Keep hits where source → sink is reachable from an unauthenticated route. Reachability is a hypothesis until black-box agrees.

### 4. Black-box — one field, one marker

Against the lab, one payload at a time (`harness-web-deep`):

```
cyber_process argv=["curl","-sS","-D","-","--data-binary","@payload.json","http://127.0.0.1:<lab-port>/<path>"]
```

Marker `CVE-CANARY-<id>`. A crash is a stack marker or `503` with duration vs WAF-fast `503` (`diff-control`). Timeout alone is not a crash.

### 5. Reproduction + controls

Replay successful payload with a **fresh** marker. Control: original value, no trigger. If impact is file write/RCE, the only written file is `/tmp/cve-canary-<id>.txt` **in the lab**.

Patched-lab negative control: apply the one-line fix (or next vendor version), re-run the payload — must not fire. `trivy fs` on the patched lab must not be used as that control; the **same payload** must miss.

### 6. Finding contract

`cyber_finding` with inventory, semgrep/gf, lab payload, original-value control, patched-lab miss, lab `cyber_source` (function `file:line` or Dockerfile). Include a minimal patch. No live host is the proof target. Not novel until patched control holds.

### Lab isolation

Network-isolated container/VM. Same public version as inventory. Hash image/commit. One sink class (SSRF / deser / auth bypass / file write). Canary file only in `/tmp/cve-canary-<id>.txt` in the lab.

```
cyber_process argv=["docker","pull","<public-image>:<tag>"]
cyber_process argv=["semgrep","--config","p/<lang>","<lab-src>"]
```

Original-value control and patched-lab miss required. Live engagement host is never the fuzz target.

### Stop

Fuzzing production, publishing a working exploit, proprietary source outside boundaries.

### Evidence ids

Inventory, lab identity, white-box, lab payload, original-value control, patched miss, `file:line` chunk.

### Reproduction recipe

Lab same pin, one sink, original-value and patched-lab miss. Never live host.

## Verification scenarios

Keep the component pin, lab configuration and exact reproduction fixture immutable.
Use synthetic marker files rather than real system files for read/write claims.
A patched miss supports remediation; novelty needs a separate prior-art/advisory check.

| Scenario | Evidence compared | Expected classification |
|---|---|---|
| Scanner lists no advisory for the version | scanner/database state | no match found, not “no CVE exists” |
| Lab uses a different configuration from inventory | digests and feature flags | applicability unresolved |
| Same trigger works only in the vulnerable build | vulnerable/fixed traces | patch differential supported |
| Fixed build fails every request, including benign input | functional positive control | broken control, not proof of fix |
| Request times out without a process crash | process log and exit state | timeout, not confirmed crash |

Check that authentication, parser and feature prerequisites match the actual deployed component.
Record both original-value and fixed-build controls; neither replaces a fresh reproduction.
Use offline or approved cached semgrep rules when the lab is network-isolated.
Attach source location, root cause, minimal patch and affected-version limits.
Do not claim vendor confirmation, CVE assignment or public disclosure that has not occurred.

## Done

Evidence holds inventory, lab identity, white-box hits, one successful lab payload, original-value control, patched-lab miss. No finding from an advisory alone.
