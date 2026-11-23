---
name: harness-component-cve
description: "Forge a CVE on a public component or service already in the engagement evidence by reproducing it in a local lab and fuzzing white+black until a controlled crash or logic bypass."
---

# Component CVE

Source: `cve-research-whitebox`, `public-component-fuzzing`, `patch-diff-analysis`.

## Gate

The component (plugin, theme, WHMCS/Plesk/XenForo module, service binary, or container image) must already be in `<evidence-dir>` or directly reachable from the engagement target list (public registry, vendor site). No proprietary source is fetched outside the approved boundaries. Every command goes through `cyber_process` with `argv`. Do not build a shell string. Lab only: fuzz in a local container/VM, never against the live engagement host.

## Steps

1. Identify: from `evidence/` (bundles, `httpx -tech-detect`, `tlsx`, `trivy fs <evidence-dir>`), list the exact component name and version already in scope (e.g. `Plesk Obsidian 18.0.81`, `WHMCS 8.x`, `XenForo 2.1.10 P2`). Record one observation for the inventory. If `trivy fs` flagged a CVE, cite its observation; otherwise note `no NVD CVE at this version`.
2. Lab setup: pull the same public version into a local lab (`docker pull` / `git clone --depth 1` of the public repo or vendor tarball) in `/tmp/cve-lab-<name>`. Record the lab image/commit observation. The lab is the only target during fuzzing.
3. White-box pass: run the same deep pass as `harness-source-deep` on the lab source — `semgrep --config p/<lang>` + `gf` patterns — focused on one sink class (deserialize, SSRF, auth bypass, file write). Record one observation per config. Keep hits where `source → sink` is reachable from an unauthenticated route.
4. Black-box pass: against the lab container, one payload at a time (same discipline as `harness-web-deep`): a single-field mutation or a single deserialization / SSRF / XXE payload with a benign marker (`CVE-CANARY-<id>`). Record each attempt. A crash is `503` with a stack marker, not a timeout — measure duration (`diff-control --seuil-ms`) to distinguish WAF `503` fast vs worker `504` slow.
5. One controlled proof: replay the successful payload with a fresh marker and with the control (original value) that does not trigger. Record both observations. When the impact is file write or RCE, the marker is the only file written (`/tmp/cve-canary-<id>.txt` in the lab), never a real path.
6. CVE draft: when the pair holds, produce one `cyber_finding` with the component inventory observation, the semgrep/gf observation, the two lab observations as `checks`, and the lab `cyber_source` chunk (e.g. `Dockerfile`, `composer.json`, or the vulnerable function `file:line`). Include a minimal patch (one-line fix) and the `trivy fs` negative control on the patched lab. No live engagement host is ever the proof target.

### Research matrix

Separate known advisory, affected version, reachable attack surface, exploit
precondition, impact and fixed version. Test one sink class at a time and keep
the lab image, dependency lockfile, configuration and patch hash immutable.
White-box reachability is a hypothesis; black-box behavior and a patched-lab
negative control are required before calling the issue novel or CVE-worthy.

### Safety boundary

The lab is disposable and network-isolated. Use a canary file, controlled
callback or benign logic marker only. Never fuzz a production service, publish
a working exploit, or include proprietary source or secret values in the
finding. A crash without a reproducible trigger and control remains a lab bug,
not a confirmed vulnerability.

## Done

Evidence holds the component inventory, the lab image observation, the semgrep/gf hits, one successful lab payload and its control, and the CVE draft finding with patch. No finding from a public advisory alone; no finding without the lab pair.
