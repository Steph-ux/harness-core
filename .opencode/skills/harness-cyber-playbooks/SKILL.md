---
name: harness-cyber-playbooks
description: "Route an authorized engagement to one harness playbook: attack surface, API, identity, cloud, container, forensics, detection, LLM app, compliance, supply chain, IoT, mobile, or binary."
---

# Harness cyber playbooks

Load exactly one playbook. Do not load the upstream catalog.

## Gate

Select the narrowest playbook matching the authorized objective and load it
before any answer or command. Read the local skill-gate procedure before the
first active probe. If no row matches, say so and do not invent a method.
Every active command still goes through `cyber_process` with `argv`; this
router never authorizes a shell string by itself. A candidate requires a
positive and a negative control from the selected playbook.

## Steps

1. Classify the request by asset, action and proof required.
2. Load exactly one primary playbook; route a discovered secondary surface
   through its own method.
3. Verify scope, tool availability, approval and evidence location.
4. Execute the playbook order, recording each command and negative control.
5. Triage before finding; preserve `not-tested` branches and missing-tool gaps.

The router is a dispatch aid, not evidence. A result is accepted only when the
selected playbook's observation, source and control requirements are satisfied.

## Technique cards

When a method is not known yet, read the card before improvising:
`cyber_method {action:"technique", name:"T-JWT"}` returns the precondition, tool
family, the observation that closes the technique, the control that must not
match, the stop condition and the detection twin. `action:"gaps"` lists the
families with no owner. A card is a candidate, never a `cyber_finding`: it
becomes a durable method only after an authorized execution is recorded, through
`cyber_method {action:"propose"}` then `promote`. A `not-covered` card is
reported as such and is never replaced by an improvised procedure.

| Situation | Skill |
| --- | --- |
| First external map of an approved domain | harness-attack-surface |
| Subdomains of an approved domain | harness-subdomain-enum |
| DNS records or zone transfer | harness-dns-enum |
| Names from certificate transparency | harness-ct-logs |
| Authorized API assessment | harness-api-testing |
| Route seen but absent from the documented API | harness-shadow-api |
| JWT accepted or rejected | harness-jwt |
| OAuth2 or OIDC flow | harness-oauth2 |
| Object id or reference | harness-idor |
| Role, method, or function boundary | harness-access-control |
| Price, quantity, state, or workflow rule | harness-business-logic |
| GraphQL endpoint | harness-graphql |
| Scanner hit or HTTP 200 claimed as a vulnerability | harness-vuln-triage |
| Secret in a file already collected | harness-secret-scan |
| APK, IPA, or authorized mobile client | harness-mobile-pentest |
| Local binary open in Ghidra | harness-ghidra |
| Approved username correlation | harness-maigret |
| Approved phone number | harness-phone-osint |
| Approved email address | harness-email-osint |
| Metadata of a collected file | harness-exiftool |
| Deep web (SSRF/SSTI/XXE/deser/pollution/race) | harness-web-deep |
| Internal pivot from foothold | harness-network-pivot |
| Active Directory read-only | harness-ad-enum |
| Cloud read-only (AWS/GCP/Azure) | harness-cloud-enum |
| Breach and paste correlation | harness-breach-osint |
| Source deep — JS/sourcemap line-level taint + endpoint inventory | harness-source-deep |
| Logic CVE — one-field business-state forgery until persistence | harness-logic-cve |
| Component CVE — public component lab fuzz until controlled proof | harness-component-cve |
| Learned 0-day — capitalize hunter run into abstract patterns | harness-learned-0day |
| Approved container image or Kubernetes manifest | harness-container |
| SSO, RBAC, or PAM boundary | harness-iam |
| Collected memory, disk, or packet artifact | harness-forensics |
| Detection rule from a confirmed finding | harness-detection |
| Approved LLM or agent application | harness-llm-security |
| Control framework mapping | harness-compliance |
| Lockfile, SBOM, or pinned dependency | harness-supply-chain |
| Approved IoT firmware or interface | harness-iot |
| Authorized red-team emulation on named hosts (foothold, persistence, C2, evasion, staging, teardown) | harness-red-team |
| Authorized phishing or pretext simulation, canary credentials only | harness-social-engineering |

Read `/home/moon/lab/reference/harness-skill-gate.md` before the first active probe. It defines the installed pipeline and its order: passive enumeration (`subfinder` / `dnsx` / `httpx` / `tlsx`) → history (`waymore` / `gau`) → crawl (`katana` / `hakrawler` / `cariddi` / `paramspider`) → scan (`nuclei` / `gitleaks`) → (only if scope allows) brute (`naabu` / `ffuf` / `gobuster`) → OSINT / files. Do not add tools outside the gate. Every active step writes into `<evidence-dir>` as its own observation; visual proof uses `cyber_capture` linked to that observation id; a finding is only `cyber_finding` with `evidence` + `sources` + `checks` (reproduction / positive-control / negative-control). The report is the frozen snapshot chain: `cyber_report snapshot` then `<harness-core>/.opencode/skills/rapports-cyber/scripts/build_report.py <snapshot.json> --out <reportDir>`. No browser capture may show an automation banner (Chromium/Edge: `--test-type`; Playwright: `ignoreDefaultArgs: ["--enable-automation"]`), and the address bar stays visible — see `Evidence to report` in the gate file. The index of the unused upstream catalog is `/home/moon/lab/reference/acs-frontmatter-index.json`.

**Coverage contract.** One `cyber_tasks` entry per in-scope asset, closed only with a successful observation; `not-tested` needs a written reason and stays visible. Every finding maps to an OWASP Top 10 (2021) category and a MITRE ATT&CK technique; the report snapshot carries the `coverage` table. **Browser discipline.** One browser context per engagement: list open pages first, reuse the page of the same asset, close the page at the end of the asset and the browser at the end of the engagement. Never leave a Chrome window open; for evidence prefer `cyber_capture evidence`.

**Traffic.** Capture only in scope and when the mandate allows it; `tcpdump -w` gives a `dump` artifact, `tshark` analyses it, each observation is recorded. **Versions.** For every technology with a version, run `cyber_cve lookup` and link `affected-by` in the entity graph; a version is not a vulnerability until the lookup says so.

**Chain before classifying.** Read `rapports-cyber/references/chaines.md` before closing an analysis: IDOR→write, SSRF→metadata, XSS→admin, open redirect→OAuth, weak JWT→admin, subdomain takeover→OAuth. Each link needs its own observation and negative control; an unproven chain stays not-reproduced and is recorded with `cyber_entity relate kind=chains-with`.

**OSINT is a graph.** Every account, organisation, repository, technology or certificate becomes an entity with its observation; ingest dumps with `cyber_entity import` (lines / httpx / json) instead of retyping them. A partner → account → repo → host chain is a pivot only if the graph holds it.

## Done

The selected playbook is named in the session, scope and tool gaps are visible,
and each claim points to its evidence contract. No generic catalog dump,
unscoped pivot or unsupported finding is treated as completion.
