---
name: harness-compliance
description: "Map confirmed findings to CIS, NIST CSF, ISO 27001, PCI DSS or SOC 2 and record missing evidence as a gap, not as a vulnerability."
---

# Compliance — control map from evidence

Source: CIS Benchmarks, NIST CSF 2.0, ISO 27001 Annex A, PCI DSS 4.0, SOC 2 TSC. A control is satisfied by an observation, never by a policy PDF.

## Gate

The framework **and** the in-scope system must be named. Every command goes through `cyber_process` with `argv`. Do not build a shell string. This method does not invent a finding from a missing policy, does not score a maturity level, and does not copy a standard into the ledger as if it were evidence.

## Steps

### 1. Freeze the control list

List the control ids in scope (example: `CIS-5.2`, `PR.AA-01`, `A.8.5`, `PCI-8.3.6`). The list is a `cyber_source` chunk of **your** scope table, not a dump of the standard. Completion: every id has a one-line expected artifact (log, config, screenshot, interview note already collected).

### 2. Attach evidence or mark not-tested

For each control, exactly one of:
- **passed** — an observation id that demonstrates the control (config present, log showing the check, TLS capture)
- **failed** — an observation that shows the control is not met **and** that observation already backs a finding
- **not-tested** — missing artifact, named

A scanner hit cannot satisfy a control it does not demonstrate. `nuclei` on a logo is not `CIS-5.2`.

### 3. Negative control

A control with no observation cannot be marked passed. Replay: pick one control marked passed and confirm the cited observation still exists in-scope and still contains the claimed marker. If the observation is gone, the pass is void.

Also: a neighbouring control that was **not** in scope must not appear as passed.

### 4. Failed control vs finding

A failed control becomes a `cyber_finding` only when a reproduction and a negative control **already** prove the weakness (`harness-vuln-triage`). Otherwise it stays a coverage gap on the control table. Compliance language (`non-conformité`) is not a CVSS vector.

### 5. Snapshot

The report snapshot carries the control table beside finding ids. Each passed row cites observation ids. Each failed row cites the finding id. `not-tested` cites the missing artifact name.

```
cyber_process argv=["python3","-c","print('control table is the snapshot input, not a scan')"]
```

Do not run a compliance scanner and paste its score. If a tool is used (`lynis`, `inspec`), its output is an observation that still has to map to one control id.

### Control states

| State | Requires |
|---|---|
| passed | observation id + marker |
| failed | finding id already verified |
| not-tested | missing artifact named |

A scanner score is not a control. Neighbouring out-of-scope controls must not appear as passed (negative control).

## Done

Every in-scope control is passed, failed, or `not-tested`. No control is passed without an observation id. The framework name is in the mission scope, not inferred.
