---
name: harness-compliance
description: "Map confirmed findings to an approved control framework and record missing evidence as a gap, not as a vulnerability."
---

# Compliance — control map from evidence

## Gate

The framework and the in-scope system must be named. Every command goes through `cyber_process` with `argv`. Do not build a shell string. This method does not invent a finding from a missing policy.

## Steps

1. List the control ids in scope: CIS, NIST CSF, ISO 27001, PCI DSS, or SOC 2. Completion: the list is a source chunk, not a copied standard.
2. For each control, attach the observation that satisfies it, or mark `not-tested` with the missing artifact.
3. Negative control: a control with no observation cannot be marked passed. A scanner hit cannot satisfy a control it does not demonstrate.
4. A failed control becomes a `cyber_finding` only when an existing reproduction and negative control already prove the weakness. Otherwise it stays a coverage gap.
5. The report snapshot carries the control table beside the finding ids.

## Done

Every in-scope control is passed, failed, or `not-tested`. No control is passed without an observation id.
