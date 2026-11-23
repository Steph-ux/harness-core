---
name: harness-detection
description: "Turn one confirmed finding into a detection rule and prove it matches the reproduction while a clean control does not."
---

# Detection — rule from a confirmed finding

## Gate

Start from a `cyber_finding` that already has a reproduction and a negative control. Every command goes through `cyber_process` with `argv`. Do not build a shell string. The rule describes the observed behavior. It does not add an attack.

## Steps

1. Name the finding id, the reproduction observation, and the field that must match: status line, path, process, or hash. Completion: the rule cites those ids.
2. Write one Sigma, YARA, or log query in `<evidence-dir>`. Keep the target value as a hash or a path template, not a secret.
3. Run the rule on the reproduction artifact. A match is the positive control.
4. Run the same rule on a clean artifact or the original negative-control capture. A match there rejects the rule.
5. `cyber_finding` for a detection gap cites the missed reproduction, the rule text chunk, and the negative control. A rule that was not executed stays a candidate.

## Done

The rule file, the match, and the clean miss are three observations. No rule is shared if it contains a host, token, or raw secret.
