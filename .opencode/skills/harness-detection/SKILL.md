---
name: harness-detection
description: "Turn one confirmed finding into a Sigma, YARA or log rule and prove it matches the reproduction while a clean control does not."
---

# Detection — rule from a confirmed finding

Source: Sigma spec, YARA, detection-engineering loop (true positive on the reproduction, true negative on a clean twin).

## Gate

Start from a `cyber_finding` that already has a reproduction and a negative control. Every command goes through `cyber_process` with `argv`. Do not build a shell string. The rule describes the observed behavior. It does not add an attack, does not scan the operator's fleet, and does not contain a host, token or raw secret.

## Steps

### 1. Bind the finding

Name the finding id, the reproduction observation, the negative-control observation, and the field that must match: status line, path, process name, hash, or log key. Completion: those ids are in the rule comment, not guessed later.

### 2. Choose one detector family

Pick **one**:
- Sigma (process create, network, web log)
- YARA (file or memory bytes already in evidence)
- SIEM query (the log source already collected)

Do not mix families in one pass. Write the rule under the engagement `regles/` folder via an observation of the write.

### 3. Positive control — the reproduction must match

Run the rule on the reproduction artifact only:

```
cyber_process argv=["sigma","scan","--file","<repro-log>","--rules","<rule.yml>"]
cyber_process argv=["yara","-s","<rule.yar>","<repro-sample>"]
```

A match is the positive control. No match = the rule is wrong, not the finding. Fix the rule or stop. Record the command as its own observation.

### 4. Negative control — a clean twin must miss

Run the **same** rule on:
- the finding's original negative-control capture, or
- a known-clean fixture of the same format (benign process create, clean file, unrelated log window)

A match there **rejects** the rule. The same output cannot be both the claim and its refutation.

### 5. Tune once, then freeze

If the clean twin matches, narrow **one** field (image name, hash, path template). Re-run steps 3 and 4. A second tune without a new observation is narration. Do not add a second technique to "make it hit".

### 6. Finding contract

`cyber_finding` for a **detection gap** (rule missed the reproduction) cites:
- the missed reproduction observation
- the rule text as a `cyber_source` chunk
- the clean-twin observation as negative control

A rule that was not executed stays a candidate. A rule that matches both twins is not a detector.

## Done

Three observations exist: rule file write, match on reproduction, miss on clean twin. No shared rule contains a host, token, or raw secret. An untested log source stays `not-tested`.
