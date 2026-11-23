---
name: harness-llm-security
description: "Assess an approved LLM or agent application by comparing one authorized prompt with a refused control, without extracting real user data."
---

# LLM app — one approved prompt, one control

## Gate

The application, test account, and allowed prompt class must be named in the scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. One probe. No real-user data, no tool call that changes production state, no attempt to obtain another tenant's content.

## Steps

1. Record the documented tool list, data boundary, and system instruction source already collected. Completion: one `cyber_source` chunk names the boundary.
2. Send one benign in-scope prompt. That response is the positive control.
3. Send one boundary probe that asks for an out-of-scope field or tool. Record whether the app refused, redacted, or returned the marker.
4. Negative control: the same probe against a field the test identity is allowed to read must not be reported as a bypass. A refusal page is not a finding.
5. `cyber_finding` only when the reproduction observation shows the forbidden field or tool effect and the negative control does not. Map it to the OWASP LLM category that the response supports.

## Done

Evidence holds both prompts' response hashes and the source chunk. An untested tool stays `not-tested`.
