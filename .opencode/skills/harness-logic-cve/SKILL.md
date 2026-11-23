---
name: harness-logic-cve
description: "Forge a novel logic CVE on an approved workflow by mutating one business field at a time and proving the server persists the illegal state."
---

# Logic CVE

Source: `business-logic-driven-cve`, `state-machine-testing`, `race-condition-testing`.

## Gate

The full legitimate workflow (cart → checkout → payment → validation, or role → promotion, or step → next) must be named in the scope and completable with an approved test identity. Every command goes through `cyber_process` with `argv`. Do not build a shell string. One mutated field per request. Amounts are 1 XOF / 0.01 when money is involved unless the scope explicitly allows more. Use `harness-vuln-triage` before any `cyber_finding`.

## Steps

1. Baseline: complete the legitimate flow once with the approved test account. Record price, quantity, status, role, step id, and every server response as the positive control (one observation per step, ids retained).
2. Mutate one field the client should not control and replay the same step:

- `price` / `amount` → `1` or `0.01`
- `quantity` → `-1`, `0`, `999999`
- `status` / `state` → `paid`, `approved`, `admin`
- `role` / `permission` → `admin`, `owner`
- `step` / `order` → skip id, replay id

Each mutation is one `cyber_process` `argv` observation. The server recomputes or rejects as negative control when it ignores the submitted value.

3. Observe persistence, not the submit response: read back the object (`GET /order/<id>`, ledger, receipt, or second identity's view). A 200 on submit with no persistence is not a finding.
4. Race variant (when the scope allows concurrency): replay the same successful mutation twice in parallel (`cyber_process` two `argv` calls, 50 ms apart) and record both responses plus the final read. A double-credit or double-state is the signal; a single write is not.
5. One confirmed persistence is one `cyber_finding` with: the baseline step observations, the mutated submit observation, and the later read observation as `checks` (positive-control / reproduction / negative-control when the server ignored it on the control). Cite the workflow spec or collected client as `cyber_source`. Visual proof via `cyber_capture` linked to the final read when the state is UI-visible. Never reuse a `referenceId`/`idempotency` key across attempts.

### State-machine coverage

Draw the legitimate states and permitted transitions before mutation. For each
transition record actor, precondition, server-side source of truth, side effect,
and rollback. Test only one transition edge or business field per attempt:
skip, replay, reverse, cross-tenant, stale-version and duplicate-submit are
separate hypotheses. A rejected request, unchanged state, or idempotent replay
closes the corresponding negative control.

### Impact boundary

Use a fresh test identity, test object and unique reference for each attempt.
Money, credits, roles and notifications stay at the smallest reversible value.
Stop immediately if a real beneficiary, external payment, privilege, or
customer record appears. Do not turn a race check into load testing: two
requests and one final read are the maximum bounded proof.

### Proof contract

The report names the violated invariant, the exact transition, the positive
baseline, the mutated request, the negative control, and the postcondition read.
If persistence or impact cannot be demonstrated, classify it as a candidate and
leave the logic CVE unconfirmed.

## Done

Each logic CVE cites the baseline flow, the single-field mutation, and the later read that proves persistence. No finding from the submit response alone; no finding without the control.
