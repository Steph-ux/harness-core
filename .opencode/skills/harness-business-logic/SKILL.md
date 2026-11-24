---
name: harness-business-logic
description: "Forge one business field (price, quantity, step, coupon) and prove the server persisted the illegal state; submit 200 is never enough."
---

# Business logic — one-field forgery until persistence

Source: client-side price, coupon, step-skip. Payment needs a reversible bound.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Approved test data only. Payment/transfer: 1 XOF / 0.01 max, reversible. Stop if a real customer is affected. Never reuse `referenceId`.

## Steps

### 1. Write the invariant

Before any probe: `total = unit × qty`, status only forward, owner-only, payment independently verified. `cyber_source` the client JS that computes price.

### 2. Baseline

Legit add→checkout→pay→receipt once. Record `price,quantity,status,step,referenceId`. Positive control.

```
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <token>","-X","POST","--data-binary","@checkout.json","<url>"]
```

### 3. One mutation

One field per attempt: `price→1`, `quantity→-1/0/999999`, `status→paid`, `step→skip`. Server recompute / `400` = negative control.

### 4. Persistence

`GET /orders/<id>` or receipt or second identity. Illegal **persisted** = candidate. Submit `200` alone never. If a gateway is involved, separate instruction creation from settlement.

### 5. Optional race

Two identical mutations ~50ms apart + final read. Double credit = signal. One slow request is not a race.

### 6. Finding contract

`cyber_finding` with baseline, mutated submit, independent read. Checks: positive / reproduction / negative (recompute). Capture on the final read if visual, linked to that observation. Restore/purge under cleanup policy.

## Proof contract

A finding requires the illegal input, the server response, and an independent read of persisted state. `SUCCESSFUL` in a client callback is not settlement. Untested branches stay visible with the missing control named.

### Field matrix (one per attempt)

| Field | Probe | Persist proof |
|---|---|---|
| price/amount | `1` / `0.01` | GET total |
| quantity | `-1` / `0` / `999999` | GET qty |
| status | `paid` / `approved` | GET status |
| step | skip id | GET step |
| coupon | reused code | ledger line |

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","--data-binary","@mut.json","<url>"]
```

Gateway `SUCCESSFUL` callback is not settlement. Unique `referenceId` each try.

### Invariant first

Write `total = unit × qty`, forward-only status, owner-only, independent payment verify. `cyber_source` the client JS that computes price.

Race is optional: two POSTs ~50ms + final GET. One slow request is not a race. Restore/purge under cleanup. Payment bound 1 XOF / 0.01.

### Stop

Real customer, reusing `referenceId`, treating gateway callback as settlement.

### Evidence ids

Baseline, one mutation, independent read, recompute/400 negative control. Capture linked to final read if UI.

### Reproduction recipe

Invariant first, one mutation, persist via GET. Gateway callback is not settlement.

## Verification scenarios

Use synthetic orders in a sandbox; do not execute this table on live payments.
Keep the actor, currency, product and quantity constant while changing amount.
Account for tax, shipping and rounding before declaring an invariant violated.

| Scenario | Observation to collect | Expected classification |
|---|---|---|
| Amount changed but recomputed server-side | final order still has catalogue total | clean negative control |
| Submit echoes `paid`, later GET says `pending` | submit plus independent read | no persisted payment bypass |
| Illegal price persists in a new order | authoritative total and unique order id | reproducible pricing candidate |
| Identical idempotency key returns same order | two responses, one ledger entry | correct idempotency |
| Two sandbox requests create two credits | unique ledger entries and balances | race candidate, not timing alone |

An unexpected partial write needs a follow-up read even when the response is 500.
Keep the provider's settlement id separate from the application's order id.
A monetary discrepancy is not automatically a loss: show which actor benefits.
Preserve test objects until the mission's restitution and cleanup gates permit removal.

### Finding packet

Record the invariant, actor, object id and exact changed field.
Attach baseline, mutation, independent read and the actual rejecting control.
State whether settlement, delivery and notifications were tested or not-tested.
Do not substitute a different vulnerability's 400 response for this control.

## Done

Finding cites three observations. Submit `200` alone is never a finding.
