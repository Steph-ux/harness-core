---
name: harness-business-logic
description: "Test an approved price, quantity, state, or workflow rule by changing one business field and proving the server accepted the illegal state."
---

# Business logic — one-field forgery until persistence

Source: `testing-for-business-logic-vulnerabilities` (2025: client-side price, coupon, step-skip).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string.
Approved test data only; payment/transfer needs reversible bound (1 XOF / 0.01). Stop if real customer affected.

## Steps

1. Baseline legit flow once (add→checkout→pay→receipt) with approved identity. Record `price,quantity,status,step,referenceId` as positive controls. `cyber_source` the client JS computing price.
2. Mutate one client field + replay: `price→1`, `quantity→-1/0/999999`, `status→paid`, `role→admin`, `step→skip`. One `cyber_process` `argv` each. Recompute/`400` = negative control.
3. Persistence: `GET /orders/<id>` / ledger / receipt / second identity view. Illegal persisted = finding; submit `200` alone never.
4. Race variant if scope allows concurrency: two identical mutations parallel (~50ms apart) + final read. Double credit = signal.
5. One persistence → `cyber_finding` with baseline+mutated+final-read `evidence`, client+spec `sources`, `checks` positive/reproduction/negative. Never reuse `referenceId`. Visual → `cyber_capture` on final read.

### Invariant matrix

Write the server-side invariant before testing: total = unit price × quantity,
status transitions only forward, an owner can act only on its own object, and a
payment must be independently verified. Test one field at a time at creation,
update, checkout, callback and finalization. Include duplicate submission,
replay, stale version and idempotency-key cases only where the workflow exposes
them. A client-side calculation or disabled button is not proof of a server
flaw.

### Controls and restoration

The untouched flow is the positive control. A server-recomputed amount,
rejected transition, bounded quantity error, and second submission with a new
reference are negative controls. Use the minimum permitted amount and an owned
test object; restore or purge any created instruction only under the engagement
cleanup policy. Record every state transition, not just the final response.

### Proof contract

A finding requires the illegal input, the server response, and an independent
read of the persisted state or ledger. If a payment gateway is involved,
separate instruction creation from confirmed settlement; `SUCCESSFUL` in a
client callback is not settlement proof. Keep untested branches visible with
the missing control or unavailable callback reason.

## Done

Finding cites 3 observations; submit `200` alone never a finding.
