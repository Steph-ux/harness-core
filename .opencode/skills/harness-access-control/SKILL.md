---
name: harness-access-control
description: "Test an approved role or method boundary by replaying one authorized request with a lower-privilege identity."
---

# Access control — BOLA/BFLA deep

Source: `testing-for-broken-access-control` (2024-2026: BFLA, function-level, mass assignment via OpenAPI diff).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string.
The two identities (low-priv test user + higher-role test user) and the target object/method must be named in the approved scope. Approved-scope read first (`cyber_mission status`).

## Steps

1. Inventory: pull 3-5 state-changing routes from `endpoints.json`/OpenAPI in `<evidence-dir>` (from `harness-source-deep` crawl). Focus `POST/PUT/PATCH/DELETE` touching `price|role|status|owner|id`. Record observation.
2. Privileged baseline (allowed role) → positive control. Record via `cyber_process` `argv`.
3. Low-priv replay: same `method+path+body`, credential swapped. One request via `cyber_process` `argv`. Record.
4. Unauth replay: no `Authorization`. Record.
5. Decide: `200` with identical fields or state change visible on re-read `GET` = candidate. `200` with login HTML / empty / error is not. Mass assignment variant: `PUT ... {"role":"admin"}` — one field only.
6. Promote via `harness-vuln-triage` → `cyber_finding` with `evidence`=3 ids, `sources`=OpenAPI chunk, `checks`={privileged:positive-control, low-priv:reproduction, unauth:negative-control}. Add `cyber_capture` if UI-visible.

### Boundary matrix

Test the same operation across unauthenticated, low-privilege, peer-tenant and
authorized-admin identities. Cover object-level, function-level and field-level
boundaries separately. Include direct path, query, body, header and method
override references where the API exposes them. A role name in a JWT or UI is
not evidence of enforcement; the server response and a re-read are.

### Controls and safe writes

Use an owned test object and a benign reversible marker. The privileged request
is the positive control; an unrelated object, an absent permission, and an
unauthenticated replay are negative controls. Restore every accepted write and
record the restoration as its own observation. Never use a real customer,
privilege escalation outside the two approved identities, or a destructive
DELETE merely to complete the matrix.

### Proof contract

An access-control finding requires the authorized result, the lower-privilege
replay, and a post-request read from the affected identity. If the lower role
receives a generic 200 envelope, login page, stale cache, or empty result, keep
it as a control—not a finding—and record the ambiguity.

## Done

Finding cites 3 observations + source chunk. Differing 200 page is not a finding.
