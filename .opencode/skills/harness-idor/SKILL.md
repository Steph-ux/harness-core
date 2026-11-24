---
name: harness-idor
description: "Prove BOLA/IDOR with owner GET, nonexistent 404/403, other-id GET, optional reversible write re-read, and no real customer identifiers."
---

# IDOR/BOLA — owner vs other, re-read for write

Source: OWASP API1 BOLA. UUIDs still leak. `200` with an error JSON is not access.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Two approved test identities, or one identity plus a non-owned **test** reference the operator listed. Do not enumerate real customer objects. One field mutated per request. Restore any write.

## Steps

### 1. Positive control — owner read

Identity A, A's object:

```
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <token-A>","<url>/api/<resource>/<A-id>"]
```

Record status, schema, one stable field (name, balance, notes). Hash the body.

### 2. Existence-oracle control

A → nonexistent id (`000…` or operator-listed unused UUID). Expect `404`/`403`. If this returns the **same** body as step 1, stop — you cannot tell access from a template.

### 3. Cross-id read

A → B's id, **only** the reference swapped. Compare field values to B's own GET (B as positive for that object). Identical private fields = candidate. `{"error":…}` or `{}` is not BOLA.

Repeat **one** extra location if the first is clean: numeric, UUID, slug, nested child, export id, channel id. Untested types stay `not-tested`.

### 4. Write only if reversible

`PUT` as A on B's object, benign `notes:CANARY-<id>`. Proof is **B's GET** seeing the canary, not `PUT 200`. Restore + verify original. No `referenceId` reuse across attempts.

Mass assignment: one field (`ownerId` or `role`), then GET as A. Same restore.

### 5. Negative control (authz)

Unauthenticated GET of A's object must fail. If unauth sees B's fields, that is a different finding (`harness-access-control`).

### 6. Finding contract

`cyber_finding` evidence: A-own, missing, A-for-B, B-own, unauth. Checks: A-own positive, missing negative, A-for-B reproduction. `contains` is the leaked field, not `200`. Sources: endpoint chunk.

Public-by-design objects, cache hits, and redacted responses are not IDOR.

## Done

Finding cites three GETs (own, missing, cross) plus re-read if write. `200` without B's fields is not a finding.
