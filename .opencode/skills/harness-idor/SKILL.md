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

### Reference types (one extra if the first is clean)

| Type | Example | Untested if |
|---|---|---|
| numeric | `/orders/12` | only UUID in API |
| UUID | `/orders/550e…` | sequential only |
| slug | `/u/alice` | n/a |
| nested | `/orgs/1/invoices/9` | no nesting |
| export | `/export/job/3` | no export |
| channel | websocket id | no WS |

### Argv

```
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <A>","<url>/api/<res>/<A-id>"]
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <A>","<url>/api/<res>/00000000-0000-0000-0000-000000000000"]
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <A>","<url>/api/<res>/<B-id>"]
```

Restore write canaries. No customer id enumeration. Public-by-design catalogs, cache hits, and redacted 200 bodies stay controls, not findings. Untested reference types remain `not-tested` with the reason.

### Evidence ids

Keep A-own, B-own, missing, A-for-B and unauthenticated observations distinct.
For writes add the independent B read and restoration record.
Missing ownership or denial evidence leaves a candidate. `contains` is B's private marker.

### Write path

Reversible `notes:CANARY-<id>` only. Proof is B's GET, not PUT 200. Restore + verify. No `referenceId` reuse. Mass assignment: one field then GET then restore.

```
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <A>","-X","PUT","--data-binary","@canary.json","<url>/api/<res>/<B-id>"]
```

Public catalogs and cache hits are not IDOR. Untested reference types stay `not-tested`.

### Stop

Enumerating real customer ids, skipping the missing-id control.

## Verification scenarios

Use owner-created synthetic objects with unique markers, never inferred customer ids.
Treat list, detail, nested, export and download references as separate authorization paths.
Keep parent and child ownership explicit when testing nested resources.

| Scenario | Observation | Expected classification |
|---|---|---|
| A reads public B catalogue fields | policy and owner baseline | public by design, not IDOR |
| A receives B's private marker | B-own vs A-for-B response | read-isolation candidate |
| Missing id returns a generic success shell | body fingerprint | existence signal unreliable |
| Write echoes a marker but B's read is unchanged | mutation plus owner read | write bypass not established |
| Export job is denied but its download is public | job and artifact policies | separate download boundary |

Compare stable fields; timestamps and request ids can make equivalent denials look different.
Check whether a proxy cache, rather than the origin, served the private marker.
Random or unguessable ids do not replace an authorization decision.
Retain actor/object mapping and the independent owner response in every finding packet.

## Done

Finding cites three GETs (own, missing, cross) plus re-read if write. `200` without B's fields is not a finding.
