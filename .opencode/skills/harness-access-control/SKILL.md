---
name: harness-access-control
description: "Prove BFLA/function-level and field-level access control with privileged baseline, low-priv replay, unauth replay, and a re-read; 200 HTML is not access."
---

# Access control — BOLA/BFLA, two identities, re-read

Source: OWASP API1/API5, ASVS V4. A role name in a JWT is not enforcement.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Two approved identities (low + higher) and the target method/object named in scope. No real customer. No destructive DELETE to fill a matrix. Restore every accepted write.

## Steps

### 1. Inventory state-changing routes

From OpenAPI / `endpoints.json` already in evidence, pick 3–5 `POST/PUT/PATCH/DELETE` that touch `price|role|status|owner|id`. One observation for the inventory. `cyber_source` the contract chunk.

### 2. Privileged baseline

Higher identity, one approved action:

```
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <token-high>","-X","PUT","--data-binary","@body.json","<url>"]
```

Positive control. Record status, schema, one stable field. Hash body.

### 3. Low-priv replay

Same method+path+body, credential swapped. One request. Record.

### 4. Unauth replay

No `Authorization`. Negative control. `401`/`403` expected. Login HTML `200` is **not** access.

### 5. Decide

`200` with identical private fields, or a state change visible on **GET re-read**, = candidate. Empty `{}` / error envelope = control. Mass assignment: **one** field (`role`/`ownerId`), then GET, then restore.

Object-level vs function-level vs field-level: say which. Peer-tenant is `harness-idor` if only the id changed.

### 6. Finding contract

`cyber_finding` evidence = privileged + low-priv + unauth (+ re-read). Checks: privileged positive, unauth negative, low-priv reproduction. `contains` is the leaked field or persisted marker, not `200`. Capture UI only if linked to the re-read observation.

### Identity matrix

| Identity | Expected |
|---|---|
| unauth | 401/403 |
| low-priv | 200 own / 403 admin fn |
| high-priv | 200 + re-read |

```
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <low>","-X","PUT","--data-binary","@body.json","<url>"]
```

Peer-tenant id swap → `harness-idor`. Restore every write.

### Function vs object vs field

| Level | Swap | Proof |
|---|---|---|
| object | id | harness-idor |
| function | admin path | 200 + re-read |
| field | role/ownerId | GET shows change |

```
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <high>","<url>"]
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <low>","<url>"]
cyber_process argv=["curl","-sS","-D","-","<url>"]
```

Unauth is the negative control. Restore writes. OpenAPI chunk as source.

### Stop

Real customer, destructive DELETE, third identity, JWT role as sole proof.

### Evidence ids

Privileged, low-priv, unauth, re-read if write. `contains` is the field/marker.

### Reproduction recipe

Same method+path+body, only the credential changes. Persist via GET, not PUT 200. Restore the marker. Login HTML 200 is the negative control, not access. JWT role text is not enforcement. Mass assignment is one field then restore. Peer-tenant id swap is `harness-idor`. Admin function 200 for low-priv is BFLA.

Generic 200 envelopes, stale caches and empty results stay controls. Privilege outside the two approved identities is out of this method.

OpenAPI chunk is the source. Capture only if linked to the re-read observation.

Low-priv 403 on an admin function is the expected control, not a failed test.

Two identities only. No "temporary admin".

## Done

Finding cites three observations + source chunk. A different 200 page is not a finding.
