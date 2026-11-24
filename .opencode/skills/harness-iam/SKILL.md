---
name: harness-iam
description: "Test an approved SSO, OIDC, RBAC or PAM boundary by replaying one authorized action with a lower-privilege identity and a no-credential control."
---

# IAM — identity boundary, two approved actors

Source: OWASP ASVS V4 access control, OIDC core, cloud IAM (deny-by-default). Active Directory forests stay in `harness-ad-enum`. Tokens stay in `harness-jwt` / `harness-oauth2`.

## Gate

The identity provider, tenant, and **two approved test identities** must be named in the scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. No password spray, no unapproved ticket request, no policy write, no role assignment, no "temporary admin".

## Steps

### 1. Name the permission under test

Record the caller identities and the policy/role document already collected (`cyber_source`). Completion: one observation names actor A (higher), actor B (lower), and the **single** permission (read object X, call action Y).

### 2. Positive control — higher identity

Replay **one** approved action as identity A. Hash status + body shape (not the whole PII dump).

```
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <token-A>","<approved-url>"]
```

That response is the positive control (A is allowed).

### 3. Same action, lower identity

Replay the same URL/method as identity B, one field or role swapped. Record status and body shape. A 200 with an empty list is **not** the same as A's 200 with the object. Compare ids in the JSON, not the HTTP code alone.

### 4. Negative control

The same call with:
- no credential, or
- a token for an object **A also must not read** (out of both roles)

must fail (401/403 or empty authorized error). A 200 error page, a login HTML, or a verbose 500 is not "access". If B's "forbidden" response **equals** A's success body, that is the finding — not a control.

### 5. Finding contract

`cyber_finding` cites:
- higher read (A)
- lower replay (B)
- negative control (no creds or out-of-role object)
- policy chunk

Restore nothing that was not changed (this method is read-only). Horizontal vs vertical: say which. Cloud IAM (`iam:PassRole`, `*:*`) is still two identities and one action — do not dump the whole policy simulator.

### Permission matrix (one action)

| Actor | Object in role | Object out of role | No token |
|---|---|---|---|
| A higher | 200 + fields | 403 | 401 |
| B lower | 200 own only | 403 | 401 |

Horizontal = B reads A's object. Vertical = B calls A's admin action. Say which.

Cloud: still two identities, one action (`s3:GetObject`, `iam:PassRole`). No `*:*` dump.

SSO/OIDC session: after B's replay, a resource request proves the session. Token internals → `harness-jwt`. No policy write, no third identity, no spray. A 200 login HTML is not access.

### Evidence ids

A success, B replay, no-token or out-of-role control. Name both identities and the single permission in the finding title. Login HTML 200 is not access.

### Cloud vs SSO

`s3:GetObject` / `iam:PassRole` still two identities, one action. No `*:*` simulator dump. AD forest → `harness-ad-enum`. Token guts → `harness-jwt`.

### Stop

Password spray, policy write, role assignment, third identity.

## Done

The finding names both identities and the permission that differed. An untested provider stays `not-tested`. No third identity, no spray.
