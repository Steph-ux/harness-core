---
name: harness-iam
description: "Test an approved SSO, RBAC, or PAM boundary by replaying one authorized action with a lower-privilege identity."
---

# IAM — identity boundary, two approved actors

## Gate

The identity provider, tenant, and two approved test identities must be named in the scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. No password spray, no unapproved ticket request, no policy write.

Active Directory stays in `harness-ad-enum`. This method owns SSO, OIDC, RBAC, and PAM outside that forest.

## Steps

1. Record the caller identity and the policy or role document already collected. Completion: one observation names the actor and the permission under test.
2. Replay one approved action as the higher identity. That response is the positive control.
3. Replay the same action as the lower identity, one field or role swapped. Record status and body shape.
4. Negative control: the same call with no credential, or against an object the higher identity also must not read, must fail. A 200 error page is not access.
5. `cyber_finding` cites the higher read, the lower replay, the negative control, and the policy chunk. Restore nothing that was not changed.

## Done

The finding names both identities and the permission that differed. An untested provider stays `not-tested`.
