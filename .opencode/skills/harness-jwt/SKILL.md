---
name: harness-jwt
description: "Test an approved JWT: decode claims, one-byte sig flip, alg none, kid/jku/x5u, aud/iss confusion; ledger stores SHA256 never the raw token."
---

# JWT — claims vs behaviour

Source: `alg:none`, key confusion, `jku`/`x5u`/`kid` lookup. Decoder acceptance is irrelevant.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Token from the approved test account only. Ledger stores SHA256, never the raw token. No third-party decoder site. No `jku` pointed at a random Internet host — controlled callback only.

## Steps

### 1. Decode offline

```
cyber_process argv=["python3","-c","import sys,base64,json; ..."]
```

Record `alg,kid,jku/x5u,iss,aud,exp,sub,role`. `cyber_source` header names only. SHA256 of the token in the observation.

### 2. Replay original

Same protected endpoint. Positive control (200 + expected shape).

### 3. One-byte signature flip

Expect `401`/`403`. That is the negative control. If still accepted → candidate for none/key-confusion.

### 4. `alg:none` (only after flip still accepted, or as a dedicated probe)

Empty signature, `alg:none`. Accepted → finding. Cite flip + none.

### 5. `kid` / `jku` / `x5u` — one probe each

`kid` traversal (`../../etc/passwd` or `/dev/null`) and `jku` to **your** OOB JWKS. Proof = OOB fetch **and** token accepted. `200` without the callback is not a bypass. Never fetch arbitrary local files for real.

### 6. Audience / issuer

Service-A token on api-B. Wrong-audience acceptance = candidate. Expired / nbf separately, one at a time.

### 7. Finding contract

`cyber_finding` with original, flipped, none/kid/jku observations, header chunk, checks: flipped negative, none/kid reproduction. Claims on a jwt.io screenshot are not evidence.

## Done

Finding cites original + tampered responses. Decoded `alg` alone is not a finding.
