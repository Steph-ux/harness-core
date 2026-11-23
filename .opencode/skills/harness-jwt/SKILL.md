---
name: harness-jwt
description: "Test an approved JWT by comparing its decoded claims with the server's actual accept and reject behavior."
---

# JWT — claims vs behaviour, 2024-2025 confusions

Source: `testing-jwt-token-security` (`jku`/`x5u`/`kid` traversal, `alg:none`, key confusion).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string.
Token from approved test account only. Ledger stores SHA256, never raw token. No external decoder.

## Steps

1. Decode `header.payload` offline (`python -c 'import base64,json…'`). Record `alg,kid,jku/x5u,iss,aud,exp,sub,role`. `cyber_source` header chunk.
2. Replay original → positive control.
3. One-byte sig flip → expect `401/403` (negative control).
4. If flip still accepted, try `{"alg":"none"}` empty sig. Accepted → finding (cite both).
5. `kid` traversal `../../etc/passwd` / `/dev/null` + `jku`/`x5u` to attacker JWKS: one probe each `cyber_process` `argv`. Proof = JWKS fetch OOB + token accepted; `200` without hit is not.
6. `aud`/`iss` confusion: `service-A` token replayed on `api-B`. Wrong-audience acceptance = candidate.
7. → `harness-vuln-triage` → `cyber_finding` with original+flipped+`none`/`kid`/`jku` observations, header chunk `sources`, `checks` flipped:negative, `none`:reproduction. Claims alone never finding.

### Claim and key matrix

Record only the SHA256 of the approved token and the decoded claim names, not
the token. Compare `alg`, key id, issuer, audience, subject, roles, expiry,
not-before, issued-at and token type against the endpoint's expected contract.
Test one boundary at a time: expired, not-yet-valid, wrong audience, wrong
issuer, wrong key id, altered subject and altered role. A decoder's acceptance
is irrelevant; the server's accept/reject response is authoritative.

### Key lookup controls

Treat `jku`, `x5u` and `kid` as separate hypotheses. Use an approved local JWKS
or controlled callback and a benign test token only. The negative control is a
known-good token with a one-byte signature change and a key hosted at the
expected location; no callback plus rejection is not a bypass. Never point a
test at a third-party URL or retrieve arbitrary local files.

### Proof contract

An algorithm, weak secret, or claim mismatch is a candidate until the protected
endpoint accepts the forged or altered token and a second control rejects the
equivalent invalid token. Record token hashes, response status/body shape,
callback observation ids and endpoint source chunks; redact all raw tokens.

## Done

Claim cites original + tampered responses. Decoded `alg` alone not finding.
