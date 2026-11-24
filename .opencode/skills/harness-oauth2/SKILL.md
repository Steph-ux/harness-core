---
name: harness-oauth2
description: "Test an approved OAuth2/OIDC client: legit code exchange, unregistered redirect, state strip, PKCE downgrade, audience mismatch; never a production user."
---

# OAuth2/OIDC — redirect, state, PKCE, audience

Source: RFC 6749/8252, OIDC core. Missing `state` is a finding only if the stripped callback still creates a session.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. Approved `client_id`, `redirect_uri`, test account only. No device-code against a real user. One mutation per callback. Redact codes/tokens in the ledger (SHA256 only).

## Steps

### 1. Record the authorize URL

`client_id`, `redirect_uri`, `scope`, `response_type`, presence of `state`, `nonce`, PKCE. `cyber_source` the URL chunk (no code).

### 2. Positive control

Legit `code→token` with the test user:

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-d","grant_type=authorization_code","<token-endpoint>"]
```

Protected-resource request after that is the session proof.

### 3. Unregistered redirect

```
cyber_process argv=["curl","-sS","-D","-","-o","NUL","<authorize>?client_id=<id>&redirect_uri=https://attacker.example/cb&response_type=code"]
```

`400 invalid_redirect_uri` = negative control. `302` to unregistered with a `code` = signal.

### 4. State / PKCE

Callback with `state` removed or swapped. If the client still creates a session, record both. PKCE downgrade: strip `code_challenge`. Redeemed code replay must fail.

### 5. Audience

Client-A token on api-B. Acceptance = candidate → `harness-jwt` / triage. Implicit and device-code grants stay `not-tested` unless named.

### 6. Finding contract

`cyber_finding` with legit flow, one mutated flow, server/client decision, and (for session claims) a resource request. Sources: authorize URL shape. Checks: legit positive, bad-redirect negative, stripped reproduction.

## Done

Each flaw cites legit + altered flow. Missing `state` is weakness only when the stripped callback still creates a session.
