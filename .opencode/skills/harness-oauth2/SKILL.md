---
name: harness-oauth2
description: "Test an approved OAuth2 or OIDC flow for redirect, state, and audience failures without using a production user."
---

# OAuth2/OIDC — redirect, state, PKCE, audience

Source: `testing-oauth2-implementation-flaws` (2024: `state` fixation, `redirect_uri` open redirector, `code` replay).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string.
Approved `client_id`, `redirect_uri`, test account only. No device-code flow vs real user. One mutation per callback.

## Steps

1. Record authorize URL, `client_id`, `redirect_uri`, `scope`, `response_type`, `state`+`nonce`+`PKCE` presence. `cyber_source` authorize URL chunk.
2. Legit `code→token` exchange with test user → positive control.
3. `redirect_uri` not registered (`https://attacker.example/cb`) via `cyber_process` `argv`. `302` to unregistered = signal; `400 invalid_redirect_uri` = negative control.
4. Callback `state` removed/swapped — if client still creates session, record both. `PKCE` downgrade (strip `code_challenge`) same.
5. `aud`/`azp` confusion: `client A` token replayed on `api B` that should reject `aud!=B`. Acceptance = candidate → `harness-vuln-triage`.
6. `cyber_finding` with legit+altered-redirect+`state`-less observations, authorize chunk `sources`, `checks` legit:positive, bad-redirect:negative, stripped:reproduction.

### Flow matrix

Record authorization-code, PKCE method, state, nonce, redirect URI, client id,
scope, issuer and token audience. Test one callback mutation at a time:
unregistered redirect, equivalent-encoding redirect, missing or swapped state,
replayed code, wrong client id, missing PKCE verifier, wrong nonce, and token
audience mismatch. Use only an approved test client and account; do not test
implicit or device-code flows against a production user.

### Controls and replay

The untouched authorization flow is the positive control. An unregistered
redirect must be rejected without sending a code; an altered state must not
create a session; and a redeemed code must fail on replay. Capture the browser
or HTTP callback only when it contains no token or personal data. A redirect
to an error page, a token issued for the wrong resource, or a client-side
warning is not proof of account takeover.

### Proof contract

Each OAuth finding needs the legitimate flow, the single mutated flow, the
server/client decision, and (for session claims) a protected-resource request
showing the resulting session. Preserve authorization URL and response shape
as sources, redact codes/tokens, and leave unsupported grant types explicitly
`not-tested`.

## Done

Each flaw cites legit + altered flow. Missing `state` is weakness only when stripped callback still creates session.
