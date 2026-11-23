---
name: harness-credential-spray
description: "Test password spray, credential stuffing, and brute-force protections with bounded attempts, lockout detection, and timing analysis."
---

# Credential spray — bounded, lockout-aware, timing-analyzed

Source: `testing-credentials`, `password-spraying`, `credential-stuffing` (2024: MFA bypass via rate limit, OTP brute-force, lockout policy enumeration, timing-based user enumeration).

## Gate

Approved `host+auth endpoint+test accounts` only. Every command via `cyber_process` `argv`. Maximum 10 attempts per account per test cycle. Stop immediately on lockout detection. Test accounts only — never spray production credentials. → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. Authentication endpoint mapping

Identify all auth surfaces:
- Login forms (username+password)
- API authentication (`/api/auth`, `/oauth/token`)
- SSO/SAML endpoints
- Password reset / forgot password
- OTP/MFA verification
- Account registration (for user enumeration)

### 2. User enumeration (timing-based)

Before spraying, check if the endpoint leaks valid usernames:
- Send valid username + wrong password → measure response time
- Send invalid username + wrong password → measure response time
- 5 samples each, compare median response times
- Difference > 100ms consistently → timing-based user enumeration

Also check:
- Different error messages ("invalid username" vs "invalid password")
- Different HTTP status codes
- Different response lengths

### 3. Lockout policy detection

Before any spray, determine the lockout policy:
1. Send 3 wrong passwords for a test account → still accessible?
2. Send 5 wrong passwords → locked?
3. Send 10 wrong passwords → locked?
4. If locked, wait 5 min → unlocked? 15 min? 30 min?
5. Record: threshold, lockout duration, reset mechanism

**If no lockout detected after 10 attempts → vulnerability (no account lockout).**

### 4. Rate limit analysis

Test rate limiting on the auth endpoint:
- Send 10 requests in 1 second → throttled?
- Send 10 requests over 10 seconds → throttled?
- Rotate source IP (if proxy available) → still throttled?
- Change User-Agent → still throttled?
- Use different HTTP methods (GET vs POST) → different limits?

### 5. Password spray (bounded)

If no lockout or rate limit was detected:
1. Select 3-5 common passwords: `Password1!`, `Summer2024!`, `Welcome1!`, `Company123!`, `Changeme1!`
2. For each test account: try ONE password, wait 30 seconds, try the next
3. Never try more than 5 passwords per account per hour
4. Monitor for lockout after each attempt

Spray pattern: one password across all accounts before moving to the next password (avoids per-account lockout).

### 6. MFA bypass testing

If MFA is present:
- OTP brute-force: is the OTP rate-limited? (try 10 wrong OTPs)
- OTP reuse: can the same OTP be used twice?
- OTP expiry: does the OTP expire? After how long?
- MFA fatigue: can unlimited push notifications be sent?
- Fallback: can MFA be bypassed via a recovery flow?
- API bypass: does the API enforce MFA or only the web UI?

### 7. Session management

After successful authentication:
- Session token entropy (is it predictable?)
- Session fixation (can you set the session before auth?)
- Concurrent sessions (is there a limit?)
- Session revocation on password change

### 8. Negative controls

- Control 1: valid credentials → successful login (positive control)
- Control 2: clearly invalid credentials → rejected (negative control)
- Control 3: locked account → spray rejected (if lockout exists)
- Control 4: rate-limited request → 429 or block (if rate limit exists)

## Proof contract

A finding needs: (1) identified auth endpoint and policy, (2) demonstrated weakness (no lockout, no rate limit, user enumeration, MFA bypass), (3) bounded evidence (not exhaustive brute-force), (4) reproduction, (5) four negative controls. A wrong password error is not a finding — missing lockout is.

## Done

Each finding cites the auth endpoint, the policy gap (lockout threshold, rate limit, MFA bypass), the bounded test results, and all negative controls. Never report a valid password found via spray — report the missing protection.
