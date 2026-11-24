---
name: harness-credential-spray
description: "Test password spray, credential stuffing, and brute-force protections with bounded attempts, lockout detection, and timing analysis."
---

# Credential spray — bounded, lockout-aware, timing-analyzed

Source: `testing-credentials`, `password-spraying`, `credential-stuffing` (2024: MFA bypass via rate limit, OTP brute-force, lockout policy enumeration, timing-based user enumeration).

## Gate

Approved `host+auth endpoint+test accounts` only. Every command via `cyber_process` `argv`. Maximum 10 attempts per account per test cycle. Stop immediately on lockout detection. Test accounts only — never spray production credentials. → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. Positive control — valid login

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"username\":\"<test-user>\",\"password\":\"<test-pass>\"}","<url>/api/auth/login"]
```

Record status (`200`), `Set-Cookie`, body schema. Hash the response. This is the functional baseline.

### 2. Negative control — invalid credentials

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"username\":\"<test-user>\",\"password\":\"WRONG-aZ9x$\"}","<url>/api/auth/login"]
```

Record status, body, `Content-Length`. Then repeat with an invalid username:

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"username\":\"nonexistent-user-xK3\",\"password\":\"anything\"}","<url>/api/auth/login"]
```

Compare the two rejection responses. If error message, status, or body length differ → user enumeration signal.

### 3. Timing-based user enumeration

Five samples each, valid then invalid username, same wrong password:

```
cyber_process argv=["curl","-sS","-o","/dev/null","-w","%{time_total}","-X","POST","-H","Content-Type: application/json","-d","{\"username\":\"<test-user>\",\"password\":\"WRONG\"}","<url>/api/auth/login"]
```

```
cyber_process argv=["curl","-sS","-o","/dev/null","-w","%{time_total}","-X","POST","-H","Content-Type: application/json","-d","{\"username\":\"fake-nonexistent-9Zx\",\"password\":\"WRONG\"}","<url>/api/auth/login"]
```

Median difference > 100ms across 5 samples → timing-based enumeration candidate. Record each `time_total`.

### 4. Lockout policy detection

Three wrong passwords spaced 2 seconds apart for the test account:

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"username\":\"<test-user>\",\"password\":\"WRONG-1\"}","<url>/api/auth/login"]
```

After 3 failures, attempt valid login. Still works → no lockout at 3. Repeat to 5, then 10, testing valid login after each batch. Record the threshold where valid login fails or returns `423`/`429`.

If no lockout after 10 attempts → missing account lockout candidate.

### 5. Rate limit analysis

Ten requests in rapid succession:

```
cyber_process argv=["curl","-sS","-D","-","-o","/dev/null","-w","status:%{http_code} time:%{time_total}","-X","POST","-H","Content-Type: application/json","-d","{\"username\":\"<test-user>\",\"password\":\"WRONG\"}","<url>/api/auth/login"]
```

Run 10 times. Record each status and time. If no `429`, `503`, or CAPTCHA challenge after 10 rapid requests → missing rate limit candidate. Test also with different `User-Agent` and `X-Forwarded-For` to check if limits are per-IP or per-session.

### 6. Bounded spray — one password, all accounts

Spray pattern: ONE common password across all test accounts (wait 5s between each), then verify valid login still works:

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"username\":\"<test-user-1>\",\"password\":\"Password1!\"}","<url>/api/auth/login"]
```

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"username\":\"<test-user-2>\",\"password\":\"Password1!\"}","<url>/api/auth/login"]
```

Maximum 5 passwords per account per hour. After each pass, re-login with valid credentials to confirm no lockout.

### 7. MFA bypass — OTP rate limit

If MFA is present, test OTP brute-force resistance:

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"otp\":\"000000\"}","<url>/api/auth/verify-otp"]
```

Send 5 wrong OTPs. If still accepted on 6th → no OTP rate limit. Test OTP reuse (send same valid OTP twice). Test OTP expiry (use a valid OTP after 5 min).

### 8. API vs UI enforcement

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"username\":\"<test-user>\",\"password\":\"<test-pass>\"}","<url>/api/v1/login"]
```

If the web UI enforces CAPTCHA or MFA but the API endpoint at a different path does not → MFA/CAPTCHA bypass candidate.

### Stop

More than 10 attempts per account per cycle. Production accounts. Sustained brute-force. Lockout without recovery plan.

### Evidence ids

Keep positive-login, invalid-user-rejection, valid-user-rejection, timing samples (5+5), lockout probes, rate-limit probes, spray attempts, and MFA probes as separate observations. Each observation records status, body hash, and `time_total`.

## Verification scenarios

| Scenario | Observation | Expected classification |
|---|---|---|
| Valid login returns session token | 200 + Set-Cookie | positive control confirmed |
| Invalid user vs invalid password same response | identical status+length+body | user enumeration: not vulnerable |
| Invalid user 50ms, valid user 250ms, 5 samples | consistent delta > 100ms | timing-based enumeration candidate |
| 10 wrong passwords, valid login still works | 200 on 11th attempt | missing account lockout candidate |
| 10 rapid requests all return 200 | no 429/503/CAPTCHA | missing rate limit candidate |
| OTP endpoint accepts 10 wrong codes | no block after 10 | OTP brute-force candidate |
| API login skips CAPTCHA present in web UI | 200 without challenge | CAPTCHA bypass candidate |
| Rate limit triggers at 5 req/s | 429 on 6th | negative control: rate limit present |
| Account locks at 5 wrong passwords | 423 on 6th | negative control: lockout present |

A wrong password rejection is not a finding. The finding is the missing protection (no lockout, no rate limit, differential responses, OTP bypass).

## Done

`cyber_finding` cites the auth endpoint, the policy gap, the bounded evidence (attempt count, timing deltas, status codes), and all controls. A valid password discovered by spray is never reported — only the missing protection is. Untested MFA or API paths stay `not-tested`.
