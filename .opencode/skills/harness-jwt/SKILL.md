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
cyber_process argv=["node","-e","const f=require('node:fs'),c=require('node:crypto');const t=f.readFileSync(process.argv[1],'utf8').trim();console.log(JSON.stringify({sha256:c.createHash('sha256').update(t).digest('hex'),headerNames:Object.keys(JSON.parse(Buffer.from(t.split('.')[0],'base64url').toString('utf8')))}));","<restricted-token-file>"]
```

Record `alg,kid,jku/x5u,iss,aud,exp,sub,role`. `cyber_source` header names only. SHA256 of the token in the observation.

### 2. Replay original

Same protected endpoint. Positive control (200 + expected shape).

### 3. One-byte signature flip

Expect `401`/`403`. That is the negative control. If still accepted → candidate for none/key-confusion.

### 4. `alg:none` (only after flip still accepted, or as a dedicated probe)

Empty signature, `alg:none`. A protected-resource marker is needed for acceptance,
not HTTP 200 alone. Cite the original, mutation and an actual rejecting twin.

### 5. `kid` / `jku` / `x5u` — one probe each

Use only a lab-owned key fixture for `kid` path handling.
For `jku`/`x5u`, use your approved OOB JWKS endpoint and correlate fetch plus acceptance.
For local `kid`, proof is the attributed key-selection effect and protected-resource result.

### 6. Audience / issuer

Service-A token on api-B. Wrong-audience acceptance = candidate. Expired / nbf separately, one at a time.

### 7. Finding contract

`cyber_finding` with original, mutation, protected-resource result and header chunk.
The flip is a negative control only when it is actually rejected; an accepted
flip is a reproduction signal, so use a separate rejecting twin for the control.
Claims on a jwt.io screenshot are not evidence.

### Probe matrix (one row per observation)

| Probe | Expect | If accepted |
|---|---|---|
| Original | 200 + expected shape | positive control |
| 1-byte sig flip | 401/403 | negative control failed → none/kid next |
| `alg:none` empty sig | reject | candidate if protected marker returned |
| `kid` lab-owned fixture | reject wrong key selection | attributed key effect + protected marker |
| `jku` to your JWKS | fetch may occur but acceptance denied | OOB fetch + protected marker |
| `aud` of service-A on api-B | reject | candidate if private API-B data returned |
| expired `exp` | reject beyond configured leeway | candidate if protected marker returned |

SHA256 of the token in every observation. Never the compact serialization.

```
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <redact>","<url>"]
```

### Stop

Third-party jwt.io, `jku` to a random host, retrieving real `/etc/passwd`, spraying `HS256` secrets against production. One probe row per observation — do not batch alg/kid/aud in a single request.

### Evidence ids

Record observation ids for original, flip, and the winning probe. Missing any → candidate. `contains` is the accept/reject body marker, never the JWT itself. Reproduction must be a new request-id after the original claim.

### Token handling

Ledger stores SHA256 only. Compact serialization never in titles. `jku` only to an OOB you control. Expired and nbf are separate rows.

### Stop

jwt.io, random Internet JWKS, reading real `/etc/passwd`, HS256 spray on production.

### Reproduction recipe

SHA256 only. Flip is negative control. none/kid/jku one row each. No jwt.io.

## Verification scenarios

Mutate decoded signature bytes, then re-encode canonically.
Changing unused base64url padding bits can leave the actual signature unchanged.
Keep signing-key trust, algorithm selection and claim validation as separate hypotheses.

| Scenario | Observation | Expected classification |
|---|---|---|
| Modified token receives a public login page | protected response marker absent | no signature-bypass proof |
| Controlled JWKS is fetched but token is rejected | callback and authorization decision | fetch observed, no acceptance |
| Wrong-audience token accesses a protected test resource | actor and private marker | audience boundary candidate |
| Expired token succeeds inside documented clock leeway | expiry and server time | not necessarily an expiry defect |
| Valid token works while signature-byte twin is rejected | same endpoint and actor | negative control |

Use protected header/token files so argv and process traces do not expose bearer values.
The offline decoder above outputs only a fingerprint and header names; it does not verify trust.
Key-id traversal needs a lab-owned key fixture, never a real system file.
An OOB fetch is relevant to JWKS/URL resolution, not required for every kid claim.
Attach accepted resource effect, actual changed bytes, key/claim hypothesis and denial control.

### Executed local regression

`node test/opencode-skill-fixtures.cjs` executes the offline Node recipe from this
file plus loopback HTTP checks: valid HS256, signature-byte rejection, unsigned
fixture access vs strict denial, audience denial, soft-login 200 and padding-bit alias.
The report binds these observations to this file's SHA256.
This is a deterministic protocol fixture, not proof that an agent follows every step.
JWKS/x5u, asymmetric-key confusion, expiry leeway and real deployments remain unvalidated.

## Done

Finding cites original + tampered responses. Decoded `alg` alone is not a finding.
