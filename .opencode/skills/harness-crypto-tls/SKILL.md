---
name: harness-crypto-tls
description: "Audit TLS configuration, cipher suites, certificate chain, key management, and cryptographic implementation weaknesses."
---

# Crypto & TLS — config, ciphers, certificates, key management

Source: `testing-tls`, `ssl-audit`, `crypto-failures` (2024: TLS 1.0/1.1 deprecation, RSA key size <2048, ROBOT attack, certificate transparency bypass).

## Gate

Approved `host:port` only. Every command via `cyber_process` `argv`. Read-only analysis — no modification. → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. TLS version and cipher enumeration

```
cyber_process argv=["testssl.sh","--quiet","--color","0","--jsonfile","evidence/tls-scan.json","https://<host>"]
```

If `testssl.sh` is absent, fall back to `nmap`:

```
cyber_process argv=["nmap","--script","ssl-enum-ciphers","-p","443","<host>"]
```

Or `openssl` direct probes for each protocol version:

```
cyber_process argv=["openssl","s_client","-connect","<host>:443","-servername","<host>","-tls1"]
cyber_process argv=["openssl","s_client","-connect","<host>:443","-servername","<host>","-tls1_1"]
cyber_process argv=["openssl","s_client","-connect","<host>:443","-servername","<host>","-tls1_2"]
cyber_process argv=["openssl","s_client","-connect","<host>:443","-servername","<host>","-tls1_3"]
```

Record supported versions, cipher suites, key exchange algorithms, signature algorithms.

### 2. Protocol weakness probes

Test specific vulnerabilities:

```
cyber_process argv=["testssl.sh","--protocols","--color","0","https://<host>"]
cyber_process argv=["testssl.sh","--rc4","--color","0","https://<host>"]
cyber_process argv=["testssl.sh","--heartbleed","--color","0","https://<host>"]
cyber_process argv=["testssl.sh","--robot","--color","0","https://<host>"]
cyber_process argv=["testssl.sh","--compression","--color","0","https://<host>"]
cyber_process argv=["testssl.sh","--reneg","--color","0","https://<host>"]
```

| Weakness | Probe | Severity |
|---|---|---|
| TLS 1.0/1.1 enabled | `-tls1` / `-tls1_1` accepts | Medium-High |
| SSLv3 (POODLE) | `-ssl3` accepts | Critical |
| RC4 cipher | `--rc4` | High |
| CBC + TLS 1.0 (BEAST) | cipher list + protocol | Medium |
| Export ciphers (FREAK/Logjam) | `--export` | Critical |
| NULL ciphers | `--null` | Critical |
| 3DES (Sweet32) | `--3des` | Medium |
| No PFS (RSA key exchange) | cipher list lacks ECDHE/DHE | Medium |
| Weak DH (<2048) | DH parameter size in handshake | High |
| Compression (CRIME) | `--compression` | High |
| Heartbleed | `--heartbleed` | Critical |
| ROBOT | `--robot` | High |

### 3. Certificate analysis

```
cyber_process argv=["openssl","s_client","-connect","<host>:443","-servername","<host>","-showcerts"]
```

Extract and parse:

```
cyber_process argv=["openssl","s_client","-connect","<host>:443","-servername","<host>"]
```

Pipe to `openssl x509 -text -noout` or parse directly. Check:

| Check | Command | Finding if |
|---|---|---|
| Validity | dates in cert | expired or >398 days |
| Hostname match | Subject + SANs | mismatch |
| Issuer | CA in cert | self-signed |
| Key size | public key bits | RSA <2048 or ECDSA <256 |
| Signature | signature algorithm | SHA-1 |
| Chain | `-showcerts` | incomplete chain |
| CT | SCT presence | no SCTs |

CAA record:

```
cyber_process argv=["nslookup","-type=CAA","<host>"]
```

### 4. HSTS and transport

```
cyber_process argv=["curl","-sS","-D","-","-o","/dev/null","https://<host>/"]
cyber_process argv=["curl","-sS","-D","-","-o","/dev/null","http://<host>/"]
```

Check `Strict-Transport-Security` in HTTPS response. Check if HTTP redirects to HTTPS (301 vs 302). If HSTS absent and HTTP serves content → transport downgrade candidate.

### 5. Application-layer crypto

If source/evidence is available, check for weak crypto patterns:

```
cyber_process argv=["grep","-rnE","ECB|DES|MD5|SHA1|Math\\.random|rand\\(\\)|alg.*none","<evidence-dir>/"]
```

JWT algorithm confusion:

```
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <token-with-alg-none>","<url>/api/protected"]
```

If accepted with `alg: none` → JWT algorithm confusion candidate.

### 6. Key management

```
cyber_process argv=["grep","-rnE","BEGIN (RSA |EC )?PRIVATE KEY|-----BEGIN PRIVATE","<evidence-dir>/"]
```

Private keys in source/config/error responses = key exposure candidate.

### 7. Negative controls

```
cyber_process argv=["openssl","s_client","-connect","<host>:443","-servername","<host>","-tls1_3","-cipher","TLS_AES_256_GCM_SHA384"]
```

| Control | Probe | Expected |
|---|---|---|
| TLS 1.3 + strong cipher | `-tls1_3` with AES-256-GCM | connection succeeds |
| TLS 1.0 attempt | `-tls1` | rejected (if properly configured) |
| Self-signed cert | openssl verify | chain validation fails |

### Stop

Cipher brute-force, sustained probing, any write operation.

### Evidence ids

Keep testssl-json, each protocol probe, certificate details, HSTS check, HTTP downgrade check, grep results, and all controls as separate observations.

## Verification scenarios

| Scenario | Observation | Expected classification |
|---|---|---|
| TLS 1.0 handshake succeeds | `-tls1` returns `CONNECTED` | TLS 1.0 enabled candidate |
| TLS 1.0 handshake rejected | connection refused or error | negative control confirmed |
| RC4 cipher accepted | testssl `--rc4` VULNERABLE | RC4 enabled candidate |
| Heartbleed detected | testssl `--heartbleed` VULNERABLE | Heartbleed candidate |
| RSA key <2048 bits | openssl shows 1024-bit key | weak key candidate |
| SHA-1 signature | openssl shows sha1WithRSAEncryption | SHA-1 signature candidate |
| Self-signed cert | issuer == subject | self-signed candidate |
| Certificate expired | notAfter in the past | expired cert candidate |
| No HSTS + HTTP serves content | no redirect, no HSTS header | transport downgrade candidate |
| HSTS with max-age ≥ 31536000 | header present | negative control confirmed |
| JWT `alg: none` accepted | 200 on protected endpoint | algorithm confusion candidate |
| Private key in source | grep match on BEGIN PRIVATE KEY | key exposure candidate |
| All TLS 1.3 + ECDHE + AES-256 | testssl clean report | properly configured |

An old TLS version alone is a finding. AES-128 vs AES-256 is informational. testssl.sh JSON is the primary evidence artifact.

## Done

`cyber_finding` cites the protocol/cipher/cert weakness, the tool output, severity based on exploitability, and all controls. Informational items (AES-128, missing CAA) are noted but not findings.
