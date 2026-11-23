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

```bash
# Full scan with testssl.sh
testssl.sh --quiet --color 0 --jsonfile evidence/tls-scan.json https://target

# Or with nmap
nmap --script ssl-enum-ciphers -p 443 target

# Or with sslscan
sslscan --no-colour target:443
```

Record:
- Supported TLS versions (1.0, 1.1, 1.2, 1.3)
- Cipher suites offered and their order
- Key exchange algorithms (RSA, ECDHE, DHE)
- Signature algorithms

### 2. Protocol weakness detection

| Weakness | Test | Severity |
|---|---|---|
| TLS 1.0/1.1 enabled | `testssl.sh --protocols` | Medium-High |
| SSLv3 enabled | POODLE | Critical |
| RC4 cipher | `testssl.sh --rc4` | High |
| CBC ciphers with TLS 1.0 | BEAST | Medium |
| Export ciphers (40/56-bit) | FREAK/Logjam | Critical |
| NULL ciphers | No encryption | Critical |
| DES/3DES | Sweet32 | Medium |
| RSA key exchange (no PFS) | No forward secrecy | Medium |
| Weak DH parameters (<2048) | Logjam | High |
| Compression (CRIME) | `testssl.sh --compression` | High |
| Heartbleed | `testssl.sh --heartbleed` | Critical |
| ROBOT | `testssl.sh --robot` | High |
| Renegotiation | `testssl.sh --reneg` | Medium |

### 3. Certificate analysis

```bash
openssl s_client -connect target:443 -servername target < /dev/null 2>/dev/null | openssl x509 -text -noout
```

Check:
- **Validity**: not expired, not too far in future (>398 days)
- **Subject**: matches the hostname
- **SANs**: complete list of covered domains
- **Issuer**: trusted CA, not self-signed
- **Key size**: RSA ≥2048, ECDSA ≥256
- **Signature algorithm**: SHA-256 or better (not SHA-1)
- **Chain**: complete chain to root CA
- **Revocation**: OCSP stapling, CRL distribution point
- **CT**: certificate transparency logs (SCTs present)
- **CAA**: DNS CAA record restricting issuers

### 4. HSTS and related headers

- `Strict-Transport-Security`: present? `max-age` ≥ 31536000? `includeSubDomains`? `preload`?
- Mixed content: does HTTPS page load HTTP resources?
- HTTP → HTTPS redirect: 301 permanent or 302 temporary?
- HSTS preload list: is the domain in the browser's preload list?

### 5. Application-layer crypto

If the application implements its own crypto:
- **Key derivation**: PBKDF2/scrypt/bcrypt/argon2 with sufficient iterations
- **Encryption**: AES-256-GCM preferred, no ECB mode
- **Random**: CSPRNG used (not `Math.random()`, not `rand()`)
- **Hash**: SHA-256+ for integrity, bcrypt/argon2 for passwords
- **JWT**: algorithm confusion (`alg: none`, RS→HS confusion)
- **API keys**: sufficient entropy (≥128 bits), proper rotation

### 6. Key management

- Private keys not exposed in source code, config, or error messages
- Key rotation policy documented
- Revocation mechanism exists and works
- Backup keys stored securely

### 7. Negative controls

- Control 1: TLS 1.3 connection with strong cipher succeeds (positive control)
- Control 2: attempt with TLS 1.0 → rejected (if properly configured)
- Control 3: expired/self-signed cert → client warns (baseline behavior)

## Proof contract

A finding needs: (1) identified TLS/crypto configuration, (2) specific weakness (weak cipher, old protocol, bad cert), (3) tool output as evidence, (4) reproduction, (5) three negative controls. An old TLS version is a finding; using AES-128 instead of AES-256 is informational.

## Done

Each finding cites the specific configuration weakness, the tool that detected it, the severity based on exploitability, and the negative controls. testssl.sh JSON output is the primary evidence artifact.
