---
name: harness-websocket
description: "Test WebSocket security: CSWSH, authentication bypass, injection, message tampering, and origin validation."
---

# WebSocket — hijack, injection, auth bypass

Source: `testing-websockets`, `cross-site-websocket-hijacking` (2024: CSWSH via missing Origin check, binary message injection, chat application message spoofing).

## Gate

Approved `host+ws endpoint` only. Every command via `cyber_process` `argv`. One message per test. No flood, no DoS. → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. Discover and fingerprint the endpoint

```
cyber_process argv=["curl","-sS","-D","-","-o","/dev/null","-H","Upgrade: websocket","-H","Connection: Upgrade","-H","Sec-WebSocket-Version: 13","-H","Sec-WebSocket-Key: dGVzdA==","<approved-url>"]
```

Record status (`101` or refusal), `Sec-WebSocket-Accept`, response headers (`X-Powered-By`, `Server`). Hash the handshake. Identify subprotocol from `Sec-WebSocket-Protocol`.

### 2. Positive control — authorized message

Connect with the approved test token and send one benign action the identity is allowed to use:

```
cyber_process argv=["node","-e","const ws=require('ws');const c=new ws('<wss-url>',{headers:{'Cookie':'<session>','Origin':'<approved-origin>'}});c.on('open',()=>{c.send(JSON.stringify({action:'get_profile'}));});c.on('message',d=>{process.stdout.write(d.toString());c.close();});c.on('error',e=>console.error(e.message));setTimeout(()=>c.terminate(),5000);"]
```

This is the functional positive control. Hash the response body.

### 3. CSWSH — Origin validation

Replay the same handshake with a foreign `Origin`:

```
cyber_process argv=["node","-e","const ws=require('ws');const c=new ws('<wss-url>',{headers:{'Cookie':'<session>','Origin':'https://evil.example'}});c.on('open',()=>{c.send(JSON.stringify({action:'get_profile'}));});c.on('message',d=>{process.stdout.write(d.toString());c.close();});c.on('error',e=>console.error(e.message));setTimeout(()=>c.terminate(),5000);"]
```

If the server returns the same profile → CSWSH candidate. Test also `Origin: null`. If the server rejects → negative control confirmed.

### 4. Auth bypass — no token

```
cyber_process argv=["node","-e","const ws=require('ws');const c=new ws('<wss-url>');c.on('open',()=>{c.send(JSON.stringify({action:'get_profile'}));});c.on('message',d=>{process.stdout.write(d.toString());c.close();});c.on('error',e=>console.error(e.message));setTimeout(()=>c.terminate(),5000);"]
```

No cookie, no token. The server must reject or return nothing private. If it accepts and returns data → auth bypass.

### 5. Privilege escalation — low-priv action

Connect with a low-privilege test identity and send a privileged message:

```
cyber_process argv=["node","-e","const ws=require('ws');const c=new ws('<wss-url>',{headers:{'Cookie':'<low-priv-session>','Origin':'<approved-origin>'}});c.on('open',()=>{c.send(JSON.stringify({action:'admin_list_users'}));});c.on('message',d=>{process.stdout.write(d.toString());c.close();});c.on('error',e=>console.error(e.message));setTimeout(()=>c.terminate(),5000);"]
```

If the response contains admin data → vertical escalation candidate.

### 6. Message injection

Modify a known message field to reference another user's object:

```
cyber_process argv=["node","-e","const ws=require('ws');const c=new ws('<wss-url>',{headers:{'Cookie':'<session>','Origin':'<approved-origin>'}});c.on('open',()=>{c.send(JSON.stringify({action:'get_order',id:'<other-user-id>'}));});c.on('message',d=>{process.stdout.write(d.toString());c.close();});c.on('error',e=>console.error(e.message));setTimeout(()=>c.terminate(),5000);"]
```

Compare response to the owner's legitimate read. Private fields present = IDOR over WebSocket.

### 7. Negative controls

| Control | Description | Expected |
|---|---|---|
| Authorized origin + valid token | functional baseline | profile returned |
| Foreign origin | CSWSH control | connection rejected or empty |
| No token | auth control | connection rejected |
| Low-priv → admin action | vertical control | action denied |
| Benign field modification | injection control | own data only |

### Stop

Sustained flooding, production message injection, real-user session, more than one message per test vector.

### Evidence ids

Handshake hash, positive-control body hash, CSWSH probe hash, auth-bypass hash, escalation hash. Keep origin, token presence, and action in every observation.

## Verification scenarios

| Scenario | Observation | Expected classification |
|---|---|---|
| Foreign origin accepted with victim data | profile body with CSWSH origin | CSWSH candidate |
| Foreign origin rejected or empty | rejection or close | negative control confirmed |
| No-token connection returns public-only | public schema vs profile | not auth bypass |
| Admin action refused for low-priv | error body | vertical control confirmed |
| Modified id returns other-user private field | own-read vs cross-read | WS IDOR candidate |
| Socket.IO namespace join without auth | room subscription trace | namespace isolation candidate |
| Malformed JSON triggers stack trace | error body | information disclosure signal |

A `101` handshake alone is not a finding. The forbidden effect (private data, admin action, cross-user read) must be in the response body.

## Done

`cyber_finding` cites the endpoint, the attack vector, the forbidden effect in the response body, and all five controls. A connection upgrade is not evidence. Untested subprotocols stay `not-tested`.
