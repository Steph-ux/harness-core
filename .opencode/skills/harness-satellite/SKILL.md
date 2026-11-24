---
name: harness-satellite
description: "Assess an approved satellite/ground segment from collected RF recordings or ground-API docs: identify link, one read-only API or IQ hash, never transmit, never jam."
---

# Satellite / ground — listen or documented API, never transmit

Source: ground-station APIs, IQ recordings. ITU/licensing: **no uplink** unless the operator's license names it.

## Gate

Ground station, spacecraft id, or recording must be in scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. **No transmit, no jam, no spoofed TC, no SDR TX.** RF work is receive-only on an approved frequency list.

## Steps

### 1. Identity from evidence

Hash the IQ/pcap/recording or the ground-API OpenAPI:

```
cyber_process argv=["sha256sum","<capture.iq>"]
```

or `cyber_source` the API doc.

### 2. Decode or inventory (receive-only)

If a demod toolchain is present (`gnuradio-companion` batch, `satdump` CLI):

```
cyber_process argv=["satdump","<pipeline>","<capture.iq>","<out-dir>"]
```

Missing tool → `not-tested`. Do not retune a dish.

If the surface is a **ground HTTP API**, one GET of a documented telemetry path with the test identity (`harness-api-testing` discipline).

### 3. Negative control

A frequency or spacecraft **not** on the approved list must not be decoded or requested. A second API path that 404s is the control for "shadow telemetry".

### 4. Finding contract

`cyber_finding` for: unauthenticated ground API exposing TC/TM, credentials in a collected config, version with `cyber_cve` match. Never a finding that required an uplink. RF intercept of another nation's satellite is **out of scope** even if the SDR can see it.

## Proof contract

Unauthenticated ground API or credentials in a collected config need the hash/GET observation and the out-of-list frequency or 404 control. An uplink is never the proof.

### Receive-only budget

| Path | Max |
|---|---|
| IQ/pcap hash | 1 capture |
| Decode pipeline | 1 if tool present |
| Ground HTTP GET | 1 documented TM path |
| Uplink / jam / spoof TC | 0 |

```
cyber_process argv=["sha256sum","<capture.iq>"]
cyber_process argv=["curl","-sS","-D","-","-H","Authorization: Bearer <test>","<approved-tm-url>"]
```

Frequency or spacecraft not on the list must not be decoded (negative control). Other-nation intercept is out even if the SDR sees it.

### Stop

TX, jam, dish retune, undocumented TC.

### Evidence ids

Capture/API hash, one decode or GET, out-of-list control. An uplink is never the proof. Ground-API IDOR is `harness-idor`, not this method.

## Done

Evidence holds capture/API hash, one decode or GET, and a control. No TX.
