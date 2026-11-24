---
name: harness-automotive-can
description: "Lab-only CAN/UDS on an approved bench or isolated ECU: log hash, one read DID, never brake/steer/powertrain on a road vehicle."
---

# Automotive CAN — bench, one DID, never the road

Source: ISO 14229 UDS, ISO 11898. A moving vehicle is out.

## Gate

ECU/bench name in scope, **not** a public road. Every command goes through `cyber_process` with `argv`. Do not build a shell string. **No frames that actuate brakes, steering, throttle, airbag, or charging on a vehicle that can move.** Lab harness or disconnected ECU only.

## Steps

### 1. Hash the capture or config

```
cyber_process argv=["sha256sum","<candump.log>"]
```

or the DBC already in evidence (`cyber_source`).

### 2. Identify, do not flood

If a live bus is approved on the **bench**:

```
cyber_process argv=["candump","-L","-n","20","can0"]
```

Bounded window. Do not `cangen` random IDs on a vehicle.

### 3. One UDS read

One named DID (e.g. `0xF190` VIN) if the operator listed it:

```
cyber_process argv=["isotpsend","-?"]
```

This is a CLI preflight, not a DID read. can-utils `isotpsend` consumes ASCII hex
on stdin; this harness's process tool does not expose stdin. Use an already approved
file-input reader or mark live read `not-tested`; do not invent positional PDU arguments.
Security-access seed/key only on a **disconnected** ECU if explicitly approved.

### 4. Negative control

Use a clean offline fixture or a permitted denied response on the same bench.
Unsent arbitration IDs and excluded ECUs are scope restrictions, not observed denials.

### 5. Finding contract

`cyber_finding` needs the diagnostic access requirement, attributable log/read,
and actual fixture/bench control. A public DID or one observed seed does not prove a weakness.
Never use actuator commands. Wireless TPMS/BLE → `harness-wireless`.

### DID budget

| Action | Allowed |
|---|---|
| candump bounded | bench only |
| one UDS read DID | if named (e.g. 0xF190) |
| security-access | disconnected ECU + approval |
| cangen random | never on a vehicle |
| brake/steer/throttle | never |

```
cyber_process argv=["sha256sum","<candump.log>"]
cyber_process argv=["file","<candump.log>"]
```

Arbitration IDs outside the DBC remain unsent. Execute controls only on approved fixtures. TPMS/BLE → `harness-wireless`.

### Stop

Road vehicle, actuator frames, random ID flood.

### Evidence ids

Capture hash, at most one DID, executed fixture/bench control.

### Bench only

Disconnected ECU or named harness. `cangen` random IDs never on a vehicle that can move. Security-access seed/key only if explicitly approved on that ECU.

```
cyber_process argv=["candump","-L","-n","20","can0"]
```

Bounded window. DBC in evidence as `cyber_source`. Fixture denial is the negative control. TPMS/BLE → `harness-wireless`.

### Stop

Road, actuator (brake/steer/throttle/airbag), random ID flood.

## Verification scenarios

An unsent arbitration id is a scope boundary, not an observed negative control.
Use a virtual CAN fixture or an operator-approved bench responder for comparisons.
Bound passive collection by frame count and the process deadline.

| Scenario | Observation | Expected classification |
|---|---|---|
| Known synthetic diagnostic response in a fixture | response service, DID and source id | parser positive control |
| Same fixture without the test DID response | same decoder, no marker | parser negative control |
| ECU exposes a public identification DID by design | documented access requirement | not an authentication bypass |
| Protected test DID rejected in the default session | negative response code | access control holds |
| Response truncated across ISO-TP frames | incomplete reassembly | not-tested for returned value |

Preserve ECU/session identity, DBC revision and ISO-TP addressing configuration.
Do not infer seed predictability from one observed seed.
Finding evidence needs a requirement, correlated request/response and an executed control.
Reference for stdin semantics: linux-can/can-utils `isotpsend.c`, `print_usage`.

## Done

Evidence holds capture hash, at most one DID read, control. No road vehicle, no actuator.
