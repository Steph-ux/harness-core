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
cyber_process argv=["candump","-L","can0"]
```

Bounded window. Do not `cangen` random IDs on a vehicle.

### 3. One UDS read

One named DID (e.g. `0xF190` VIN) if the operator listed it:

```
cyber_process argv=["isotp-send","-s","<tx>","-d","<rx>","can0","22","F1","90"]
```

Missing tool → `not-tested`. Security-access seed/key only on a **disconnected** ECU if explicitly approved.

### 4. Negative control

An arbitration ID **not** in the DBC/list must not be sent. A second ECU not on the bench must not be reached. Same DID on an unused tester is not "the car".

### 5. Finding contract

`cyber_finding` for: unauthenticated diagnostic session, default seed, cleartext DID with PII — with log/read observation and unsent-ID control. Never a finding that required an actuator command. Wireless TPMS/BLE → `harness-wireless`.

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
cyber_process argv=["isotp-send","-s","<tx>","-d","<rx>","can0","22","F1","90"]
```

Arbitration ID not in the DBC must not be sent (negative control). TPMS/BLE → `harness-wireless`.

### Stop

Road vehicle, actuator frames, random ID flood.

### Evidence ids

Capture hash, at most one DID, unsent-ID control.

## Done

Evidence holds capture hash, at most one DID read, control. No road vehicle, no actuator.
