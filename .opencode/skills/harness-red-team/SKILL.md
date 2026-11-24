---
name: harness-red-team
description: "Run an authorized red-team emulation on named hosts: foothold, persistence, C2 channel, evasion, staged collection and exfiltration, each with a detection twin and a teardown proof."
---

# Red team — emulation with a detection twin and a teardown

Source: `red-team-operations`, `adversary-emulation`, `c2-infrastructure`. This
method replaces the previous `gap` on persistence and exfiltration, and the
`not-covered` entry on C2 and evasion. It stays an evaluation method: it proves
a channel, a survival and a detection gap on hosts that are named in writing.

## Gate

A written authorization must name: the hosts, the time window, the allowed
families (persistence / C2 / evasion / exfiltration), the approved destination
for any transfer, and the absence of availability impact. Every command goes
through `cyber_process` with `argv`. Do not build a shell string. No third
party, no production data, no service degradation, no destruction. A removal
command is written before the artifact is deployed. The blue team is informed
or not per the engagement letter; its detection is a result, not a failure.

Stop immediately on: a host outside the list, unexpected real data, an
availability effect, a second artifact before the first is removed, or a
destination that is not the approved one.

## Steps (each step writes into `<evidence-dir>` and is its own observation)

1. Baseline the approved host: scheduled tasks, services, autostart paths,
   outbound connection shape and the telemetry query that would reveal each
   family. This baseline is the control for every later claim.
2. Foothold: prove the approved identity executes on the approved host with a
   canary command that writes a marker into `<evidence-dir>`. No privilege
   beyond that identity.
3. Persistence: one approved mechanism, one host. Record the presence command,
   the removal command and, when a restart is authorized, the survival
   observation. Without an authorized restart the survival stays `not-tested`.
4. C2: name the framework family (`sliver`, `mythic`, `havoc`, or a plain HTTPS
   listener), one beacon, a collector in the operator lab. Prove one callback
   with timestamp and host identity. No collection over the channel.
5. Evasion: one change at a time against the baseline, then re-run the same
   collection query. Prove the artifact still executes while the query no
   longer returns the marker.
6. Staging: canary markers only, volume capped, inside the approved directory.
   Prove the marker is readable and hashed before transfer.
7. Exfiltration: approved destination, canary file, size cap. Prove the hash
   read back at the destination. Nothing else travels.
8. Quiesce emulation at the approved window boundary; preserve its evidence.
   Record the teardown plan in the report. Remove mission resources only after
   the reviewed report has recorded restitution and the cleanup gate permits it.
   Then re-run the presence and telemetry queries to verify removal.

Negative controls: the baseline query before any change (step 1), the second
approved host that never received the mechanism, the un-obfuscated artifact
against the step-5 query, and the approved destination before the transfer. A
callback without a matching host identity is a lab error, not a channel.

### Stage table

| Stage | Observation | Control | Teardown |
|---|---|---|---|
| Baseline | tasks/services/egress | second host untouched | n/a |
| Foothold | canary in evidence-dir | identity not extra priv | delete canary |
| Persistence | presence cmd | second host | removal cmd + gone |
| C2 | one callback ts+host | callback without host id = lab error | stop beacon |
| Evasion | query misses marker | un-obfuscated still hits | revert change |
| Exfil | dest hash match | dest empty before | delete canary dest |

One artifact at a time. Second artifact before teardown = stop.

```
cyber_process argv=["<presence-cmd>"]
cyber_process argv=["<removal-cmd>"]
```

Detection twin → `harness-detection` using preserved synthetic artifacts.
A `cyber_finding` needs the stage observation and baseline negative control.
Track teardown as pending until the restitution/cleanup gate allows execution.

### Reproduction recipe

One artifact, observed second-host control and preserved detection twin.
Quiesce at the deadline; teardown proof follows the restitution/cleanup gate.

## Verification scenarios

Use only synthetic canaries in a named isolated emulation environment.
Bind each stage to its authorization family; permission for one stage does not authorize all.
Separate execution success, sensor collection and alert delivery.

| Scenario | Evidence compared | Expected classification |
|---|---|---|
| Collector receives a callback without an attributable host id | source record and host log | unproven channel |
| Telemetry query misses both baseline and changed artifact | sensor health control | monitoring unavailable, not evasion |
| Canary reaches the approved destination with matching digest | source and destination artifacts | synthetic transfer supported |
| Restart is not approved | persistence presence only | survival not-tested |
| Cleanup is requested before report restitution | mission stage and approval record | deny cleanup |

An untouched second host is useful only if it is actually observed with the same query.
Record sensor clock skew and ingestion delay before claiming a detection miss.
Preserve evidence even when the emulation must be halted for safety.
Report pending teardown explicitly; never fabricate completion to close a stage.

## Done

Evidence holds the authorization reference, the baseline, one observation per
stage with its control, and the teardown verification. A channel, survival or
bypass without its control stays a candidate.
