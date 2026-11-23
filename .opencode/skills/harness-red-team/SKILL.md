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
8. Teardown: remove every artifact with the removal command written in step 3,
   re-run the presence command to show it is gone, and take a final telemetry
   read. A finding cannot be filed while an artifact remains.

Negative controls: the baseline query before any change (step 1), the second
approved host that never received the mechanism, the un-obfuscated artifact
against the step-5 query, and the approved destination before the transfer. A
callback without a matching host identity is a lab error, not a channel.

## Done

Evidence holds the authorization reference, the baseline, one observation per
stage with its control, and the teardown verification. Every stage is `carded`,
`not-tested` with its missing condition, or `stopped` with the reason. A finding
is `cyber_finding` with the stage observation, the baseline control and the
teardown proof; a channel, a survival or a detection bypass without its control
stays a candidate. The detection twin is handed to `harness-detection`.
