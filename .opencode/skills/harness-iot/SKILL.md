---
name: harness-iot
description: "Assess an approved IoT or embedded device from firmware and interfaces already collected, without radio disruption or a live exploit."
---

# IoT — collected firmware and approved interface

## Gate

The device, firmware, and interface must be named in the scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. No jamming, no deauthentication, no firmware write, no exploit against the live device.

## Steps

1. Hash the firmware image and record the device identity. Completion: SHA256 is in evidence.
2. Inventory exposed services and files already collected. A native binary goes to `harness-ghidra`; a secret string goes to `harness-secret-scan`.
3. One read-only probe on an approved interface: banner, TLS, or API version. Record the response hash.
4. Negative control: an interface that is not in scope, or a closed port on the same device, must not be queried or reported as exposed.
5. `cyber_finding` needs the firmware hash, the interface observation, the negative control, and the source chunk. A version string alone is not a vulnerability until `cyber_cve lookup` says so.

## Done

Evidence holds the firmware hash and the interface result. An unparsed format stays `not-tested`.
