---
name: harness-hypervisor
description: "Lab-only hypervisor/guest escape review: hash hypervisor build, one guest-to-host interface (VSock/Virtio/VMCI), snapshot restore, never production cluster."
---

# Hypervisor — lab guest, one interface, snapshot first

Source: KVM/Xen/VMware/Hyper-V guest tools, virtio. Production cluster is out.

## Gate

Hypervisor type and **lab** host/guest names in scope. Snapshot before the pass. Every command goes through `cyber_process` with `argv`. Do not build a shell string. **No production ESXi/cluster. No random fuzz of virtio until host panic. Restore snapshot after.**

## Steps

### 1. Identity

Hash the guest tools / hypervisor build string already collected:

```
cyber_process argv=["virsh","version"]
```

or vendor `vmware -v` if present. Missing → `not-tested`.

### 2. Map one guest-to-host interface

VSock, 9p, virtio-serial, VMCI, shared folder — **one** named interface from the lab inventory. Quote the device path the guest sees.

```
cyber_process argv=["ls","-l","/dev/vhost-vsock"]
```

### 3. One benign probe

A documented read (list shared folder, vsock connect to an **approved** host port). Do not spray IOCTLs (that is `harness-windows-kernel` in a nested VM, still lab).

### 4. Negative control

An interface **not** attached to this guest must not be present. A second VM not in scope must not be used. Host panic without a reproduced guest command is not a finding — restore and stop.

### 5. Finding contract

`cyber_finding` with version obs, interface listing, one probe, missing-interface control, source chunk. Escape claims need host-side evidence (file/process on the host) plus the guest command observation. Nested `harness-container` issues are not hypervisor escape.

## Proof contract

Escape needs host-side evidence plus the guest command observation. A host panic without a reproduced guest command is not a finding.

### Interface matrix (one only)

| Interface | Guest path | Benign probe |
|---|---|---|
| VSock | /dev/vhost-vsock | connect approved host port |
| 9p / shared folder | mount list | ls one named share |
| virtio-serial | /dev/vport* | write canary, read back |
| VMCI | vmci device | query only |

```
cyber_process argv=["virsh","version"]
cyber_process argv=["ls","-l","/dev/vhost-vsock"]
```

Missing tool → `not-tested`. Host panic: hash dump, restore snapshot, stop. Nested container issues are `harness-container`, not escape.

### Stop

Production ESXi/cluster, random virtio fuzz, second VM not in scope, no snapshot.

### Evidence ids

Build string, interface listing, one probe, missing-interface negative control, restore note. Escape needs host-side file/process plus the guest command. A host panic without a reproduced guest command is not a finding.

Restore the snapshot before filing.

A second VM not in scope must not be used as a "control guest".

### Reproduction recipe

Snapshot, one guest interface, restore. Host panic without guest command is not escape.

## Verification scenarios

Record both management-plane and guest-plane versions: they are different surfaces.
Device visibility alone does not prove host access or an escape.
For Linux, `/dev/vhost-vsock` is normally a host acceleration device;
discover the actual guest endpoint instead of assuming this path exists there.

| Scenario | Evidence required | Expected result |
|---|---|---|
| Guest lists an explicitly shared directory | VM configuration and guest mount | intended sharing, not escape |
| Unshared lab directory is requested | guest request and permission denial | negative control |
| Interface absent on the guest | device inventory | not-tested for interface probes |
| Guest command affects host state outside an allowed share | guest request plus host-side marker | candidate boundary violation |
| Snapshot restore removes test changes | restored guest and host inventories | recorded restoration |

A valid host marker must identify its host path and the test time.
A marker inside the intended shared folder proves the share works, not escape.
Hypervisor-management API authorization uses separate admin and low-privilege identities.
CPU side channels, device passthrough and nested virtualization remain separate branches.

### Finding packet

Attach hypervisor build, guest build, VM device configuration and snapshot id.
Attach the specific interface request, host result and denied-interface control.
State which control plane was tested; do not generalize a share misconfiguration.
Use a guest snapshot plus a host cleanup plan: guest restore does not restore the host.

## Done

Evidence holds build string, one interface, one probe, snapshot restore. Production cluster untouched.
