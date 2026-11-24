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

## Done

Evidence holds build string, one interface, one probe, snapshot restore. Production cluster untouched.
