---
name: harness-windows-kernel
description: "Lab-only Windows driver/IOCTL review: hash the sys, map DeviceIoControl codes, one non-destructive IOCTL on a VM snapshot, never BSOD production."
---

# Windows kernel — lab VM, one IOCTL, snapshot first

Source: Windows driver IOCTL surface. Production kernel is out.

## Gate

The `.sys` / driver package must already be in evidence. Target is a **named lab VM with a snapshot**. Every command goes through `cyber_process` with `argv`. Do not build a shell string. No production machine. No random IOCTL spray. No BYOVD against the operator's host. Restore snapshot after the pass.

## Steps

### 1. Hash the driver

```
cyber_process argv=["sha256sum","<driver.sys>"]
cyber_process argv=["file","<driver.sys>"]
```

Identity observation. Authenticode info if `signtool`/`osslsigncode` present; missing tool → `not-tested`.

### 2. Static map

`harness-ghidra` on the sys: device names, `IRP_MJ_DEVICE_CONTROL`, dispatch table. Quote `0x...` IOCTL codes the tool returned. No address = hypothesis.

### 3. One IOCTL on the snapshot

Revert snapshot. Load only if the lab procedure says so. Send **one** documented IOCTL with a **benign** buffer:

```
cyber_process argv=["ioctl-probe","--device","<device>","--code","<ioctl>","--in","<benign.bin>"]
```

If the probe binary is absent: stop at static map (`not-tested` for runtime). A BSOD is a **lab** observation — capture the dump hash, restore snapshot, do not repeat.

### 4. Negative control

An IOCTL code **not** in the dispatch table, or the same IOCTL with a truncated buffer the driver must reject, must not produce the claimed effect. Same crash on a **different** driver in the lab rejects "this sys is uniquely bad" without a second sample.

### 5. Finding contract

`cyber_finding` with hash, Ghidra dispatch observation, one runtime IOCTL or explicit `not-tested`, negative control, source chunk (decompile at address). No public exploit against a live estate. Privilege-escalation claims need the lab token/process proof, not "should be SYSTEM".

### Lab budget

| Step | Max |
|---|---|
| IOCTL codes sent | 1 documented |
| BSODs | 1 then restore, stop |
| Production hosts | 0 |

```
cyber_process argv=["sha256sum","<driver.sys>"]
```

BYOVD on the operator's host is a method violation.

### Lab sequence

1. Snapshot. 2. Hash sys. 3. Ghidra dispatch `0x...`. 4. One documented IOCTL, benign buffer. 5. Restore.

```
cyber_process argv=["sha256sum","<driver.sys>"]
cyber_process argv=["ioctl-probe","--device","<device>","--code","<ioctl>","--in","<benign.bin>"]
```

Missing probe binary → static only, runtime `not-tested`. One BSOD then stop. Undocumented IOCTL or truncated buffer is the negative control.

### Stop

Production, BYOVD on the operator PC, IOCTL spray, public exploit vs live estate.

### Evidence ids

Hash, dispatch, one runtime or not-tested, truncated-buffer control, decompile chunk. SYSTEM claims need lab token proof.

## Done

Evidence holds driver hash, dispatch map, at most one runtime IOCTL, snapshot restore note. Production not touched.
