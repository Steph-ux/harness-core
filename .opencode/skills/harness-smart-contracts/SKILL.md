---
name: harness-smart-contracts
description: "Review an approved contract at a pinned address/commit: hash source+bytecode, one static analyzer, one view-call control, no mainnet state change."
---

# Smart contracts — pin, static, view-call, no mainnet write

Source: Slither, Echidna (lab), Mythril. Mainnet `send`/`write` is out unless a named testnet.

## Gate

Chain, address or git commit, and compiler version must be in scope. Every command goes through `cyber_process` with `argv`. Do not build a shell string. **No mainnet transaction that changes state.** Fork/testnet only for exploits. No drain of a live pool "to prove it".

## Steps

### 1. Pin

```
cyber_process argv=["sha256sum","<Contract.sol>"]
```

Record address, compiler (`solc` version), optimization. Bytecode hash if verifying against explorer JSON. Mismatch → stop.

### 2. One static analyzer

```
cyber_process argv=["slither","<path>","--json","<evidence-dir>/slither.json"]
```

Missing slither → `not-tested`. One config. Do not paste four scanners as one observation.

### 3. View-call control

One `eth_call` / `cast call` of a **view** function on the pinned address (or fork):

```
cyber_process argv=["cast","call","<address>","owner()(address)","--rpc-url","<approved-rpc>"]
```

A write ABI on mainnet is a method violation.

### 4. Negative control

A finding from Slither that does not hold on a **view replay** (or on a patched fork) is a candidate. A second contract the analyzer flags the same way without the same source line is not "this bug".

### 5. Finding contract

`cyber_finding` with source hash, slither obs, view-call, patched-fork or benign-function control, `cyber_source` function chunk. Reentrancy/oracle claims need the fork trace, not the detector name. Secret keys in `.env` → `harness-secret-scan`.

### Analyzer budget

| Tool | Use | Not |
|---|---|---|
| slither | one config, json out | four scanners in one obs |
| echidna | lab/fork only | mainnet fuzz |
| cast call | view ABI | send/write |

```
cyber_process argv=["slither","<path>","--json","<evidence-dir>/slither.json"]
cyber_process argv=["cast","call","<address>","owner()(address)","--rpc-url","<approved-rpc>"]
```

Patched fork or benign function is the negative control. Reentrancy needs the fork trace, not the detector name. Keys in `.env` → `harness-secret-scan`.

### Stop

Mainnet state change, draining a live pool, mixing four scanners as one observation.

### Evidence ids

Source hash, slither, view-call, patched/benign control, function chunk. Compiler version mismatch vs explorer bytecode → stop.

## Done

Evidence holds pin, one analyzer, one view-call, control. No mainnet state change.
