---
name: harness-chip-off
description: "Document a chip-off or dump already collected: hash the image, parse filesystem read-only, never desolder a production device, never flash back."
---

# Chip-off — collected dump only, never the iron

Source: physical extraction. This method does **not** authorize destroying a customer's device.

## Gate

The dump/image must **already** be in evidence, or the operator must have written approval to extract **a lab/sacrificial** board. Every command goes through `cyber_process` with `argv`. Do not build a shell string. **No desolder of production hardware. No write-back / reflash. No glitcher on a live fleet.**

## Steps

### 1. Hash the dump

```
cyber_process argv=["sha256sum","<nand.bin>"]
cyber_process argv=["file","<nand.bin>"]
```

Identity first. If there is no dump, this method is `not-tested` — do not invent an extraction.

### 2. Parse read-only

```
cyber_process argv=["binwalk","-e","-M","<nand.bin>"]
```

or `ubireader` / `jefferson` if present. Missing parser → `not-tested`. Inventory partitions, keys, `passwd`, certs. Native blobs → `harness-ghidra`. Secrets → `harness-secret-scan`. Firmware crypto → `harness-iot`.

### 3. Negative control

A second dump the operator listed as **blank/erased** must not yield the same key material. Same `root:$1$...` on a public eval board image is not "this customer's device".

### 4. Finding contract

`cyber_finding` for keys/config in the dump with hash, parser obs, blank-dump control, `cyber_source` chunk (not the whole NAND). Physical presence of a header is not a vuln. Do not claim you extracted a production phone unless the approval and the dump hash say so.

## Proof contract

Keys or config in the dump need the hash, parser observation, blank-dump control, and a source chunk.

Physical presence of a header is not a vulnerability. Production extraction requires written approval and that dump hash. Do not claim a production phone unless the approval and the dump hash say so.

### Parse matrix

| Artifact | Tool | Next method |
|---|---|---|
| squashfs / ubifs | binwalk / ubireader | iot |
| ELF/PE in dump | file + ghidra | ghidra |
| key material | grep path only | secret-scan |
| lockfile | hash pin | supply-chain |

```
cyber_process argv=["binwalk","-e","-M","<nand.bin>"]
```

No write-back, no glitcher on a live fleet.

### No-dump path

If there is no image in evidence and no written approval for a sacrificial board, the method is `not-tested`. Do not desolder production.

```
cyber_process argv=["sha256sum","<nand.bin>"]
cyber_process argv=["file","<nand.bin>"]
```

Blank/erased dump listed by the operator is the negative control. Same `$1$` hash as a public eval board is not this customer's device.

### Stop

Iron on production, reflash, glitcher on a live fleet, claiming a phone extract without dump hash.

### Evidence ids

Dump hash, parse, blank-dump control, chunk not the whole NAND.

### Reproduction recipe

No dump and no sacrificial approval → `not-tested`. Hash first. Parse read-only. Blank dump must not yield the same keys. Do not flash back. Production phone only with written approval + that hash.

## Verification scenarios

Parse a working copy and compare its hash with the sealed intake image.
Record NAND page, spare/OOB, ECC and bad-block handling before extracting files.
Use an isolated parser environment: recursive unpackers execute helper programs.

| Scenario | Observation | Expected result |
|---|---|---|
| Blank synthetic dump is scanned | no filesystem or key marker | parser negative control |
| Header magic appears without a valid filesystem | parser rejects offsets/checksums | format candidate only |
| Same key belongs to an included test certificate | source path and certificate metadata | fixture, not private device key |
| ECC correction modifies the working image | before/after hashes and correction log | derived artifact, preserve original |
| Volume is encrypted and keys are unavailable | parser/decryption error | extraction not-tested |

Do not compare an erased image of unrelated geometry as if extraction methods were identical.
Separate evidence of key bytes from evidence that a live service trusts that key.
The finding cites dump identity, partition offset, parsed path and a real parser control.
Physical extraction success alone is not an authorization or confidentiality flaw.

## Done

Evidence holds dump hash, parse listing, control. No iron, no reflash.
