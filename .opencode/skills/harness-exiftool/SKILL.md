---
name: harness-exiftool
description: "Hash a collected file, extract ExifTool JSON read-only, clean-fixture control; GPS or author needs a second source before a finding."
---

# ExifTool — hash then meta, never fetch

Source: ExifTool. Embedded GPS/author are privacy leads, not identity proof.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. File already in evidence. Do not fetch remote. Do not `-overwrite_original`. Do not publish precise personal locations. Do not extract embedded binaries without scope.

## Steps

### 1. Hash first

```
cyber_process argv=["sha256sum","<file>"]
cyber_process argv=["file","<file>"]
```

Identity observation. Prefer a **copy** if the parser might touch mtime.

### 2. JSON extract (trace is the file)

```
cyber_process argv=["exiftool","-json","-n","<file>"]
```

No shell redirect. Own observation. Read CreateDate, GPS*, Author, Creator, Producer, Software, XMP/IPTC, thumbnails listed but not dumped unless scoped.

Distinguish filesystem mtime from embedded CreateDate.

### 3. Relevance gates

- GPS: candidate until it sits in engagement geography **and** a second source agrees.
- Author: candidate until an in-scope principal matches.
- Software version: `cyber_cve` / `harness-supply-chain`, not this method.

### 4. Negative control

Known-clean fixture of the same type, plus the copy hash. Must not invent GPS/author. Same Author as a public Word template is not "the operator".

### 5. Finding contract

`cyber_finding` needs hash + JSON `cyber_source` + second observation (CVE or second doc) + clean-fixture control. Redact GPS/author/serial unless necessary to the claim.

## Done

Evidence holds hash + JSON. No field alone is a finding.
