---
name: harness-exiftool
description: "Hash a file already in evidence, extract ExifTool JSON read-only, and require a second observation before GPS or author becomes a finding."
---

# ExifTool — hash then meta, never fetch

Source: ExifTool. GPS/author in delivered docs are privacy leads, not identity proof.

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string. File must already be in the evidence directory. Do not fetch remote. Do not `exiftool -overwrite_original`. Do not publish precise personal locations.

## Steps

### 1. Hash first

```
cyber_process argv=["sha256sum","<file>"]
```

File-identity observation. Process a **copy** if the parser might touch mtime; never the only original.

### 2. Extract JSON

```
cyber_process argv=["exiftool","-json","-n","<file>"]
```

Redirect is the harness trace, not a shell `>`. Own observation. Read CreateDate, GPS*, Author, Creator, Producer, Software, XMP/IPTC.

### 3. Relevance

GPS is a candidate until it sits in engagement geography **and** a second source agrees. Author is a candidate until an in-scope principal matches. Software version → `cyber_cve` / `harness-supply-chain`, not this method.

### 4. Negative control

A known-clean fixture of the same type, and the copy's hash, must not invent GPS/author. Same author string on a public template is not "the operator".

### 5. Finding contract

`cyber_finding` needs hash + JSON `cyber_source` chunk + second observation (trivy CVE or second doc same author) + clean-fixture control. Redact GPS/author/serial unless necessary.

## Done

Evidence holds hash + JSON. No field alone is a finding.
