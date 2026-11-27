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
- Software version: `cyber_cve search` (NVD + searchsploit) for software/CMS/firmware or `cyber_cve lookup` / `harness-supply-chain` for OSV packages, not this method.

### 4. Negative control

Known-clean fixture of the same type, plus the copy hash. Must not invent GPS/author. Same Author as a public Word template is not "the operator".

### 5. Finding contract

`cyber_finding` needs hash + JSON `cyber_source` + second observation (CVE or second doc) + clean-fixture control. Redact GPS/author/serial unless necessary to the claim.

### Fields vs claims

| Field | Becomes a finding only with |
|---|---|
| GPS | geography in scope + second source |
| Author | in-scope principal match |
| Software | `cyber_cve search` (or `cyber_cve lookup` for OSV) on exact version |

```
cyber_process argv=["exiftool","-json","-n","<file>"]
```

Clean-fixture negative control. No `-overwrite_original`.

### Hash then parse

```
cyber_process argv=["sha256sum","<file>"]
cyber_process argv=["file","<file>"]
```

Prefer a copy if mtime might change. Distinguish filesystem mtime from embedded CreateDate. Thumbnails listed, not dumped unless scoped. Clean fixture of the same type is the negative control.

### Stop

Remote fetch, `-overwrite_original`, publishing precise GPS, extracting embedded binaries without scope.

### Evidence ids

Hash, JSON extract, clean-fixture control, second source if GPS/author/software is the claim.

### Reproduction recipe

Hash then JSON. GPS/author need a second source. Clean fixture control. No overwrite.

## Verification scenarios

Read metadata from a copy in a restricted parser environment.
Record ExifTool version, file signature and intake hash before interpreting fields.
Use grouped/duplicate tags where needed to distinguish EXIF, XMP and filesystem values.

| Scenario | Observation | Expected classification |
|---|---|---|
| Synthetic photo has a known GPS tag | JSON tag group and numeric value | parser positive control |
| Clean twin has the tag removed | same extraction command | negative control |
| PDF inherits an author's name from a template | template and document metadata | no personal attribution |
| CreateDate lacks timezone | raw timestamp and format | ambiguous time, not exact UTC |
| File embeds a thumbnail with old metadata | thumbnail provenance | separate artifact, not current scene |

Metadata is editable; consistency across fields does not establish authenticity.
Software tags identify the producer that wrote a field, not a currently exposed server.
A privacy finding needs evidence that the file was disclosed across a real boundary.
Attach only the minimum redacted fields and the source proving disclosure.
Keep derived-file hashes distinct from the original intake hash.

## Done

Evidence holds hash + JSON. No field alone is a finding.
