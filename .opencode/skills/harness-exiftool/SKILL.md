---
name: harness-exiftool
description: "Extract metadata from a file already collected in an engagement, recording the file hash and the result."
---

# ExifTool — hash then meta, never fetch

Source: ExifTool 13.59 (2024: `creator: GPS** / `producer: CVE` leaks in delivered docs).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string.
File must already be in `<evidence-dir>`. Do not fetch remote.

## Steps

1. Hash first:
```text
sha256sum <file>
```
Record as file-identity observation.

2. Then:
```text
exiftool -json -n <file> > <evidence-dir>/exiftool-<basename>.json
```
Own observation.

3. Read `CreateDate`, `GPS*`, `Author`, `Creator`, `Producer`, `Software`. Candidate until relevance shown (GPS in engagement geography, author = in-scope principal, software CVE via `trivy fs`).
4. No write: `exiftool -overwrite_original` forbidden. `cyber_finding` needs hash + JSON `cyber_source` chunk + second observation (trivy CVE or second doc same author).

### Metadata matrix

Record file type, size, hash, timestamps, GPS, author/creator, producer,
software, embedded thumbnails, comments, XMP/IPTC and revision data. Distinguish
filesystem timestamps from embedded timestamps. A GPS coordinate or author is a
privacy lead, not proof of identity, location or compromise without an
independent source.

### Negative controls and privacy

Process a known-clean fixture and a copy hash as controls. Never alter the
source, extract embedded files without scope, or publish precise personal
locations. Redact GPS, author and serial values unless necessary to the finding.

## Done

Evidence holds hash + JSON. No field alone is a finding.
