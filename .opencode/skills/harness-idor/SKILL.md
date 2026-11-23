---
name: harness-idor
description: "Test an approved object reference by comparing the owner's response with another authorized test identity's response."
---

# IDOR/BOLA — owner vs other, re-read for write

Source: `exploiting-idor-vulnerabilities` (2024: BOLA #1 API risk; UUIDs still leak via enumeration).

## Gate

Every command goes through `cyber_process` with `argv`. Do not build a shell string.
Two approved test identities or one + non-owned ref. Do not read real customer object. One field mutated per request.

## Steps

1. A → `GET /api/<resource>/<A-id>` own object. Record stable field. Positive control.
2. A → `GET /api/<resource>/000...` non-existent. Record `404/403`. Existence-oracle negative control.
3. A → `GET /api/<resource>/<B-id>` only ref swapped. Identical fields to B's own GET = candidate. `{"error":…}`/`{}` not.
4. Write variant (if reversible scope): `PUT /api/<resource>/<B-id>` benign field `notes:CANARY-<id>` as A → `GET` as B to see write land. Re-read is proof, not `PUT 200`. Restore + record.
5. Mass assignment: `PUT ... {"ownerId":"<B-id>"}` or `{"role":"admin"}` — one field, then `GET` as A to see ownership/role changed.
6. `cyber_finding` with A-own+missing+A-for-B + B-own comparison + final re-read `evidence`, endpoint chunk `sources`, `checks` A-own:positive, missing:negative, A-for-B:reproduction. No `referenceId` reuse.

### Reference matrix

Repeat the owner-vs-other comparison for every reference location exposed by
the route: numeric id, UUID, slug, filename, tenant id, nested child id,
cursor, export id and websocket/channel id. Start with one known-owned object
and one known-nonexistent object; do not enumerate real customer identifiers.
Compare status, response schema, field values, timing only as supporting data,
and side effects after a re-read.

### Write proof and controls

Only use a reversible field on an object owned by the test account. The owner
read is the positive control, the nonexistent reference is the negative
control, and the other-owner read is the reproduction. A write is confirmed
only when the other authorized test account can re-read the marker; the PUT
response is insufficient. Restore the marker and verify the original value.

### Limits

An object that is intentionally public, a redacted response, a cache hit, or a
404/403 without comparison is not an IDOR proof. Keep untested reference types
visible as `not-tested`, with the reason and the missing observation.

## Done

Finding cites 3 GETs + re-read. `200` without B's fields is not finding.
