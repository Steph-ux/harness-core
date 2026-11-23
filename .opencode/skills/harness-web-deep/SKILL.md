---
name: harness-web-deep
description: "Test SSRF, SSTI, XXE, deserialization, prototype pollution, and race conditions with single-field mutations and out-of-band controls."
---

# Web deep — one field, one payload, OOB-verified

Source: `testing-for-server-side-vulnerabilities`, `testing-for-race-conditions`, `testing-for-prototype-pollution` (2024: IMDSv2 SSRF, `__proto__`→RCE via `ejs`).

## Gate

Approved `host+method+injection point` only (param/header/JSON field/XML node in scope). Every command `cyber_process` `argv`. One mutation per request. → `harness-vuln-triage` before `cyber_finding`.

## Steps

1. Baseline: same request with original value → positive control.
2. One payload, one request (OOB per-attempt token you control or `httpx` listener in evidence):
   - SSRF: `http://127.0.0.1/` then `http://169.254.169.254/latest/meta-data/` (IMDSv2: `PUT /latest/api/token` first). Success = OOB hit or `127.0.0.1` banner, not `200` alone.
   - SSTI: `{{7*7}}`→`49`, then `${7*7}` (SPEL/Jinja), `{{'a'*5}}`→`aaaaa`. One engine each.
   - XXE: `<!ENTITY x SYSTEM "file:///etc/hostname">`+`&x;`. Marker in response, never full file.
   - Deser: `{"__type":"java.lang.Runtime"}` sleep(2) Canary; measure `diff-control --seuil-ms`.
   - Pollution: `{"__proto__":{"polluted":"1"}}` then `GET` polluted object (read-back proof, not `POST 200`).
   - Race: two identical state-changing requests parallel (~50ms apart) + final `GET` double effect.
3. Record each as own observation. WAF block (`WAF_SIGNS` `_lib/net.py`) / `5xx` is not confirmation — measure duration.
4. Repro once with fresh OOB token / `request-id`. Control (original value) no hit = negative control.
5. `cyber_finding` with baseline+payload+OOB listener+repro `evidence`, tainted chunk `sources`, `checks` payload:reproduction, baseline:positive, control:negative + OOB `contains`. Hash any marker.

### Payload discipline

Classify the injection point first: URL, header, JSON, form, XML, template,
deserializer or state transition. Use one harmless marker and one transport per
attempt. Prefer a controlled callback or local listener; never read sensitive
files, query cloud metadata beyond the minimum approved marker, spawn a shell,
or use a destructive delay. A WAF page, timeout, 5xx, reflected string or
parser error is a lead until the intended server-side effect is observed.

### Negative controls and replay

Replay the original value and a syntactically invalid value as separate
controls. For SSRF, a non-routable or approved external control must not create
the same callback; for SSTI/XXE/deserialization the literal marker must remain
literal; for pollution the clean object must lack the property. Reproduce once
with a new correlation id and stop after the bounded proof.

### Proof contract

The evidence chain contains the baseline, mutated request, callback or
read-back, and reproduction. Record callback timestamps and correlation ids,
not arbitrary response data. Map the confirmed sink and impact; static payload
acceptance without execution remains `not-tested` or candidate.

## Done

Each flaw cites baseline, payload, OOB listener. `200`/`500` alone never finding.
