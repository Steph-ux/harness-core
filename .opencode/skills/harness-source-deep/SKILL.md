---
name: harness-source-deep
description: "Deep source audit on collected JS bundles and sourcemaps: AST-level sink tracking, endpoint and param inventory, taint from request to dangerous sink."
---

# Source deep — bundles → taint → endpoints

Source: `javascript-security-audit`, `sourcemap-analysis`, `taint-tracking` (2024: `postMessage` → `innerHTML`, client-side price).

## Gate

Collected code only. The `.js` / `.js.map` must already be in `<evidence-dir>` (via `katana -jc`, `hakrawler`, `cariddi`, `gau`/`waymore`, or a direct collect in scope). Every command goes through `cyber_process` with `argv`. Do not build a shell string. `semgrep 1.182.1` at `~/.local/bin/semgrep` and `gf` 23 patterns at `~/.gf` are already installed — do not reinstall. Offline only; do not send code externally.

## Steps

1. Inventory: `find <evidence-dir> -name "*.js" -o -name "*.js.map"` → record as its own observation. Unpack maps into `sourcemaps/<name>/` (`semgrep` handles maps natively, or `npx source-map-explorer` style) — one observation for the unpack. No map = work on the minified bundle and note the limitation.
2. Static sink pass — one config per observation, on the unpacked maps:
```text
semgrep --config p/javascript --include="*.js" --json -o <evidence-dir>/semgrep-js.json <evidence-dir>/sourcemaps
semgrep --config p/xss --include="*.js" --json -o <evidence-dir>/semgrep-xss.json <evidence-dir>/sourcemaps
semgrep --config p/command-injection --include="*.js" --json -o <evidence-dir>/semgrep-cmd.json <evidence-dir>/sourcemaps
semgrep --config p/sql-injection --include="*.js" --json -o <evidence-dir>/semgrep-sqli.json <evidence-dir>/sourcemaps
# second opinion when semgrep is silent:
gf xss <evidence-dir>/sourcemaps/**/*.js
gf sqli <evidence-dir>/sourcemaps/**/*.js
```
Each config is its own observation.

3. Taint inventory: from each hit, extract `source → sink` (`req.query`/`req.body`/`location.hash`/`postMessage`/`localStorage` → `eval`/`Function`/`innerHTML`/`outerHTML`/`document.write`/`insertAdjacentHTML`/`querySelector`/`exec`/`spawn`/`sql.query`/`deserialize`/`JSON.parse`+`__proto__`). Normalize as `file:line: sink (tainted by param)` → `taint-inventory.json`. One observation for the inventory file.
4. Endpoint + param inventory: from the same code, extract every `fetch`/`XMLHttpRequest`/`axios`/`$.ajax` call plus the `paramspider`/`arjun` lists already in evidence → `endpoints.json` (`method + path template + host + params + source file:line`). `cyber_source` ingest the key chunks.
5. One live confirmation per tainted sink, approved host only: replay the request that feeds the sink with a benign marker (`XSS-CANARY-<id>` / `SLEEP(2)` timing / `{{7*7}}` → `49` check), then the control (original value). Both via `cyber_process` `argv`. No hit on the marker = not a finding.
6. `cyber_finding` with `evidence` = unpack + semgrep/gf hit + taint/endpoints JSONs + the two live observations, `sources` = the tainted file chunk + the endpoint chunk, `checks` = baseline inventory:positive-control, marker hit:reproduction, original value:negative-control. DOM-side sink → `cyber_capture` linked to the reproduction observation. No static hit alone, no `HTTP 200` alone.

### Review matrix

Trace sources from URL/query/body, `postMessage`, storage, DOM and server
responses through sanitizers and encoders to sinks. Cover HTML, attribute,
JavaScript, URL, CSS, DOM, shell, SQL, template and deserialization contexts.
Record whether a sanitizer is context-appropriate and whether the value is
user-controlled at runtime; a dangerous API name without a taint path is not a
finding. Compare bundle, sourcemap and source URL hashes so stale maps are not
treated as current code.

### Static controls

Run a clean known-safe fixture through the same rules as a false-positive
control. For every candidate identify the exact source line, parameter, call
path, encoding boundary and expected sink behavior. Keep secrets out of the
ledger: record location and hash and hand confirmed credentials to
`harness-secret-scan`, never to the report or a network request.

### Proof contract

Static evidence establishes reachability; a finding additionally needs the
approved live or runtime observation and a negative input that does not reach or
execute the sink. If the application is unavailable, preserve the taint chain
as a candidate with the missing runtime proof.

## Done

Evidence holds the unpack, per-rule semgrep JSONs, `taint-inventory.json`, `endpoints.json`, and one live pair per sink.
