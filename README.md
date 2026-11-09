# Harness core

Evidence and mission-tracking kernel for OpenCode v2. Observations, findings,
tasks and methods live in a shared state that stays independent of the host.
The adapter is in `opencode/`; `src/` uses Node's native modules.
Node 24 or newer is required. Command supervision needs Linux and a `node`
executable the server can reach (`HARNESS_NODE` can pin its path).
A trace capture opens in the operator's terminal (qterminal), decorations
included, then the window is closed; without a display, or with
`HARNESS_CAPTURE_TERMINAL=off`, a printed rendering is produced instead (Python 3
and Pillow). Capturing a real window needs X11 (`import`, `identify`) and a
display.

## Install in OpenCode v2

The verified native version is **2.0.26**, npm package `@opencode/cli`, command
`opencode2`. The `opencode-ai` package belongs to the other version line.

Set `HARNESS_CORE` to the absolute path of this repository. Add the `opencode/`
**directory** to the `plugins` array of the existing configuration, keeping the
other settings and plugins:

```json
{
  "plugins": ["/absolute/path/harness-core/opencode"],
  "permissions": [
    {"action": "harness_operator", "resource": "*", "effect": "ask"}
  ]
}
```

The directory exposes `index.ts`. Discovery through
`~/.config/opencode/plugins/harness-core` is another option; choose a single
method to avoid a duplicate plugin identifier. Wait for the host to activate the
plugin before reading its catalogue. Then check `harness-core.proof` in
`plugin.list` and the two procedures in `skill.list`.

`capitaliser-cyber` and `rapports-cyber` are served from `.opencode/skills/`.
The other `harness-*` methods of the router belong to an external catalogue.
Their absence must be resolved before an operation that requires them. A failed
load never satisfies that requirement.

## Guarantees and limits

- Operational observations are immutable and confined to their scope. The
  fingerprint covers the whole output, even beyond the kept excerpt. Inputs and
  outputs shown to the model are redacted.
- Launching a command does not prove it succeeded. `cyber_process read` checks
  the whole trace and only reports a successful result after a clean exit with
  code 0. States: `running`, `succeeded`, `failed`, `timed_out`, `stopped`,
  `unknown`. An old process without a reliable result stays `unknown`.
- The Node supervisor is independent of the server. Default deadline: 120 s;
  maximum: 600 s. Descendants in the group that outlive their parent are killed
  and make the result fail. A program that deliberately leaves its group cannot
  be fully supervised here.
- Registry commands and reads are redacted. Full traces, results and control
  files stay local, under restricted access. The control key of a run is never
  returned to the model.
- A lock covers every task mutation. A conflict asks for a retry. Tasks are not
  truncated to the last twenty. A missing or blocked dependency prevents
  starting; a closure without valid evidence stays visible as a blocker on
  resume.
- Verifying a finding binds its revision to a reproduction and a negative
  control observed in a distinct session, after its creation and after any
  reopened validation. It is not human approval. A marker proves the observed
  result; the analysis must justify the impact.
- The harness tracks evidence and permissions. It is not a network sandbox and
  does not infer a target authorisation from a folder. Define the mandate and
  the scope in the mission.

Native shell permissions remain mandatory. On 2.0.26, the fallback through the
official CLI client checks that it reaches the same server PID. A different
private server is refused. Versions that expose `ctx.permission.assert` use it
directly. Operator transitions require a `once` answer to `harness_operator` in
`ask`; a remembered `allow` is not a human decision.

## Reports and restitution

The `rapports-cyber` procedure describes this path:

1. Record observations, sources and findings. Produce the attestations with
   `cyber_verification`, then close the `validation` stage citing them and
   verify the findings with `cyber_finding verify`.
2. Create `cyber_report snapshot` with the editorial details. Vulnerabilities
   must be verified; observations and untested cases keep their classification.
   Sources and fingerprints are frozen.
3. Generate Word, PDF and images of every page with the provided script.
   Register the three artifacts and link them with `cyber_report register`.
4. Read every page and record the owner's decision. The `report` stage requires
   the latest approved report and its unchanged files. A change to the findings
   invalidates the review and reopens the report.
5. If validation must be reopened, use `cyber_mission reopen-validation` with a
   reason. After the operator's decision, the harness keeps the checkpoints,
   returns the findings to verification and reopens validation, evidence and
   report. The old verification observations cannot be reused as fresh
   evidence for that reopen. No external test is replayed automatically.
6. Record the effective restitution with the operator's agreement and its
   evidence. A planned restitution is not a performed one.
7. **Clean only after restitution** with `cyber_cleanup`:
   `plan` → `run` → `result` → `verify` → `result`.
   Execution and its verification use distinct processes. Until then, keep the
   evidence, accounts and test objects according to the mandate. No PoC,
   generator or capitalisation pass removes them automatically.

Transitions and their events are written in one transaction. Concurrent cleanup
transitions are refused before launch. Closing a report and the follow-up after
restitution are distinct: `cyber_report status` exposes restitution,
capitalisation and cleanup. Do not announce the folder as fully closed while
these actions remain.

The local generator does not run the snapshot's PoCs:

```bash
python3 -m pip install -r .opencode/skills/rapports-cyber/scripts/requirements.txt
# Also install LibreOffice, Poppler and DejaVu Sans Mono or an equivalent font.
python3 .opencode/skills/rapports-cyber/scripts/build_report.py /mission/snapshot.json --out /mission/rapport-v2
```

It refuses to overwrite an existing version and produces `rapport.docx`,
`rapport.pdf`, `page-N.png`, `qa.json`. `SOFFICE` can point at LibreOffice.
The manifest links the fingerprints and leaves the visual review pending.
The computation covers the **CVSS 3.1 base score only**, per
[FIRST](https://www.first.org/cvss/v3.1/specification-document). An unsupported
vector or an inconsistent score is refused. Justify the metrics and the
business risk separately.

`cyber_capture shot` photographs a real window. `evidence` shows a recorded
trace tied to the process that was read, without replaying it. This second form
carries `rendered-trace` and must not be presented as a native capture of the
test.

## Capitalise Cyber

A bounded pass turns verified learnings into scripts, rules, fixtures or
procedures. `cyber_capitalise` records `none`, `candidate` or `validated`.
Validation requires an artifact plus distinct positive and negative tests. No
useful learning is a valid outcome. This pass does not change the model weights
and does not generate skills recursively.

Learned methods always require two supporting sessions and a confidence ≥ 0.75
to become active. Global promotion requires an operator decision and anonymised
examples. Capitalisation is not authorisation to clean up.

Automatic extraction waits for ten minutes of inactivity. It compares
observation fingerprints: a resumed session can be read again and a failure
retried after one minute. `HARNESS_VERIFIER` or `state/verifier` pins a single
model. Without a pinned model, the requesting session's provider is reused;
others are only considered in `HARNESS_VERIFIER_PROVIDERS`. At most three
candidates, 30 s per call and 24,000 characters of accepted answer. **The
stateless 2.0.26 API exposes no output token ceiling**; the character limit is
not a server billing cap.

## State and migration

`HARNESS_HOME` defaults to `~/.local/share/harness-core`.
`HARNESS_STATE_ROOT` can set the state directory directly.

| File | Contents |
|---|---|
| `knowledge.sqlite` | Sessions, observations, knowledge, rules and audits |
| `platform.sqlite` | Missions, findings, sources, artifacts, reports, restitutions and cleanup |
| `tasks-<scope>.json` | Tasks locked per scope |
| `processes.json`, `traces/` | Runs, private traces, results and control files |
| `reports/` | Report snapshots kept by version |
| `skills/` | Revisions and learned methods |

SQLite migrations are additive. No missing full hash is invented for old
observations, and no old process is turned into a success. Back up the state
before an upgrade; do not open a migrated database with an older version. An
abandoned lock needs an inspection, not an automatic removal.

## Verify

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run check             # TypeScript, host neutrality and procedure resources
npm test                  # standalone suites, no external model
python3 test/report-pipeline.py
npm run test:report       # render dependencies required
npm run verify            # the three checks above, in one command
OPENCODE_BINARY=/path/opencode2 node scripts/native-smoke.cjs
```

The hosted workflow may be unavailable (Actions billing). The repository then
provides an equivalent local check, run before every push:

```bash
git config core.hooksPath .githooks   # once per clone
```

`.githooks/pre-push` runs `npm run verify`: TypeScript and neutrality, the
standalone suites, then the report contracts. A push that fails one of the
three is refused locally.

## Maintenance

Observations are the evidence of a finding: they are never pruned, and the audit
log is append-only by schema. Maintenance covers the transcript and disk space:

```bash
npm run prune -- --messages-days 180 --dry-run   # what would be removed
npm run prune -- --messages-days 180             # removal, then VACUUM
```

The script removes messages older than the window (the search index follows),
leaves observations and the audit log untouched, then compacts the database and
folds the WAL. It is run by hand: no model tool can trigger a deletion.

The tests use synthetic fixtures with no client target. The native 2.0.26 check
covers the catalogue, the tools within their scope and the refusal of the
private server. Execution events, `once` decisions and command results are
checked with a test host. No native run with an external model is claimed.
Captures of real windows require a display. The external Pi check remains
optional with `npm run test:gate` or `HARNESS_PI_GATE`.

The `.github/workflows/verify.yml` workflow runs three checks on pull requests:
kernel contracts, a real Word/PDF render and the native OpenCode 2.0.26 load.
The rendered pages are kept as a CI artifact for the human visual review.
`ci/verify.yml` keeps a copy; only the `.github/workflows/` path is active.

Decisions are in `DECISIONS.md`, the module map in `src/ARCHITECTURE.md`.

## Live tools: discovery, creation and reuse during a session

The OpenCode plugin exposes `cyber_toolbox`. Its shared registry is kept under
`HARNESS_STATE_ROOT/capabilities/registry.json`, outside the repository. A
mission can propose, test, validate and activate a script **without changing
session**. Open sessions re-read the index on the next context or call to
`cyber_toolbox discover`. Activated scripts are available **immediately**
through the existing shell/process tools and their permissions. The plugin does
not add a native OpenCode tool per script.

- `discover`: ranks commands from `PATH`, from the `HARNESS_TOOL_HOME`
  directory (no default value), from `HARNESS_TOOL_PATHS`, the managed scripts
  and the host catalogue tools. This is not proof of execution. Linked paths are
  ignored.
- `plan`: compares up to 25 objectives with the current inventory. A match only
  indicates a candidate tool, never a genuinely tested coverage.
- `list`: returns the versions of the scope, with candidates and history.
- `propose`: writes a **candidate** version, without executing it or making it
  available to other missions. Supported formats: `mjs`, `py`, `sh`.
  Candidates stay isolated under `capabilities/staging/`.
- `validate`: checks the syntax without running the script, then requires two
  distinct successful observations (a positive test and a negative test) from
  the same scope, containing the exact path of the candidate and the expected
  result. Both runs must first have been performed with the host's authorised
  tools; the mere output of a text generator is not evidence.
- `activate`: makes the validated version immediately visible to its project,
  removing the previous one from the active index. Published files are checked
  by SHA-256 before every use.
- `promote`: requires an explicit operator decision, copies the validated
  script into the global registry and checks for the absence of current target
  identifiers. The evidence stays in the source project.
- `rollback`: requires an explicit operator decision, and can only restore a
  version that was already validated. Pass `global: true` to restore a
  previously retired global version.
- `retire`: retires a project's active version, or the global catalogue's with
  `global: true`, after operator agreement.
- `prune`: removes abandoned candidates older than 30 days by default, or the
  candidates named by `candidateIds`, without touching validated or active
  versions. Quotas: 25 candidates and 250 revisions per project, 2,000 revisions
  in the registry. Saturation requires an explicit purge of candidates, not a
  silent overwrite.

The context shows a short selection of managed and native tools, **without
scanning PATH** on every message. The CLI scan is reserved for `discover` and
`plan`, with a 60-second cache, and `discover refresh:true` to force the update.
An unreachable `HARNESS_TOOL_HOME` or `HARNESS_TOOL_PATHS` path raises an
explicit error. Tools with identical names are deduplicated by priority
managed → host → PATH.

The catalogue is not an execution log. The existing immutable observations carry
the effective calls. `cyber_toolbox usage` exposes their results and a
conservative *candidateManagedCommand* hint: it never proves that a script
produced the expected effects. No extra audit row is written on each injection
of the capability block or each operational call.

Creating files grants neither target authorisation nor extra system access.
Validation is not a substitute for a human security review. Execution evidence
and real-condition tests under Kali remain to be performed on the operator's
environment. No candidate tool is executed automatically by the registry.
