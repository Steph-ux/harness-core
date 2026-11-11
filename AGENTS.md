# harness-core

This is the proof and discipline system shared by the agent hosts: every tool
call becomes an immutable observation, a task closes only against a successful
observation, and a learned method needs evidence before it is served. State lives
outside the repository, so a host can be replaced without losing the evidence.

## Verify before claiming anything

```bash
npm test          # the core's own suites; must exit 0
npm run check     # TypeScript, host-neutrality and authored procedure resources
npm run test:gate # external host gate, when installed
```

`npm test` runs `test/run.cjs`, which is self-contained: it loads the suites
next to the code they exercise and counts real assertions. `npm run test:gate`
runs the legacy harness host (`~/.pi/agent/cyber-harness/tests/run.cjs`), which
calls the same suites inside its own gate. Exit code 0 is the only "done".

A suite that needs a platform the machine does not have is skipped with its
reason, and the runner reports how many were skipped. The command supervision
owns a process group and reads a durable terminal result: it runs on Linux
only, so the suites that cover it are skipped elsewhere and checked on Linux.
A skipped suite is never a suite that passed.

The runtime has no third-party dependency (Node built-ins only). The test
runner needs `jiti` to load the TypeScript sources, so `jiti` is a
devDependency with a committed lockfile; it never reaches the runtime.

## Where the state lives

`HARNESS_HOME` (default `~/.local/share/harness-core`), `HARNESS_STATE_ROOT`
(default `<HARNESS_HOME>/state`).

- `state/knowledge.sqlite` — sessions, observations, knowledge, reviews, audit log.
- `state/platform.sqlite` — missions, findings and their evidence, sources and
  chunks, approvals, checkpoints.
- `state/skills/{revisions,candidates,learned}/<scope>/<category>/<name>/` —
  learned methods; `scope` is `project-<hash of the directory>` or `global`.
- `state/captures/` — visual attestations.
- `state/verifier` — one line, `provider/model`, the model that serves a direct
  call (reviews, lesson extraction). `HARNESS_VERIFIER` wins when set.

A session is read by the learning loop once it has been quiet for ten minutes:
a host that never marked a session closed leaves it `active` forever, so time,
not status, decides what is finished. Each extraction records the model that
answered (`lessons.extracted.model`).

## Invariants

- **No claim without evidence.** A finding cites observation ids that exist in
  the same scope; a review is checked by a model that cannot use tools.
- **A task does not close by narration.** It needs a successful observation, and
  a blocked task states its reason.
- **A method needs support.** Two distinct sessions and confidence ≥ 0.75 before
  it becomes active; a failing observation keeps it a candidate.
- **Global methods are promoted, never proposed,** carry no evidence of their
  own (`promotedFrom` slugs only), and are refused when their text names a host,
  URL, IP, email, hash or token.
- **The core stays host-neutral.** `src/` imports no host runtime and names no
  host or target; `scripts/check-neutrality.cjs` fails the build otherwise.
- **A path is compared by the object it denotes, not by its spelling.** A short
  name for a directory is an alias, not a redirection; a symlink, a junction or
  a hard link is refused, and so is a volume that is not the one it is named as.
- **A negative control observes a different output.** It cannot observe what
  the reproduction observed, or the same output would be both the claim and
  its refutation.
- **Never edit `src/` or `opencode/plugin.ts` while an A/B bench is running:**
  each run reloads the module, so the arms would mix.

## Map

| Path | What it is |
|---|---|
| `src/store.ts` | SQLite knowledge store: observations, knowledge, reviews, audit |
| `src/platform-store.ts` | Engagements: missions, stages, findings, sources, approvals |
| `src/capsule.ts` | What a session finds on return, and the closing gate |
| `src/skills.ts` | Learned methods: propose, activate, deprecate, promote to `global` |
| `src/routing.ts` | Deterministic request → method table, injected per turn; declares the method catalogue |
| `src/lessons.ts` | End-of-session extraction prompt and its application |
| `src/process.ts` | Commands the harness owns, their trace and their stop |
| `src/memory-ranking.ts` | Which facts fit in the injected budget |
| `opencode/` | The only part that knows OpenCode: hooks, tools, injection |
| `test/` | Suites consumed by the runner; a new suite must be listed there |
| `test/opencode-paths.cjs` | The path guard: an alias is accepted, a redirection is refused |

Design decisions and their reasons: `DECISIONS.md`. Module-level map:
`src/ARCHITECTURE.md`. Keep both current when an invariant changes.

## Proof corrections

A process launch is not a successful execution. Read its durable result and
verify its whole trace before closing work. Unknown recovered processes stay
unknown. A completed stage needs successful evidence; verification must bind
fresh reproduction and negative controls from another session. Never invent a
human approval from technical verification. Cleanup of mission resources is
permitted only after recorded restitution of the reviewed report.

For reporting changes, run `node scripts/run-python.cjs test/report-pipeline.py`
(the launcher finds the interpreter the machine has). For layout changes,
run `npm run test:report` with the optional rendering dependencies and inspect
every page. Temporary synthetic unit fixtures are not client mission resources.
Never claim visual review from the technical QA manifest alone. Use the native
SDK smoke test with the documented binary version before claiming native loading.
The CI entry point is `.github/workflows/verify.yml`; it has no second copy, so
there is nothing to keep synchronized. CI rendering does not replace human page
review.
