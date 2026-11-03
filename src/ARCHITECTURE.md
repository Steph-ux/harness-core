# Architecture

The core is one-way: a host turns a tool call into an observation, the stores
own the truth, and everything the model sees is derived from them.

```
tool call ──► observation (immutable, scoped) ──► task / finding / review
                                   │
                     capsule + routing table ──► injected context
                                   │
                     lesson extraction (no tools) ──► facts / methods
```

## Two stores, two jobs

| Store | Holds | Why not one file |
|---|---|---|
| `knowledge.sqlite` | sessions, observations, knowledge, reviews, audit log | Written on every tool call; must stay small and fast, and it is read by the learning loop |
| `platform.sqlite` | missions, stages, findings, finding evidence and citations, sources, chunks, approvals, checkpoints | Engagement data outlives a project scope and is read by different code paths |

`StorePort` (`src/types.ts`) is the seam: the core depends on the port, not on a
database, so a test can hand it a stub and a host can hand it the real store.

## Modules and the invariant each one enforces

| Module | Enforces |
|---|---|
| `store.ts` | An observation is written once and never edited; a finding cites only evidence from its own scope; operator rules override inferred knowledge |
| `platform-store.ts` | A mission takes its stages in order; a scope is approved before work is dispatched; a finding is verified by an observation that is not its own evidence |
| `tasks.ts` | `complete` requires a successful observation id; `block` requires a reason |
| `capsule.ts` | The returning session gets the exact state: open steps, blocked steps with reasons, the mission stage, pending approvals, commands the harness still owns. `closingGate` answers "are we done?" from that state alone |
| `skills.ts` | A method becomes active only with support from two sessions and confidence ≥ 0.75; a global method is promotion-only, evidence-free, identifier-free, and visible from every project (project shadows global) |
| `routing.ts` | One route per request, weighted triggers, an anti-noise guard (a single hit on a long text is not a route) |
| `lessons.ts` | The extractor proposes; the ordinary gates dispose. A proposal without a successful observation is refused |
| `process.ts` | A long command is owned: full output to a named file, detached lifetime, stop by id |
| `capture.ts` | A visual attestation is one window, framed, never the desktop |
| `memory-ranking.ts` | Operator rules keep a reserved budget (`operatorModelChars`) and learned facts never crowd them out |
| `util.ts` | The scope slug (`project-<24 hex>`), hashing, and the text redaction used before anything reaches an audit row |

## Where the host plugs in

`opencode/plugin.ts` is the only file that knows the host. It registers:

- `context` — injects continuity, the routing table and the closing gate; starts
  the background lesson extraction for pending sessions.
- `tool.execute.after` — records the observation, including failures.
- `tool.execute.before` — refuses a finding whose enforced method was not loaded.
- tools `cyber_*` — tasks, findings, sources, missions, approvals, processes,
  memory, methods, reviews, captures.
- `skill.transform` — serves the active learned methods, global first, project
  shadowing by name.

A known host limitation shapes the design: OpenCode hands the `context` hook no
request text (`event.messages[0].parts` is empty). `routeFor()` therefore never
matches live on this host; the whole table is injected and the binding
constraint is the tool gate, not the router. Any host that passes the text gets
the sharper behaviour for free.

## The learning loop

```
session ends ──► pendingLessons(scope)
         └──► extractLessons: one model call, no tools, untrusted input
                 ├── facts ──► knowledge (pending, ranked, injected)
                 └── methods ──► skills.propose ──► candidate | active
                                                   └── promote ──► global
```

The verifier runs on an ordered candidate list and retries: `opencode` and
`opencode-go` are excluded because they refuse a direct call (measured), and an
empty list is reported as "no model can serve the harness" rather than recorded
as a session that taught nothing.

## Rules for changing the core

- Read the module and its tests before editing; the invariants live in the
  tests, not only in the prose.
- A new invariant needs a negative control: a test that shows the refusal.
- No host name, no target name, no secret in `src/` (`npm run check`).
- A new suite must be added to the runner's list, or it never runs.
