# Decisions

One entry per decision that is expensive to reverse. Each states what was
decided, why, and what it costs. New entries go at the top.

## 2026-11-09 — A dump becomes a graph, not a paragraph

**Decision.** `cyber_entity import` reads a collected host/URL/httpx/JSON dump and
records its entities and relations in one call, bound to the observation that
produced it. A dump outside the declared engagement is refused.
**Why.** Re-typing forty hosts as forty upserts is where discipline collapses and
hosts get lost. The dump already exists as evidence; it should become graph
facts, not a summary.
**Cost.** One more parser to keep, and the graph inherits whatever the dump
contains: a wrong line becomes a wrong entity, tied to the wrong evidence.

## 2026-11-09 — A branch is a role, and it closes after its sub-steps

**Decision.** `cyber_tasks assets` seeds one branch per known entity, with the
steps its kind needs (`src/coverage-roles.ts`), and a task cannot be completed
while a sub-step under it is still open.
**Why.** A host is not "done" because someone looked at it once; it is done when
its ports, TLS, HTTP surface and validation are observed. A role is data, so the
checklist adapts to the kind of thing instead of being the same five words for
everything.
**Cost.** More tasks per asset and a stricter closure; a role that does not fit
falls back to surface plus validation, and the model still has to observe each
step.

## 2026-11-09 — A target is a tree, and its coverage is a file

**Decision.** Tasks nest to a bounded depth, `cyber_tasks assets` seeds one branch
per known host, domain or URL, and `export` writes `couverture.md` into the
declared engagement.
**Why.** A flat list lets a fifty-host target look covered after five steps. A
tree makes every branch visible, and the exported map is what a person reads to
see what was done, blocked, or never started.
**Cost.** More tasks to keep current, and a file that must be regenerated when
the list changes. The depth bound and the task capacity limit still apply.

## 2026-11-09 — A fact is a typed entity, and a pivot is a path

**Decision.** `cyber_entity` records typed nodes (`domain`, `host`, `ip`, `url`,
`org`, `person`, `account`, `repo`, `secret`, `certificate`, `service`,
`technology`) and typed relations, each bound to the observations it was read
from. The same `type`/`key` merges instead of duplicating; `path` returns the
shortest chain between two entities.
**Why.** A list of findings cannot answer "how do we reach this asset". OSINT and
recon produce relations, not only claims: partner → account → repository → host
is a pivot, and it must be queryable instead of retyped in prose.
**Cost.** Two more tables and a graph to keep current. An entity without an
observation is refused, so every node needs the read that produced it.

## 2026-11-09 — An artifact is typed and filed by its kind

**Decision.** An artifact carries one kind, and a mission that declared a root
stores it in the folder of that kind: `poc`/`script` under `pocs/`, `capture`
under `preuves/captures` and only as a PNG or JPEG, `dump` under
`preuves/dumps`, `fixture` under `preuves/fixtures`, `evidence` under
`preuves/extraits`, `rule` under `regles`. A capture whose bytes are not an
image, a PoC whose file is not executable source, and a kind filed in another
folder are refused.
**Why.** One folder for everything produced 34 text files and 75 response bodies
presented as evidence, and a 404 body cited as a proof. A body is an annex, not
a proof; the proof of a request is the observation of the command and the
capture of its recorded trace.
**Cost.** Every artifact now needs its folder and its real type; an engagement
created without a root keeps the old freedom until its next mission declares one.

## 2026-11-05 — The engagement root anchors the evidence

**Decision.** `cyber_mission action=create` takes a `root`: the directory that
owns the engagement. Captures are written under `<root>/preuves/captures`, the
report artifacts must stay under `<root>/rapport-vN`, and the snapshot returns
that `reportDir`. A mission created without a root keeps the session working
directory the harness used before.
**Why.** Evidence was landing wherever the agent happened to run: captures in
the harness state, PoCs in `/tmp`, reports next to the notes. A delivered
mission could not be told apart from its own working files.
**Cost.** The root is validated once, at creation (absolute, existing directory,
no symlink), and cannot be changed afterwards. A mission created without one
keeps the loose behaviour, so the anchor has to be declared deliberately.

## 2026-11-04 — A launch is not a proof outcome

**Decision.** The supervisor writes a nonce-bound terminal result carrying the
full trace hash, and `read` re-hashes every byte before trusting it. A recovered
PID without a reliable result stays `unknown`, and a command whose group outlives
it is `failed`.
**Why.** A spawn, a stop, or the displayed tail proves nothing on its own; only a
terminal result bound to the run key and to the whole trace can be cited.
**Cost.** One result file per command and a full read on every verification.
Legacy rows keep their weaker metadata instead of being rewritten.

## 2026-11-04 — Task locks cover the whole read-modify-write

**Decision.** A task mutation holds its lock across the complete read, check and
write; a missing dependency blocks execution; old tasks are never dropped by tail
slicing.
**Why.** Two concurrent updates could otherwise both read the same open state and
both close it.
**Cost.** The lock is held longer, and a closed task whose proof disappeared
stays a continuity blocker instead of being silently forgotten.

## 2026-11-04 — Verification, review and restitution are distinct

**Decision.** `cyber_finding verify` binds the current finding revision to fresh
reproduction and negative controls observed in a distinct session. The visual
review and the effective restitution are operator transitions, separate from the
technical verification.
**Why.** A technical reproduction is not a person approving a report, and a
restitution that was planned is not a restitution that happened.
**Cost.** More transitions to record. Reopening validation keeps the node's
previous result in the mission history but deletes the old verification links, so
fresh proof has to be produced.

## 2026-11-04 — Reports are versioned snapshots

**Decision.** A report starts from a snapshot bound to the source fingerprint,
then links Word, PDF and a QA manifest that covers every rendered page. The
latest approved report must stay unchanged; a changed finding invalidates the
review and reopens the snapshot.
**Why.** A report is a claim about a fixed state; if the state or the files move,
the approval no longer covers what would be delivered.
**Cost.** Every correction produces a new version and a new visual review.

## 2026-11-04 — Cleanup follows restitution, in two processes

**Decision.** Cleanup is allowed only after the restitution is recorded, and its
execution and verification are two separate traced processes.
**Why.** A planned restitution is not a performed one, and a cleanup that
verifies itself proves nothing.
**Cost.** Cleanup takes two commands, and the evidence, accounts and test objects
must be kept until restitution instead of being purged along the way.

## 2026-11-04 — The verifier is isolated and pinned

**Decision.** `HARNESS_VERIFIER`, or `state/verifier`, pins one model; a
cross-provider fallback is an explicit ordered list with a timeout and an
accepted response limit; the current model is remembered per session.
**Why.** A verification already in flight must not be silently re-routed, and the
stateless 2.0.26 API exposes no token ceiling, so a character limit cannot be
sold as a billing limit.
**Cost.** A bad pin fails loudly as that provider's refusal, and a concurrent
request cannot change the provider of a verification or an extraction already
running.

## 2026-10-26 — Idle, not status, decides that a session is finished

**Decision.** `pendingLessons` reads a session once it has been quiet for ten
minutes; the "status is not active" test is gone.
**Why.** Measured on the real store: 72 sessions had observations and had never
been read, most of them marked `active` because the host never closed them. The
old filter made them permanently invisible to the learning loop.
**Cost.** A session abandoned mid-work is read like a finished one; the
extractor sees partial evidence and proposes what it can, which the gates check.

## 2026-10-26 — The verifier is a setting, and it is named in the record

**Decision.** `HARNESS_VERIFIER`, or `state/verifier` when the environment says
nothing; every extraction records the model that answered.
**Why.** The host's own provider refuses a request of its own (free tier, Go
plans), and the operator chooses what a background call may cost. Without the
model in the record, "the loop ran" cannot be checked afterwards.
**Cost.** One more file to keep; a pin that stops working fails loudly as a
refusal from that provider.


## 2026-10-26 — Documentation inside the repository

**Decision.** The repository carries `AGENTS.md`, `src/ARCHITECTURE.md` and this
file; runtime state stays in the store.
**Why.** An agent opening `harness-core` found nothing: instructions were global,
state was in SQLite, and the module map existed only in a session's head.
**Cost.** Three files to keep current. We do **not** add `PROGRESS.md`,
`feature_list.json` or Makefile verification targets: they would duplicate the
store, and two sources of truth is the failure this harness exists to prevent.

## 2026-10-25 — A global tier for methods only

**Decision.** `GLOBAL_SCOPE = "global"`. `cyber_method {action:"promote"}` copies
an **active** method out of its project; the copy carries `promotedFrom` project
slugs and no evidence; `assertGloballyReusable` refuses text that names a host,
URL, IP, email, hash or token.
**Why.** Learning was per project, so a method proved on one target was invisible
on the next. Facts are the opposite case: what one target answered is worthless
elsewhere and would carry one engagement into another.
**Cost.** The global skill list grows in every project; a local candidate of the
same name hides the global method; promotion stays manual.

## 2026-10-25 — Ordered verifier candidates, with retry

**Decision.** A review and a lesson extraction try a list (requested → live →
configured providers) instead of one provider; `opencode` and `opencode-go` are
excluded; an empty list is an explicit refusal.
**Why.** 67 `lessons.failed` came from picking `opencode-go` alone (subscription,
data-training policy). The free tier was measured to refuse as well
("Free usage limit reached").
**Cost.** Several quick failures before the working provider is found.

## 2026-10-25 — No per-binary gate on `cyber_process`

**Decision.** Commands are not refused because a method was not loaded.
**Why.** The binding constraint is evidence: a task does not close and a finding
is not accepted without it. Blocking a binary adds friction to every engagement
for a benefit that is not measured.
**Cost.** A model can still skip the method and answer in prose; the ledger, not
the command, is what catches it.

## 2026-10-24 — Learning thresholds unchanged

**Decision.** `minimumSkillSessions: 2`, `minimumSkillConfidence: 0.75`.
**Why.** One session is an anecdote. Lowering it to make the loop look productive
would promote noise.
**Cost.** Single-shot projects produce candidates that never activate.

## 2026-10-23 — One route per request, controllable

**Decision.** `routeFor(text, 1)` with weighted triggers and an anti-noise guard
(> 800 chars and a single hit is not a route); `HARNESS_ROUTER=off` disables the
table and the load requirement.
**Why.** A catalogue is inert; a table is a decision. An off switch is what makes
an A/B measurement possible.
**Cost.** One row can miss a compound request; the calibration is re-run when the
routes change.

## 2026-10-23 — The model loads the skill itself

**Decision.** The injected context names the method; it does not paste the skill
body. `cyber_finding` refuses until the enforced skill was loaded in the session.
**Why.** Loading leaves a trace, and the model reads the whole skill instead of a
truncated excerpt. Silent injection made "did it follow the method?" unanswerable.
**Cost.** The instruction must be imperative ("The method is mandatory… call the
skill tool with that id"), or the model simply ignores the table — measured: 0
calls with the soft wording.

## 2026-10-23 — The finding gate routes on the finding's own text

**Decision.** When the host hands the hook no request text, the gate matches the
finding's title and description; the native prompt hook supplies the text when
the host does provide it.
**Why.** OpenCode does not pass the request (`event.messages[0].parts` empty). A
gate that cannot see the request must still be able to decide.
**Cost.** The gate is narrower than the request: it sees the claim, not the work
that led to it.

## 2026-10-22 — State outside the repository

**Decision.** `HARNESS_HOME` defaults to `~/.local/share/harness-core`.
**Why.** The evidence must outlive the host and the working directory; a store
inside a host's folder disappears with the host.
**Cost.** The repository alone is not self-describing — hence the docs above, and
`HARNESS_STATE_ROOT` for tests.

## 2026-10-22 — Observations, not transcripts

**Decision.** Every tool call becomes an immutable observation (id derived from
the session and the call); nothing rewrites one.
**Why.** A claim is only checkable if the thing it rests on cannot be edited
afterwards. A session log is a narrative; an observation is a datum.
**Cost.** Two stores and a strict scope rule: evidence never crosses a project.

## 2026-11-04 — Capitalisation is a bounded, validated pass

**Decision.** A capitalisation pass records one bounded outcome (`none`,
`candidate`, `validated`); `validated` requires artifacts and distinct positive
and negative observation tests. It never claims to change model weights, native
tools or permissions.
**Why.** A lesson is only reusable if something observed backs it, and a pass that
rewrites itself on every run cannot be audited.
**Cost.** More evidence per pass, and a repeated snapshot rewrites the same
capitalisation row instead of accumulating duplicates.

