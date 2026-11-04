# Decisions

One entry per decision that is expensive to reverse. Each states what was
decided, why, and what it costs. New entries go at the top.

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
finding's title and description.
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

## 2026-11-04 — Proof outcomes and concurrent updates

The command supervisor writes a nonce-bound terminal result and full trace
hash. A launch or stop is not evidence of success; an unknown recovered PID
is never treated as completed. Descendants in the owned process group may
not outlive a successful parent result. Complete output hashes detect changes
beyond the displayed tail. Legacy rows keep their original proof metadata.

Task locks cover the complete read-modify-write. Missing dependencies block
execution, and old tasks never disappear due to tail slicing. A closed task
with missing proof remains a continuity blocker. Finding verification binds
the current finding revision to fresh controls in a distinct session; it
never fabricates human approval. The native prompt hook supplies routing text.
