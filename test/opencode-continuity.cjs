/**
 * The state a resumed session finds, and the review that guards a claim.
 *
 * A capsule carries the running step list and the observations that close it.
 * A review needs observations, and it is checked by a model that has no tools
 * and no sight of the session.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");
const PLUGIN = path.join(CORE, "opencode", "plugin.ts");

module.exports = async ({ assert, jiti }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-continuity-"));
  const state = path.join(workspace, "state");
  fs.mkdirSync(state, { recursive: true });
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;

  const plugin = jiti(PLUGIN).default;
  const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
  const { TaskStore } = jiti(path.join(CORE, "src", "tasks.ts"));
  const { capsule, capsuleText, capsuleTask, closingGate } = jiti(
    path.join(CORE, "src", "capsule.ts"),
  );
  const { scopeFor } = jiti(path.join(CORE, "src", "util.ts"));
  const { observationId } = jiti(path.join(CORE, "src", "observation-id.ts"));

  const store = new KnowledgeStore(path.join(state, "knowledge.sqlite"));
  const taskStore = new TaskStore(state);
  const scope = scopeFor(workspace);

  store.upsertSession({
    id: "ses_ctx",
    scope,
    cwd: workspace,
    status: "active",
    updatedAt: new Date().toISOString(),
  });
  const proof = store.recordObservation({
    id: observationId("ses_ctx", "call-proof"),
    sessionId: "ses_ctx",
    scope,
    tool: "shell",
    input: { command: "echo proved" },
    output: "proved\n",
    success: true,
    timestamp: new Date().toISOString(),
  });

  // The rules of the capsule, one by one.
  assert.equal(
    capsuleTask({
      id: "t1",
      title: "open task",
      status: "pending",
    }).status,
    "pending",
    "a pending task travels",
  );
  assert.equal(
    capsuleTask({
      id: "t2",
      title: "blocked without reason",
      status: "blocked",
    }),
    undefined,
    "a blocked task without a reason does not travel",
  );
  assert.equal(
    capsuleTask({
      id: "t3",
      title: "blocked with reason",
      status: "blocked",
      reason: "the target is down",
    }).reason,
    "the target is down",
    "a blocked task travels with its reason",
  );
  assert.equal(
    capsuleTask({
      id: "t4",
      title: "closed without proof",
      status: "completed",
    }),
    undefined,
    "a task closed without proof does not travel",
  );
  assert.deepEqual(
    capsuleTask({
      id: "t5",
      title: "closed with proof",
      status: "completed",
      evidence: [proof.id],
    }).evidence,
    [proof.id],
    "a task closed with proof travels with it",
  );

  // The capsule of a scope.
  const pending = taskStore.add(scope, { title: "still open" });
  const blocked = taskStore.add(scope, { title: "waiting" });
  taskStore.block(scope, blocked.id, "the target refuses the connection");
  const closed = taskStore.add(scope, { title: "done" });
  taskStore.complete(scope, closed.id, [proof.id]);

  const value = capsule(taskStore, store, scope, "ses_ctx");
  const titles = value.tasks.map((task) => task.title);
  assert.ok(titles.includes("still open"), "the open task travels");
  assert.ok(
    titles.includes("waiting"),
    "the blocked task travels with its reason",
  );
  assert.ok(titles.includes("done"), "the closed task travels");
  assert.equal(value.open, 2, "the capsule counts what is still open");
  assert.equal(value.blocked, 1, "the capsule counts what is blocked");
  assert.ok(
    value.observations.some((item) => item.id === proof.id),
    "the proof of the closed task travels with it",
  );
  assert.match(capsuleText(value), /Continuity/, "the capsule is rendered");

  // The closing gate answers "are we done?" from the state.
  assert.equal(
    closingGate({
      scope,
      sessionID: "ses_ctx",
      tasks: [],
      open: 0,
      blocked: 0,
      observations: [],
    }),
    "",
    "a scope with nothing open has no gate",
  );
  const gated = closingGate(value);
  assert.match(gated, /^Closing gate\./, "the gate names itself");
  assert.match(gated, /step\(s\) still open/, "an open step is a blocker");
  assert.match(gated, /step\(s\) blocked/, "a blocked step is a blocker");
  const missionGate = closingGate({
    ...value,
    tasks: [],
    open: 0,
    blocked: 0,
    mission: {
      id: "mission-1",
      title: "Engagement",
      boundaries: "local",
      state: "ACTIVE",
      stages: [
        { id: "scope-validation", state: "COMPLETED" },
        { id: "recon", state: "PENDING" },
      ],
    },
  });
  assert.match(missionGate, /recon \(PENDING\)/, "an open stage is a blocker");
  assert.ok(
    !missionGate.includes("scope-validation"),
    "a closed stage is not a blocker",
  );
  const waiting = closingGate({
    ...value,
    tasks: [],
    open: 0,
    blocked: 0,
    approvals: [{ id: "a1", action: "write", justification: "needs a yes" }],
    processes: [{ id: "p1", command: "sleep 1", status: "running" }],
  });
  assert.match(waiting, /wait for the operator/, "a pending approval is a blocker");
  assert.match(waiting, /still owned/, "an owned command is a blocker");

  // A closed task whose proof is gone does not travel.
  const orphan = taskStore.add(scope, { title: "claimed without proof" });
  taskStore.complete(scope, orphan.id, [proof.id]);
  const tasks = JSON.parse(
    fs.readFileSync(path.join(state, `tasks-${scope}.json`), "utf8"),
  );
  const entry = tasks.find((task) => task.id === orphan.id);
  entry.evidence = ["obs-does-not-exist"];
  fs.writeFileSync(
    path.join(state, `tasks-${scope}.json`),
    JSON.stringify(tasks, null, 1),
  );
  const after = capsule(taskStore, store, scope, "ses_ctx");
  assert.ok(
    !after.tasks.some((task) => task.id === orphan.id),
    "a task whose proof cannot be resolved does not travel",
  );
  const failedProof = store.recordObservation({
    id: "obs-failed-proof", sessionId: "ses_ctx", scope, tool: "shell",
    input: {}, output: "command failed", success: false,
    timestamp: new Date().toISOString(),
  });
  const failedTask = taskStore.add(scope, { title: "closed with failed proof" });
  taskStore.complete(scope, failedTask.id, [failedProof.id]);
  assert.ok(
    !capsule(taskStore, store, scope, "ses_ctx").tasks.some((task) => task.id === failedTask.id),
    "a completed task backed only by failures does not travel",
  );
  const tooMany = taskStore.add(scope, { title: "too many proofs" });
  assert.throws(
    () => taskStore.complete(scope, tooMany.id, Array.from({ length: 21 }, (_, i) => `obs-${i}`)),
    /at most 20/,
    "proof ids are rejected before persistence instead of being truncated",
  );

  const corruptRoot = path.join(workspace, "corrupt-tasks");
  fs.mkdirSync(corruptRoot);
  const corruptStore = new TaskStore(corruptRoot);
  fs.writeFileSync(path.join(corruptRoot, `tasks-${scope}.json`), "{broken");
  assert.throws(
    () => corruptStore.add(scope, { title: "must not overwrite" }),
    /JSON/,
    "corrupt task state fails closed",
  );
  assert.equal(
    fs.readFileSync(path.join(corruptRoot, `tasks-${scope}.json`), "utf8"),
    "{broken",
    "corrupt task state remains available for recovery",
  );

  // The plugin injects the capsule, and the review is a tool.
  const fixture = makeContext(workspace);
  await plugin.setup(fixture.ctx);
  assert.ok(fixture.tools.has("cyber_review"), "the plugin exposes the review");

  const event = fixture.contextEvent({ sessionID: "ses_ctx" });
  await fixture.hooks.get("context")(event);
  const injected = event.system
    .map((block) => String(block.text ?? ""))
    .find((text) => text.startsWith("Continuity."));
  assert.ok(injected, "the capsule is injected in the prompt");
  assert.ok(
    injected.includes("still open"),
    "the injected capsule carries the running step list",
  );
  const injectedGate = event.system
    .map((block) => String(block.text ?? ""))
    .find((text) => text.startsWith("Closing gate."));
  assert.ok(injectedGate, "the closing gate is injected while work is open");
  assert.match(
    injectedGate,
    /step\(s\) still open/,
    "the gate names what still stands instead of leaving it to the model",
  );

  const { PlatformStore } = jiti(path.join(CORE, "src/platform-store.ts"));
  const platform = new PlatformStore(path.join(state, "platform.sqlite"), store);
  const mission = platform.createMission(scope, "Continuity mission", "Local fixtures only");
  const approval = platform.requestApproval(scope, mission.id, "Await operator", "Needs a decision", "test-agent");
  const chunks = platform.ingest(scope, "source-continuity", "file:///fixture.md", "Fixture reference", "Capsule reference body");
  platform.recall(scope, "ses_ctx", "turn-reference", "Capsule reference", 8000);
  const richEvent = fixture.contextEvent({ sessionID: "ses_ctx" });
  await fixture.hooks.get("context")(richEvent);
  const richText = richEvent.system.find((block) => block.text.startsWith("Continuity.")).text;
  const rich = JSON.parse(richText.slice(richText.indexOf("\n\n") + 2));
  assert.equal(rich.mission.id, mission.id, "the active mission travels");
  assert.equal(rich.mission.stages.length, 7, "all mission stages travel");
  assert.equal(rich.mission.state, "WAITING_APPROVAL", "a pending scope is never shown as approved");
  assert.ok(rich.approvals.some((entry) => entry.id === approval.id), "pending approvals travel");
  assert.ok(rich.references.some((entry) => chunks.some((chunk) => chunk.id === entry.id)), "recalled references travel");
  assert.ok(rich.references.every((entry) => entry.hash), "references retain their content hashes");
  platform.decideApproval(scope, approval.id, false, "operator");
  const decided = fixture.contextEvent({ sessionID: "ses_ctx" });
  await fixture.hooks.get("context")(decided);
  assert.ok(!decided.system.some((block) => block.text.includes(approval.id)), "decided approvals no longer wait in the capsule");
  const foreignDirectory = path.join(workspace, "foreign");
  fs.mkdirSync(foreignDirectory);
  fixture.sessions.set("ses_foreign", foreignDirectory);
  const foreign = fixture.contextEvent({ sessionID: "ses_foreign" });
  await fixture.hooks.get("context")(foreign);
  assert.ok(!foreign.system.some((block) => block.text.includes(mission.id)), "another scope cannot see the mission");
  assert.ok(!foreign.system.some((block) => chunks.some((chunk) => block.text.includes(chunk.id))), "another scope cannot see recalled references");
  const toolHook = fixture.hooks.get("execute.after");
  await toolHook({
    tool: "shell", sessionID: "ses_move", id: "call-before-move",
    input: { command: "echo before" }, status: "completed",
    result: { content: [{ type: "text", text: "before" }], metadata: { exit: 0 } },
  });
  const movedDirectory = path.join(workspace, "moved");
  fs.mkdirSync(movedDirectory);
  fixture.sessions.set("ses_move", movedDirectory);
  await toolHook({
    tool: "shell", sessionID: "ses_move", id: "call-after-move",
    input: { command: "echo after" }, status: "completed",
    result: { content: [{ type: "text", text: "after" }], metadata: { exit: 0 } },
  });
  assert.equal(
    store.evidence(scopeFor(movedDirectory), [observationId("ses_move", "call-after-move")]).length,
    1,
    "a moved session records new evidence in its current scope",
  );
  assert.match(capsuleText({ scope, sessionID: "ses_empty", tasks: [], open: 0, blocked: 0, observations: [], mission: rich.mission }), /Continuity mission/, "a mission-only capsule is not discarded");
  platform.close();

  // A review needs observations.
  const call = (input, sessionID = "ses_ctx") =>
    fixture.tools.get("cyber_review").execute(input, {
      sessionID,
      agent: "build",
      messageID: "msg_test",
      id: "call-review",
      progress: () => {},
      signal: new AbortController().signal,
    });
  await assert.rejects(
    () =>
      call({ action: "run", claim: "something happened" }, "ses_without_anything"),
    /needs an observation/,
    "a review without observation is refused",
  );

  // A review is checked by a model that has no tools and no session.
  fixture.answer.value = JSON.stringify({
    verdict: "confirmed",
    reason: "the observation shows it",
    evidence: [proof.id],
  });
  const callsBefore = fixture.generated.length;
  const verdict = JSON.parse(
    (await call({ action: "run", claim: "the command printed proved" })).content,
  );
  assert.equal(verdict.verdict, "confirmed", "the verdict is recorded");
  assert.deepEqual(verdict.evidence, [proof.id], "the verdict cites the proof");
  assert.equal(
    fixture.generated.length - callsBefore,
    1,
    "the verifier was called once for the review",
  );
  assert.match(
    fixture.generated[callsBefore].prompt,
    /the command printed proved/,
    "the verifier receives the claim",
  );
  assert.match(
    fixture.generated[0].prompt,
    new RegExp(proof.id),
    "the verifier receives the observations",
  );
  const reviews = store.reviews(scope, 10);
  assert.equal(reviews.length, 1, "the review is recorded in the store");
  assert.equal(reviews[0].status, "completed", "the review reached its end");

  // A confirmation that cites nothing is not a confirmation.
  fixture.answer.value = JSON.stringify({
    verdict: "confirmed",
    reason: "trust me",
    evidence: [],
  });
  const empty = JSON.parse(
    (await call({ action: "run", claim: "another claim" })).content,
  );
  assert.equal(empty.verdict, "unsupported", "a confirmation without a citation is not one");

  // A citation nobody provided is dropped.
  fixture.answer.value = JSON.stringify({
    verdict: "confirmed",
    reason: "trust me",
    evidence: ["obs-not-provided"],
  });
  const forged = JSON.parse(
    (await call({ action: "run", claim: "a third claim" })).content,
  );
  assert.deepEqual(forged.evidence, [], "a forged citation is dropped");
  assert.equal(forged.verdict, "unsupported", "a forged citation does not confirm");

  // The verifier: the free tier cannot serve a review, so the harness looks
  // for a model that accepts a direct call.
  const freeTier = fixture.contextEvent({
    sessionID: "ses_ctx",
    model: { providerID: "opencode", id: "beam-free" },
  });
  await fixture.hooks.get("context")(freeTier);
  const before = fixture.generated.length;
  await call({ action: "run", claim: "a fourth claim" });
  const used = fixture.generated[fixture.generated.length - 1].model;
  assert.equal(
    used.providerID,
    "Ed",
    "the harness picks a model that accepts a direct call",
  );
  assert.ok(fixture.generated.length > before, "the verifier was called again");

  // With no other provider, the review says so plainly.
  fixture.models = [{ providerID: "opencode", id: "beam-free" }];
  await assert.rejects(
    () => call({ action: "run", claim: "a fifth claim" }),
    /no model can serve the harness/,
    "the review says that no verifier is available",
  );

  store.close();
  fs.rmSync(workspace, { recursive: true, force: true });
};
