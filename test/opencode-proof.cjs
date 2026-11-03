/**
 * The proof layer on the OpenCode surface.
 *
 * The plugin is driven directly, without a model, so the guarantees are
 * checked as behaviour and not as narration:
 *
 *  - a tool call leaves an immutable observation;
 *  - a task closes only against a successful observation;
 *  - the store is the one the Pi harness writes to, not a copy of it.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");
const PLUGIN = path.join(CORE, "opencode", "plugin.ts");

/** A tool event shaped like the one the host delivers after a tool call. */
function toolEvent(overrides) {
  return {
    tool: "shell",
    sessionID: "ses_test_0001",
    agent: "build",
    messageID: "msg_test_0001",
    id: "call-0001",
    input: { command: "echo proof" },
    status: "completed",
    result: {
      output: { exit: 0, truncated: false, output: "proof\n", status: "completed" },
      content: [{ type: "text", text: "proof\n" }],
      metadata: { status: "completed", truncated: false, exit: 0 },
    },
    ...overrides,
  };
}

module.exports = async ({ assert, jiti }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-opencode-"));
  const state = path.join(workspace, "state");
  fs.mkdirSync(state, { recursive: true });
  // The plugin reads its locations when it is loaded, so they are set first.
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;

  const plugin = jiti(PLUGIN).default;
  assert.ok(plugin, "the OpenCode adapter exports a plugin definition");
  assert.equal(plugin.id, "harness-core.proof", "the plugin declares its identity");
  assert.equal(typeof plugin.setup, "function", "the plugin declares a setup");

  const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
  const { TaskStore } = jiti(path.join(CORE, "src", "tasks.ts"));
  const { observationId } = jiti(path.join(CORE, "src", "observation-id.ts"));
  const { scopeFor } = jiti(path.join(CORE, "src", "util.ts"));

  const { ctx, hooks, tools } = makeContext(workspace);
  await plugin.setup(ctx);

  // The proof surface exists on this host.
  assert.ok(hooks.has("execute.after"), "the plugin hooks tool execution");
  assert.ok(tools.has("cyber_tasks"), "the plugin exposes the task list");
  assert.ok(tools.has("cyber_memory"), "the plugin exposes the memory store");

  const store = new KnowledgeStore(path.join(state, "knowledge.sqlite"));
  const taskStore = new TaskStore(state);
  const scope = scopeFor(workspace);
  const after = hooks.get("execute.after");
  const call = (name, input) =>
    tools.get(name).execute(input, {
      sessionID: "ses_test_0001",
      agent: "build",
      messageID: "msg_test_0001",
      id: "call-tool",
      progress: () => {},
      signal: new AbortController().signal,
    });

  // A tool call leaves an observation.
  await after(toolEvent({}));
  const id = observationId("ses_test_0001", "call-0001");
  const [observation] = store.evidence(scope, [id]);
  assert.ok(observation, "the tool call left an observation");
  assert.equal(observation.tool, "shell", "the observation names the tool");
  assert.equal(observation.success, true, "a clean call is a success");
  assert.equal(observation.output.trim(), "proof", "the observation holds the output");
  assert.ok(observation.hash.length === 64, "the observation carries a content digest");

  // A call that failed is not a success.
  await after(
    toolEvent({
      id: "call-0002",
      status: "error",
      result: undefined,
      error: { message: "tool exploded" },
    }),
  );
  const [failed] = store.evidence(scope, [
    observationId("ses_test_0001", "call-0002"),
  ]);
  assert.equal(failed.success, false, "a failed call is not a success");
  assert.match(failed.output, /tool exploded/, "the failure is kept as evidence");

  // A command that exits non zero is a failure, like on the Pi host.
  await after(
    toolEvent({
      id: "call-0003",
      result: {
        output: { exit: 2, truncated: false, output: "boom\n", status: "completed" },
        content: [
          { type: "text", text: "boom\n" },
          { type: "text", text: "Exited with code 2" },
        ],
        metadata: { status: "completed", truncated: false, exit: 2 },
      },
    }),
  );
  const [nonZero] = store.evidence(scope, [
    observationId("ses_test_0001", "call-0003"),
  ]);
  assert.equal(nonZero.success, false, "a non zero exit is a failure");

  // The harness does not testify for itself.
  await after(toolEvent({ tool: "cyber_tasks", id: "call-0004" }));
  assert.throws(
    () => store.evidence(scope, [observationId("ses_test_0001", "call-0004")]),
    /Missing evidence/,
    "the harness own tools are not evidence",
  );

  // A task cannot close on narration.
  const task = taskStore.add(scope, { title: "prove the surface" });
  await assert.rejects(
    () => call("cyber_tasks", { action: "complete", id: task.id }),
    /requires the observation ids/,
    "a task cannot close without evidence",
  );
  await assert.rejects(
    () =>
      call("cyber_tasks", {
        action: "complete",
        id: task.id,
        evidence: ["obs-00000000000000000000000000000000"],
      }),
    /Missing evidence/,
    "a task cannot close on an unknown observation",
  );
  await assert.rejects(
    () =>
      call("cyber_tasks", {
        action: "complete",
        id: task.id,
        evidence: [observationId("ses_test_0001", "call-0003")],
      }),
    /successful observation/,
    "a task cannot close on a failed observation",
  );
  assert.equal(
    taskStore.get(scope, task.id).status,
    "pending",
    "the task is still open after the refused attempts",
  );

  // A task closes against a successful observation.
  await call("cyber_tasks", {
    action: "complete",
    id: task.id,
    evidence: [id],
  });
  const closed = taskStore.get(scope, task.id);
  assert.equal(closed.status, "completed", "the task closed on real evidence");
  assert.deepEqual(closed.evidence, [id], "the task keeps the proof that closed it");

  // An observation cannot be rewritten.
  store.recordObservation({
    id,
    sessionId: "ses_test_0001",
    scope,
    tool: "shell",
    input: { command: "echo proof" },
    output: "proof\n",
    success: true,
    timestamp: new Date().toISOString(),
  });
  const [same] = store.evidence(scope, [id]);
  assert.equal(same.hash, observation.hash, "a replay of the same call is idempotent");
  assert.throws(
    () =>
      store.recordObservation({
        id,
        sessionId: "ses_test_0001",
        scope,
        tool: "shell",
        input: { command: "echo proof" },
        output: "a different result",
        success: true,
        timestamp: new Date().toISOString(),
      }),
    /Immutable observation collision/,
    "an observation cannot be rewritten",
  );
  const [afterAttempt] = store.evidence(scope, [id]);
  assert.equal(afterAttempt.output, observation.output, "the refused rewrite changed nothing");
  assert.equal(afterAttempt.hash, observation.hash, "the digest is untouched");

  // The memory surface reads the same store and states the operator rules.
  const rules = JSON.parse((await call("cyber_memory", { action: "operator" })).content);
  assert.ok(Array.isArray(rules), "the operator model is readable");
  await call("cyber_memory", {
    action: "remember",
    key: "proof-test",
    content: "A fact stated for the test",
    stated: "the operator said so",
  });
  const withRule = JSON.parse((await call("cyber_memory", { action: "operator" })).content);
  assert.equal(
    withRule.filter((rule) => rule.key === "proof-test").length,
    1,
    "a stated rule is recorded",
  );
  await call("cyber_memory", { action: "forget", key: "proof-test", stated: "remove the fixture rule" });
  const withoutRule = JSON.parse(
    (await call("cyber_memory", { action: "operator" })).content,
  );
  assert.equal(
    withoutRule.filter((rule) => rule.key === "proof-test").length,
    0,
    "a retracted rule is gone",
  );
  const getSession = ctx.session.get;
  ctx.session.get = async () => { throw new Error("lookup failed"); };
  await assert.rejects(
    () => call("cyber_memory", { action: "operator" }),
    /lookup failed/,
    "a failed session lookup cannot fall back to another project scope",
  );
  ctx.session.get = getSession;

  // The store is shared, not a copy: another handle on the same file sees it.
  const second = new KnowledgeStore(path.join(state, "knowledge.sqlite"));
  assert.equal(
    second.evidence(scope, [id]).length,
    1,
    "a second handle on the same file sees the observation",
  );

  // The scope of the harness workspace is the one the operator already uses,
  // so evidence collected by either host belongs to the same workspace.
  assert.equal(
    scopeFor("/home/moon/hacking"),
    "project-b8395f87f74add1a470b73af",
    "the harness workspace keeps its historical scope",
  );
  const shared = makeContext("/home/moon/hacking", "/home/moon/hacking");
  await plugin.setup(shared.ctx);
  await shared.hooks.get("execute.after")(
    toolEvent({ sessionID: "ses_test_scope", id: "call-scope" }),
  );
  const operatorScope = scopeFor("/home/moon/hacking");
  assert.equal(
    store.evidence(operatorScope, [
      observationId("ses_test_scope", "call-scope"),
    ]).length,
    1,
    "a session in the harness workspace lands in the operator scope",
  );

  store.close();
  fs.rmSync(workspace, { recursive: true, force: true });
};
