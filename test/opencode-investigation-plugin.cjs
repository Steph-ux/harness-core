/**
 * The investigation engine, wired into the host.
 *
 * A pure engine that nothing calls is inert. These checks prove the plugin
 * registers the tool, the tool enforces the proof discipline, and the context
 * hook injects a mandatory directive when the observation stream shows a loop
 * or a premature conclusion — and stays silent when the work progresses.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext, loadPlugin, unloadPlugins } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");
const PLUGIN = path.join(CORE, "opencode", "plugin.ts");

module.exports = async ({ assert, jiti }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-inv-plugin-"));
  const state = path.join(workspace, "state");
  fs.mkdirSync(state, { recursive: true });
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;

  const plugin = jiti(PLUGIN).default;
  const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
  const { scopeFor } = jiti(path.join(CORE, "src", "util.ts"));

  const store = new KnowledgeStore(path.join(state, "knowledge.sqlite"));
  const scope = scopeFor(workspace);

  const { ctx, hooks, tools } = makeContext(workspace);
  await loadPlugin(plugin, ctx);
  const onContext = hooks.get("context");

  // The tool is registered.
  assert.ok(tools.has("cyber_investigation"), "the investigation tool is registered");
  const inv = tools.get("cyber_investigation");
  const call = (input, sessionID = "ses_inv_loop") =>
    inv.execute(input, { sessionID });
  const parse = (result) => JSON.parse(result.content);

  // Hypothesis lifecycle through the tool.
  const proposed = parse(await call({ action: "hypothesis", op: "propose", id: "H1", text: "SQLi on login" }));
  assert.equal(proposed.state, "proposed", "the tool proposes a hypothesis");
  const testing = parse(await call({ action: "hypothesis", op: "test", id: "H1" }));
  assert.equal(testing.state, "testing", "the tool starts testing");

  // A successful observation is a reproduction, not a confirmation.
  store.upsertSession({ id: "ses_inv_loop", scope, cwd: workspace, status: "active", updatedAt: new Date().toISOString() });
  const goodObs = store.recordObservation({
    id: "obs-inv-good", sessionId: "ses_inv_loop", scope, tool: "sqlmap",
    input: {}, output: "injectable", success: true, timestamp: new Date().toISOString(),
  });
  const controlObs = store.recordObservation({
    id: "obs-inv-ctrl", sessionId: "ses_inv_loop", scope, tool: "sqlmap",
    input: {}, output: "not injectable", success: true, timestamp: new Date().toISOString(),
  });
  const replayObs = store.recordObservation({
    id: "obs-inv-replay", sessionId: "ses_inv_loop", scope, tool: "sqlmap",
    input: {}, output: "injectable", success: true, timestamp: new Date().toISOString(),
  });
  const badObs = store.recordObservation({
    id: "obs-inv-bad", sessionId: "ses_inv_loop", scope, tool: "sqlmap",
    input: {}, output: "error", success: false, timestamp: new Date().toISOString(),
  });
  await assert.rejects(
    call({ action: "hypothesis", op: "evidence", id: "H1", observationId: badObs.id }),
    /successful observation/,
    "a failed observation cannot be a reproduction",
  );
  const reproduced = parse(await call({ action: "hypothesis", op: "evidence", id: "H1", observationId: goodObs.id }));
  assert.equal(reproduced.state, "testing", "a successful observation does not confirm through the tool");
  await assert.rejects(
    call({ action: "hypothesis", op: "control", id: "H1", observationId: goodObs.id }),
    /cannot be the reproduction/,
    "the tool refuses a control that is the reproduction",
  );
  await assert.rejects(
    call({ action: "hypothesis", op: "control", id: "H1", observationId: replayObs.id }),
    /different output/,
    "the tool refuses a control that observes the same output",
  );
  await assert.rejects(
    call({ action: "hypothesis", op: "control", id: "H1", observationId: badObs.id }),
    /successful observation/,
    "a failed observation cannot be a negative control",
  );
  const confirmed = parse(await call({ action: "hypothesis", op: "control", id: "H1", observationId: controlObs.id }));
  assert.equal(confirmed.state, "confirmed", "reproduction plus a distinct control confirms through the tool");

  // Surface coverage through the tool, with the proof discipline.
  await call({ action: "surface", op: "add", id: "auth", label: "Authentication" });
  await call({ action: "surface", op: "add", id: "sqli", label: "SQL injection" });
  await call({ action: "surface", op: "add", id: "xss", label: "XSS" });
  await assert.rejects(
    call({ action: "surface", op: "complete", id: "auth", evidence: [] }),
    /observation ids/,
    "a surface cannot be tested without evidence",
  );
  await call({ action: "surface", op: "start", id: "auth" });
  await call({ action: "surface", op: "complete", id: "auth", evidence: [goodObs.id] });
  await call({ action: "surface", op: "block", id: "xss", reason: "WAF blocks probes" });
  const cov = parse(await call({ action: "surface", op: "list" }));
  assert.equal(cov.tested, 1, "the tool reports tested surfaces");
  assert.equal(cov.blocked, 1, "the tool reports blocked surfaces");
  assert.equal(cov.untested, 1, "the tool reports untested surfaces");

  // --- The context hook injects a directive on a tool loop -----------------

  // Five nmap calls in a row: the observation stream is a loop.
  for (let i = 0; i < 5; i++) {
    store.recordObservation({
      id: `obs-inv-loop-${i}`, sessionId: "ses_inv_loop", scope, tool: "nmap",
      input: { command: "nmap target" }, output: `scan ${i}`, success: true,
      timestamp: new Date(Date.now() - (5 - i) * 1000).toISOString(),
    });
  }
  // An open task so the work is visibly unfinished.
  const tasksTool = tools.get("cyber_tasks");
  await tasksTool.execute({ action: "add", title: "Enumerate the target" }, { sessionID: "ses_inv_loop" });

  const loopEvent = makeContext(workspace).contextEvent({ sessionID: "ses_inv_loop" });
  await onContext(loopEvent);
  const invBlock = loopEvent.system.find(
    (b) => typeof b.text === "string" && b.text.startsWith("Investigation directives."),
  );
  assert.ok(invBlock, "a looping session receives an investigation block");
  assert.match(invBlock.text, /\[MANDATORY\].*STAGNATION/, "the loop is a mandatory directive");

  // The block is not injected twice on the same event.
  await onContext(loopEvent);
  const count = loopEvent.system.filter(
    (b) => typeof b.text === "string" && b.text.startsWith("Investigation directives."),
  ).length;
  assert.equal(count, 1, "the investigation block appears once");

  // --- A healthy session stays silent --------------------------------------

  store.upsertSession({ id: "ses_inv_ok", scope, cwd: workspace, status: "active", updatedAt: new Date().toISOString() });
  const okTools = ["nmap", "curl", "sqlmap"];
  okTools.forEach((tool, i) => {
    store.recordObservation({
      id: `obs-inv-ok-${i}`, sessionId: "ses_inv_ok", scope, tool,
      input: {}, output: `result ${i}`, success: true,
      timestamp: new Date(Date.now() - (3 - i) * 1000).toISOString(),
    });
  });
  const okEvent = makeContext(workspace).contextEvent({ sessionID: "ses_inv_ok" });
  await onContext(okEvent);
  // Coverage is shared per scope, so the untested-surface nudge may fire; the
  // point is that no MANDATORY stagnation directive fires on a healthy stream.
  const okBlock = okEvent.system.find(
    (b) => typeof b.text === "string" && b.text.startsWith("Investigation directives."),
  );
  if (okBlock) {
    assert.ok(
      !/\[MANDATORY\].*STAGNATION/.test(okBlock.text),
      "a healthy stream produces no mandatory stagnation directive",
    );
  }

  // --- status action returns the assembled directives ----------------------

  const status = parse(await call({ action: "status" }));
  assert.ok(Array.isArray(status.directives), "status returns directives");
  assert.ok(status.coverage.total >= 3, "status returns the coverage map");
  assert.ok(
    status.directives.some((d) => d.priority === "mandatory"),
    "the looping session status carries a mandatory directive",
  );

  // --- Task-tree fallback: no declared surfaces, coverage from tasks -------

  // A scope with tasks but no surfaces: the tool still reports coverage.
  // Add root tasks with known evidence.
  await tasksTool.execute({ action: "add", title: "Recon target ports" }, { sessionID: "ses_inv_loop" });
  await tasksTool.execute({ action: "add", title: "Test authentication" }, { sessionID: "ses_inv_loop" });
  const taskList = parse(await tasksTool.execute({ action: "list" }, { sessionID: "ses_inv_loop" }));
  // The first root task we added ("Enumerate the target") plus the two new ones = 3 root tasks.
  const rootTasks = taskList.tasks.filter((t) => !t.parentId);
  assert.ok(rootTasks.length >= 3, "there are at least 3 root tasks");

  // Complete one with evidence so it counts as tested.
  const toComplete = rootTasks.find((t) => t.title === "Recon target ports");
  await tasksTool.execute(
    { action: "complete", id: toComplete.id, evidence: [goodObs.id] },
    { sessionID: "ses_inv_loop" },
  );

  // The surface list should derive from the task tree (no explicit surfaces were added in this new scope... wait, we did add some above in the same scope).
  // Instead, test via status which uses the same fallback: the coverage.total should reflect tasks.
  // Actually, we DID add explicit surfaces (auth, sqli, xss) above. So the fallback won't fire for this scope.
  // Create a fresh scope to test the fallback cleanly.
  const ws2 = fs.mkdtempSync(path.join(os.tmpdir(), "harness-inv-fallback-"));
  const state2 = path.join(ws2, "state");
  fs.mkdirSync(state2, { recursive: true });
  process.env.HARNESS_STATE_ROOT = state2;

  const { ctx: ctx2, hooks: hooks2, tools: tools2 } = makeContext(ws2);
  await loadPlugin(plugin, ctx2);
  const tasksTool2 = tools2.get("cyber_tasks");
  const inv2 = tools2.get("cyber_investigation");
  const call2 = (input) => inv2.execute(input, { sessionID: "ses_fallback" });

  const store2b = new KnowledgeStore(path.join(state2, "knowledge.sqlite"));
  const scope2 = scopeFor(ws2);
  store2b.upsertSession({ id: "ses_fallback", scope: scope2, cwd: ws2, status: "active", updatedAt: new Date().toISOString() });
  const fbObs = store2b.recordObservation({
    id: "obs-fb-1", sessionId: "ses_fallback", scope: scope2, tool: "nmap",
    input: {}, output: "open ports", success: true, timestamp: new Date().toISOString(),
  });

  // Add tasks (no surfaces declared).
  await tasksTool2.execute({ action: "add", title: "Port scan" }, { sessionID: "ses_fallback" });
  await tasksTool2.execute({ action: "add", title: "Service fingerprint" }, { sessionID: "ses_fallback" });
  const tl2 = parse(await tasksTool2.execute({ action: "list" }, { sessionID: "ses_fallback" }));
  const portTask = tl2.tasks.find((t) => t.title === "Port scan");
  await tasksTool2.execute(
    { action: "complete", id: portTask.id, evidence: [fbObs.id] },
    { sessionID: "ses_fallback" },
  );

  // surface list should derive 2 surfaces from the 2 root tasks.
  const fbCov = parse(await call2({ action: "surface", op: "list" }));
  assert.equal(fbCov.total, 2, "fallback coverage derives surfaces from root tasks");
  assert.equal(fbCov.tested, 1, "one task completed with evidence is tested");
  assert.equal(fbCov.untested, 1, "one open task is untested");

  // status also uses the fallback.
  const fbStatus = parse(await call2({ action: "status" }));
  assert.equal(fbStatus.coverage.total, 2, "status fallback also shows task-derived coverage");

  store2b.close();
  await unloadPlugins();
  fs.rmSync(ws2, { recursive: true, force: true });

  store.close();
  fs.rmSync(workspace, { recursive: true, force: true });
};
