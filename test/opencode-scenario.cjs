/**
 * One synthetic engagement, end to end: a target, a read, a graph, a checklist,
 * a map, and the gate that refuses to call it finished.
 *
 * Nothing here is a demo of the model: it is the host contract a real session
 * has to follow, replayed without a model so a regression fails the suite.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-scenario-"));
  const state = path.join(workspace, "state");
  const engagement = path.join(workspace, "engagement");
  fs.mkdirSync(state, { recursive: true });
  fs.mkdirSync(engagement, { recursive: true });
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;
  process.env.HARNESS_CAPTURE_TERMINAL = "off";
  const fixture = makeContext(workspace);
  const unload = await jiti(path.join(CORE, "opencode", "plugin.ts")).default.setup(
    fixture.ctx,
  );
  const context = {
    sessionID: "ses_scenario",
    agent: "build",
    messageID: "msg_scenario",
    id: "call_scenario",
    progress: () => {},
    signal: new AbortController().signal,
  };
  const call = async (name, input, id = "call_scenario") =>
    JSON.parse(
      (
        await fixture.tools
          .get(name)
          .execute(input, { ...context, id })
      ).content,
    );
  const { ProcessRegistry, processStatus } = jiti(
    path.join(CORE, "src", "process.ts"),
  );
  const registry = new ProcessRegistry(state);
  const until = async (predicate) => {
    const end = Date.now() + 8000;
    while (!predicate() && Date.now() < end)
      await new Promise((resolve) => setTimeout(resolve, 30));
    assert.ok(predicate(), "process reached the expected state");
  };
  try {
    const mission = await call("cyber_mission", {
      action: "create",
      title: "Scenario bank.test",
      boundaries: "Fixture locale uniquement.",
      root: engagement,
    });
    assert.ok(
      ["PENDING", "WAITING_APPROVAL"].includes(mission.state),
      "the mission starts unapproved",
    );

    const ran = await call(
      "cyber_process",
      {
        action: "run",
        argv: [process.execPath, "-e", "console.log('HTTP/1.1 200 OK')"],
        timeout: 10,
      },
      "call-run",
    );
    await until(() =>
      ["succeeded", "failed", "timed_out", "stopped"].includes(
        processStatus(registry.get(ran.scope, ran.id)),
      ),
    );
    const rawRead = await fixture.tools
      .get("cyber_process")
      .execute({ action: "read", id: ran.id }, { ...context, id: "call-read" });
    const read = JSON.parse(rawRead.content);
    await fixture.hooks.get("execute.after")({
      tool: "cyber_process",
      sessionID: context.sessionID,
      id: "call-read",
      input: { action: "read", id: ran.id },
      status: "completed",
      result: rawRead,
    });
    assert.equal(read.status, "succeeded", "the read is the proof");
    assert.match(read.trace, /200 OK/);

    const host = await call("cyber_entity", {
      action: "upsert",
      type: "host",
      key: "www.bank.test",
      observationIds: [read.observationId],
    });
    const domain = await call("cyber_entity", {
      action: "upsert",
      type: "domain",
      key: "bank.test",
      observationIds: [read.observationId],
    });
    await call("cyber_entity", {
      action: "relate",
      from: host.id,
      to: domain.id,
      kind: "resolves-to",
      observationIds: [read.observationId],
    });
    const pivot = await call("cyber_entity", {
      action: "path",
      from: host.id,
      to: domain.id,
    });
    assert.equal(pivot.relations.length, 1, "the graph answers the pivot");

    const planted = await call("cyber_tasks", { action: "assets" });
    assert.equal(planted.assets, 2, "the host and the domain are two assets");
    const tree = await call("cyber_tasks", { action: "tree" });
    const branch = tree.find((node) =>
      node.title.startsWith("host:www.bank.test"),
    );
    assert.ok(branch, "the asset is a branch");
    assert.equal(branch.children.length, 6, "a host grows its own six steps");
    await call("cyber_tasks", {
      action: "complete",
      id: branch.children[0].id,
      evidence: [read.observationId],
    });
    const after = await call("cyber_tasks", { action: "tree" });
    assert.equal(
      after.find((node) => node.title.startsWith("host:")).children[0].status,
      "completed",
      "a branch closes only with its observation",
    );

    const exported = await call("cyber_tasks", { action: "export" });
    const map = fs.readFileSync(exported.path, "utf8");
    assert.match(map, /host:www\.bank\.test/, "the map lists the branch");
    assert.match(map, /- \[x\] /, "the closed step is marked");

    const event = fixture.contextEvent({ sessionID: context.sessionID });
    await fixture.hooks.get("context")(event);
    const gate = event.system.map((block) => String(block.text)).join("\n");
    assert.match(gate, /Closing gate/, "the gate speaks");
    assert.match(gate, /engagement .* is [A-Z_]+/, "an open mission blocks");
  } finally {
    if (typeof unload === "function") unload();
    fs.rmSync(workspace, { recursive: true, force: true });
  }
};
