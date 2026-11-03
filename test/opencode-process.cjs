const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { makeContext } = require("./opencode-fixture.cjs");
const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti, modules }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-process-"));
  const state = path.join(workspace, "state");
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;
  const { ProcessRegistry, spawnTraced, readTrace, processStatus } = jiti(path.join(CORE, "src/process.ts"));
  const registry = new ProcessRegistry(state);
  const { KnowledgeStore } = jiti(path.join(CORE, "src/store.ts"));
  const { observationId } = jiti(path.join(CORE, "src/observation-id.ts"));
  const fixture = makeContext(workspace);
  const { default: plugin, assertOperatorDecision, assertProcessPermission } = jiti(path.join(CORE, "opencode/plugin.ts"));
  await plugin.setup(fixture.ctx);
  const context = { sessionID: "ses_process", agent: "build", messageID: "msg_process", id: "call_process", signal: new AbortController().signal };
  const call = async (input, sessionID = context.sessionID) => JSON.parse((await fixture.tools.get("cyber_process").execute(input, { ...context, sessionID })).content);
  const until = async (predicate) => {
    const end = Date.now() + 5000;
    while (!predicate() && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 30));
    assert.ok(predicate(), "process reached the expected state");
  };
  try {
    assert.ok(fixture.tools.has("cyber_process"));
    let deliver;
    const oldApi = {
      permission: {},
      event: { subscribe: async function* ({ signal }) {
        while (!signal.aborted) {
          const event = await new Promise((resolve) => {
            deliver = resolve;
            signal.addEventListener("abort", () => resolve(null), { once: true });
          });
          if (event) yield event;
        }
      } },
    };
    const permissionRequest = (effect, reply) => async (args) => {
      if (args[0] === "get") return { pid: process.pid };
      const input = JSON.parse(args[3]);
      assert.equal(input.action, "shell");
      assert.deepEqual(input.resources, ["echo permitted"]);
      if (reply) deliver({ type: "permission.replied", data: { sessionID: context.sessionID, requestID: input.id, reply } });
      return { data: { id: input.id, effect } };
    };
    await assertProcessPermission(oldApi, context, "echo permitted", permissionRequest("allow"));
    await assert.rejects(() => assertProcessPermission(oldApi, context, "echo permitted", permissionRequest("deny")), /denied/);
    await assertProcessPermission(oldApi, context, "echo permitted", permissionRequest("ask", "once"));
    await assert.rejects(() => assertProcessPermission(oldApi, context, "echo permitted", permissionRequest("ask", "reject")), /rejected/);
    await assert.rejects(() => assertProcessPermission(oldApi, context, "echo permitted", async () => ({ pid: -1 })), /another server/);
    const explicitApi = { permission: {}, event: oldApi.event };
    const operatorRequest = (effect, reply) => async (args) => {
      if (args[0] === "get") return { pid: process.pid };
      const input = JSON.parse(args[3]);
      assert.equal(input.action, "harness_operator");
      if (reply) deliver({ type: "permission.replied", data: { sessionID: context.sessionID, requestID: input.id, reply } });
      return { data: { id: input.id, effect } };
    };
    await assertOperatorDecision(explicitApi, context, "approve:test", operatorRequest("ask", "once"));
    await assert.rejects(
      () => assertOperatorDecision(explicitApi, context, "approve:test", operatorRequest("allow")),
      /configured as ask/,
    );
    await assert.rejects(
      () => assertOperatorDecision(explicitApi, context, "approve:test", operatorRequest("ask", "always")),
      /approve this transition once/,
    );
    await assert.rejects(() => call({ action: "unknown" }), /Invalid process action/);
    await assert.rejects(() => call({ action: "run", argv: ["true"], timeout: 601 }), /Invalid timeout/);
    fixture.ctx.permission.assert = async () => { throw new Error("denied"); };
    await assert.rejects(() => call({ action: "run", argv: ["touch", "forbidden"] }), /denied/);
    assert.equal(fs.existsSync(path.join(workspace, "forbidden")), false);
    fixture.ctx.permission.assert = async () => {};
    const moved = path.join(workspace, "moved");
    fs.mkdirSync(moved);
    fixture.sessions.set("ses_process", moved);
    const record = await call({
      action: "run",
      argv: [process.execPath, "-e", "console.log(process.cwd()); console.log('api_key=not-a-real-secret'); setTimeout(()=>{}, 10000)"],
      timeout: 2,
    });
    assert.equal(record.cwd, moved, "the session directory is authoritative");
    await until(() => readTrace(record.logPath).includes(moved));
    assert.match((await call({ action: "read", id: record.id })).trace, /api_key=<REDACTED>/);
    await fixture.hooks.get("execute.after")({
      tool: "cyber_process", sessionID: "ses_process", id: "call-process-read",
      input: { action: "read", id: record.id }, status: "completed",
      result: { content: JSON.stringify(await call({ action: "read", id: record.id })) },
    });
    const proof = new KnowledgeStore(path.join(state, "knowledge.sqlite"));
    assert.equal(
      proof.evidence(record.scope, [observationId("ses_process", "call-process-read")]).length,
      1,
      "operational harness tools leave observations",
    );
    proof.close();
    assert.equal(fs.statSync(record.logPath).mode & 0o777, 0o600);
    const recovered = new ProcessRegistry(state);
    assert.equal(recovered.get(record.scope, record.id).pid, record.pid);
    await assert.rejects(() => call({ action: "read", id: record.id }, "ses_other"), /Unknown process/);
    await assert.rejects(() => call({ action: "read", id: record.id, tail: -1 }), /Invalid trace tail/);
    const event = fixture.contextEvent({ sessionID: "ses_process" });
    await fixture.hooks.get("context")(event);
    assert.ok(event.system.some((block) => block.text.includes(record.id)), "running commands travel in the capsule");
    await call({ action: "stop", id: record.id });
    await until(() => processStatus(recovered.get(record.scope, record.id)) === "finished");

    // An entirely separate host exits before its command's deadline.
    const launcher = path.join(workspace, "launcher.cjs");
    fs.writeFileSync(launcher, `
      const {createJiti} = require(${JSON.stringify(path.join(modules, "jiti"))});
      const jiti = createJiti(__filename);
      const {ProcessRegistry,spawnTraced} = jiti(${JSON.stringify(path.join(CORE, "src/process.ts"))});
      const registry = new ProcessRegistry(${JSON.stringify(state)});
      const record = registry.prepare("crash-scope","ses_crash","trap '' TERM; echo survived; sleep 20",${JSON.stringify(workspace)},900);
      const started = spawnTraced(record.command,{cwd:record.cwd,logPath:record.logPath,deadlineMs:record.deadlineMs});
      const stored = registry.add({...record,pid:started.pid});
      console.log(JSON.stringify(stored));
      process.exit(0);
    `);
    const launched = spawnSync(process.execPath, [launcher], { encoding: "utf8", timeout: 5000 });
    assert.equal(launched.status, 0, launched.stderr);
    const orphan = JSON.parse(launched.stdout.trim());
    assert.equal(processStatus(orphan), "running", "the command survives the host exit");
    await until(() => processStatus(orphan) === "finished");
    assert.match(readTrace(orphan.logPath), /survived/);
    assert.equal(new ProcessRegistry(state).get("crash-scope", orphan.id).id, orphan.id);
    const fake = { ...orphan, pid: process.pid, identity: "old-boot:old-pid" };
    registry.add(fake);
    // Simulate a stale record instead of allowing add() to refresh its identity.
    const records = JSON.parse(fs.readFileSync(path.join(state, "processes.json")));
    records.find((entry) => entry.id === orphan.id).identity = "old-boot:old-pid";
    fs.writeFileSync(path.join(state, "processes.json"), JSON.stringify(records));
    registry.stop("crash-scope", orphan.id);
    assert.equal(processStatus(fake), "finished", "a reused pid is not treated as the old command");
    assert.throws(() => registry.tracePath("../../escape"), /Invalid process id/);
    const large = path.join(workspace, "large.log");
    fs.writeFileSync(large, "x".repeat(500000) + "\nlast-line\n");
    assert.match(readTrace(large, 2), /last-line/);
    assert.ok(readTrace(large).length <= 24000);
  } finally {
    const file = path.join(state, "processes.json");
    for (const record of fs.existsSync(file) ? JSON.parse(fs.readFileSync(file)) : []) {
      registry.stop(record.scope, record.id);
    }
    fs.rmSync(workspace, { recursive: true, force: true });
  }
};
