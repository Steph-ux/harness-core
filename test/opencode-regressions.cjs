/** Synthetic regression cases for proof, scope, redaction and concurrent updates. */
const fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path"),
  { spawn } = require("node:child_process");
const { makeContext } = require("./opencode-fixture.cjs");
module.exports = async ({ assert, jiti, modules }) => {
  const root = path.resolve(__dirname, ".."),
    work = fs.mkdtempSync(path.join(os.tmpdir(), "harness-regressions-")),
    state = path.join(work, "state");
  fs.mkdirSync(state);
  process.env.HARNESS_CORE = root;
  process.env.HARNESS_STATE_ROOT = state;
  const { scopeFor, redactText, hash } = jiti(path.join(root, "src/util.ts")),
    { KnowledgeStore } = jiti(path.join(root, "src/store.ts")),
    { TaskStore } = jiti(path.join(root, "src/tasks.ts")),
    { ProcessRegistry, processStatus, verifiedOutcome } = jiti(
      path.join(root, "src/process.ts"),
    ),
    { observationId } = jiti(path.join(root, "src/observation-id.ts")),
    { requestText } = jiti(path.join(root, "src/routing.ts"));
  const fixture = makeContext(work),
    unload = await jiti(path.join(root, "opencode/plugin.ts")).default.setup(
      fixture.ctx,
    ),
    store = new KnowledgeStore(path.join(state, "knowledge.sqlite")),
    scope = scopeFor(work),
    tasks = new TaskStore(state),
    registry = new ProcessRegistry(state);
  const c = (id) => ({
    sessionID: "ses_regression",
    agent: "build",
    messageID: "msg_regression",
    id,
    signal: new AbortController().signal,
  });
  const call = (name, input, id = "call") =>
    fixture.tools.get(name).execute(input, c(id));
  const until = async (fn) => {
    const end = Date.now() + 8000;
    while (!fn() && Date.now() < end)
      await new Promise((r) => setTimeout(r, 30));
    assert.ok(fn(), "terminal result available");
  };
  try {
    assert.equal(
      requestText({ prompt: { text: "Texte natif" } }),
      "Texte natif",
    );
    assert.equal(
      requestText({
        prompt: { parts: [{ type: "text", text: "Pièce de texte" }] },
      }),
      "Pièce de texte",
    );
    const safe = redactText(
      '{"password":"SECRET_A","motdepasse":"SECRET_B","access_token":"SECRET_C"}\nCookie: sid=SECRET_D; auth=SECRET_E\nSet-Cookie: sid=SECRET_F',
    );
    for (const secret of [
      "SECRET_A",
      "SECRET_B",
      "SECRET_C",
      "SECRET_D",
      "SECRET_E",
      "SECRET_F",
    ])
      assert.ok(!safe.includes(secret));
    store.upsertSession({
      id: "ses_regression",
      scope,
      cwd: work,
      status: "active",
      updatedAt: new Date().toISOString(),
    });
    const policyEvidence = store.recordObservation({
      id: "obs-policy",
      sessionId: "ses_regression",
      scope,
      tool: "shell",
      input: {},
      output: "synthetic policy evidence",
      success: true,
      timestamp: new Date().toISOString(),
    });
    for (const [sessionID, providerID, id] of [
      ["ses_policy_a", "alpha", "model-a"],
      ["ses_policy_b", "beta", "model-b"],
    ]) {
      await fixture.hooks.get("context")(
        fixture.contextEvent({ sessionID, model: { providerID, id } }),
      );
    }
    await fixture.tools.get("cyber_review").execute(
      { action: "run", claim: "Synthetic policy check", observationIds: [policyEvidence.id] },
      { ...c("policy-review"), sessionID: "ses_policy_a" },
    );
    assert.equal(
      fixture.generated.at(-1).model.providerID,
      "alpha",
      "a second session cannot change the first session's verifier provider",
    );
    await assert.rejects(
      () => fixture.tools.get("cyber_review").execute(
        {
          action: "run",
          claim: "Synthetic policy check",
          observationIds: [policyEvidence.id],
          model: { providerID: "beta", id: "model-b" },
        },
        { ...c("policy-refusal"), sessionID: "ses_policy_a" },
      ),
      /outside the operator policy/,
    );
    const raw = "x".repeat(25000) + "first-tail",
      record = {
        id: "obs-long",
        sessionId: "ses_regression",
        scope,
        tool: "shell",
        input: {},
        output: raw,
        success: true,
        timestamp: new Date().toISOString(),
      },
      long = store.recordObservation(record);
    assert.equal(long.truncated, true);
    assert.equal(long.rawBytes, 25010);
    assert.equal(long.rawHash, hash(raw));
    assert.throws(
      () =>
        store.recordObservation({
          ...record,
          output: "x".repeat(25000) + "other-tail",
        }),
      /collision/,
    );
    const first = tasks.add(scope, { title: "Keep this open" });
    for (let i = 0; i < 25; i++) tasks.add(scope, { title: `Extra ${i}` });
    assert.ok(tasks.list(scope).some((t) => t.id === first.id));
    assert.throws(
      () =>
        tasks.add(scope, {
          title: "Missing dependency",
          dependsOn: ["missing"],
        }),
      /dependency/,
    );
    const blocked = tasks.add(scope, { title: "Prerequisite" });
    tasks.block(scope, blocked.id, "Waiting");
    const dependent = tasks.add(scope, {
      title: "Dependent",
      dependsOn: [blocked.id],
    });
    assert.ok(!tasks.delegable(scope).some((t) => t.id === dependent.id));
    assert.throws(() => tasks.start(scope, dependent.id), /dependency/);
    const lock = path.join(state, `tasks-${scope}.json.lock`);
    fs.writeFileSync(lock, "");
    assert.throws(() => tasks.add(scope, { title: "Race" }), /Concurrent/);
    fs.unlinkSync(lock);
    const worker = path.join(work, "worker.cjs");
    fs.writeFileSync(
      worker,
      `
   const {createJiti}=require(${JSON.stringify(path.join(modules, "jiti"))});const {TaskStore}=createJiti(__filename)(${JSON.stringify(path.join(root, "src/tasks.ts"))});const store=new TaskStore(${JSON.stringify(state)});
   (async()=>{for(let i=0;i<12;i++){for(let attempt=0;;attempt++){try{store.add(${JSON.stringify(scope)},{title:process.argv[2]+'-'+i});break}catch(e){if(!String(e).includes('Concurrent')||attempt>200)throw e;await new Promise(r=>setTimeout(r,5));}}}})().catch(e=>{console.error(e);process.exitCode=1});`,
    );
    await Promise.all(
      ["a", "b", "c"].map(
        (n) =>
          new Promise((resolve, reject) => {
            const child = spawn(process.execPath, [worker, n], {
              stdio: ["ignore", "ignore", "pipe"],
            });
            let error = "";
            child.stderr.on("data", (b) => (error += b));
            child.on("error", reject);
            child.on("close", (code) =>
              code === 0 ? resolve() : reject(Error(error)),
            );
          }),
      ),
    );
    assert.equal(tasks.list(scope).length, 64);
    const launched = await call(
      "cyber_process",
      {
        action: "run",
        argv: [
          process.execPath,
          "-e",
          "console.log('synthetic failure');process.exit(7)",
        ],
        timeout: 2,
      },
      "launch",
    );
    const proc = JSON.parse(launched.content);
    assert.equal(launched.metadata.evidenceSuccess, false);
    assert.equal(proc.runKey, undefined);
    await fixture.hooks.get("execute.after")({
      tool: "cyber_process",
      sessionID: "ses_regression",
      id: "launch",
      input: { action: "run" },
      status: "completed",
      result: launched,
    });
    assert.equal(
      store.evidence(scope, [observationId("ses_regression", "launch")])[0]
        .success,
      false,
    );
    await until(() => processStatus(registry.get(scope, proc.id)) === "failed");
    const read = await call(
      "cyber_process",
      { action: "read", id: proc.id },
      "read",
    );
    assert.equal(JSON.parse(read.content).exitCode, 7);
    assert.equal(read.metadata.evidenceSuccess, false);
    await fixture.hooks.get("execute.after")({
      tool: "cyber_process",
      sessionID: "ses_regression",
      id: "read",
      input: { action: "read", id: proc.id },
      status: "completed",
      result: read,
    });
    assert.equal(
      store.evidence(scope, [observationId("ses_regression", "read")])[0]
        .success,
      false,
    );
    fs.appendFileSync(proc.logPath, "tampered");
    assert.throws(
      () => verifiedOutcome(registry.get(scope, proc.id)),
      /integrity/,
    );
    const background = JSON.parse(
      (
        await call(
          "cyber_process",
          {
            action: "run",
            argv: ["/bin/sh", "-c", "(sleep 2; printf late) &"],
            timeout: 3,
          },
          "background",
        )
      ).content,
    );
    await until(
      () => processStatus(registry.get(scope, background.id)) === "failed",
    );
    assert.equal(
      verifiedOutcome(registry.get(scope, background.id)).status,
      "failed",
    );
  } finally {
    unload();
    store.close();
    fs.rmSync(work, { recursive: true, force: true });
  }
};
