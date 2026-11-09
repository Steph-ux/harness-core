const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext } = require("./opencode-fixture.cjs");
const CORE = path.resolve(__dirname, "..");
module.exports = async ({ assert, jiti }) => {
  const { ToolRegistry } = jiti(path.join(CORE, "src", "tool-registry.ts"));
  const { scopeFor } = jiti(path.join(CORE, "src", "util.ts"));
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "harness-live-tools-"));
  const state = path.join(base, "state");
  const scope = scopeFor(base);
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;
  try {
    const registry = new ToolRegistry(state);
    assert.equal(registry.discover(scope, "definitelynotinstalled-92347").total, 0);
    // Context construction must not readdir PATH (regression: 31ms/turn).
    const originalScan = registry.scan.bind(registry);
    registry.scan = () => { throw new Error("context unexpectedly scanned PATH"); };
    assert.match(registry.context(scope, "fixture"), /^Harness capabilities\./);
    registry.scan = originalScan;
    const originalCustom = process.env.HARNESS_TOOL_HOME;
    process.env.HARNESS_TOOL_HOME = path.join(base, "missing-custom-tool-dir");
    assert.throws(() => registry.scan(true), /Configured tool directory is unavailable/);
    if (originalCustom === undefined) delete process.env.HARNESS_TOOL_HOME;
    else process.env.HARNESS_TOOL_HOME = originalCustom;
    // A configured tool directory has to be scanned only on explicit discovery.
    const custom = path.join(base, "my-tools");
    fs.mkdirSync(custom);
    const executable = path.join(custom, "fixture-cli");
    fs.writeFileSync(executable, "#!/bin/sh\necho fixture\n", { mode: 0o700 });
    process.env.HARNESS_TOOL_HOME = custom;
    assert.ok(registry.discover(scope, "fixture cli", [], 0, 15, true)
      .tools.some((entry) => entry.name === "fixture-cli"));
    if (originalCustom === undefined) delete process.env.HARNESS_TOOL_HOME;
    else process.env.HARNESS_TOOL_HOME = originalCustom;
    assert.throws(() => registry.propose("other", {
      name: "example", description: "Example script", language: "mjs", source: "console.log('ok')",
    }), /scope/);
    const candidate = registry.propose(scope, {
      name: "fixture-validator", description: "Parse and check a synthetic fixture",
      language: "mjs", source: "const value = process.argv[2]; if(value === 'positive') console.log('positive case passed'); else { console.log('negative case rejected'); }",
    });
    assert.equal(candidate.status, "candidate");
    assert.equal(registry.list(scope).length, 0, "candidate is not exposed");
    assert.throws(() => registry.activate(scope, candidate.id), /Validated/);
    assert.throws(() => registry.validate(scope, candidate.id, [], () => []),
      /positive and negative/);
    const { spawnSync } = require("node:child_process");
    const positives = spawnSync(process.execPath, [candidate.file, "positive"], { encoding: "utf8" });
    const negatives = spawnSync(process.execPath, [candidate.file, "negative"], { encoding: "utf8" });
    assert.equal(positives.status, 0);
    assert.equal(negatives.status, 0);
    const proofs = [
      { id: "good", scope, tool: "shell", success: positives.status === 0, output: positives.stdout,
        input: { command: "node " + candidate.file + " positive" } },
      { id: "bad", scope, tool: "shell", success: negatives.status === 0, output: negatives.stdout,
        input: { command: "node " + candidate.file + " negative" } },
    ];
    const tests = [
      { observationId: "good", contains: "positive case passed", kind: "positive" },
      { observationId: "bad", contains: "negative case rejected", kind: "negative" },
    ];
    assert.throws(() => registry.validate(scope, candidate.id, tests, () =>
      proofs.map((proof) => ({ ...proof, input: { command: "node someone-else.mjs" } }))),
      /exact candidate/);
    assert.throws(() => registry.validate(scope, candidate.id, tests, () =>
      proofs.map((proof) => ({ ...proof, scope: "global" }))),
      /scope-bound/);
    assert.throws(() => registry.validate(scope, candidate.id, tests, () =>
      proofs.map((proof) => ({
        ...proof, input: { command: "echo node " + candidate.file },
      }))), /exact candidate/, "echoed candidate command is not validation");
    assert.throws(() => registry.validate(scope, candidate.id, tests, () =>
      proofs.map((proof) => ({
        ...proof, input: { command: "node " + candidate.file + "; echo PASS" },
      }))), /exact candidate/, "chained commands cannot validate");
    const valid = registry.validate(scope, candidate.id, tests, () => proofs);
    assert.equal(valid.status, "validated");
    const active = registry.activate(scope, candidate.id);
    assert.equal(active.status, "active");
    const sibling = new ToolRegistry(state);
    assert.ok(sibling.discover(scope, "fixture validator").tools.some((t) =>
      t.name === "fixture-validator" && t.version === 1),
    "another registry instance sees the activation immediately");
    assert.equal(sibling.list(scope).length, 1);
    const otherScope = scopeFor(os.tmpdir());
    assert.equal(sibling.list(otherScope).length, 0,
      "different project cannot see local tools before promotion");
    assert.deepEqual(sibling.matchExecution(scope, { command: "node " + active.file }, "shell"), {
      name: "fixture-validator", version: 1, scope,
    });
    const second = registry.propose(scope, {
      name: "fixture-validator", description: "Improved synthetic validator",
      language: "mjs", source: "console.log('changed');",
    });
    assert.equal(second.version, 2);
    assert.equal(registry.list(scope)[0].version, 1,
      "unvalidated changes never replace a working script");
    const sourced = registry.propose(scope, {
      name: "fixture-adapted",
      description: "Adapted from a public script",
      language: "py",
      source: "print('adapted')\n",
      provenance: {
        url: "https://github.com/example/tool",
        commit: "abc1234",
        license: "MIT",
      },
    });
    assert.equal(sourced.provenance.url, "https://github.com/example/tool");
    assert.ok(
      registry
        .list(scope, true)
        .some(
          (item) =>
            item.name === "fixture-adapted" &&
            item.provenance?.license === "MIT",
        ),
      "the provenance is kept with the revision",
    );
    assert.throws(
      () =>
        registry.propose(scope, {
          name: "fixture-insecure",
          description: "Insecure source",
          language: "py",
          source: "print('x')\n",
          provenance: { url: "http://example.com/tool" },
        }),
      /https/,
      "an insecure provenance URL is refused",
    );
    assert.throws(
      () =>
        registry.propose(scope, {
          name: "fixture-secret",
          description: "Credential in the URL",
          language: "py",
          source: "print('x')\n",
          provenance: { url: "https://user:pass@example.com/tool" },
        }),
      /credentials/,
      "a provenance URL with credentials is refused",
    );
    fs.appendFileSync(second.file, "// tampered\n");
    assert.throws(() => registry.validate(scope, second.id, tests, () => proofs),
      /changed since proposal/);
    const shared = registry.activate(scope, candidate.id, true);
    assert.equal(shared.scope, "global");
    assert.equal(registry.list(otherScope).length, 1,
      "other project sees globally promoted version only");
    assert.equal(registry.list(otherScope)[0].scope, "global");
    registry.retire(scope, "fixture-validator", true);
    assert.equal(registry.list(otherScope).length, 0);
    registry.rollback(scope, "fixture-validator", shared.version, true);
    assert.equal(registry.list(otherScope).length, 1);
    assert.deepEqual(registry.prune(scope, [second.id]).removed, [second.id]);
    assert.deepEqual(registry.prune(scope, [active.id]).removed, [],
      "active tools cannot be pruned");
    assert.equal(registry.matchExecution(scope, { command: "echo " + active.file }, "shell"), null);
    assert.equal(registry.matchExecution(scope, { command: "node " + active.file }, "text-only"), null);
    const plugin = jiti(path.join(CORE, "opencode", "plugin.ts")).default;
    const fixture = makeContext(base);
    await plugin.setup(fixture.ctx);
    assert.ok(fixture.tools.has("cyber_toolbox"));
    const toolbox = fixture.tools.get("cyber_toolbox");
    const context = {
      sessionID: "ses_toolbox", agent: "build", messageID: "msg_toolbox",
      id: "call_toolbox", signal: new AbortController().signal, progress: () => {},
    };
    const exposed = JSON.parse((await toolbox.execute({
      action: "discover", query: "fixture validator",
    }, context)).content);
    assert.ok(exposed.tools.some((item) => item.origin === "managed"));
    const coverage = JSON.parse((await toolbox.execute({
      action: "plan", objectives: ["fixture validator", "uniquely-not-installed-123abc"],
    }, context)).content);
    assert.equal(coverage[0].status, "candidate-tools");
    assert.equal(coverage[1].status, "unmatched");
    const prompt = fixture.contextEvent({
      sessionID: context.sessionID,
      messages: [{ info: { role: "user" }, parts: [{
        type: "text", text: "validate fixture validator",
      }] }],
    });
    await fixture.hooks.get("context")(prompt);
    assert.ok(prompt.system.some((entry) =>
      String(entry.text).includes("Harness capabilities.")), "live catalogue injected");
    // A new version is validated after the plugin and session already exist.
    // The next context read must see it, without reload or a new session ID.
    const live = registry.propose(scope, {
      name: "fixture-validator", description: "Live refresh validator",
      language: "mjs", source: "console.log(process.argv[2] === 'positive' ? 'positive case passed' : 'negative case rejected');",
    });
    assert.equal(live.version, 3);
    const liveGood = spawnSync(process.execPath, [live.file, "positive"], { encoding: "utf8" });
    const liveBad = spawnSync(process.execPath, [live.file, "negative"], { encoding: "utf8" });
    const liveTests = [
      { observationId: "live-good", contains: "positive case passed", kind: "positive" },
      { observationId: "live-bad", contains: "negative case rejected", kind: "negative" },
    ];
    registry.validate(scope, live.id, liveTests, () => [
      { id: "live-good", scope, tool: "shell", success: liveGood.status === 0,
        output: liveGood.stdout, input: { command: "node " + live.file + " positive" } },
      { id: "live-bad", scope, tool: "shell", success: liveBad.status === 0,
        output: liveBad.stdout, input: { command: "node " + live.file + " negative" } },
    ]);
    registry.activate(scope, live.id);
    const liveDiscover = JSON.parse((await toolbox.execute({
      action: "discover", query: "fixture validator",
    }, context)).content);
    assert.ok(liveDiscover.tools.some((item) => item.origin === "managed" &&
      item.scope === scope && item.version === 3),
      "already-running plugin sees a newly activated version");
    const secondPrompt = fixture.contextEvent({
      sessionID: context.sessionID, messages: prompt.messages,
    });
    await fixture.hooks.get("context")(secondPrompt);
    assert.ok(secondPrompt.system.some((entry) =>
      String(entry.text).includes("fixture-validator v3")),
      "same session sees the newest activated version");
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
};