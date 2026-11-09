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
    const valid = registry.validate(scope, candidate.id, tests, () => proofs);
    assert.equal(valid.status, "validated");
    const shared = registry.activate(scope, candidate.id, true);
    assert.equal(shared.scope, "global", "explicitly promoted version is shared");
    const active = registry.activate(scope, candidate.id);
    assert.equal(active.status, "active");
    const sibling = new ToolRegistry(state);
    assert.ok(sibling.discover(scope, "fixture validator").tools.some((t) =>
      t.name === "fixture-validator" && t.version === 1),
    "another registry instance sees the activation immediately");
    assert.equal(sibling.list(scope).length, 1);
    assert.equal(sibling.list(scopeFor(os.tmpdir())).length, 0,
      "a different project cannot see project-local scripts");
    assert.deepEqual(sibling.matchExecution(scope, { command: "node " + active.file }), {
      name: "fixture-validator", version: 1, scope,
    });
    const second = registry.propose(scope, {
      name: "fixture-validator", description: "Improved synthetic validator",
      language: "mjs", source: "console.log('changed');",
    });
    assert.equal(second.version, 2);
    assert.equal(registry.list(scope)[0].version, 1,
      "unvalidated changes never replace a working script");
    fs.appendFileSync(second.file, "// tampered\n");
    assert.throws(() => registry.validate(scope, second.id, tests, () => proofs),
      /changed since proposal/);
    assert.ok(registry.list(scopeFor(os.tmpdir())).some((entry) =>
      entry.scope === "global" && entry.name === "fixture-validator"));
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
    const secondPrompt = fixture.contextEvent({
      sessionID: context.sessionID, messages: prompt.messages,
    });
    await fixture.hooks.get("context")(secondPrompt);
    assert.ok(secondPrompt.system.some((entry) =>
      String(entry.text).includes("fixture-validator")), "same session sees the tool");
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
};