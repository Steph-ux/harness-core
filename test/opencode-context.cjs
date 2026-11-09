/**
 * The context the harness injects on the OpenCode surface.
 *
 * The rules the operator stated must reach every turn, in priority order,
 * ahead of anything else. Learned knowledge must not share that block: it is
 * unproven by definition.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");
const PLUGIN = path.join(CORE, "opencode", "plugin.ts");

module.exports = async ({ assert, jiti }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-context-"));
  const state = path.join(workspace, "state");
  fs.mkdirSync(state, { recursive: true });
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;

  const plugin = jiti(PLUGIN).default;
  const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
  const { operatorSnapshot, operatorBlock } = jiti(
    path.join(CORE, "src", "context.ts"),
  );
  const { scopeFor } = jiti(path.join(CORE, "src", "util.ts"));
  const { DEFAULT_CONFIG } = jiti(path.join(CORE, "src", "types.ts"));

  const store = new KnowledgeStore(path.join(state, "knowledge.sqlite"));
  const scope = scopeFor(workspace);

  store.setOperatorRule(scope, {
    key: "preuves-ou-rien",
    content: "Pas de trouvaille sans observation reussie.",
  });
  store.setOperatorRule(scope, {
    key: "francais-sans-emoji",
    content: "Repondre en francais, sans emoji.",
  });
  store.setOperatorRule(scope, {
    key: "terminal-possede",
    content: "Hors nmap, nuclei, httpx et ffuf, un outil Kali passe par cyber_terminal.",
  });
  // A learned fact needs a real observation behind it.
  store.upsertSession({
    id: "ses_ctx_seed",
    scope,
    cwd: workspace,
    status: "completed",
    updatedAt: new Date().toISOString(),
  });
  const seed = store.recordObservation({
    id: "obs-context-seed",
    sessionId: "ses_ctx_seed",
    scope,
    tool: "shell",
    input: { command: "echo seed" },
    output: "seed\n",
    success: true,
    timestamp: new Date().toISOString(),
  });
  store.proposeKnowledge(scope, {
    key: "appris-fact",
    content: "Fait appris sans preuve, qui ne doit pas etre injecte.",
    kind: "workflow",
    evidence: [seed.id],
  });

  const { ctx, hooks } = makeContext(workspace);
  await plugin.setup(ctx);
  assert.ok(hooks.has("context"), "the plugin hooks the model request");
  const onContext = hooks.get("context");

  // The rules reach the turn, ahead of the other blocks.
  const event = makeContext(workspace).contextEvent({ sessionID: "ses_ctx" });
  await onContext(event);
  assert.equal(event.system.length, 5, "operator, routing and capability blocks are added");
  assert.equal(event.system[0].text, "base prompt", "the host prompt stays first");
  assert.match(
    event.system[1].text,
    /Operator rules/,
    "the operator block sits right after the host prompt",
  );
  assert.match(
    event.system[2].text,
    /^Harness routing\./,
    "the route follows the rules it is constrained by",
  );
  assert.match(
    event.system[3].text,
    /^Harness capabilities\./,
    "the advisory capabilities follow operator rules and routing",
  );
  assert.equal(
    event.system[4].text,
    "another block",
    "the blocks that were there are kept",
  );

  const injected = event.system[1].text;
  const entries = JSON.parse(injected.slice(injected.indexOf("[")));

  // Every rule is present, in priority order.
  const keys = entries.map((entry) => entry.key);
  assert.deepEqual(
    keys,
    ["terminal-possede", "francais-sans-emoji", "preuves-ou-rien"],
    "the rules travel most recent first",
  );
  assert.match(injected, /Pas de trouvaille sans observation reussie\./, "the rule text travels");
  assert.match(injected, /Repondre en francais, sans emoji\./, "every rule travels");

  // Learned knowledge does not share the operator block.
  assert.ok(
    !injected.includes("appris-fact"),
    "the injected context holds no trace of learned knowledge",
  );
  assert.ok(
    !injected.includes("Fait appris sans preuve"),
    "the injected context holds no learned text",
  );
  assert.ok(
    !entries.some((entry) => entry.kind !== "operator"),
    "only operator rules are injected",
  );

  // The rules the host injects are the rules the Pi harness injects. That
  // comparison needs the other host, so it is checked where that host exists.
  const piMemory = path.join(
    process.env.USERPROFILE || process.env.HOME,
    ".pi/agent/cyber-harness",
    "memory.ts",
  );
  if (fs.existsSync(piMemory)) {
    const memory = jiti(piMemory);
    const { CyberMemory } = memory;
    const snapshot = JSON.parse(
      new CyberMemory(store, { ...DEFAULT_CONFIG }).snapshot(scope),
    );
    assert.deepEqual(
      snapshot
        .filter((entry) => entry.kind === "operator")
        .map((entry) => entry.key),
      keys,
      "both hosts select the same rules in the same order",
    );
  } else {
    console.log("  note: no Pi harness here, the cross-host rule parity is not exercised");
  }

  // The reserved budget keeps the rules, and one oversized rule does not
  // silently drop the ones stated after it.
  const roomy = operatorSnapshot(store, scope, DEFAULT_CONFIG);
  assert.equal(roomy.length, 3, "the default budget holds the whole rule set");

  // A rule that does not fit is skipped, not fatal: the rules stated after it
  // still reach the turn. Two rules in their own scope, so the arithmetic is
  // exact: the long one is stated last, so it comes first.
  const budgetScope = scopeFor(path.join(workspace, "budget"));
  store.setOperatorRule(budgetScope, {
    key: "regle-courte",
    content: "Courte.",
  });
  store.setOperatorRule(budgetScope, {
    key: "regle-longue",
    content: "Une regle bien plus longue que le budget. ".repeat(6),
  });
  const all = operatorSnapshot(store, budgetScope, {
    operatorModelChars: 100000,
    memoryMaxChars: 100000,
  });
  assert.equal(all[0].key, "regle-longue", "the most recent rule comes first");
  const shortest = all.find((entry) => entry.key === "regle-courte");
  const tight = operatorSnapshot(store, budgetScope, {
    operatorModelChars: JSON.stringify(shortest).length + 10,
    memoryMaxChars: 6000,
  });
  assert.ok(
    !tight.some((entry) => entry.key === "regle-longue"),
    "the oversized rule does not fit",
  );
  assert.ok(
    tight.some((entry) => entry.key === "regle-courte"),
    "a rule that fits is kept instead of the list stopping at the first",
  );

  // The block is empty when there is nothing to state.
  const other = scopeFor(path.join(workspace, "empty"));
  assert.equal(operatorBlock([]), "", "no rule means no block");

  // The block is injected once per request, even if the prompt already
  // carries it.
  const twice = makeContext(workspace).contextEvent({ sessionID: "ses_ctx" });
  await onContext(twice);
  const count = twice.system.filter(
    (block) => typeof block.text === "string" && block.text.startsWith("Operator rules."),
  ).length;
  assert.equal(count, 1, "the operator block appears once");
  await onContext(twice);
  const after = twice.system.filter(
    (block) => typeof block.text === "string" && block.text.startsWith("Operator rules."),
  ).length;
  assert.equal(after, 1, "the operator block is not injected twice");

  fs.writeFileSync(path.join(state, "processes.json"), "{broken");
  const degraded = makeContext(workspace).contextEvent({ sessionID: "ses_ctx" });
  await onContext(degraded);
  assert.ok(
    degraded.system.some((block) => String(block.text).startsWith("Operator rules.")),
    "auxiliary continuity corruption cannot remove operator authority",
  );
  assert.ok(
    degraded.system.some((block) => String(block.text).startsWith("Harness continuity unavailable")),
    "degraded continuity is explicit",
  );

  store.close();
  fs.rmSync(workspace, { recursive: true, force: true });
};
