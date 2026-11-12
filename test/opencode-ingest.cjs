/**
 * A collected dump becomes graph facts, bound to the observation that read it.
 *
 * The parser is pure; the tool writes nothing it cannot tie to a read, and a
 * dump that sits outside the declared engagement is refused.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti }) => {
  const { planIngest } = jiti(path.join(CORE, "src", "osint-ingest.ts"));
  const lines = planIngest("lines", "a.test\nhttps://b.test/x\n\n# comment\n!!!\n");
  assert.deepEqual(
    lines.entities.map((entity) => `${entity.type}:${entity.key}`).sort(),
    ["host:a.test", "host:b.test", "url:https://b.test/x"],
    "hosts and URLs are read from the lines",
  );
  assert.deepEqual(lines.relations, [
    {
      source: { type: "url", key: "https://b.test/x" },
      target: { type: "host", key: "b.test" },
      kind: "resolves-to",
    },
  ]);
  assert.equal(lines.skipped, 1, "a line that is not a host is skipped");

  const httpx = planIngest(
    "httpx",
    [
      JSON.stringify({ input: "https://c.test/", tech: ["WordPress", "PHP"] }),
      JSON.stringify({ input: "not a url" }),
    ].join("\n"),
  );
  assert.ok(
    httpx.entities.some((entity) => entity.type === "technology" && entity.key === "wordpress"),
    "the technology is recorded",
  );
  assert.ok(
    httpx.relations.some(
      (relation) => relation.kind === "uses" && relation.target.type === "technology",
    ),
    "the host uses the technology",
  );
  assert.equal(httpx.skipped, 1, "a line without a URL is skipped");

  const json = planIngest(
    "json",
    JSON.stringify([
      { type: "account", key: "github:someone" },
      { type: "planet", key: "mars" },
      { hex: true },
    ]),
  );
  assert.deepEqual(
    json.entities.map((entity) => `${entity.type}:${entity.key}`),
    ["account:github:someone"],
  );
  assert.equal(json.skipped, 2, "unknown and incomplete rows are skipped");
  assert.throws(() => planIngest("json", "not json"), /not valid JSON/);

  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-ingest-"));
  const state = path.join(workspace, "state");
  const engagement = path.join(workspace, "engagement");
  fs.mkdirSync(state, { recursive: true });
  fs.mkdirSync(path.join(engagement, "preuves", "dumps"), { recursive: true });
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;
  process.env.HARNESS_CAPTURE_TERMINAL = "off";
  const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
  const { PlatformStore } = jiti(path.join(CORE, "src", "platform-store.ts"));
  const { scopeFor } = jiti(path.join(CORE, "src", "util.ts"));
  const store = new KnowledgeStore(path.join(state, "knowledge.sqlite"));
  const platform = new PlatformStore(path.join(state, "platform.sqlite"), store);
  const scope = scopeFor(workspace);
  try {
    store.upsertSession({
      id: "ses_ing",
      scope,
      cwd: workspace,
      status: "active",
      updatedAt: new Date().toISOString(),
    });
    const proof = store.recordObservation({
      id: "obs-ing-1",
      sessionId: "ses_ing",
      scope,
      tool: "shell",
      input: {},
      output: "a.test\nhttps://b.test/x",
      success: true,
      timestamp: new Date().toISOString(),
    });
    const dump = path.join(engagement, "preuves", "dumps", "hosts.txt");
    fs.writeFileSync(dump, "a.test\nhttps://b.test/x\n");

    const fixture = makeContext(workspace);
    const unload = await jiti(path.join(CORE, "opencode", "plugin.ts")).default.setup(
      fixture.ctx,
    );
    try {
      const tool = fixture.tools.get("cyber_entity");
      const missionTool = fixture.tools.get("cyber_mission");
      const context = {
        sessionID: "ses_ing",
        agent: "build",
        messageID: "msg_ing",
        id: "call_ing",
        progress: () => {},
        signal: new AbortController().signal,
      };
      const call = async (input, id = "call_ing") =>
        JSON.parse((await tool.execute(input, { ...context, id })).content);
      await assert.rejects(
        () =>
          call({
            action: "import",
            path: dump,
            format: "lines",
            observationIds: [],
          }),
        /observation/,
        "an import without its observation is refused",
      );
      await assert.rejects(
        () =>
          call({
            action: "import",
            path: dump,
            format: "wrong",
            observationIds: [proof.id],
          }),
        /format/,
        "an unknown format is refused",
      );
      await missionTool.execute(
        {
          action: "create",
          title: "Ingest fixture",
          boundaries: "Fixture locale uniquement.",
          root: engagement,
        },
        { ...context, id: "call-mission" },
      );
      const outside = path.join(workspace, "outside.txt");
      fs.writeFileSync(outside, "z.test\n");
      await assert.rejects(
        () =>
          call({
            action: "import",
            path: outside,
            format: "lines",
            observationIds: [proof.id],
          }),
        /engagement/,
        "a dump outside the engagement is refused",
      );
      const imported = await call(
        {
          action: "import",
          path: dump,
          format: "lines",
          observationIds: [proof.id],
        },
        "call-import",
      );
      assert.equal(imported.entities, 3, "two hosts and one URL");
      assert.equal(imported.relations, 1, "the URL resolves to its host");
      const hosts = await call({ action: "query", type: "host" }, "call-hosts");
      assert.equal(hosts.length, 2, "the graph kept both hosts");
    } finally {
      if (typeof unload === "function") unload();
    }
  } finally {
    platform.close();
    store.close();
    fs.rmSync(workspace, { recursive: true, force: true });
  }
};
