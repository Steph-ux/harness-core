/**
 * Entities and relations turn reads into pivots.
 *
 * A fact is bound to observations, the same type/key merges instead of
 * duplicating, and the shortest chain between two entities is what a report
 * calls an attack path.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-entity-"));
  const state = path.join(workspace, "state");
  fs.mkdirSync(state);
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;
  process.env.HARNESS_CAPTURE_TERMINAL = "off";
  const { PlatformStore } = jiti(path.join(CORE, "src", "platform-store.ts"));
  const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
  const { scopeFor } = jiti(path.join(CORE, "src", "util.ts"));
  const store = new KnowledgeStore(path.join(state, "knowledge.sqlite"));
  const platform = new PlatformStore(path.join(state, "platform.sqlite"), store);
  const scope = scopeFor(workspace);
  const seed = (id) => {
    store.upsertSession({
      id: "ses_ent",
      scope,
      cwd: workspace,
      status: "completed",
      updatedAt: new Date().toISOString(),
    });
    return store.recordObservation({
      id,
      sessionId: "ses_ent",
      scope,
      tool: "shell",
      input: {},
      output: "read",
      success: true,
      timestamp: new Date().toISOString(),
    });
  };
  const a = seed("obs-ent-a"),
    b = seed("obs-ent-b");
  try {
    assert.throws(
      () =>
        platform.upsertEntity(scope, {
          type: "domain",
          key: "exemple.test",
          observationIds: [],
        }),
      /observations/,
      "an entity without evidence is refused",
    );
    assert.throws(
      () =>
        platform.upsertEntity(scope, {
          type: "domain",
          key: "exemple.test",
          observationIds: ["obs-missing"],
        }),
      /missing/,
      "an unknown observation is refused",
    );
    assert.throws(
      () =>
        platform.upsertEntity(scope, {
          type: "planet",
          key: "mars",
          observationIds: [a.id],
        }),
      /entity type/,
      "an unknown type is refused",
    );

    const domain = platform.upsertEntity(scope, {
      type: "domain",
      key: "exemple.test",
      label: "Exemple",
      observationIds: [a.id],
    });
    const again = platform.upsertEntity(scope, {
      type: "domain",
      key: "exemple.test",
      attributes: { registrar: "Example Registrar" },
      observationIds: [b.id],
    });
    assert.equal(again.id, domain.id, "the same type/key merges");
    assert.deepEqual(
      [...again.observationIds].sort(),
      [a.id, b.id].sort(),
      "the evidence of both reads is kept",
    );
    assert.equal(again.attributes.registrar, "Example Registrar");

    const host = platform.upsertEntity(scope, {
      type: "host",
      key: "www.exemple.test",
      observationIds: [a.id],
    });
    const account = platform.upsertEntity(scope, {
      type: "account",
      key: "github:someone",
      observationIds: [a.id],
    });
    const repo = platform.upsertEntity(scope, {
      type: "repo",
      key: "github:someone/tool",
      attributes: { visibility: "public" },
      observationIds: [b.id],
    });
    const org = platform.upsertEntity(scope, {
      type: "org",
      key: "partner.test",
      observationIds: [a.id],
    });

    platform.relate(scope, {
      from: host.id,
      to: domain.id,
      kind: "resolves-to",
      observationIds: [a.id],
    });
    platform.relate(scope, {
      from: account.id,
      to: repo.id,
      kind: "owns",
      observationIds: [b.id],
    });
    platform.relate(scope, {
      from: repo.id,
      to: host.id,
      kind: "mentions",
      observationIds: [b.id],
    });
    platform.relate(scope, {
      from: org.id,
      to: host.id,
      kind: "operates",
      observationIds: [a.id],
    });
    assert.throws(
      () =>
        platform.relate(scope, {
          from: host.id,
          to: host.id,
          kind: "self",
          observationIds: [a.id],
        }),
      /itself/,
      "an entity does not relate to itself",
    );
    assert.throws(
      () =>
        platform.relate(scope, {
          from: host.id,
          to: domain.id,
          kind: "not a kind",
          observationIds: [a.id],
        }),
      /kind/,
      "an invalid relation kind is refused",
    );

    const pivot = platform.path(scope, org.id, account.id, 4);
    assert.ok(pivot, "a pivot path is found");
    assert.equal(pivot.relations.length, 3, "the chain keeps its edges");
    assert.equal(pivot.entities[0].id, org.id, "the path starts at the source");
    assert.equal(
      pivot.entities[pivot.entities.length - 1].id,
      account.id,
      "the path ends at the target",
    );
    assert.equal(
      platform.path(scope, org.id, account.id, 1),
      null,
      "the depth bounds the search",
    );
    assert.equal(
      platform.path(scope, domain.id, repo.id, 4).relations.length,
      2,
      "the shortest chain is returned",
    );

    assert.equal(
      platform.entities(scope, { query: "exemple" }).length,
      2,
      "a substring finds the key and the host",
    );
    assert.equal(
      platform.entities(scopeFor(os.tmpdir()), {}).length,
      0,
      "another project sees nothing",
    );
    const read = platform.relations(scope, host.id);
    assert.equal(read.length, 3, "relations are listed for both directions");
    assert.equal(platform.entity(scope, domain.id).key, "exemple.test");

    const fixture = makeContext(workspace);
    const unload = await jiti(path.join(CORE, "opencode", "plugin.ts")).default.setup(
      fixture.ctx,
    );
    try {
      const tool = fixture.tools.get("cyber_entity");
      assert.ok(tool, "the entity tool is registered");
      const context = {
        sessionID: "ses_ent",
        agent: "build",
        messageID: "msg_ent",
        id: "call_ent",
        progress: () => {},
        signal: new AbortController().signal,
      };
      const listed = JSON.parse(
        (await tool.execute({ action: "query", type: "domain" }, context)).content,
      );
      assert.equal(listed.length, 1, "the tool reads the same graph");
      const upserted = JSON.parse(
        (
          await tool.execute(
            {
              action: "upsert",
              type: "technology",
              key: "wordpress:6.5",
              observationIds: [a.id],
            },
            context,
          )
        ).content,
      );
      assert.equal(upserted.type, "technology", "the tool records a fact");
    } finally {
      if (typeof unload === "function") unload();
    }
  } finally {
    platform.close();
    store.close();
    fs.rmSync(workspace, { recursive: true, force: true });
  }
};
