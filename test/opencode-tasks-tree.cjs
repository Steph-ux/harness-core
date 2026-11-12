/**
 * A target is a tree, not a flat list.
 *
 * Tasks nest to a bounded depth, the tree renders as a Markdown map, and the
 * known assets can seed one branch each so nothing is silently skipped.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext, loadPlugin, unloadPlugins } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-tree-"));
  const state = path.join(workspace, "state");
  const engagement = path.join(workspace, "engagement");
  fs.mkdirSync(state, { recursive: true });
  fs.mkdirSync(engagement, { recursive: true });
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;
  process.env.HARNESS_CAPTURE_TERMINAL = "off";
  const { TaskStore } = jiti(path.join(CORE, "src", "tasks.ts"));
  const { PlatformStore } = jiti(path.join(CORE, "src", "platform-store.ts"));
  const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
  const { scopeFor } = jiti(path.join(CORE, "src", "util.ts"));
  const tasks = new TaskStore(state);
  const store = new KnowledgeStore(path.join(state, "knowledge.sqlite"));
  const platform = new PlatformStore(path.join(state, "platform.sqlite"), store);
  const scope = scopeFor(workspace);
  try {
    const target = tasks.add(scope, { title: "bank.test" });
    const surface = tasks.add(scope, {
      title: "surface",
      parent: target.id,
    });
    const leaf = tasks.add(scope, {
      title: "www.bank.test",
      parent: surface.id,
    });
    assert.equal(tasks.tree(scope).length, 1, "one root");
    const tree = tasks.tree(scope)[0];
    assert.equal(tree.children[0].id, surface.id, "the child is nested");
    assert.equal(
      tree.children[0].children[0].id,
      leaf.id,
      "the grandchild is nested",
    );
    assert.throws(
      () => tasks.add(scope, { title: "orphan", parent: "task-unknown" }),
      /Unknown parent/,
      "a task cannot attach to a missing parent",
    );
    let parent = target;
    for (let index = 0; index < 6; index += 1)
      parent = tasks.add(scope, {
        title: `level-${index}`,
        parent: parent.id,
      });
    assert.throws(
      () => tasks.add(scope, { title: "too-deep", parent: parent.id }),
      /too deep/,
      "the tree is bounded",
    );
    assert.throws(
      () => tasks.remove(scope, target.id),
      /subtasks/,
      "a parent with children is not removed",
    );
    const pair = tasks.add(scope, { title: "pair" });
    const pairChild = tasks.add(scope, {
      title: "pair-child",
      parent: pair.id,
    });
    assert.throws(
      () => tasks.complete(scope, pair.id, ["obs-pair"]),
      /subtasks/,
      "a branch closes only after its sub-steps",
    );
    tasks.complete(scope, pairChild.id, ["obs-pair-child"]);
    assert.equal(
      tasks.complete(scope, pair.id, ["obs-pair"]).status,
      "completed",
      "the branch closes once its sub-steps are done",
    );

    tasks.start(scope, leaf.id);
    tasks.complete(scope, leaf.id, ["obs-tree-1"]);
    tasks.block(scope, surface.id, "scope not approved");
    const markdown = tasks.markdown(scope);
    assert.match(markdown, /^# Coverage map/, "the map has a title");
    assert.match(markdown, /- \[x\] www\.bank\.test — obs-tree-1/, "a closed step carries its proof");
    assert.match(markdown, /- \[!\] surface — blocked: scope not approved/, "a blocked step carries its reason");
    assert.match(markdown, /^  - /m, "the outline is indented by level");

    const fixture = makeContext(workspace);
    const unload = await jiti(path.join(CORE, "opencode", "plugin.ts")).default.setup(
      fixture.ctx,
    );
    try {
      const context = {
        sessionID: "ses_tree",
        agent: "build",
        messageID: "msg_tree",
        id: "call_tree",
        progress: () => {},
        signal: new AbortController().signal,
      };
      const tool = fixture.tools.get("cyber_tasks");
      const rendered = await tool.execute({ action: "markdown" }, context);
      assert.match(String(rendered.content), /Coverage map/);
      await assert.rejects(
        () => tool.execute({ action: "export" }, context),
        /engagement root/,
        "writing the map needs a declared engagement",
      );

      store.upsertSession({
        id: "ses_tree",
        scope,
        cwd: workspace,
        status: "active",
        updatedAt: new Date().toISOString(),
      });
      const proof = store.recordObservation({
        id: "obs-tree-2",
        sessionId: "ses_tree",
        scope,
        tool: "shell",
        input: {},
        output: "read",
        success: true,
        timestamp: new Date().toISOString(),
      });
      platform.upsertEntity(scope, {
        type: "host",
        key: "www.bank.test",
        observationIds: [proof.id],
      });
      platform.upsertEntity(scope, {
        type: "domain",
        key: "bank.test",
        observationIds: [proof.id],
      });
      platform.createMission(
        scope,
        "Cible bank.test",
        "Fixture locale uniquement.",
        undefined,
        engagement,
      );
      const planted = JSON.parse(
        (await tool.execute({ action: "assets" }, context)).content,
      );
      assert.equal(planted.assets, 2, "both assets are seen");
      assert.equal(planted.created.length, 13, "each asset grows its own branch");
      const second = JSON.parse(
        (await tool.execute({ action: "assets" }, context)).content,
      );
      assert.equal(second.created.length, 0, "the planting is idempotent");
      platform.upsertEntity(scope, {
        type: "account",
        key: "github:someone",
        observationIds: [proof.id],
      });
      const accountPlanted = JSON.parse(
        (await tool.execute({ action: "assets" }, context)).content,
      );
      assert.equal(
        accountPlanted.created.length,
        5,
        "an account gets its own role",
      );
      const accountBranch = tasks
        .tree(scope)
        .find((node) => node.title === "account:github:someone");
      assert.deepEqual(
        accountBranch.children.map((node) => node.title.split(" — ").pop()),
        ["osint", "repos", "secrets", "validation"],
        "an account is OSINT, repositories, secrets, then validation",
      );
      const exported = JSON.parse(
        (await tool.execute({ action: "export" }, context)).content,
      );
      assert.ok(fs.existsSync(exported.path), "the map is written");
      assert.match(
        fs.readFileSync(exported.path, "utf8"),
        /host:www\.bank\.test/,
        "the map carries the asset branches",
      );
    } finally {
      if (typeof unload === "function") unload();
    }
  } finally {
    platform.close();
    store.close();
    await unloadPlugins();
    fs.rmSync(workspace, { recursive: true, force: true });
  }
};
