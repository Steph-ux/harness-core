/**
 * The plugin boots without HARNESS_CORE.
 *
 * The host loads the plugin from its own directory, often through a symlink,
 * and sets no environment variable. The core must therefore be found from the
 * plugin's own file: a hardcoded home path breaks on the first move.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");
const PLUGIN = path.join(CORE, "opencode", "plugin.ts");

module.exports = async ({ assert, jiti }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-bootstrap-"));
  process.env.HARNESS_STATE_ROOT = path.join(workspace, "state");
  const saved = process.env.HARNESS_CORE;
  delete process.env.HARNESS_CORE;
  try {
    const plugin = jiti(PLUGIN).default;
    const fixture = makeContext(workspace);
    await plugin.setup(fixture.ctx);
    assert.ok(
      fixture.tools.has("cyber_tasks"),
      "the plugin loads when HARNESS_CORE is absent",
    );
    assert.ok(
      fixture.tools.has("cyber_capture"),
      "the core modules resolve from the plugin's own file",
    );
  } finally {
    if (saved === undefined) delete process.env.HARNESS_CORE;
    else process.env.HARNESS_CORE = saved;
    fs.rmSync(workspace, { recursive: true, force: true });
  }
};
