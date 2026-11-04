/** Resolve the optional external host gate without depending on clone depth. */
const fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path"),
  { spawnSync } = require("node:child_process");
const gate =
  process.env.HARNESS_PI_GATE ||
  path.join(os.homedir(), ".pi/agent/cyber-harness/tests/run.cjs");
if (!fs.existsSync(gate)) {
  console.error(
    "External host gate unavailable. Install it or set HARNESS_PI_GATE.",
  );
  process.exitCode = 2;
} else {
  const result = spawnSync(process.execPath, [gate], { stdio: "inherit" });
  process.exitCode = result.status ?? 1;
}
