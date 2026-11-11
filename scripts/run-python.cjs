#!/usr/bin/env node
/**
 * Run the Python report contract with the interpreter the machine has.
 *
 * The interpreter is named differently on the platforms the harness runs on
 * (python3 on Linux, python on Windows), and a gate that only works on one
 * of them is a gate that is skipped on the other. The interpreter is
 * looked up, and its absence is reported as such.
 */
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const args = process.argv.slice(2);
if (!args.length) {
  console.error("usage: node scripts/run-python.cjs <script> [args...]");
  process.exit(2);
}

const candidates =
  process.platform === "win32"
    ? ["python", "python3", "py"]
    : ["python3", "python"];

for (const candidate of candidates) {
  // A candidate is an interpreter only if it answers. The Microsoft Store
  // alias launches and exits with 9009, which is not an answer: it has to be
  // passed over, or the gate reports the store's message instead of the
  // interpreter it never found.
  const probe = spawnSync(candidate, ["--version"], { stdio: "ignore" });
  if (probe.error || probe.status !== 0) continue;
  const result = spawnSync(candidate, args, { stdio: "inherit" });
  process.exit(result.status === null ? 1 : result.status);
}

console.error(
  `No Python interpreter found (tried: ${candidates.join(", ")}). ` +
    "The report contract needs Python 3.",
);
process.exit(1);
