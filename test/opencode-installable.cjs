const path = require("node:path");
const childProcess = require("node:child_process");
const { mock } = require("node:test");
const { syncBuiltinESMExports } = require("node:module");
const CORE = path.resolve(__dirname, "..");
module.exports = async ({ assert, jiti }) => {
  const { lookupInstall, listInstallable, ensure } = jiti(
    path.join(CORE, "src", "installable.ts"),
  );

  // Catalog is populated.
  const all = listInstallable();
  assert.ok(all.length > 30, "catalog has >30 entries");

  // Lookup by name.
  const nmap = lookupInstall("nmap");
  assert.ok(nmap, "nmap is in the catalog");
  assert.equal(nmap.method, "apt");
  assert.equal(nmap.package, "nmap");

  const subfinder = lookupInstall("subfinder");
  assert.ok(subfinder, "subfinder is in the catalog");
  assert.equal(subfinder.method, "go");

  // Unknown tool.
  assert.equal(lookupInstall("definitely-not-a-tool-293847"), undefined);

  // Unit checks of discovery, independent of Unix `which`/`ls` installation.
  // Only discovery is allowed here; no package manager can actually run.
  const whichCmd = process.platform === "win32" ? "where.exe" : "which";
  const discovery = mock.method(childProcess, "spawnSync", (binary, argv, options) => {
    assert.equal(binary, whichCmd, "unit tests cannot invoke an installer");
    assert.equal(options.timeout, 5000);
    return {
      status: argv[0] === "fixture-present-tool" ? 0 : 1,
      stdout: "", stderr: "",
    };
  });
  syncBuiltinESMExports();
  try {
    const result = ensure("fixture-present-tool");
    assert.equal(result.wasPresent, true);
    assert.equal(result.installed, true);
    const unknown = ensure("definitely-not-a-tool-293847");
    assert.equal(unknown.wasPresent, false);
    assert.equal(unknown.installed, false);
    assert.match(unknown.error, /Unknown tool/);
  } finally {
    discovery.mock.restore();
    syncBuiltinESMExports();
  }

  // Every catalog entry has required fields.
  for (const entry of all) {
    assert.ok(entry.name, `entry has name: ${entry.name}`);
    assert.ok(entry.method, `entry has method: ${entry.name}`);
    assert.ok(entry.package, `entry has package: ${entry.name}`);
    assert.ok(entry.description, `entry has description: ${entry.name}`);
  }

  // No duplicate names in catalog.
  const names = all.map((e) => e.name);
  assert.equal(names.length, new Set(names).size, "no duplicate names");
};
