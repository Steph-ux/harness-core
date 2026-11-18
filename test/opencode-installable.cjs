const path = require("node:path");
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

  // Ensure on a tool already present (node is always there).
  // We test with "node" but it's not in the catalog, so ensure returns
  // an error. Instead test with a tool that's guaranteed present: "ls".
  // Actually, ensure checks the catalog first. For a present tool, it
  // just checks `which` and returns wasPresent: true.
  // The tricky part: ensure() calls `which` on the name. We can test
  // with any tool known to be present.
  const result = ensure("ls");
  // "ls" is not in the catalog but which finds it, so wasPresent: true.
  assert.equal(result.wasPresent, true);
  assert.equal(result.installed, true);

  // Ensure on unknown tool — not present, not in catalog.
  const unknown = ensure("definitely-not-a-tool-293847");
  assert.equal(unknown.wasPresent, false);
  assert.equal(unknown.installed, false);
  assert.match(unknown.error, /Unknown tool/);

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
