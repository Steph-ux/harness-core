const fs = require("node:fs"),
  path = require("node:path"),
  assert = require("node:assert/strict");
const { auditSkills } = require("./skill-audit.cjs");
const catalogue = auditSkills(path.resolve(__dirname, "../.opencode/skills"));
assert.deepEqual(catalogue.errors, [], catalogue.errors.join("\n"));
console.log(
  `Validated pentest catalogue: total=${catalogue.total} lt80=${catalogue.lt80} ge100=${catalogue.ge100}`,
);
for (const name of ["capitaliser-cyber", "rapports-cyber"]) {
  const dir = path.resolve(__dirname, "../.opencode/skills", name),
    body = fs
      .readFileSync(path.join(dir, "SKILL.md"), "utf8")
      .replace(/\r\n/g, "\n");
  assert.match(
    body,
    new RegExp(`^---\\nname: ${name}\\ndescription: .+\\n---\\n`),
  );
  assert.ok(body.split("\n").length < 500);
  assert.match(body, /nettoyage.*uniquement après restitution/i);
  for (const [, resource] of body.matchAll(
    /`((?:references|scripts)\/[A-Za-z0-9_./-]+)`/g,
  ))
    assert.ok(
      fs.existsSync(path.join(dir, resource)),
      `Missing ${name}/${resource}`,
    );
  console.log(`Validated project procedure: ${name}`);
}
