const fs = require("node:fs"),
  path = require("node:path"),
  assert = require("node:assert/strict");
const { auditSkills } = require("./skill-audit.cjs");
const skillsRoot = path.resolve(__dirname, "../.opencode/skills");
const catalogue = auditSkills(skillsRoot);
assert.deepEqual(catalogue.errors, [], catalogue.errors.join("\n"));
console.log(
  `Validated pentest catalogue: total=${catalogue.total} lt80=${catalogue.lt80} ge100=${catalogue.ge100}`,
);
for (const name of ["capitaliser-cyber", "rapports-cyber"]) {
  const dir = path.join(skillsRoot, name),
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
  )) {
    const resourcePath = path.join(dir, resource);
    assert.ok(
      fs.existsSync(resourcePath) && fs.statSync(resourcePath).isFile() && fs.statSync(resourcePath).size > 0,
      `Missing or empty ${name}/${resource}`,
    );
  }
  console.log(`Validated project procedure: ${name}`);
}
