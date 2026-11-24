const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti }) => {
  const { auditSkills } = require("../scripts/skill-audit.cjs");
  const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "skill-depth-"));
  try {
    const dir = path.join(fixture, "harness-fixture");
    fs.mkdirSync(dir);
    const file = path.join(dir, "SKILL.md");
    fs.writeFileSync(file, "---\nname: harness-fixture\n---\n\n## Done\n");
    const short = auditSkills(fixture);
    assert.equal(short.total, 1);
    assert.equal(short.ge100, 0);
    assert.ok(short.errors.some((error) => error.includes("100 lines")));

    fs.appendFileSync(file, "\n".repeat(120));
    assert.equal(
      auditSkills(fixture).ge100,
      0,
      "trailing blank lines cannot satisfy the depth target",
    );
    assert.ok(short.errors.some((error) => error.includes("description")));
    assert.ok(short.errors.some((error) => error.includes("negative control")));

    // Synthetic text tests the checker, not the quality of a real procedure.
    const valid = [
      "---",
      "name: harness-fixture",
      "description: Synthetic structural test only.",
      "---",
      "## Gate",
      "cyber_process argv=[]; test fixture only, never execute.",
      "## Steps",
      "A negative control and cyber_finding contract.",
      ...Array.from({ length: 90 }, (_, index) => `Fixture record ${index}.`),
      "## Done",
      "Fixture complete.",
    ].join("\n");
    fs.writeFileSync(file, valid);
    assert.deepEqual(
      auditSkills(fixture).errors,
      [],
      "100 normalized lines satisfy structure",
    );
    fs.writeFileSync(file, valid.replace(/\n/g, "\r\n") + "\r\n\r\n");
    assert.equal(
      auditSkills(fixture).skills[0].lines,
      100,
      "CRLF and trailing blanks normalize",
    );

    fs.writeFileSync(file, valid + '\ncyber_process argv=["true"]');
    assert.ok(auditSkills(fixture).errors.some((error) => error.includes("no-op")));
    fs.writeFileSync(
      file,
      valid + "\nA second pass is a new method load, not a longer observation.",
    );
    assert.ok(
      auditSkills(fixture).errors.some((error) => error.includes("boilerplate")),
      "old count-padding text cannot return",
    );
    fs.rmSync(file);
    assert.throws(
      () => auditSkills(fixture),
      /SKILL\.md/,
      "a missing bundled skill fails instead of becoming a skipped check",
    );
    fs.rmdirSync(dir);
    assert.ok(auditSkills(fixture).errors.some((error) => error.includes("empty")));
  } finally {
    fs.rmSync(fixture, { recursive: true, force: true });
  }

  const root = path.join(CORE, ".opencode", "skills");
  const result = auditSkills(root);
  assert.deepEqual(result.errors, [], result.errors.join("\n"));
  assert.equal(result.lt80, 0, "no bundled pentest skill is below 80 lines");
  assert.equal(
    result.ge100,
    result.total,
    "all bundled pentest skills reach 100 lines",
  );
  const { EXTERNAL_METHODS, ROUTES } = jiti(path.join(CORE, "src/routing.ts"));
  assert.deepEqual(
    result.skills.map((skill) => skill.name).sort(),
    [...EXTERNAL_METHODS].sort(),
    "the audit covers exactly the methods the router declares",
  );
  for (const route of ROUTES) {
    for (const name of route.skills.filter((name) => name.startsWith("harness-")))
      assert.ok(
        result.skills.some((skill) => skill.name === name),
        `${name} ships`,
      );
  }
  console.log(
    `Bundled skill audit: total=${result.total} lt80=${result.lt80} ge100=${result.ge100}`,
  );
};
