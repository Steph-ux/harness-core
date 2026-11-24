/** Execute trusted synthetic services, not target applications or live scans. */
module.exports = async ({ assert }) => {
  const { validate } = require("../scripts/validate-skill-fixtures.cjs");
  const report = await validate({ assert });
  assert.equal(report.scope, "trusted-local-fixtures");
  assert.equal(report.address, "127.0.0.1");
  for (const domain of ["jwt", "dns", "upload"]) {
    for (const kind of ["positive", "negative", "false-positive"]) {
      const cases = report.cases.filter(
        (item) => item.domain === domain && item.kind === kind,
      );
      assert.ok(cases.length, `${domain}: ${kind} was executed`);
      for (const item of cases) {
        assert.equal(item.verdict, "pass", item.id);
        assert.match(item.outputHash, /^[a-f0-9]{64}$/, `${item.id} has output proof`);
      }
    }
  }
  assert.ok(
    report.limits.includes("dig CLI not exercised"),
    "wire-protocol fixtures are not falsely reported as dig validation",
  );
  assert.deepEqual(
    report.recipes.map((item) => item.skill).sort(),
    ["harness-dns-enum", "harness-file-upload", "harness-jwt"],
    "observations are bound to the exact playbook bytes",
  );
  for (const item of report.recipes)
    assert.match(item.sha256, /^[a-f0-9]{64}$/);
  console.log(`Skill fixture validation: ${report.cases.length} executed cases, 3 domains`);
};

if (require.main === module) {
  module.exports({ assert: require("node:assert/strict") }).catch((error) => {
    console.error(error.stack);
    process.exitCode = 1;
  });
}
