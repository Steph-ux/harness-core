const path = require("node:path");

const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti }) => {
  const { COVERAGE_PROFILES, coverageProfile } = jiti(
    path.join(CORE, "src", "coverage-profiles.ts"),
  );
  assert.deepEqual(Object.keys(COVERAGE_PROFILES), ["mobile", "cloud", "harness"]);
  assert.ok(
    coverageProfile("MOBILE").steps.includes("WebView, JavaScript bridges and file access"),
    "mobile coverage includes WebView and bridge review",
  );
  assert.ok(
    coverageProfile("cloud").steps.includes("IAM principals, roles and trust policies"),
    "cloud coverage includes IAM and trust policies",
  );
  assert.ok(
    coverageProfile("harness").steps.includes("finding reproduction and negative controls"),
    "harness coverage includes proof controls",
  );
  assert.throws(() => coverageProfile("unknown"), /Unknown coverage profile/);
};
