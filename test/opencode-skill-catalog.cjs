/**
 * The router names a set of methods; each one has to be a real procedure.
 *
 * The catalogue is a contract, not a list that depends on what one machine
 * happens to have installed. The declarations live in `routing.ts`; when the
 * host's skill directory is present, every declared method is checked for the
 * shape the ledger accepts: frontmatter, a gate, steps, a done condition, and
 * the `cyber_process` + `argv` discipline. The broad profiles (mobile, cloud)
 * must carry their coverage checklist verbatim, so the profile the harness
 * seeds and the skill the operator reads cannot drift apart.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti, skip }) => {
  const { EXTERNAL_METHODS, SHIPPED_METHODS, ROUTES } = jiti(
    path.join(CORE, "src", "routing.ts"),
  );
  const { COVERAGE_PROFILES } = jiti(
    path.join(CORE, "src", "coverage-profiles.ts"),
  );

  // The shipped procedures always travel with the repository, so they are
  // checked here regardless of the host.
  for (const name of SHIPPED_METHODS)
    assert.ok(
      fs.existsSync(path.join(CORE, ".opencode", "skills", name, "SKILL.md")),
      `${name} ships with the repository`,
    );

  // Every method the router can select has to be reachable: a route names it,
  // and it is declared. This holds without any host installed.
  const routed = new Set(ROUTES.flatMap((route) => route.skills));
  for (const name of EXTERNAL_METHODS)
    assert.ok(
      routed.has(name),
      `the declared method ${name} is named by a route`,
    );
  assert.equal(
    new Set(EXTERNAL_METHODS).size,
    EXTERNAL_METHODS.length,
    "the external catalogue has no duplicate",
  );

  // The host's own catalogue. Absent on a clean clone, so the depth check is
  // skipped rather than failed there.
  const skillsDir =
    process.env.HARNESS_SKILLS_DIR ||
    path.join(os.homedir(), ".config", "opencode", "skills");
  if (!fs.existsSync(skillsDir))
    skip("host skill catalogue is not installed");

  const read = (name) => {
    const file = path.join(skillsDir, name, "SKILL.md");
    if (!fs.existsSync(file)) return null;
    return fs.readFileSync(file, "utf8").replace(/\r\n/g, "\n");
  };

  for (const name of EXTERNAL_METHODS) {
    const body = read(name);
    assert.ok(body, `the declared method has a SKILL.md: ${name}`);
    assert.match(
      body,
      new RegExp(`^---\\nname: ${name}\\n`),
      `${name} carries its own frontmatter name`,
    );
    assert.match(body, /^## Gate\b/m, `${name} states its gate`);
    assert.match(body, /^## Steps\b/m, `${name} states its steps`);
    assert.match(body, /^## Done\b/m, `${name} states its done condition`);
    assert.ok(body.includes("cyber_process"), `${name} goes through cyber_process`);
    assert.ok(/\bargv\b/.test(body), `${name} passes an argv, not a shell string`);
    assert.match(body, /negative(?:[- ]|\s+)control/i, `${name} states a negative control`);
    assert.match(body, /cyber_finding/i, `${name} states its finding contract`);
  }

  // The two broad profiles seed a task branch; the skill and the profile are
  // one contract, so every profile step is a checklist item in the skill.
  const profiles = [
    ["mobile", "harness-mobile-pentest"],
    ["cloud", "harness-cloud-enum"],
  ];
  for (const [profile, skill] of profiles) {
    const body = read(skill);
    assert.ok(body, `${skill} exists`);
    for (const step of COVERAGE_PROFILES[profile].steps)
      assert.ok(
        body.includes(`- [ ] ${step}`),
        `${skill} checklist covers the ${profile} step: "${step}"`,
      );
  }
};
