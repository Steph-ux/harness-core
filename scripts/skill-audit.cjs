/** Static catalogue checks; these do not attest to live security-test outcomes. */
const fs = require("node:fs");
const path = require("node:path");

function auditSkills(root) {
  const errors = [];
  const skills = fs
    .readdirSync(root, { withFileTypes: true })
    .filter(
      (entry) =>
        entry.isDirectory() &&
        entry.name.startsWith("harness-") &&
        entry.name !== "harness-cyber-playbooks",
    )
    .map((entry) => entry.name)
    .sort()
    .map((name) => {
      const file = path.join(root, name, "SKILL.md");
      const body = fs.readFileSync(file, "utf8").replace(/\r\n/g, "\n");
      const lines = body.trimEnd().split("\n").length;
      if (!body.startsWith(`---\nname: ${name}\n`))
        errors.push(`${name}: frontmatter name does not match its directory`);
      if (!/^description: .+/m.test(body.split("\n---")[0]))
        errors.push(`${name}: missing frontmatter description`);
      for (const heading of ["Gate", "Steps", "Done"]) {
        if (!new RegExp(`^## ${heading}\\b`, "m").test(body))
          errors.push(`${name}: missing ${heading}`);
      }
      for (const [label, pattern] of [
        ["argv discipline", /cyber_process[\s\S]*\bargv\b/],
        ["negative control", /negative(?:[- ]|\s+)control/i],
        ["finding contract", /\bcyber_finding\b/],
      ]) {
        if (!pattern.test(body)) errors.push(`${name}: missing ${label}`);
      }
      if (lines < 100)
        errors.push(`${name}: ${lines}, expected at least 100 lines`);
      if (lines >= 500)
        errors.push(`${name}: disclose references before 500 lines`);
      if (/cyber_process argv=\["true"\]/.test(body))
        errors.push(`${name}: a no-op cannot serve as evidence`);
      if (
        body.includes("### Close-out") ||
        body.includes("A second pass is a new method load") ||
        body.includes(
          "Missing any required observation id leaves the claim a candidate.",
        )
      )
        errors.push(`${name}: remove count-padding boilerplate`);
      return { name, lines };
    });
  if (!skills.length) errors.push("empty pentest skill catalogue");
  return {
    total: skills.length,
    lt80: skills.filter((skill) => skill.lines < 80).length,
    ge100: skills.filter((skill) => skill.lines >= 100).length,
    skills,
    errors,
  };
}

module.exports = { auditSkills };

if (require.main === module) {
  const root = process.argv[2] || path.resolve(__dirname, "../.opencode/skills");
  const result = auditSkills(root);
  console.log(JSON.stringify(result, null, 2));
  if (result.errors.length) process.exitCode = 1;
}
