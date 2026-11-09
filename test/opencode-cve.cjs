/**
 * A version is not a vulnerability until the public database says so.
 *
 * The OSV answer is bounded before it reaches the model, and the lookup itself
 * is a tool call, so it leaves the observation a finding can cite.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti }) => {
  const { summarizeOsv } = jiti(path.join(CORE, "src", "osv.ts"));
  const sample = {
    vulns: [
      {
        id: "CVE-2024-0001",
        summary: "Example vulnerability",
        aliases: ["GHSA-aaaa", 42],
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
        affected: [
          { ranges: [{ events: [{ introduced: "0" }, { fixed: "1.2.3" }] }] },
          { ranges: [{ events: [{ fixed: "1.2.3" }, { fixed: "2.0.0" }] }] },
        ],
      },
      { id: "CVE-2024-0002", summary: "Second", database_specific: { severity: "HIGH" } },
      { nope: true },
    ],
  };
  const out = summarizeOsv(sample);
  assert.equal(out.length, 2, "only rows with an id are kept");
  assert.equal(out[0].id, "CVE-2024-0001");
  assert.equal(out[0].summary, "Example vulnerability");
  assert.deepEqual(out[0].aliases, ["GHSA-aaaa"], "non-string aliases are dropped");
  assert.match(String(out[0].severity), /^CVSS:3\.1\//, "the CVSS vector is kept");
  assert.deepEqual(
    out[0].fixed,
    ["1.2.3", "2.0.0"],
    "every fixed version is kept, without duplicates",
  );
  assert.equal(out[1].severity, "HIGH", "a database severity is a fallback");
  assert.deepEqual(summarizeOsv(null), [], "no payload, no vulnerability");
  assert.deepEqual(summarizeOsv({ vulns: "nope" }), []);

  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-cve-"));
  process.env.HARNESS_STATE_ROOT = path.join(workspace, "state");
  process.env.HARNESS_CORE = CORE;
  try {
    const fixture = makeContext(workspace);
    const unload = await jiti(path.join(CORE, "opencode", "plugin.ts")).default.setup(
      fixture.ctx,
    );
    try {
      const tool = fixture.tools.get("cyber_cve");
      assert.ok(tool, "the CVE tool is registered");
      const context = {
        sessionID: "ses_cve",
        agent: "build",
        messageID: "msg_cve",
        id: "call_cve",
        progress: () => {},
        signal: new AbortController().signal,
      };
      await assert.rejects(
        () =>
          tool.execute(
            { action: "lookup", ecosystem: "Wrong", package: "x" },
            context,
          ),
        /ecosystem/,
        "an unknown ecosystem is refused",
      );
      await assert.rejects(
        () =>
          tool.execute(
            { action: "lookup", ecosystem: "PyPI", package: "bad name!" },
            context,
          ),
        /package name/,
        "an invalid package name is refused",
      );
      await assert.rejects(
        () =>
          tool.execute(
            {
              action: "lookup",
              ecosystem: "PyPI",
              package: "requests",
              version: "1 2",
            },
            context,
          ),
        /version/,
        "an invalid version is refused",
      );
    } finally {
      if (typeof unload === "function") unload();
    }
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
};
