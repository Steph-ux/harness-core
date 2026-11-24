/**
 * A version is not a vulnerability until the public database says so.
 *
 * The OSV answer is bounded before it reaches the model, and the lookup itself
 * is a tool call, so it leaves the observation a finding can cite.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const childProcess = require("node:child_process");
const { mock } = require("node:test");
const { syncBuiltinESMExports } = require("node:module");
const { makeContext, loadPlugin, unloadPlugins } = require("./opencode-fixture.cjs");

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

  // --- Multi-source: categorizeTech and searchsploit ----------------------

  const { categorizeTech, querySearchsploit } = jiti(
    path.join(CORE, "src", "cve-sources.ts"),
  );
  assert.equal(categorizeTech("Apache 2.4.49"), "service", "apache is a service");
  assert.equal(categorizeTech("OpenSSH 8.2"), "service", "openssh is a service");
  assert.equal(categorizeTech("nginx 1.21"), "service", "nginx is a service");
  assert.equal(categorizeTech("WordPress 6.4"), "service", "wordpress is a service");
  assert.equal(categorizeTech("some-random-thing"), "unknown", "unknown technology is unknown");
  assert.equal(categorizeTech("Jenkins 2.401"), "service", "jenkins is a service");
  assert.equal(categorizeTech("Cisco IOS 15.1"), "service", "cisco is a service");

  // Test the adapter deterministically, without assuming a Kali host/database.
  const execution = mock.method(childProcess, "execFileSync", (binary, argv, options) => {
    assert.equal(binary, "searchsploit");
    assert.deepEqual(argv, ["-j", "apache", "2.4.49"]);
    assert.equal(options.timeout, 15000);
    assert.equal(options.maxBuffer, 2 * 1024 * 1024);
    return JSON.stringify({
      RESULTS_EXPLOIT: [{
        Title: "Synthetic test entry",
        "EDB-ID": "123456",
        Path: "/synthetic/entry.txt",
        Codes: "CVE-2024-0001;not-a-cve",
      }],
    });
  });
  syncBuiltinESMExports();
  try {
    const ssResult = querySearchsploit("apache", "2.4.49");
    assert.equal(ssResult.results[0]?.source, "searchsploit");
    assert.equal(ssResult.results[0].id, "EDB-123456");
    assert.equal(ssResult.results[0].summary, "Synthetic test entry");
    assert.deepEqual(ssResult.results[0].aliases, ["CVE-2024-0001"]);
    execution.mock.mockImplementation(() => JSON.stringify({ RESULTS_EXPLOIT: [] }));
    assert.deepEqual(querySearchsploit("apache", "2.4.49"), { results: [] });
    execution.mock.mockImplementation(() => {
      const error = new Error("spawnSync searchsploit ENOENT");
      error.code = "ENOENT";
      throw error;
    });
    assert.deepEqual(querySearchsploit("apache", "2.4.49"), {
      results: [], error: "searchsploit not installed",
    });
    execution.mock.mockImplementation(() => "invalid json");
    const malformed = querySearchsploit("apache", "2.4.49");
    assert.deepEqual(malformed.results, []);
    assert.ok(malformed.error, "malformed output is not a clean empty lookup");
  } finally {
    execution.mock.restore();
    syncBuiltinESMExports();
  }

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

      // search action validation
      await assert.rejects(
        () => tool.execute({ action: "search" }, context),
        /technology/,
        "search without a technology name is refused",
      );
      await assert.rejects(
        () => tool.execute({ action: "search", technology: "" }, context),
        /technology/,
        "search with an empty technology name is refused",
      );
    } finally {
      if (typeof unload === "function") unload();
    }
  } finally {
    await unloadPlugins();
    fs.rmSync(workspace, { recursive: true, force: true });
  }
};
