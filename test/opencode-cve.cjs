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

  // --- OSV bounds and truncation caps -------------------------------------
  const longId = "CVE-" + "1".repeat(80);
  const longAlias = "GHSA-" + "a".repeat(80);
  const longFixed = "9.".repeat(60) + "1";
  const cappedOsv = summarizeOsv({
    vulns: [
      { id: "   ", summary: "blank id skipped" },
      {
        id: longId,
        summary: "S".repeat(600),
        aliases: [
          ...Array.from({ length: 12 }, (_, i) => (i === 0 ? longAlias : `GHSA-${i}`)),
        ],
        affected: [
          // 49 empty affected entries (indices 0..48)
          ...Array.from({ length: 49 }, () => ({ ranges: [] })),
          // index 49 (50th affected entry) IS within MAX_AFFECTED = 50
          {
            ranges: [
              // 49 empty ranges (indices 0..48)
              ...Array.from({ length: 49 }, () => ({ events: [] })),
              // index 49 (50th range) IS within MAX_RANGES = 50
              {
                events: [
                  ...Array.from({ length: 199 }, () => ({ introduced: "0" })),
                  // index 199 (200th event) IS within MAX_EVENTS = 200
                  { fixed: longFixed },
                  // index 200 (201st event) MUST be ignored by MAX_EVENTS = 200
                  { fixed: "201.0.0" },
                ],
              },
              // index 50 (51st range) MUST be ignored by MAX_RANGES = 50
              { events: [{ fixed: "51-range.0.0" }] },
            ],
          },
          // index 50 (51st affected) MUST be ignored by MAX_AFFECTED = 50
          { ranges: [{ events: [{ fixed: "51-affected.0.0" }] }] },
        ],
      },
    ],
  });
  assert.equal(cappedOsv.length, 1, "blank OSV id is skipped");
  assert.equal(cappedOsv[0].id.length, 64, "OSV row.id is capped at 64 chars");
  assert.equal(cappedOsv[0].summary.length, 500, "OSV summary is capped at 500 chars");
  assert.equal(cappedOsv[0].aliases.length, 10, "OSV aliases are capped at 10");
  assert.equal(cappedOsv[0].aliases[0].length, 64, "each OSV alias is capped at 64 chars");
  assert.deepEqual(
    cappedOsv[0].fixed,
    [longFixed.slice(0, 100)],
    "OSV fixed strings are capped at 100 chars and affected/ranges/events loops stop at 50/50/200",
  );

  // Verify affected index 50 and range index 50 are ignored even when fixed is empty before them
  const beyondAffected = summarizeOsv({
    vulns: [
      {
        id: "CVE-2024-BOUND-1",
        affected: [
          ...Array.from({ length: 50 }, () => ({ ranges: [] })),
          { ranges: [{ events: [{ fixed: "9.9.9" }] }] },
        ],
      },
      {
        id: "CVE-2024-BOUND-2",
        affected: [
          {
            ranges: [
              ...Array.from({ length: 50 }, () => ({ events: [] })),
              { events: [{ fixed: "8.8.8" }] },
            ],
          },
        ],
      },
    ],
  });
  assert.deepEqual(beyondAffected[0].fixed, [], "affected past index 50 is ignored");
  assert.deepEqual(beyondAffected[1].fixed, [], "ranges past index 50 is ignored");

  // --- Multi-source: categorizeTech, queryNvd, searchsploit, multiSource --

  const {
    categorizeTech,
    nvdSeverity,
    queryNvd,
    querySearchsploit,
    multiSourceLookup,
  } = jiti(path.join(CORE, "src", "cve-sources.ts"));
  assert.equal(categorizeTech("Apache 2.4.49"), "service", "apache is a service");
  assert.equal(categorizeTech("OpenSSH 8.2"), "service", "openssh is a service");
  assert.equal(categorizeTech("nginx 1.21"), "service", "nginx is a service");
  assert.equal(categorizeTech("WordPress 6.4"), "service", "wordpress is a service");
  assert.equal(categorizeTech("IIS 10.0"), "service", "iis is a service");
  assert.equal(categorizeTech("some-random-thing"), "unknown", "unknown technology is unknown");
  assert.equal(categorizeTech("   "), "unknown", "blank technology is unknown");
  assert.equal(categorizeTech("Jenkins 2.401"), "service", "jenkins is a service");
  assert.equal(categorizeTech("Cisco IOS 15.1"), "service", "cisco is a service");
  for (const pkgTech of [
    "@scope/pkg",
    "@babel/core 7.20.0",
    "npm:express",
    "pypi:django",
    "go:github.com/gin-gonic/gin",
    "crates:serde",
    "maven:org.springframework:spring-core",
    "packagist:laravel/framework",
    "rubygems:rails",
    "nuget:Newtonsoft.Json",
    "pkg:npm/lodash",
  ]) {
    assert.equal(categorizeTech(pkgTech), "package", `${pkgTech} is categorized as package`);
  }

  // nvdSeverity supports CVSS v3.1, v3.0, and v2.0
  assert.equal(
    nvdSeverity({
      cve: {
        id: "CVE-1",
        metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } }] },
      },
    }),
    "CVSS:3.1 9.8 CRITICAL",
  );
  assert.equal(
    nvdSeverity({
      cve: {
        id: "CVE-2",
        metrics: { cvssMetricV30: [{ cvssData: { baseScore: 7.5, baseSeverity: "HIGH" } }] },
      },
    }),
    "CVSS:3.0 7.5 HIGH",
  );
  assert.equal(
    nvdSeverity({
      cve: {
        id: "CVE-3",
        metrics: { cvssMetricV2: [{ cvssData: { baseScore: 6.8 }, baseSeverity: "MEDIUM" }] },
      },
    }),
    "CVSS:2.0 6.8 MEDIUM",
  );
  assert.equal(
    nvdSeverity({
      cve: {
        id: "CVE-4",
        metrics: { cvssMetricV2: [{ cvssData: { baseScore: 5.0 } }] },
      },
    }),
    "CVSS:2.0 5",
  );
  assert.equal(nvdSeverity({ cve: { id: "CVE-5" } }), null);

  // Mocked queryNvd & multiSourceLookup tests
  const savedNvdKey = process.env.NVD_API_KEY;
  delete process.env.NVD_API_KEY;
  const nvdFetch = mock.method(globalThis, "fetch", async () =>
    new Response(JSON.stringify({ vulnerabilities: [] }), { status: 200 }),
  );
  try {
    // 1. NVD_API_KEY header included only when non-empty; redirect: "error"
    process.env.NVD_API_KEY = "nvd-secret-key-test";
    const seenHeaders = [];
    const seenUrls = [];
    nvdFetch.mock.mockImplementation(async (url, init) => {
      seenUrls.push(String(url));
      seenHeaders.push(init.headers ?? null);
      assert.equal(init.redirect, "error", "queryNvd sets redirect: error");
      return new Response(
        JSON.stringify({
          vulnerabilities: [
            {
              cve: {
                id: "CVE-2021-41773",
                descriptions: [{ lang: "en", value: "Apache HTTP Server 2.4.49 path traversal" }],
                metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.5, baseSeverity: "HIGH" } }] },
              },
            },
          ],
        }),
        { status: 200 },
      );
    });
    const keyed = await queryNvd("Apache", "2.4.49");
    assert.equal(keyed.results.length, 1);
    assert.equal(keyed.results[0].severity, "CVSS:3.1 7.5 HIGH");
    assert.equal(seenHeaders[0]?.apiKey, "nvd-secret-key-test", "NVD_API_KEY sets apiKey header");
    assert.match(seenUrls[0], /keywordSearch=Apache\+2\.4\.49/);

    // Without NVD_API_KEY, no apiKey header is sent
    delete process.env.NVD_API_KEY;
    seenHeaders.length = 0;
    await queryNvd("nginx");
    assert.equal(seenHeaders[0], null, "no apiKey header when NVD_API_KEY is unset");

    // 2. Direct CPE lookup (cpe:... -> cpeName param, no keywordSearch fallback)
    seenUrls.length = 0;
    nvdFetch.mock.mockImplementation(async (url, init) => {
      seenUrls.push(String(url));
      assert.equal(init.redirect, "error");
      return new Response(
        JSON.stringify({
          vulnerabilities: [
            {
              cve: {
                id: "CVE-2021-42013",
                descriptions: [{ lang: "en", value: "Path traversal in Apache 2.4.49/2.4.50" }],
                metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } }] },
              },
            },
            {
              cve: {
                id: "CVE-2021-41524",
                descriptions: [{ lang: "en", value: "Null pointer deref in Apache 2.4.49" }],
                metrics: { cvssMetricV30: [{ cvssData: { baseScore: 5.3, baseSeverity: "MEDIUM" } }] },
              },
            },
          ],
        }),
        { status: 200 },
      );
    });
    const cpeRes = await queryNvd("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*");
    assert.equal(seenUrls.length, 1, "CPE lookup makes single cpeName request");
    assert.match(seenUrls[0], /cpeName=cpe%3A2\.3%3Aa%3Aapache%3Ahttp_server/);
    assert.ok(!seenUrls[0].includes("keywordSearch="), "CPE lookup uses cpeName instead of keywordSearch");
    assert.deepEqual(
      cpeRes.results.map((r) => r.id),
      ["CVE-2021-42013", "CVE-2021-41524"],
      "CPE results sorted by CVSS descending",
    );
    assert.equal(cpeRes.results[1].severity, "CVSS:3.0 5.3 MEDIUM");

    // 3. Version fallback + CPE range & summary matching + sorting
    seenUrls.length = 0;
    nvdFetch.mock.mockImplementation(async (url) => {
      const u = String(url);
      seenUrls.push(u);
      const q = new URL(u).searchParams.get("keywordSearch");
      if (q === "Apache 2.4.49") {
        return new Response(JSON.stringify({ vulnerabilities: [] }), { status: 200 });
      }
      assert.equal(q, "Apache", "fallback queries bounded keywordSearch=cleanKeyword");
      return new Response(
        JSON.stringify({
          vulnerabilities: [
            {
              cve: {
                id: "CVE-EXCLUDED-FIXED",
                descriptions: [{ lang: "en", value: "Fixed in Apache 2.4.49" }],
                metrics: { cvssMetricV31: [{ cvssData: { baseScore: 10.0, baseSeverity: "CRITICAL" } }] },
                configurations: [
                  {
                    nodes: [
                      {
                        cpeMatch: [
                          {
                            vulnerable: true,
                            criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                            versionEndExcluding: "2.4.49",
                          },
                        ],
                      },
                    ],
                  },
                ],
              },
            },
            {
              cve: {
                id: "CVE-SUMMARY-BEFORE-EXCLUDED",
                descriptions: [{ lang: "en", value: "Apache 2.4.x before 2.4.48 issue" }],
                metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.5, baseSeverity: "CRITICAL" } }] },
              },
            },
            {
              cve: {
                id: "CVE-NEGATED-NODE",
                descriptions: [{ lang: "en", value: "Unrelated node" }],
                metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.0, baseSeverity: "CRITICAL" } }] },
                configurations: [
                  {
                    nodes: [
                      {
                        negate: true,
                        cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" }],
                      },
                      {
                        cpeMatch: [{ vulnerable: false, criteria: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*" }],
                      },
                    ],
                  },
                ],
              },
            },
            {
              cve: {
                id: "CVE-SUMMARY-MATCH",
                descriptions: [{ lang: "en", value: "Apache HTTP Server 2.4.0 through 2.4.50 flaw" }],
                metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.9, baseSeverity: "CRITICAL" } }] },
              },
            },
            {
              cve: {
                id: "CVE-CPE-EXACT",
                descriptions: [{ lang: "en", value: "Exact CPE match" }],
                metrics: { cvssMetricV2: [{ cvssData: { baseScore: 5.0 }, baseSeverity: "MEDIUM" }] },
                configurations: [
                  {
                    nodes: [
                      {
                        cpeMatch: [
                          {
                            vulnerable: true,
                            criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                          },
                        ],
                      },
                    ],
                  },
                ],
              },
            },
            {
              cve: {
                id: "CVE-CPE-RANGE-LOW",
                descriptions: [{ lang: "en", value: "Range lower score" }],
                metrics: { cvssMetricV30: [{ cvssData: { baseScore: 7.5, baseSeverity: "HIGH" } }] },
                configurations: [
                  {
                    nodes: [
                      {
                        cpeMatch: [
                          {
                            vulnerable: true,
                            criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                            versionStartExcluding: "2.4.48",
                            versionEndIncluding: "2.4.49",
                          },
                        ],
                      },
                    ],
                  },
                ],
              },
            },
            {
              cve: {
                id: "CVE-CPE-RANGE-HIGH",
                descriptions: [{ lang: "en", value: "Range higher score" }],
                metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } }] },
                configurations: [
                  {
                    nodes: [
                      {
                        cpeMatch: [
                          {
                            vulnerable: true,
                            criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                            versionStartIncluding: "2.4.0",
                            versionEndExcluding: "2.4.50",
                          },
                        ],
                      },
                    ],
                  },
                ],
              },
            },
          ],
        }),
        { status: 200 },
      );
    });
    const fallbackRes = await queryNvd("Apache", "2.4.49");
    assert.equal(seenUrls.length, 2, "falls back to keywordSearch=cleanKeyword when version query returns 0");
    assert.deepEqual(
      fallbackRes.results.map((r) => r.id),
      ["CVE-CPE-RANGE-HIGH", "CVE-CPE-RANGE-LOW", "CVE-CPE-EXACT", "CVE-SUMMARY-MATCH"],
      "filters excluded versions and ranks CPE matches ahead of summary matches sorted by CVSS descending",
    );

    // 4. HTTP errors, size limit, malformed payload, invalid query
    nvdFetch.mock.mockImplementation(async () => new Response("rate limit", { status: 429 }));
    const err429 = await queryNvd("nginx");
    assert.deepEqual(err429, { results: [], error: "nvd-429" });

    nvdFetch.mock.mockImplementation(
      async () =>
        new Response("x".repeat(2 * 1024 * 1024 + 16), { status: 200 }),
    );
    const errStreamSize = await queryNvd("nginx");
    assert.deepEqual(errStreamSize.results, []);
    assert.match(String(errStreamSize.error), /too-large/);

    nvdFetch.mock.mockImplementation(async () => new Response("{broken-json", { status: 200 }));
    const errJson = await queryNvd("nginx");
    assert.deepEqual(errJson.results, []);
    assert.ok(errJson.error, "malformed JSON returns error");

    nvdFetch.mock.mockImplementation(
      async () => new Response(JSON.stringify({ vulnerabilities: "not-array" }), { status: 200 }),
    );
    const errShape = await queryNvd("nginx");
    assert.deepEqual(errShape, { results: [], error: "invalid-nvd-payload" });

    const errEmpty = await queryNvd("   ");
    assert.deepEqual(errEmpty, { results: [], error: "invalid-nvd-query" });
  } finally {
    nvdFetch.mock.restore();
    if (savedNvdKey === undefined) delete process.env.NVD_API_KEY;
    else process.env.NVD_API_KEY = savedNvdKey;
  }

  // Test the adapter and multiSourceLookup deterministically, without assuming a Kali host/database.
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

    // multiSourceLookup: service queries NVD + searchsploit; package skips NVD
    const msFetch = mock.method(globalThis, "fetch", async () =>
      new Response(
        JSON.stringify({
          vulnerabilities: [
            {
              cve: {
                id: "CVE-2024-9999",
                descriptions: [{ lang: "en", value: "Apache 2.4.49 test" }],
                metrics: { cvssMetricV31: [{ cvssData: { baseScore: 8.1, baseSeverity: "HIGH" } }] },
              },
            },
          ],
        }),
        { status: 200 },
      ),
    );
    execution.mock.mockImplementation(() =>
      JSON.stringify({
        RESULTS_EXPLOIT: [
          { Title: "Multi exploit", "EDB-ID": "55555", Path: "/x/55555.py", Codes: "CVE-2024-9999" },
        ],
      }),
    );
    try {
      const svcLookup = await multiSourceLookup("Apache", "2.4.49");
      assert.deepEqual(svcLookup.sources, ["nvd", "searchsploit"]);
      assert.equal(svcLookup.results.length, 2);
      assert.equal(svcLookup.results[0].source, "nvd");
      assert.equal(svcLookup.results[1].source, "searchsploit");

      const pkgLookup = await multiSourceLookup("npm:express", "4.17.1");
      assert.deepEqual(pkgLookup.sources, ["searchsploit"], "package tech skips NVD in multiSourceLookup");
      assert.equal(pkgLookup.results.length, 1);
      assert.equal(pkgLookup.results[0].source, "searchsploit");
    } finally {
      msFetch.mock.restore();
    }
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
