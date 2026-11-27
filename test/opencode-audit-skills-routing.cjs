/**
 * Regression suite for skills, routing, lessons, memory ranking, context,
 * util, phases, observation-id, and live tool registry/installable fixes.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-audit-sr-"));
  const state = path.join(workspace, "state");
  fs.mkdirSync(state, { recursive: true });
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;

  const { SkillUpdater, GLOBAL_SCOPE, assertGloballyReusable } = jiti(
    path.join(CORE, "src", "skills.ts"),
  );
  const { ROUTES, routeFor, routingTable, requestText } = jiti(
    path.join(CORE, "src", "routing.ts"),
  );
  const { lessonPrompt, parseLessonProposal, publishToolImprovements } = jiti(
    path.join(CORE, "src", "lessons.ts"),
  );
  const { memoryQuery, memoryFragment, rankMemory } = jiti(
    path.join(CORE, "src", "memory-ranking.ts"),
  );
  const { operatorBudget, operatorSnapshot, operatorBlock, operatorContext } =
    jiti(path.join(CORE, "src", "context.ts"));
  const {
    redactText,
    redact,
    assertLearningText,
    parseObject,
    atomicWrite,
    scopeFor,
  } = jiti(path.join(CORE, "src", "util.ts"));
  const { detectPhase, phaseDirective } = jiti(
    path.join(CORE, "src", "phases.ts"),
  );
  const { observationId } = jiti(path.join(CORE, "src", "observation-id.ts"));
  const { ToolRegistry } = jiti(path.join(CORE, "src", "tool-registry.ts"));
  const { toolNote } = jiti(path.join(CORE, "src", "tool-catalog.ts"));
  const { identifyToolGaps } = jiti(path.join(CORE, "src", "tool-gap.ts"));
  const { isPresent, ensure } = jiti(path.join(CORE, "src", "installable.ts"));
  const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
  const { DEFAULT_CONFIG } = jiti(path.join(CORE, "src", "types.ts"));

  try {
    // -----------------------------------------------------------------------
    // 1. src/skills.ts
    // -----------------------------------------------------------------------
    const store = new KnowledgeStore(path.join(state, "knowledge.sqlite"));
    const skills = new SkillUpdater(state, store, DEFAULT_CONFIG);
    const scopeA = scopeFor(path.join(workspace, "proj-a"));
    const scopeB = scopeFor(path.join(workspace, "proj-b"));
    for (const [s, sc] of [
      ["s1", scopeA],
      ["s2", scopeA],
      ["s3", scopeA],
      ["s4", scopeA],
      ["sb1", scopeB],
      ["sb2", scopeB],
    ]) {
      store.upsertSession({
        id: s,
        scope: sc,
        cwd: workspace,
        status: "completed",
        updatedAt: new Date().toISOString(),
      });
    }
    const obs1 = store.recordObservation({
      id: "obs-sk-1",
      sessionId: "s1",
      scope: scopeA,
      tool: "shell",
      input: {},
      output: "verified token output",
      success: true,
      timestamp: new Date().toISOString(),
    });
    const obs2 = store.recordObservation({
      id: "obs-sk-2",
      sessionId: "s2",
      scope: scopeA,
      tool: "shell",
      input: {},
      output: "verified token output",
      success: true,
      timestamp: new Date().toISOString(),
    });
    const obsFail = store.recordObservation({
      id: "obs-sk-fail",
      sessionId: "s3",
      scope: scopeA,
      tool: "shell",
      input: {},
      output: "failure marker output",
      success: false,
      timestamp: new Date().toISOString(),
    });
    const obsFresh1 = store.recordObservation({
      id: "obs-sk-f1",
      sessionId: "s3",
      scope: scopeA,
      tool: "shell",
      input: {},
      output: "verified token output",
      success: true,
      timestamp: new Date().toISOString(),
    });
    const obsFresh2 = store.recordObservation({
      id: "obs-sk-f2",
      sessionId: "s4",
      scope: scopeA,
      tool: "shell",
      input: {},
      output: "verified token output",
      success: true,
      timestamp: new Date().toISOString(),
    });

    const baseProposal = {
      name: "check-token-scope",
      description: "Verify token authorization boundaries.",
      category: "investigation-patterns",
      prerequisites: [],
      procedure: ["Send request with token.", "Compare authorized output."],
      validation: [{ observationId: obs1.id, contains: "verified token" }],
      evidence: [obs1.id, obs2.id],
    };

    const act1 = skills.propose(scopeA, baseProposal);
    assert.equal(act1.status, "active");
    assert.equal(skills.active(scopeA).length, 1);

    // Same-procedure failure MUST deactivate active skill and remove runtimeFile.
    const failedSame = skills.propose(scopeA, {
      ...baseProposal,
      evidence: [obsFail.id],
      validation: [{ observationId: obsFail.id, contains: "failure marker" }],
    });
    assert.equal(failedSame.status, "candidate");
    assert.equal(skills.active(scopeA).length, 0);
    assert.throws(() => skills.load(scopeA, "check-token-scope"), /No active/);

    // Re-activate with 2 clean sessions, then deprecate.
    const react = skills.propose(scopeA, {
      ...baseProposal,
      name: "dep-resurrect-check",
    });
    assert.equal(react.status, "active");
    skills.deprecate(scopeA, "dep-resurrect-check");
    // 1 fresh session after deprecation must NOT merge pre-deprecation evidence!
    const afterDep1 = skills.propose(scopeA, {
      ...baseProposal,
      name: "dep-resurrect-check",
      evidence: [obsFresh1.id],
      validation: [{ observationId: obsFresh1.id, contains: "verified token" }],
    });
    assert.equal(afterDep1.status, "candidate");
    assert.deepEqual(afterDep1.sourceSessions, ["s3"]);
    // 2nd fresh session activates it.
    const afterDep2 = skills.propose(scopeA, {
      ...baseProposal,
      name: "dep-resurrect-check",
      evidence: [obsFresh2.id],
      validation: [{ observationId: obsFresh2.id, contains: "verified token" }],
    });
    assert.equal(afterDep2.status, "active");
    assert.deepEqual(afterDep2.sourceSessions, ["s3", "s4"]);

    // promote() checks: local candidate shadowing global must refuse, cross-project overwrite refused, deprecated global refused.
    const obsB1 = store.recordObservation({
      id: "obs-skb-1",
      sessionId: "sb1",
      scope: scopeB,
      tool: "shell",
      input: {},
      output: "verified token output",
      success: true,
      timestamp: new Date().toISOString(),
    });
    const obsB2 = store.recordObservation({
      id: "obs-skb-2",
      sessionId: "sb2",
      scope: scopeB,
      tool: "shell",
      input: {},
      output: "verified token output",
      success: true,
      timestamp: new Date().toISOString(),
    });
    skills.propose(scopeA, { ...baseProposal, name: "shared-skill" });
    skills.promote(scopeA, "shared-skill");
    // Local candidate in scopeB shadows global shared-skill -> promote(scopeB) must throw!
    skills.propose(scopeB, {
      ...baseProposal,
      name: "shared-skill",
      procedure: ["Different procedure in project B."],
      evidence: [obsB1.id],
      validation: [{ observationId: obsB1.id, contains: "verified token" }],
    });
    assert.throws(
      () => skills.promote(scopeB, "shared-skill"),
      /Only an active method can be promoted/,
    );
    // Activate different procedure in scopeB -> cross-project overwrite refused!
    skills.propose(scopeB, {
      ...baseProposal,
      name: "shared-skill",
      procedure: ["Different procedure in project B."],
      evidence: [obsB2.id],
      validation: [{ observationId: obsB2.id, contains: "verified token" }],
    });
    assert.throws(
      () => skills.promote(scopeB, "shared-skill"),
      /another project|different procedure/i,
    );
    // Deprecate global skill -> silent reactivation via promote() refused!
    skills.deprecate(GLOBAL_SCOPE, "shared-skill");
    assert.throws(
      () => skills.promote(scopeA, "shared-skill"),
      /deprecated global method/i,
    );

    // assertGloballyReusable() checks:
    for (const badText of [
      "Connect to 2001:db8::1 for test",
      "Check ::1 loopback",
      "Dump s3://client-bucket/dump",
      "SSH via ssh://bastion",
      "Check 1password.com login",
      "Check 10x.corp.net portal",
      "Test vs.victim.com response",
      "Test ex.target.org endpoint",
      "Connect host: target.rs on port 443",
      "Fetch portal.py/api directly",
      "Test bank.sh:8443 endpoint",
    ]) {
      assert.throws(
        () =>
          assertGloballyReusable({
            ...baseProposal,
            procedure: [badText],
          }),
        /global method cannot/i,
        `expected rejection for: ${badText}`,
      );
    }
    for (const goodText of [
      "Send Content-Type: application/x-www-form-urlencoded",
      "Inspect Content-Security-Policy-Report-Only header",
      "Run helper.py against bundle.js",
    ]) {
      assert.doesNotThrow(
        () =>
          assertGloballyReusable({
            ...baseProposal,
            procedure: [goodText],
          }),
        `expected acceptance for: ${goodText}`,
      );
    }

    // Lock contention on publish/propose:
    const lockPath = path.join(state, "skills", ".lock");
    fs.writeFileSync(lockPath, "");
    assert.throws(
      () => skills.propose(scopeA, { ...baseProposal, name: "locked-skill" }),
      /Concurrent skill update/,
    );
    fs.unlinkSync(lockPath);

    // archiveUnused(): audit happens after deprecate, not on failure.
    const oldTs = new Date(Date.now() - 90 * 86_400_000).toISOString();
    const obsOld1 = store.recordObservation({
      id: "obs-old-cur1",
      sessionId: "s1",
      scope: scopeA,
      tool: "shell",
      input: {},
      output: "verified token output",
      success: true,
      timestamp: oldTs,
    });
    const obsOld2 = store.recordObservation({
      id: "obs-old-cur2",
      sessionId: "s2",
      scope: scopeA,
      tool: "shell",
      input: {},
      output: "verified token output",
      success: true,
      timestamp: oldTs,
    });
    skills.propose(scopeA, {
      ...baseProposal,
      name: "curator-fail-skill",
      evidence: [obsOld1.id, obsOld2.id],
      validation: [{ observationId: obsOld1.id, contains: "verified token" }],
    });
    const runtimeFile = skills.active(scopeA).find((e) => e.revision.name === "curator-fail-skill").filePath;
    fs.writeFileSync(runtimeFile, "external edit");
    const archivedFail = skills.archiveUnused(scopeA, []);
    assert.deepEqual(archivedFail, []);
    assert.equal(
      store
        .audits(scopeA, "skill.curator", 20)
        .some((a) => a.detail.includes("curator-fail-skill")),
      false,
      "skill.curator must not be logged when deprecate fails",
    );

    // -----------------------------------------------------------------------
    // 2. src/routing.ts
    // -----------------------------------------------------------------------
    assert.ok(routeFor("rapid api").ids.includes("api"), "scans all indexOf matches for 'api'");
    assert.ok(routeFor("openssl ssl test").ids.includes("crypto"), "scans all indexOf matches for 'ssl'");
    assert.ok(!routeFor("american business").ids.includes("can"), "multi-word boundary keeps 'can bus' out of 'american business'");
    assert.ok(!routeFor("extract logs").ids.includes("recon"), "multi-word boundary keeps 'ct log' out of 'extract logs'");

    const pad = "neutral prose word ".repeat(50);
    assert.deepEqual(routeFor(`${pad} reflected xss`).ids, [], "overlapping 'xss' inside 'reflected xss' does not bypass >800 anti-noise");
    assert.deepEqual(routeFor(`${pad} c2 beacon`).ids, [], "overlapping 'c2' inside 'c2 beacon' does not bypass >800 anti-noise");
    assert.deepEqual(routeFor(`${pad} shadow api`).ids, [], "overlapping 'api' inside 'shadow api' does not bypass >800 anti-noise");
    assert.ok(routeFor(`${pad} reflected xss and stored xss`).ids.includes("xss"), "two independent triggers pass >800 anti-noise");

    assert.equal(
      requestText({
        messages: [{ role: "user", content: [{ type: "text", text: "check jwt" }] }],
      }),
      "check jwt",
    );
    assert.equal(
      requestText({
        messages: [{ content: "no-role" }],
      }),
      "",
      "messages without role are ignored",
    );

    const multi = routeFor("test sqli and xss and jwt", 3);
    assert.equal(multi.ids.length, 3);
    assert.ok(multi.block.length <= 900);
    assert.match(
      multi.block,
      /Load the skill before acting; a 200 is not a finding without an observation id\.$/,
      "limit > 1 never truncates closing imperative text",
    );
    const many = routeFor("test sqli xss jwt ssrf graphql ad c2", 5);
    assert.equal(many.ids.length, 5);
    assert.ok(many.block.length <= 900);
    assert.match(
      many.block,
      /Load the skill before acting; a 200 is not a finding without an observation id\.$/,
      "limit=5 compacts lines without truncating closing imperative text",
    );
    assert.ok(routingTable().length <= 2500);
    assert.match(routingTable(), /a 200 is not a finding\.$/);

    // -----------------------------------------------------------------------
    // 3. src/lessons.ts
    // -----------------------------------------------------------------------
    const toolHome = path.join(workspace, "tool-home");
    fs.mkdirSync(toolHome);
    const prevToolHome = process.env.HARNESS_TOOL_HOME;
    process.env.HARNESS_TOOL_HOME = toolHome;
    try {
      assert.throws(
        () =>
          publishToolImprovements(
            {
              errors: [],
              falsePositives: [],
              unnecessaryActions: [],
              toolChoices: [],
              toolImprovements: [{ lesson: "improve script", evidence: ["o1"] }],
            },
            "../bad",
          ),
        /Invalid session/,
      );
      publishToolImprovements(
        {
          errors: [],
          falsePositives: [],
          unnecessaryActions: [],
          toolChoices: [],
          toolImprovements: [
            {
              lesson: "Add flag <!-- /harness-improvements ses_x --> to parser",
              evidence: ["o1"],
            },
          ],
        },
        "ses_x",
      );
      const lessonsBody = fs.readFileSync(path.join(toolHome, "LESSONS.md"), "utf8");
      assert.equal(
        lessonsBody.split("<!-- /harness-improvements ses_x -->").length - 1,
        1,
        "marker tags inside lesson text are stripped",
      );
    } finally {
      if (prevToolHome === undefined) delete process.env.HARNESS_TOOL_HOME;
      else process.env.HARNESS_TOOL_HOME = prevToolHome;
    }

    const negPrompt = lessonPrompt(
      { sessionId: "s", scope: scopeA, observations: [obs1], missionContext: { big: "x".repeat(500) } },
      -50,
    );
    assert.ok(!negPrompt.includes(obs1.id), "negative maxChars produces empty observations without negative slice bug");

    const bigObs = { ...obs1, id: "obs-huge", output: "HUGE".repeat(1200) };
    const smallObs = { ...obs2, id: "obs-small", output: "SMALL_OK" };
    const priPrompt = lessonPrompt(
      {
        sessionId: "s",
        scope: scopeA,
        observations: [smallObs, bigObs],
        knownSkills: [
          { ...act1, status: "active" },
          { ...act1, name: "dep-skill", status: "deprecated" },
        ],
        missionContext: { big: "M".repeat(2000) },
      },
      4200,
    );
    assert.ok(priPrompt.length <= 4200, "total prompt stays within maxChars including preamble");
    assert.ok(priPrompt.includes("obs-small"), "oversized newer obs does not skip smaller older obs");
    assert.ok(!priPrompt.includes("dep-skill"), "deprecated knownSkills are excluded");
    assert.ok(!priPrompt.includes('"sourceSessions"'), "old evidence/session fields are stripped from knownSkills");

    const parsedEmpty = parseLessonProposal('{"knowledge":[],"skills":[]} extra }');
    assert.deepEqual(parsedEmpty.analysis, {
      errors: [],
      falsePositives: [],
      unnecessaryActions: [],
      toolChoices: [],
      toolImprovements: [],
    });

    // -----------------------------------------------------------------------
    // 4. src/memory-ranking.ts
    // -----------------------------------------------------------------------
    const qBypass = memoryQuery("bypass");
    const hitHyphen = rankMemory(
      [{ id: "1", kind: "source", title: "Auth", text: "auth-bypass via header" }],
      qBypass,
    );
    assert.equal(hitHyphen.length, 1, "hyphenated text matches subtoken query like FTS5");
    const hitCve = rankMemory(
      [{ id: "2", kind: "source", title: "Advisory", text: "Fixed in CVE-2024-1234" }],
      memoryQuery("2024 1234"),
    );
    assert.equal(hitCve.length, 1, "CVE subtokens match");
    assert.equal(
      typeof memoryFragment("knowledge", '{"content":123}'),
      "string",
      "non-string JSON content does not throw",
    );
    assert.deepEqual(
      rankMemory(
        [
          {
            id: "f1",
            kind: "finding",
            title: "SQLi",
            text: JSON.stringify({
              title: "SQLi",
              severity: "critical",
              limitations: "only admin",
              scope: "project-x",
            }),
          },
        ],
        memoryQuery("scope"),
      ),
      [],
      "raw JSON schema keys do not match",
    );
    assert.equal(
      rankMemory(
        [
          {
            id: "k1",
            kind: "knowledge",
            title: "rule",
            text: JSON.stringify({ key: "rule", kind: "workflow", content: "step one" }),
          },
        ],
        memoryQuery("workflow"),
      ).length,
      1,
      "knowledge.kind metadata is searchable",
    );
    const dedupQ = memoryQuery("security securite");
    assert.equal(dedupQ.groups.length, 1, "duplicate synonym groups are deduplicated");
    const longSynQ = memoryQuery(
      "authentication authorization network security evidence encryption log patch vulnerability browser timeout permission memory process failure " +
        Array.from({ length: 40 }, (_, i) => `extra${i}`).join(" "),
    );
    assert.ok(longSynQ.terms.length <= 60);
    assert.ok(
      longSynQ.groups.every((g) => g.every((t) => longSynQ.terms.includes(t))),
      "groups stay aligned with sliced terms",
    );
    const tied = rankMemory(
      [
        { id: "b", kind: "source", title: "Zulu", text: "alpha" },
        { id: "a", kind: "source", title: "Alpha", text: "alpha" },
      ],
      memoryQuery("alpha"),
    );
    assert.deepEqual(tied.map((r) => r.id), ["a", "b"], "deterministic en tie-break");

    const ctxSource = fs.readFileSync(path.join(CORE, "src", "context.ts"), "utf8");
    for (const prefix of ["boa-", "mtn-", "julaya-", "snedai-", "anip-", "loterie-", "azure-"]) {
      assert.ok(!ctxSource.includes(prefix), `src/context.ts must not hardcode ${prefix}`);
    }

    // -----------------------------------------------------------------------
    // 5. src/context.ts, src/util.ts, src/types.ts
    // -----------------------------------------------------------------------
    assert.equal(
      operatorBudget({ operatorModelChars: NaN, memoryMaxChars: 6000 }),
      5000,
    );
    assert.equal(
      operatorBudget({ operatorModelChars: "", memoryMaxChars: 6000 }),
      5000,
    );
    const ctxScope = scopeFor(path.join(workspace, "ctx-scope"));
    store.setOperatorRule(ctxScope, {
      key: "scope-engagement-2026-10-26",
      content: "Contextual scope rule ".repeat(5),
    });
    store.setOperatorRule(ctxScope, {
      key: "core-discipline",
      content: "Foundational rule.",
    });
    const ctxSnap = operatorContext(store, ctxScope, {
      operatorModelChars: 220,
      memoryMaxChars: 6000,
    });
    assert.ok(ctxSnap.block.length <= 220, "header accounted for in budget");
    assert.equal(ctxSnap.chars, ctxSnap.block.length, "chars telemetry equals block.length");
    assert.equal(ctxSnap.entries[0].key, "core-discipline", "foundational rule prioritized");

    for (const [rawSecret, leaked] of [
      ["secret=mysecretvalue", "mysecretvalue"],
      ["private_key=myprivkey", "myprivkey"],
      ["token=mytokenval", "mytokenval"],
      ["cookie=sid=SECRETCOOKIE", "SECRETCOOKIE"],
      ['password="my secret pass"', "secret pass"],
      ["Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"],
      ["key=ASIAIOSFODNN7EXAMPLE", "ASIAIOSFODNN7EXAMPLE"],
      ["-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK", "MIIEowIBAAK"],
      ["postgres://user:pgpass@host/db", "pgpass"],
      ["https://:ghp_secret123@github.com/org/repo", "ghp_secret123"],
    ]) {
      assert.ok(
        !redactText(rawSecret).includes(leaked),
        `expected redaction of ${leaked} in ${rawSecret}`,
      );
    }
    assert.doesNotThrow(() =>
      assertLearningText("Test authorization: verify that user B cannot read user A data."),
    );
    assert.doesNotThrow(() =>
      assertLearningText("Verify password: check minimum length policy."),
    );
    assert.throws(() => assertLearningText("bad\x00char"), /Control characters/);
    assert.equal(redact({ "x-api-key": "SEC1", "proxy-authorization": "SEC2" })["x-api-key"], "<REDACTED>");
    assert.equal(typeof redact(new Date()), "string");
    assert.equal(redact(new Error("boom secret=abc")).message, "boom secret=<REDACTED>");
    assert.ok(Array.isArray(redact(new Set(["secret=xyz"]))));
    assert.ok(Array.isArray(redact(new Map([["password", "xyz"]]))));
    assert.deepEqual(parseObject('```json{"ok":true}```'), { ok: true });
    assert.throws(() => atomicWrite("", "x"), /Invalid file path/);

    const savedHome = process.env.HOME;
    const savedUserProfile = process.env.USERPROFILE;
    delete process.env.HOME;
    delete process.env.USERPROFILE;
    try {
      assert.match(scopeFor(workspace), /^project-[a-f0-9]{24}$/);
    } finally {
      if (savedHome !== undefined) process.env.HOME = savedHome;
      if (savedUserProfile !== undefined) process.env.USERPROFILE = savedUserProfile;
    }

    // -----------------------------------------------------------------------
    // 6. src/tool-registry.ts, tool-catalog.ts, tool-gap.ts, installable.ts
    // -----------------------------------------------------------------------
    const reg = new ToolRegistry(state);
    const cand = reg.propose(scopeA, {
      name: "argv-checker",
      description: "Check argv execution and SQLi parsing",
      language: "mjs",
      source: "console.log(process.argv[2] === 'pos' ? 'pos-unique-output' : 'neg-unique-output');",
    });
    const posOut = spawnSync(process.execPath, [cand.file, "pos"], { encoding: "utf8" }).stdout;
    const negOut = spawnSync(process.execPath, [cand.file, "neg"], { encoding: "utf8" }).stdout;

    // Trivial contains & identical pos/neg output rejected:
    assert.throws(
      () =>
        reg.validate(
          scopeA,
          cand.id,
          [
            { observationId: "p1", contains: "pos-unique-output", kind: "positive" },
            { observationId: "n1", contains: "pos-unique-output", kind: "negative" },
          ],
          () => [
            { id: "p1", scope: scopeA, tool: "cyber_process", success: true, output: posOut, input: { argv: ["node", cand.file, "pos"] } },
            { id: "n1", scope: scopeA, tool: "cyber_process", success: true, output: posOut, input: { argv: ["node", cand.file, "neg"] } },
          ],
        ),
      /different outputs/,
    );
    assert.throws(
      () =>
        reg.validate(
          scopeA,
          cand.id,
          [
            { observationId: "p1", contains: "true", kind: "positive" },
            { observationId: "n1", contains: "neg-unique-output", kind: "negative" },
          ],
          () => [
            { id: "p1", scope: scopeA, tool: "cyber_process", success: true, output: "true pos-unique-output", input: { argv: ["node", cand.file, "pos"] } },
            { id: "n1", scope: scopeA, tool: "cyber_process", success: true, output: negOut, input: { argv: ["node", cand.file, "neg"] } },
          ],
        ),
      /exact candidate/,
    );
    // Hardened directInvocation rejects -e / -c / < / > / \r / ${...} / non-executed target:
    for (const badInput of [
      { command: `node -e "console.log('x')" ${cand.file}` },
      { command: `node ${cand.file} > /tmp/out` },
      { command: `node ${cand.file}\r` },
      { command: `node ${cand.file} \${IFS}` },
      { argv: ["node", "-e", "x", cand.file] },
      { argv: ["bash", "-c", "x", cand.file] },
    ]) {
      assert.throws(
        () =>
          reg.validate(
            scopeA,
            cand.id,
            [
              { observationId: "p1", contains: "pos-unique-output", kind: "positive" },
              { observationId: "n1", contains: "neg-unique-output", kind: "negative" },
            ],
            () => [
              { id: "p1", scope: scopeA, tool: "cyber_process", success: true, output: posOut, input: badInput },
              { id: "n1", scope: scopeA, tool: "cyber_process", success: true, output: negOut, input: { argv: ["node", cand.file, "neg"] } },
            ],
          ),
        /exact candidate/,
      );
    }

    // cyber_process argv validation + matchExecution works!
    const validated = reg.validate(
      scopeA,
      cand.id,
      [
        { observationId: "p1", contains: "pos-unique-output", kind: "positive" },
        { observationId: "n1", contains: "neg-unique-output", kind: "negative" },
      ],
      () => [
        { id: "p1", scope: scopeA, tool: "cyber_process", success: true, output: posOut, input: { action: "run", argv: [process.execPath, cand.file, "pos"] } },
        { id: "n1", scope: scopeA, tool: "cyber_process", success: true, output: negOut, input: { action: "run", argv: [process.execPath, cand.file, "neg"] } },
      ],
    );
    assert.equal(validated.status, "validated");
    const activated = reg.activate(scopeA, cand.id);
    assert.deepEqual(
      reg.matchExecution(scopeA, { action: "run", argv: [process.execPath, activated.file, "pos"] }, "cyber_process"),
      { name: "argv-checker", version: 1, scope: scopeA },
    );

    // Global promotion strips project tests and checks description/tests/bare domains/Windows paths:
    const globalCand = reg.activate(scopeA, cand.id, true);
    assert.deepEqual(globalCand.tests, []);
    reg.retire(scopeA, "argv-checker", true);
    assert.equal(reg.rollback(scopeA, "argv-checker", globalCand.version, true).status, "active");
    const badGlobal = reg.propose(scopeA, {
      name: "bad-global-desc",
      description: "Probe internal.corp.net endpoint",
      language: "mjs",
      source: "console.log(process.argv[2] === '1' ? 'alpha-out' : 'beta-out');",
    });
    reg.validate(
      scopeA,
      badGlobal.id,
      [
        { observationId: "gp", contains: "alpha-out", kind: "positive" },
        { observationId: "gn", contains: "beta-out", kind: "negative" },
      ],
      () => [
        { id: "gp", scope: scopeA, tool: "cyber_process", success: true, output: "alpha-out\n", input: { argv: ["node", badGlobal.file, "1"] } },
        { id: "gn", scope: scopeA, tool: "cyber_process", success: true, output: "beta-out\n", input: { argv: ["node", badGlobal.file, "2"] } },
      ],
    );
    assert.throws(() => reg.activate(scopeA, badGlobal.id, true), /target\/customer/);

    // toolNote prototype guard + 2-char & synonym tool gaps + MCP cap in context():
    assert.equal(toolNote("constructor"), undefined);
    assert.equal(toolNote("__proto__"), undefined);
    const gaps = identifyToolGaps(
      ["xss", "ad enumeration"],
      [
        { name: "dalfox", origin: "path", description: toolNote("dalfox") },
        { name: "bloodhound", origin: "path", description: toolNote("bloodhound") },
      ],
    );
    assert.equal(gaps[0].candidates[0].name, "dalfox");
    assert.equal(gaps[1].candidates[0].name, "bloodhound");

    const noisyHost = Array.from({ length: 10 }, (_, i) => ({
      name: `burpsuite_tool_${i}`,
      description: "Proxy action",
    }));
    const ctxOut = reg.context(scopeA, "", noisyHost);
    assert.ok(ctxOut.includes("argv-checker"), "managed tool surfaces ahead of MCP noise");
    assert.ok(
      (ctxOut.match(/burpsuite_tool_/g) ?? []).length <= 2,
      "MCP noise is capped in context()",
    );

    // scan() JS header parsing (// and /* */), cache key explicit flag, 2-char/synonym discover, installable checks:
    const jsDir = path.join(workspace, "js-tools");
    fs.mkdirSync(path.join(jsDir, "01-web"), { recursive: true });
    const jsTool = path.join(jsDir, "js-probe.mjs");
    fs.writeFileSync(jsTool, "// Inspect JWT claims safely.\nconsole.log('ok');\n", { mode: 0o755 });
    const blockJsTool = path.join(jsDir, "01-web", "sqli-check.ts");
    fs.writeFileSync(blockJsTool, "/**\n * Automated SQLi differential scanner.\n */\nexport {};\n", { mode: 0o755 });
    const savedPath = process.env.PATH;
    const savedHomeEnv = process.env.HARNESS_TOOL_HOME;
    process.env.PATH = jsDir;
    delete process.env.HARNESS_TOOL_HOME;
    try {
      const scanned = reg.scan(true);
      assert.match(scanned.find((t) => t.name === "js-probe.mjs").description, /Inspect JWT/);
      if (process.platform !== "win32") {
        assert.equal(scanned.some((t) => t.name === "sqli-check.ts"), false, "PATH does not descend subdirs");
        process.env.HARNESS_TOOL_HOME = jsDir;
        const explicitScanned = reg.scan(false);
        const tsEntry = explicitScanned.find((t) => t.name === "sqli-check.ts");
        assert.ok(tsEntry, "cache key changes when HARNESS_TOOL_HOME makes dir explicit");
        assert.match(tsEntry.description, /Automated SQLi/, "/* */ block comment header is parsed");
        assert.ok(reg.discover(scopeA, "js").tools.some((t) => t.name === "js-probe.mjs"), "2-char security term 'js' preserved");

        const nonExec = path.join(jsDir, "not-exec");
        fs.writeFileSync(nonExec, "#!/bin/sh\n", { mode: 0o644 });
        assert.equal(isPresent("not-exec"), false, "non-executable file is not present on POSIX");
        const impBin = path.join(jsDir, "impacket-secretsdump");
        fs.writeFileSync(impBin, "#!/bin/sh\n", { mode: 0o755 });
        assert.equal(ensure("impacket").wasPresent, true, "impacket detects impacket-secretsdump");

        if (typeof process.getuid !== "function" || process.getuid() !== 0) {
          const aptLog = path.join(workspace, "sudo-args.txt");
          fs.writeFileSync(
            path.join(jsDir, "sudo"),
            `#!/bin/sh\nprintf '%s\\n' "$*" > ${JSON.stringify(aptLog)}\nexit 1\n`,
            { mode: 0o755 },
          );
          fs.writeFileSync(path.join(jsDir, "apt-get"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
          const aptRes = ensure("nmap");
          assert.equal(aptRes.installed, false);
          const recorded = fs.readFileSync(aptLog, "utf8");
          assert.match(recorded, /-n/);
          assert.match(recorded, /DEBIAN_FRONTEND=noninteractive/);
        }
      }
    } finally {
      process.env.PATH = savedPath;
      if (savedHomeEnv === undefined) delete process.env.HARNESS_TOOL_HOME;
      else process.env.HARNESS_TOOL_HOME = savedHomeEnv;
    }

    // -----------------------------------------------------------------------
    // 7. src/phases.ts & src/observation-id.ts
    // -----------------------------------------------------------------------
    assert.equal(
      detectPhase({
        toolsUsed: ["cyber_report"],
        observationCount: 5,
        surfacesTotal: 2,
        surfacesTested: 2,
        surfacesUntested: 0,
        surfacesInProgress: 0,
        confirmedFindings: 1,
        consecutiveExploitFailures: 0,
      }),
      "report",
    );
    const expDirective = phaseDirective(
      {
        toolsUsed: ["sqlmap"],
        observationCount: 15,
        surfacesTotal: 3,
        surfacesTested: 3,
        surfacesUntested: 0,
        surfacesInProgress: 0,
        confirmedFindings: 1,
        consecutiveExploitFailures: 0,
      },
      [],
    );
    assert.equal(expDirective?.phase, "post-exploit");
    assert.notEqual(
      observationId("a:b", "c"),
      observationId("a", "b:c"),
      "observationId uses prefix-free delimiter",
    );

    store.close();
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
};
