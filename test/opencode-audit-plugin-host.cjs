/**
 * Stage-2 regression & security suite for OpenCode plugin host, tools,
 * permissions, ledger/workflow wrappers, and unconditional neutrality checks.
 */
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { makeContext, loadPlugin, unloadPlugins } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");
const PLUGIN = path.join(CORE, "opencode", "plugin.ts");

const TINY_PNG = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
  0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
  0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
  0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41,
  0x54, 0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00,
  0x00, 0x00, 0x02, 0x00, 0x01, 0xe2, 0x21, 0xbc,
  0x33, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e,
  0x44, 0xae, 0x42, 0x60, 0x82,
]);

function encodeWsTextFrame(text) {
  const payload = Buffer.from(text, "utf8");
  if (payload.length < 126) {
    return Buffer.concat([Buffer.from([0x81, payload.length]), payload]);
  }
  const header = Buffer.alloc(4);
  header[0] = 0x81;
  header[1] = 126;
  header.writeUInt16BE(payload.length, 2);
  return Buffer.concat([header, payload]);
}

function startMockCdpServer(pngBase64) {
  return new Promise((resolve) => {
    const sockets = new Set();
    let serverPort = 0;
    const server = http.createServer((req, res) => {
      if (req.url === "/json" || req.url === "/json/list") {
        res.writeHead(200, {
          "content-type": "application/json",
          connection: "close",
        });
        res.end(
          JSON.stringify([
            {
              type: "page",
              title: "Mock Isolated Page",
              url: "http://127.0.0.1/mock",
              webSocketDebuggerUrl: `ws://127.0.0.1:${serverPort}/devtools/page/1`,
            },
          ]),
        );
        return;
      }
      res.writeHead(404);
      res.end();
    });
    server.on("upgrade", (req, socket) => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
      const key = req.headers["sec-websocket-key"];
      const accept = crypto
        .createHash("sha1")
        .update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
        .digest("base64");
      socket.write(
        "HTTP/1.1 101 Switching Protocols\r\n" +
          "Upgrade: websocket\r\n" +
          "Connection: Upgrade\r\n" +
          `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
      );
      let replied = false;
      socket.on("data", (buf) => {
        if (!replied) {
          replied = true;
          socket.write(
            encodeWsTextFrame(JSON.stringify({ id: 1, result: { data: pngBase64 } })),
          );
          return;
        }
        if ((buf[0] & 0x0f) === 0x08) {
          socket.end(Buffer.from([0x88, 0x00]));
        }
      });
    });
    server.listen(0, "127.0.0.1", () => {
      serverPort = server.address().port;
      resolve({
        port: serverPort,
        close: () =>
          new Promise((r) => {
            for (const s of sockets) s.destroy();
            server.closeAllConnections?.();
            server.close(r);
          }),
      });
    });
  });
}

module.exports = async ({ assert, jiti, skip }) => {
  const savedEnv = {
    HARNESS_STATE_ROOT: process.env.HARNESS_STATE_ROOT,
    HARNESS_CORE: process.env.HARNESS_CORE,
    HARNESS_ROUTER: process.env.HARNESS_ROUTER,
    HARNESS_CAPTURE_TERMINAL: process.env.HARNESS_CAPTURE_TERMINAL,
    HARNESS_VERIFIER: process.env.HARNESS_VERIFIER,
  };
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-audit-host-"));
  const state = path.join(workspace, "state");
  const projA = path.join(workspace, "proj-a");
  const projB = path.join(workspace, "proj-b");
  const projC = path.join(workspace, "proj-c");
  const engagement = path.join(workspace, "engagement");
  fs.mkdirSync(state, { recursive: true });
  fs.mkdirSync(projA, { recursive: true });
  fs.mkdirSync(projB, { recursive: true });
  fs.mkdirSync(projC, { recursive: true });
  fs.mkdirSync(engagement, { recursive: true });
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;
  process.env.HARNESS_CAPTURE_TERMINAL = "off";

  const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
  const { PlatformStore } = jiti(path.join(CORE, "src", "platform-store.ts"));
  const { SkillUpdater, GLOBAL_SCOPE } = jiti(path.join(CORE, "src", "skills.ts"));
  const { ToolRegistry } = jiti(path.join(CORE, "src", "tool-registry.ts"));
  const { ProcessRegistry, processStatus, verifiedOutcome } = jiti(
    path.join(CORE, "src", "process.ts"),
  );
  const { observationId } = jiti(path.join(CORE, "src", "observation-id.ts"));
  const { scopeFor, hash } = jiti(path.join(CORE, "src", "util.ts"));
  const { DEFAULT_CONFIG } = jiti(path.join(CORE, "src", "types.ts"));
  const { EXTERNAL_METHODS, SHIPPED_METHODS } = jiti(
    path.join(CORE, "src", "routing.ts"),
  );
  const {
    assertOperatorDecision,
    assertProcessPermission,
    default: plugin,
  } = jiti(PLUGIN);

  const knowledge = new KnowledgeStore(path.join(state, "knowledge.sqlite"));
  const platform = new PlatformStore(path.join(state, "platform.sqlite"), knowledge);
  const skills = new SkillUpdater(state, knowledge, DEFAULT_CONFIG);
  const registry = new ProcessRegistry(state);
  const toolRegistry = new ToolRegistry(state);

  try {
    // ── 1. Neutrality unconditional check & lockfile license ──────────────
    const { checkNeutrality } = require("../scripts/check-neutrality.cjs");
    const mockSrc = path.join(workspace, "mock-src");
    fs.mkdirSync(mockSrc, { recursive: true });
    fs.writeFileSync(path.join(mockSrc, "leak.ts"), 'export const x = "boa-token";\n');
    const neut = checkNeutrality(mockSrc);
    assert.ok(
      neut.offenders.some((line) => line.includes("hardcoded client prefix")),
      "checkNeutrality catches hardcoded client prefixes unconditionally by default",
    );
    const pkg = JSON.parse(fs.readFileSync(path.join(CORE, "package.json"), "utf8"));
    const lock = JSON.parse(fs.readFileSync(path.join(CORE, "package-lock.json"), "utf8"));
    assert.equal(lock.packages[""].license, pkg.license, "package-lock license matches package.json");

    // ── 2. Permissions anti-deadlock when subscribe ignores AbortSignal ───
    const hungApi = {
      permission: {},
      event: {
        subscribe: async function* () {
          await new Promise(() => {});
        },
      },
    };
    const t0 = Date.now();
    await assertProcessPermission(
      hungApi,
      { sessionID: "ses_perm", agent: "build", messageID: "m1", id: "c1", signal: new AbortController().signal },
      "echo ok",
      async (args) => {
        if (args[0] === "get") return { pid: process.pid };
        return { data: { id: JSON.parse(args[3]).id, effect: "allow" } };
      },
    );
    assert.ok(Date.now() - t0 < 2000, "assertProcessPermission does not deadlock on hung subscribe");

    const ac = new AbortController();
    setTimeout(() => ac.abort(new Error("cancelled")), 30);
    await assert.rejects(
      () =>
        assertOperatorDecision(
          hungApi,
          { sessionID: "ses_perm", agent: "build", messageID: "m2", id: "c2", signal: ac.signal },
          "approve:hung",
          async (args) => {
            if (args[0] === "get") return { pid: process.pid };
            return { data: { id: JSON.parse(args[3]).id, effect: "ask" } };
          },
        ),
      /cancelled|Aborted/,
      "assertOperatorDecision unblocks on signal abort even if subscribe hangs",
    );

    // ── 3. Repo-wide skills + multi-scope + GLOBAL_SCOPE archiveUnused ────
    const scopeA = scopeFor(projA);
    const scopeB = scopeFor(projB);
    const scopeC = scopeFor(projC);
    for (const [sid, sc, dir] of [
      ["ses_a1", scopeA, projA],
      ["ses_a2", scopeA, projA],
      ["ses_b1", scopeB, projB],
      ["ses_b2", scopeB, projB],
      ["ses_c1", scopeC, projC],
      ["ses_c2", scopeC, projC],
    ]) {
      knowledge.upsertSession({
        id: sid,
        scope: sc,
        cwd: dir,
        status: "completed",
        updatedAt: new Date().toISOString(),
      });
    }
    const oldStamp = new Date(Date.now() - 60 * 86_400_000).toISOString();
    const g1 = knowledge.recordObservation({
      id: "obs-g1", sessionId: "ses_c1", scope: scopeC, tool: "shell",
      input: {}, output: "global method proof alpha", success: true, timestamp: oldStamp,
    });
    const g2 = knowledge.recordObservation({
      id: "obs-g2", sessionId: "ses_c2", scope: scopeC, tool: "shell",
      input: {}, output: "global method proof alpha", success: true, timestamp: oldStamp,
    });
    const b1 = knowledge.recordObservation({
      id: "obs-b1", sessionId: "ses_b1", scope: scopeB, tool: "shell",
      input: {}, output: "local method proof beta", success: true, timestamp: new Date().toISOString(),
    });
    const b2 = knowledge.recordObservation({
      id: "obs-b2", sessionId: "ses_b2", scope: scopeB, tool: "shell",
      input: {}, output: "local method proof beta", success: true, timestamp: new Date().toISOString(),
    });
    skills.propose(scopeC, {
      name: "shared-audit-method",
      description: "Reusable verification procedure across scopes.",
      category: "investigation-patterns",
      prerequisites: [],
      procedure: ["Run positive check.", "Run differential negative check."],
      validation: [{ observationId: g1.id, contains: "global method proof" }],
      evidence: [g1.id, g2.id],
    });
    skills.promote(scopeC, "shared-audit-method");

    // Seed an old idle global skill that SHOULD be archived by startup archiveUnused(GLOBAL_SCOPE)
    skills.propose(scopeC, {
      name: "stale-global-method",
      description: "Idle global method slated for archival.",
      category: "investigation-patterns",
      prerequisites: [],
      procedure: ["Check output.", "Record observation."],
      validation: [{ observationId: g1.id, contains: "global method proof" }],
      evidence: [g1.id, g2.id],
    });
    skills.promote(scopeC, "stale-global-method");
    // Give shared-audit-method a recent GLOBAL_SCOPE exposure so only stale-global-method archives
    knowledge.audit(GLOBAL_SCOPE, "skills.exposure", {
      sessionID: "ses_prior",
      skills: [{ name: "shared-audit-method" }],
    });

    // Local skill in scopeB (different from instanceCwd projA)
    skills.propose(scopeB, {
      name: "local-b-method",
      description: "Procedure specific to project B.",
      category: "investigation-patterns",
      prerequisites: [],
      procedure: ["Probe endpoint.", "Compare response."],
      validation: [{ observationId: b1.id, contains: "local method proof" }],
      evidence: [b1.id, b2.id],
    });

    const fixture = makeContext(projA);
    fixture.sessions.set("ses_b1", projB);
    await loadPlugin(plugin, fixture.ctx);

    // Startup archived stale-global-method from GLOBAL_SCOPE, kept shared-audit-method
    assert.equal(
      skills.active(scopeA).some((e) => e.revision.name === "stale-global-method"),
      false,
      "startup archiveUnused(GLOBAL_SCOPE) archives idle global method",
    );
    assert.equal(
      skills.active(scopeA).some((e) => e.revision.name === "shared-audit-method"),
      true,
      "recently exposed global method survives GLOBAL_SCOPE archive",
    );

    // All repo skills registered dynamically
    for (const id of [...SHIPPED_METHODS, "harness-cyber-playbooks", ...EXTERNAL_METHODS]) {
      assert.ok(fixture.skills.has(id), `repo skill ${id} is served by ctx.skill.transform`);
    }

    // Trigger scopeB resolution so scopeCache learns scopeB, then reload skills
    await fixture.hooks.get("context")(fixture.contextEvent({ sessionID: "ses_b1" }));
    await fixture.ctx.skill.reload();
    assert.ok(
      fixture.skills.has("harness.learned.local-b-method"),
      "learned skill from session scopeB is served alongside instanceCwd scopeA",
    );
    assert.ok(
      fixture.skills.has("harness.learned.shared-audit-method"),
      "global learned skill is served without duplicating IDs",
    );
    assert.ok(
      knowledge.audits(GLOBAL_SCOPE, "skills.exposure", 20).length >= 2,
      "context hook records GLOBAL_SCOPE exposure when global learned skills are active",
    );

    // ── 4. Idle active session in cyber_lessons + skip digest match ───────
    const idleTime = new Date(Date.now() - 20 * 60_000).toISOString();
    const recentTime = new Date(Date.now() - 2 * 60_000).toISOString();
    knowledge.upsertSession({
      id: "ses_idle_active", scope: scopeA, cwd: projA, status: "active", updatedAt: idleTime,
    });
    const idleObs = knowledge.recordObservation({
      id: "obs-idle-active", sessionId: "ses_idle_active", scope: scopeA, tool: "shell",
      input: {}, output: "idle active marker observed", success: true, timestamp: idleTime,
    });
    knowledge.upsertSession({
      id: "ses_fresh_active", scope: scopeA, cwd: projA, status: "active", updatedAt: recentTime,
    });
    knowledge.recordObservation({
      id: "obs-fresh-active", sessionId: "ses_fresh_active", scope: scopeA, tool: "shell",
      input: {}, output: "fresh active marker", success: true, timestamp: recentTime,
    });
    await assert.rejects(
      () =>
        fixture.tools.get("cyber_lessons").execute(
          { action: "run", sessionId: "ses_fresh_active" },
          { sessionID: "ses_a1", signal: new AbortController().signal },
        ),
      /inactive scoped session/,
      "active session younger than 10 minutes is rejected by cyber_lessons run",
    );
    fixture.answer.value = JSON.stringify({
      knowledge: [{
        key: "idle-active-fact",
        kind: "environment",
        content: "Idle active sessions are eligible for extraction.",
        evidence: [idleObs.id],
      }],
      skills: [],
    });
    const idleRes = JSON.parse(
      (
        await fixture.tools.get("cyber_lessons").execute(
          { action: "run", sessionId: "ses_idle_active" },
          { sessionID: "ses_a1", signal: new AbortController().signal },
        )
      ).content,
    );
    assert.equal(idleRes.facts, 1, "idle active session (>=10m) extracts cleanly");

    // Permanent provider failure skip digest stops pendingLessons infinite retry
    knowledge.upsertSession({
      id: "ses_perm_fail", scope: scopeA, cwd: projA, status: "completed", updatedAt: idleTime,
    });
    knowledge.recordObservation({
      id: "obs-perm-fail", sessionId: "ses_perm_fail", scope: scopeA, tool: "shell",
      input: {}, output: "perm fail obs", success: true, timestamp: idleTime,
    });
    const savedModels = [...fixture.models];
    fixture.models = [{ providerID: "opencode", id: "beam-free" }];
    // Trigger background lesson extraction from context hook on a clean scope
    await fixture.hooks.get("context")(
      fixture.contextEvent({
        sessionID: "ses_a1",
        model: { providerID: "opencode", id: "beam-free" },
      }),
    );
    await new Promise((r) => setTimeout(r, 80));
    fixture.models = savedModels;
    const pendingAfter = JSON.parse(
      (
        await fixture.tools.get("cyber_lessons").execute(
          { action: "pending" },
          { sessionID: "ses_a1", signal: new AbortController().signal },
        )
      ).content,
    );
    assert.equal(
      pendingAfter.pending.includes("ses_perm_fail"),
      false,
      "permanent provider error skip audit uses matching snapshotDigest so pendingLessons stops retrying",
    );

    // ── 5. cyber_finding method gate (HARNESS_ROUTER=off, >200 obs, cyber_method load) ─
    const mGate = platform.createMission(scopeA, "Gate Mission", "Local test only");
    platform.approveScope(scopeA, mGate.id);
    const gateChunks = platform.ingest(scopeA, "src-gate", "test://gate", "Gate Ref", "Gate source");
    knowledge.upsertSession({
      id: "ses_gate", scope: scopeA, cwd: projA, status: "active", updatedAt: new Date().toISOString(),
    });
    const gateRepro = knowledge.recordObservation({
      id: "obs-gate-r", sessionId: "ses_gate", scope: scopeA, tool: "shell",
      input: {}, output: "XSS payload executed", success: true, timestamp: new Date().toISOString(),
    });
    const gateCtrl = knowledge.recordObservation({
      id: "obs-gate-c", sessionId: "ses_gate", scope: scopeA, tool: "shell",
      input: {}, output: "benign escaped", success: true, timestamp: new Date().toISOString(),
    });
    const xssProposal = {
      action: "create",
      missionId: mGate.id,
      title: "Reflected XSS in search",
      severity: "high",
      description: "XSS confirmed via reflected payload.",
      limitations: "Local test.",
      evidence: [gateRepro.id, gateCtrl.id],
      sources: [gateChunks[0].id],
      checks: [
        { observationId: gateRepro.id, contains: "XSS payload", purpose: "reproduction" },
        { observationId: gateCtrl.id, contains: "benign escaped", purpose: "negative-control" },
      ],
    };
    await assert.rejects(
      () =>
        fixture.tools.get("cyber_finding").execute(xssProposal, {
          sessionID: "ses_gate", agent: "build", messageID: "m", id: "c",
          signal: new AbortController().signal,
        }),
      /harness-xss/,
      "enforced XSS finding refuses when harness-xss not loaded",
    );
    process.env.HARNESS_ROUTER = "off";
    const offCreated = JSON.parse(
      (
        await fixture.tools.get("cyber_finding").execute(xssProposal, {
          sessionID: "ses_gate", agent: "build", messageID: "m", id: "c",
          signal: new AbortController().signal,
        })
      ).content,
    );
    assert.ok(offCreated.id, "HARNESS_ROUTER=off bypasses cyber_finding method gate");
    delete process.env.HARNESS_ROUTER;

    // >210 observations after skill load must not push skill load out of gate window
    await fixture.hooks.get("execute.after")({
      tool: "skill",
      sessionID: "ses_deep_obs",
      id: "call-early-skill",
      status: "completed",
      input: { id: "harness-xss" },
      result: { output: "loaded" },
    });
    for (let i = 0; i < 215; i += 1) {
      knowledge.recordObservation({
        id: `obs-pad-${i}`,
        sessionId: "ses_deep_obs",
        scope: scopeA,
        tool: "shell",
        input: {},
        output: `pad-${i}`,
        success: true,
        timestamp: new Date().toISOString(),
      });
    }
    const deepRepro = knowledge.recordObservation({
      id: "obs-deep-r", sessionId: "ses_deep_obs", scope: scopeA, tool: "shell",
      input: {}, output: "XSS payload executed", success: true, timestamp: new Date().toISOString(),
    });
    const deepCtrl = knowledge.recordObservation({
      id: "obs-deep-c", sessionId: "ses_deep_obs", scope: scopeA, tool: "shell",
      input: {}, output: "benign escaped", success: true, timestamp: new Date().toISOString(),
    });
    const deepCreated = JSON.parse(
      (
        await fixture.tools.get("cyber_finding").execute(
          {
            ...xssProposal,
            evidence: [deepRepro.id, deepCtrl.id],
            checks: [
              { observationId: deepRepro.id, contains: "XSS payload", purpose: "reproduction" },
              { observationId: deepCtrl.id, contains: "benign escaped", purpose: "negative-control" },
            ],
          },
          { sessionID: "ses_deep_obs", agent: "build", messageID: "m", id: "c", signal: new AbortController().signal },
        )
      ).content,
    );
    assert.ok(deepCreated.id, "cyber_finding scans full session observations past 200-row cap");

    // cyber_method action="load" satisfies method gate
    knowledge.upsertSession({
      id: "ses_method_load", scope: scopeA, cwd: projA, status: "active", updatedAt: new Date().toISOString(),
    });
    knowledge.recordObservation({
      id: "obs-mload-1",
      sessionId: "ses_method_load",
      scope: scopeA,
      tool: "cyber_method",
      input: { action: "load", name: "harness-sqli" },
      output: "loaded",
      success: true,
      timestamp: new Date().toISOString(),
    });
    const sqliRepro = knowledge.recordObservation({
      id: "obs-sqli-r", sessionId: "ses_method_load", scope: scopeA, tool: "shell",
      input: {}, output: "SQL syntax error leaked", success: true, timestamp: new Date().toISOString(),
    });
    const sqliCtrl = knowledge.recordObservation({
      id: "obs-sqli-c", sessionId: "ses_method_load", scope: scopeA, tool: "shell",
      input: {}, output: "normal query result", success: true, timestamp: new Date().toISOString(),
    });
    const sqliCreated = JSON.parse(
      (
        await fixture.tools.get("cyber_finding").execute(
          {
            action: "create",
            missionId: mGate.id,
            title: "SQLi on /login",
            severity: "high",
            description: "SQL injection confirmed.",
            limitations: "Local test.",
            evidence: [sqliRepro.id, sqliCtrl.id],
            sources: [gateChunks[0].id],
            checks: [
              { observationId: sqliRepro.id, contains: "SQL syntax", purpose: "reproduction" },
              { observationId: sqliCtrl.id, contains: "normal query", purpose: "negative-control" },
            ],
          },
          { sessionID: "ses_method_load", agent: "build", messageID: "m", id: "c", signal: new AbortController().signal },
        )
      ).content,
    );
    assert.ok(sqliCreated.id, "cyber_finding recognizes cyber_method action=load");

    // ── 6. succeeded() metadata.exit===0 + scope collision proofSessionID + sessionCwd ──
    await fixture.hooks.get("execute.after")({
      tool: "shell",
      sessionID: "ses_a1",
      id: "call-exit0-text",
      input: { command: "grep 'Exited with code 1' log.txt" },
      status: "completed",
      result: {
        content: [{ type: "text", text: "log line: Exited with code 1\n" }],
        metadata: { status: "completed", exit: 0 },
      },
    });
    const [exit0Obs] = knowledge.evidence(scopeA, [observationId("ses_a1", "call-exit0-text")]);
    assert.equal(exit0Obs.success, true, "succeeded() trusts metadata.exit === 0 over text");

    // Scope collision: use ses_collision in scopeA first, then in scopeB
    await fixture.hooks.get("execute.after")({
      tool: "shell", sessionID: "ses_collision", id: "call-col-1",
      input: { command: "echo A" }, status: "completed",
      result: { content: [{ type: "text", text: "A" }], metadata: { exit: 0 } },
    });
    fixture.sessions.set("ses_collision", projB);
    await fixture.hooks.get("execute.after")({
      tool: "shell", sessionID: "ses_collision", id: "call-col-2",
      input: { command: "echo B" }, status: "completed",
      result: { content: [{ type: "text", text: "B" }], metadata: { exit: 0 } },
    });
    const collidedId = `${"ses_collision"}:${scopeB.slice(-24)}`;
    const [colB] = knowledge.evidence(scopeB, [observationId("ses_collision", "call-col-2")]);
    assert.equal(colB.sessionId, collidedId, "execute.after stores collided proofSessionID while keeping caller-compatible observationId");
    assert.equal(colB.output, "B");
    const memRecent = JSON.parse(
      (
        await fixture.tools.get("cyber_memory").execute(
          { action: "recent", limit: 10 },
          { sessionID: "ses_collision", agent: "build", messageID: "m", id: "c", signal: new AbortController().signal },
        )
      ).content,
    );
    assert.equal(memRecent[0].id, colB.id, "cyber_memory recent handles scope-colliding sessions via ensureSession");

    // sessionCwd spy: cyber_process run uses cached sessionCwd from scopeOf without second ctx.session.get
    if (process.platform === "linux") {
      let getCalls = 0;
      const origGet = fixture.ctx.session.get;
      fixture.ctx.session.get = async (args) => {
        getCalls += 1;
        return origGet(args);
      };
      const ranProc = JSON.parse(
        (
          await fixture.tools.get("cyber_process").execute(
            { action: "run", argv: [process.execPath, "-e", "console.log('proc-ok')"], timeout: 5 },
            { sessionID: "ses_a1", agent: "build", messageID: "m", id: "c-run", signal: new AbortController().signal },
          )
        ).content,
      );
      fixture.ctx.session.get = origGet;
      assert.equal(getCalls, 1, "cyber_process run uses sessionCwd without redundant session.get");
      const deadline = Date.now() + 8000;
      while (
        !["succeeded", "failed", "timed_out", "stopped"].includes(
          processStatus(registry.get(ranProc.scope, ranProc.id)),
        ) &&
        Date.now() < deadline
      ) {
        await new Promise((r) => setTimeout(r, 30));
      }
      // Tamper trace -> verifiedOutcome throws, cyber_process read handles cleanly, cyber_capture refuses
      fs.appendFileSync(ranProc.logPath, "tampered");
      assert.throws(() => verifiedOutcome(registry.get(ranProc.scope, ranProc.id)), /integrity/);
      const tamperRead = await fixture.tools.get("cyber_process").execute(
        { action: "read", id: ranProc.id },
        { sessionID: "ses_a1", agent: "build", messageID: "m", id: "c-read-tamp", signal: new AbortController().signal },
      );
      assert.equal(tamperRead.metadata.evidenceSuccess, false);
      const parsedTamper = JSON.parse(tamperRead.content);
      assert.equal(parsedTamper.status, "unknown");
      assert.match(parsedTamper.diagnosis, /integrity/i);
      await fixture.hooks.get("execute.after")({
        tool: "cyber_process",
        sessionID: "ses_a1",
        id: "c-read-tamp",
        input: { action: "read", id: ranProc.id },
        status: "completed",
        result: tamperRead,
      });
      await assert.rejects(
        () =>
          fixture.tools.get("cyber_capture").execute(
            { action: "evidence", processId: ranProc.id, observationId: parsedTamper.observationId },
            { sessionID: "ses_a1", agent: "build", messageID: "m", id: "c-cap-tamp", signal: new AbortController().signal },
          ),
        /integrity/,
        "cyber_capture evidence refuses tampered trace",
      );
    }

    // ── 7. cyber_capture browser validation & CDP attach ──────────────────
    const symPng = path.join(workspace, "sym.png");
    const realPng = path.join(workspace, "real.png");
    fs.writeFileSync(realPng, TINY_PNG);
    fs.symlinkSync(realPng, symPng);
    await assert.rejects(
      () =>
        fixture.tools.get("cyber_capture").execute(
          { action: "browser", file: symPng, observationId: exit0Obs.id },
          { sessionID: "ses_a1", agent: "build", messageID: "m", id: "c", signal: new AbortController().signal },
        ),
      /Linked or special/,
      "browser capture rejects symlinked file",
    );
    const badDimsPng = Buffer.from(TINY_PNG);
    badDimsPng.writeUInt32BE(0, 16);
    const zeroDimPath = path.join(workspace, "zero-dim.png");
    fs.writeFileSync(zeroDimPath, badDimsPng);
    await assert.rejects(
      () =>
        fixture.tools.get("cyber_capture").execute(
          { action: "browser", file: zeroDimPath, observationId: exit0Obs.id },
          { sessionID: "ses_a1", agent: "build", messageID: "m", id: "c", signal: new AbortController().signal },
        ),
      /not a valid PNG/,
      "browser capture rejects 0-width PNG IHDR",
    );
    await assert.rejects(
      () =>
        fixture.tools.get("cyber_capture").execute(
          { action: "browser", port: 0, observationId: exit0Obs.id },
          { sessionID: "ses_a1", agent: "build", messageID: "m", id: "c", signal: new AbortController().signal },
        ),
      /CDP port/,
      "browser capture rejects port 0",
    );
    await assert.rejects(
      () =>
        fixture.tools.get("cyber_capture").execute(
          { action: "browser", url: "file:///etc/passwd", observationId: exit0Obs.id },
          { sessionID: "ses_a1", agent: "build", messageID: "m", id: "c", signal: new AbortController().signal },
        ),
      /Unsupported URL scheme/,
      "browser capture rejects file:// URL for isolated mode",
    );
    const mockCdp = await startMockCdpServer(TINY_PNG.toString("base64"));
    try {
      const cdpCap = JSON.parse(
        (
          await fixture.tools.get("cyber_capture").execute(
            { action: "browser", port: mockCdp.port, observationId: exit0Obs.id, label: "cdp" },
            { sessionID: "ses_a1", agent: "build", messageID: "m", id: "c", signal: new AbortController().signal },
          )
        ).content,
      );
      assert.equal(cdpCap.width, 1);
      assert.ok(fs.existsSync(cdpCap.path), "CDP port capture creates valid PNG");
    } finally {
      await mockCdp.close();
    }

    // ── 8. cyber_cve batch/search & cyber_entity import & ledger-tools ────
    await assert.rejects(
      () =>
        fixture.tools.get("cyber_cve").execute(
          { action: "search", technology: "-j" },
          { sessionID: "ses_a1", signal: new AbortController().signal },
        ),
      /start with '-'/,
      "cyber_cve search blocks flag-like technology token",
    );
    await assert.rejects(
      () =>
        fixture.tools.get("cyber_cve").execute(
          { action: "search", technology: "nginx", version: "--help" },
          { sessionID: "ses_a1", signal: new AbortController().signal },
        ),
      /start with '-'/,
      "cyber_cve search blocks flag-like version token",
    );
    const savedFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response("x".repeat(520000), { status: 200 });
    try {
      const batchOut = JSON.parse(
        (
          await fixture.tools.get("cyber_cve").execute(
            {
              action: "batch",
              packages: [
                { ecosystem: "npm", package: "bad pkg!" },
                { ecosystem: "npm", package: "lodash", version: "1 2" },
                { ecosystem: "npm", package: "lodash", version: "4.17.21" },
              ],
            },
            { sessionID: "ses_a1", signal: new AbortController().signal },
          )
        ).content,
      );
      assert.equal(batchOut.batch[0].error, "invalid");
      assert.equal(batchOut.batch[1].error, "invalid");
      assert.equal(batchOut.batch[2].error, "osv-too-large");
    } finally {
      globalThis.fetch = savedFetch;
    }

    // cyber_entity import without mission root still enforces assertPlainPath & validates observationIds on empty plan
    const emptyDump = path.join(workspace, "comments-only.txt");
    fs.writeFileSync(emptyDump, "# only comments\n\n");
    const symDump = path.join(workspace, "sym-dump.txt");
    fs.symlinkSync(emptyDump, symDump);
    await assert.rejects(
      () =>
        fixture.tools.get("cyber_entity").execute(
          { action: "import", path: symDump, format: "lines", observationIds: [b1.id] },
          { sessionID: "ses_b1", signal: new AbortController().signal },
        ),
      /Linked or special/,
      "cyber_entity import enforces assertPlainPath even without mission root",
    );
    await assert.rejects(
      () =>
        fixture.tools.get("cyber_entity").execute(
          { action: "import", path: emptyDump, format: "lines", observationIds: ["obs-missing-999"] },
          { sessionID: "ses_b1", signal: new AbortController().signal },
        ),
      /Missing evidence/,
      "cyber_entity import validates observationIds even when plan.entities is empty",
    );

    // ledger-tools: cyber_tasks assets filters existing before slice(0,50) & export assertPlainPath & investigation guards
    const mEng = platform.createMission(scopeB, "Asset Mission", "Local test", undefined, engagement);
    const { TaskStore } = jiti(path.join(CORE, "src", "tasks.ts"));
    const tStore = new TaskStore(state);
    for (let i = 0; i < 55; i += 1) {
      const hKey = `h${String(i).padStart(2, "0")}.example.test`;
      platform.upsertEntity(scopeB, { type: "host", key: hKey, observationIds: [b1.id] });
      if (i < 52) {
        tStore.add(scopeB, { title: `host:${hKey}` });
      }
    }
    const assetsRes = JSON.parse(
      (
        await fixture.tools.get("cyber_tasks").execute(
          { action: "assets" },
          { sessionID: "ses_b1", signal: new AbortController().signal },
        )
      ).content,
    );
    assert.equal(assetsRes.assets, 3, "assets filters existing tasks before slicing 50");
    assert.ok(assetsRes.created.length > 0);

    const targetMap = path.join(engagement, "couverture.md");
    const realMap = path.join(workspace, "real-map.md");
    fs.writeFileSync(realMap, "real");
    fs.symlinkSync(realMap, targetMap);
    await assert.rejects(
      () =>
        fixture.tools.get("cyber_tasks").execute(
          { action: "export" },
          { sessionID: "ses_b1", signal: new AbortController().signal },
        ),
      /Linked or special/,
      "cyber_tasks export uses assertPlainPath on couverture.md",
    );

    await assert.rejects(
      () =>
        fixture.tools.get("cyber_investigation").execute(
          { action: "surface", op: "add", id: "../escape", label: "Web" },
          { sessionID: "ses_b1", signal: new AbortController().signal },
        ),
      /Invalid surface id/,
      "surface add validates input.id",
    );
    await assert.rejects(
      () =>
        fixture.tools.get("cyber_investigation").execute(
          { action: "hypothesis", op: "propose", id: " ", text: "Test" },
          { sessionID: "ses_b1", signal: new AbortController().signal },
        ),
      /Invalid hypothesis id/,
      "hypothesis propose validates input.id",
    );
    await fixture.tools.get("cyber_investigation").execute(
      { action: "surface", op: "add", id: "surf-ok", label: "Login" },
      { sessionID: "ses_b1", signal: new AbortController().signal },
    );
    const badB = knowledge.recordObservation({
      id: "obs-b-fail", sessionId: "ses_b1", scope: scopeB, tool: "shell",
      input: {}, output: "failed", success: false, timestamp: new Date().toISOString(),
    });
    await assert.rejects(
      () =>
        fixture.tools.get("cyber_investigation").execute(
          { action: "surface", op: "complete", id: "surf-ok", evidence: [b1.id, badB.id] },
          { sessionID: "ses_b1", signal: new AbortController().signal },
        ),
      /successful observations/,
      "surface complete requires ALL evidence observations to succeed",
    );

    // unused variable check silence
    assert.ok(toolRegistry);
    assert.ok(mGate);
    assert.ok(mEng);
  } finally {
    knowledge.close();
    platform.close();
    await unloadPlugins();
    for (const [key, val] of Object.entries(savedEnv)) {
      if (val === undefined) delete process.env[key];
      else process.env[key] = val;
    }
    fs.rmSync(workspace, { recursive: true, force: true });
  }
};
