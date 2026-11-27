/**
 * Regression & security suite for capture, runtime supervision, scripts, and CLI.
 */
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
const { pathToFileURL } = require("node:url");

const CORE = path.resolve(__dirname, "..");

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

function startWsServer(onUpgrade) {
  return new Promise((resolve) => {
    const sockets = new Set();
    const server = http.createServer((req, res) => {
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
      onUpgrade(socket);
    });
    server.listen(0, "127.0.0.1", () => {
      resolve({
        port: server.address().port,
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

module.exports = async ({ assert, jiti }) => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "harness-audit-cap-"));
  try {
    // ── 1. src/capture.ts ─────────────────────────────────────────────────
    const {
      assertNotRoot,
      captureDestination,
      captureLink,
      captureName,
      selectWindowById,
    } = jiti(path.join(CORE, "src", "capture.ts"));

    assert.throws(() => assertNotRoot("0x4dd", "1245"), /desktop is not a subject/);
    assert.throws(() => assertNotRoot("0x4dd", "0x04dd"), /desktop is not a subject/);
    assert.throws(() => assertNotRoot("1245", "0x4dd"), /desktop is not a subject/);
    assert.throws(() => assertNotRoot("0x4dd", "0"), /desktop is not a subject/);
    assert.throws(() => assertNotRoot("0x4dd", "0x00"), /desktop is not a subject/);
    assert.doesNotThrow(() => assertNotRoot("0x4dd", "Firefox"));
    assert.doesNotThrow(() => assertNotRoot("0x4dd", "1246"));

    assert.equal(
      selectWindowById([{ id: "1245", title: "Root" }], "0x4dd").title,
      "Root",
      "selectWindowById matches hex and decimal window IDs",
    );

    assert.equal(
      captureName("obs_1:2.345"),
      "obs-1-2-345",
      "captureName normalizes _, ., : in observationId",
    );
    assert.equal(
      captureName("obs12345", "!!!"),
      "obs12345",
      "captureName drops punctuation-only labels without trailing dash",
    );
    assert.equal(
      captureName("obs12345", `${"a".repeat(39)}-b`),
      `obs12345-${"a".repeat(39)}`,
      "captureName trims trailing dash after 40-char slice",
    );
    assert.throws(() => captureName("obs_1"), /Invalid capture name/);
    assert.throws(() => captureName("a".repeat(81)), /Invalid capture name/);

    const capDir = path.join(work, "cap-root");
    fs.mkdirSync(capDir, { recursive: true });
    assert.doesNotThrow(() => captureDestination(capDir, "obs-12345678"));
    const symCapDir = path.join(work, "cap-sym");
    fs.symlinkSync(capDir, symCapDir, "dir");
    assert.throws(
      () => captureDestination(symCapDir, "obs-12345678"),
      /Linked or special harness paths/,
      "captureDestination enforces assertPlainPath on root",
    );

    const validResult = {
      path: path.join(capDir, "obs-12345678.png"),
      bytes: 100,
      window: "0x123",
      title: "Browser",
      width: 800,
      height: 600,
    };
    assert.doesNotThrow(() =>
      captureLink("obs-12345678", validResult, "2026-11-27T00:00:00.000Z"),
    );
    assert.throws(
      () =>
        captureLink(
          "obs-12345678",
          { ...validResult, width: 0 },
          "2026-11-27T00:00:00.000Z",
        ),
      /Invalid capture dimensions/,
    );
    assert.throws(
      () =>
        captureLink(
          "obs-12345678",
          { ...validResult, height: -5 },
          "2026-11-27T00:00:00.000Z",
        ),
      /Invalid capture dimensions/,
    );
    assert.throws(
      () =>
        captureLink(
          "obs-12345678",
          { ...validResult, bytes: 0 },
          "2026-11-27T00:00:00.000Z",
        ),
      /Invalid capture size/,
    );
    assert.throws(
      () => captureLink("obs-12345678", validResult, "not-a-date"),
      /Invalid capture timestamp/,
    );

    // ── 2. opencode/display.ts ────────────────────────────────────────────
    const displayMod = jiti(path.join(CORE, "opencode", "display.ts"));
    assert.equal(
      "waitForTerminalCommand" in displayMod,
      false,
      "dead waitForTerminalCommand helper was removed",
    );
    assert.equal(typeof displayMod.hasXvfb, "function");
    assert.equal(typeof displayMod.captureBrowserIsolated, "function");
    assert.throws(
      () =>
        displayMod.captureBrowserIsolated({
          url: "file:///etc/passwd",
          dest: path.join(work, "x.png"),
        }),
      /Unsupported URL scheme/,
    );

    // ── 3. scripts/capture_browser.mjs validation & WS behavior ───────────
    const browserMod = await import(
      pathToFileURL(path.join(CORE, "scripts", "capture_browser.mjs")).href
    );
    assert.throws(() => browserMod.validatePort(0), /out of range/);
    assert.throws(() => browserMod.validatePort(65536), /out of range/);
    assert.throws(() => browserMod.validatePort("abc"), /Invalid CDP port/);
    assert.equal(browserMod.validatePort("9222"), 9222);

    assert.throws(
      () => browserMod.validateLoopbackWsUrl("ws://192.168.1.10:9222/devtools/page/1"),
      /non-loopback/,
    );
    assert.throws(
      () => browserMod.validateLoopbackWsUrl("wss://127.0.0.1:9222/devtools/page/1"),
      /Unsupported WebSocket protocol/,
    );
    assert.doesNotThrow(() =>
      browserMod.validateLoopbackWsUrl("ws://127.0.0.1:9222/devtools/page/1"),
    );

    assert.throws(
      () => browserMod.parseArgs([path.join(symCapDir, "shot.png")]),
      /Linked or special harness paths/,
      "capture_browser rejects symlinked destination path",
    );
    assert.throws(
      () => browserMod.parseArgs([path.join(work, "a.png"), "--port", "99999"]),
      /out of range/,
    );
    assert.throws(
      () => browserMod.parseArgs([path.join(work, "a.png"), "--isolated"]),
      /Launch URL is required/,
    );

    // Test WS timer preservation when malformed JSON / non-matching events arrive first.
    const wsHang = await startWsServer((socket) => {
      socket.write(encodeWsTextFrame("{bad json"));
      socket.write(encodeWsTextFrame(JSON.stringify({ method: "Page.loadEventFired" })));
      socket.write(encodeWsTextFrame(JSON.stringify({ id: 99, result: { data: "" } })));
    });
    await assert.rejects(
      () =>
        browserMod.cdpScreenshot(
          `ws://127.0.0.1:${wsHang.port}/devtools/page/1`,
          250,
          false,
        ),
      /CDP timeout/,
      "unrelated/malformed WS frames do not cancel the CDP timeout",
    );
    await wsHang.close();

    const pngB64 = TINY_PNG.toString("base64");
    const wsOk = await startWsServer((socket) => {
      socket.write(encodeWsTextFrame("not-json"));
      socket.write(encodeWsTextFrame(JSON.stringify({ method: "Runtime.consoleAPICalled" })));
      socket.write(encodeWsTextFrame(JSON.stringify({ id: 1, result: { data: pngB64 } })));
    });
    const gotShot = await browserMod.cdpScreenshot(
      `ws://127.0.0.1:${wsOk.port}/devtools/page/1`,
      2000,
      false,
    );
    assert.equal(gotShot, pngB64, "cdpScreenshot resolves when msg.id === 1 arrives after events");
    await wsOk.close();

    const cliInvalidPort = spawnSync(
      process.execPath,
      [path.join(CORE, "scripts", "capture_browser.mjs"), path.join(work, "out.png"), "--port", "0"],
      { encoding: "utf8" },
    );
    assert.notEqual(cliInvalidPort.status, 0, "CLI rejects invalid --port");

    // Exercise isolated Chromium capture if browser binary is installed.
    if (displayMod.findBrowserExecutable()) {
      const srvProc = spawn(
        process.execPath,
        [
          "-e",
          'require("node:http").createServer((_,res)=>{res.writeHead(200,{"content-type":"text/html"});res.end("<html><body><h1>Isolated Harness Test</h1></body></html>")}).listen(0,"127.0.0.1",function(){console.log(this.address().port)})',
        ],
        { stdio: ["ignore", "pipe", "ignore"] },
      );
      const srvPort = await new Promise((resolve, reject) => {
        let out = "";
        srvProc.stdout.on("data", (d) => {
          out += d;
          const m = /^(\d+)/.exec(out.trim());
          if (m) resolve(Number(m[1]));
        });
        srvProc.once("error", reject);
        srvProc.once("exit", (code) => {
          if (!out.trim()) reject(new Error(`HTTP fixture server exited ${code}`));
        });
      });
      const isoDest = path.join(work, "isolated-browser.png");
      try {
        const res = displayMod.captureBrowserIsolated({
          url: `http://127.0.0.1:${srvPort}/`,
          dest: isoDest,
          timeoutMs: 25000,
        });
        assert.equal(res.isolated, true);
        assert.ok(res.bytes > 100 && fs.existsSync(isoDest), "isolated browser capture produced PNG");
      } finally {
        try {
          srvProc.kill("SIGKILL");
        } catch {}
      }
    }

    // Exercise terminal capture script injection safety & Xvfb isolation if tools exist.
    if (
      process.platform === "linux" &&
      displayMod.hasXvfb() &&
      fs.existsSync("/usr/bin/qterminal")
    ) {
      const txt = path.join(work, "term-trace.txt");
      const termPng = path.join(work, "term-cap.png");
      const pwnFile = path.join(work, "pwned");
      fs.writeFileSync(txt, "$ echo safe\nsafe output\n");
      const injTitle = `$(touch ${pwnFile}) '"; test`;
      const termRun = spawnSync(
        "sh",
        [path.join(CORE, "scripts", "capture_terminal.sh"), "", work, injTitle, txt, termPng],
        { encoding: "utf8", timeout: 30000 },
      );
      assert.equal(termRun.status, 0, termRun.stderr);
      assert.equal(fs.existsSync(pwnFile), false, "capture_terminal.sh resists shell injection in TITLE");
      assert.ok(fs.existsSync(termPng) && fs.statSync(termPng).size > 100, "isolated Xvfb terminal capture produced PNG");
    }

    // ── 4. src/process.ts & src/process-supervisor.cjs ────────────────────
    const {
      ProcessRegistry,
      spawnTraced,
      processStatus,
      verifiedOutcome,
    } = jiti(path.join(CORE, "src", "process.ts"));
    const procState = path.join(work, "proc-state");
    const registry = new ProcessRegistry(procState);
    const lockFile = path.join(procState, "processes.json.lock");
    fs.mkdirSync(procState, { recursive: true });

    // Stale lock recovery: dead PID lock is recovered automatically.
    fs.writeFileSync(lockFile, JSON.stringify({ pid: 2147483647 }));
    const rec = registry.prepare("scope-a", "ses-a", "echo hi", work, 10000);
    const added = registry.add({ ...rec, pid: 12345, runKey: "rk-1" });
    assert.equal(added.id, rec.id, "add() recovers from dead-PID stale lock");
    assert.equal(fs.existsSync(lockFile), false, "lock file cleaned up after add");

    // Stale lock recovery: aged empty lock is recovered by prune().
    fs.writeFileSync(lockFile, "");
    const oldTime = new Date(Date.now() - 60_000);
    fs.utimesSync(lockFile, oldTime, oldTime);
    const pruned = registry.prune("scope-a");
    assert.ok(Array.isArray(pruned.archived), "prune() recovers from aged stale lock");
    assert.equal(fs.existsSync(lockFile), false, "lock file cleaned up after prune");

    // Guarded child.on("error") when HARNESS_NODE fails to spawn.
    const savedNode = process.env.HARNESS_NODE;
    process.env.HARNESS_NODE = "/nonexistent/node-binary-harness";
    try {
      const badRec = registry.prepare("scope-a", "ses-a", "echo x", work, 5000);
      spawnTraced("echo x", {
        cwd: work,
        logPath: badRec.logPath,
        deadlineMs: 5000,
        argv: [process.execPath, "-e", "process.exit(0)"],
      });
    } catch {
      /* expected synchronous throw when child.pid is unavailable */
    } finally {
      if (savedNode === undefined) delete process.env.HARNESS_NODE;
      else process.env.HARNESS_NODE = savedNode;
    }
    await new Promise((r) => setTimeout(r, 50));

    // Supervisor traceBytes & .stop cleanup.
    if (process.platform === "linux") {
      const supRec = registry.prepare("scope-sup", "ses-sup", "sleep 20", work, 15000);
      const started = spawnTraced(supRec.command, {
        cwd: supRec.cwd,
        logPath: supRec.logPath,
        deadlineMs: supRec.deadlineMs,
        argv: [process.execPath, "-e", "console.log('line1'); setTimeout(() => {}, 20000)"],
      });
      const stored = registry.add({ ...supRec, ...started });
      const endWait = Date.now() + 5000;
      while (fs.statSync(stored.logPath).size === 0 && Date.now() < endWait) {
        await new Promise((r) => setTimeout(r, 25));
      }
      registry.stop("scope-sup", stored.id);
      const termWait = Date.now() + 8000;
      while (processStatus(stored) === "running" && Date.now() < termWait) {
        await new Promise((r) => setTimeout(r, 30));
      }
      const outcome = verifiedOutcome(stored);
      assert.equal(outcome?.status, "stopped", "stopped supervisor verifies trace");
      assert.equal(
        outcome.traceBytes,
        fs.statSync(stored.logPath).size,
        "traceBytes matches exact hashed bytes",
      );
      assert.equal(
        fs.existsSync(`${stored.logPath}.result.json.stop`),
        false,
        ".stop control file is cleaned up on finalize",
      );
    }

    // ── 5. scripts/check-neutrality.cjs ───────────────────────────────────
    const { checkNeutrality } = require("../scripts/check-neutrality.cjs");
    const mockSrc = path.join(work, "mock-src");
    fs.mkdirSync(mockSrc, { recursive: true });
    fs.writeFileSync(
      path.join(mockSrc, "routing.ts"),
      'export const HOST_METHODS = ["opencode"] as const;\n',
    );
    assert.equal(
      checkNeutrality(mockSrc, { checkClientPrefixes: true }).offenders.length,
      0,
      "HOST_METHODS routing contract is preserved",
    );
    fs.writeFileSync(
      path.join(mockSrc, "sup.cjs"),
      'const sdk = require("@opencode-ai/sdk");\nconst m = require("./absent");\n',
    );
    fs.writeFileSync(
      path.join(mockSrc, "bad.ts"),
      "import './missing-single';\nconst x = import('../opencode/plugin');\nconst p = 'boa-client';\n",
    );
    const neut = checkNeutrality(mockSrc, { checkClientPrefixes: true });
    assert.ok(neut.offenders.some((o) => o.includes("sup.cjs") && o.includes("@opencode-ai/")));
    assert.ok(neut.offenders.some((o) => o.includes("sup.cjs") && o.includes("./absent")));
    assert.ok(neut.offenders.some((o) => o.includes("bad.ts") && o.includes("./missing-single")));
    assert.ok(neut.offenders.some((o) => o.includes("bad.ts") && o.includes("../opencode/plugin")));
    assert.ok(neut.offenders.some((o) => o.includes("bad.ts") && o.includes("hardcoded client prefix")));

    // ── 6. scripts/prune.cjs ──────────────────────────────────────────────
    const pruneHome = path.join(work, "prune-home");
    const pruneState = path.join(pruneHome, "state");
    const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
    const pStore = new KnowledgeStore(path.join(pruneState, "knowledge.sqlite"));
    pStore.close();

    const pruneRes = spawnSync(
      process.execPath,
      [path.join(CORE, "scripts", "prune.cjs"), "--dry-run"],
      {
        encoding: "utf8",
        env: {
          PATH: process.env.PATH,
          HARNESS_HOME: pruneHome,
        },
      },
    );
    assert.equal(pruneRes.status, 0, pruneRes.stderr);
    const pruneJson = JSON.parse(pruneRes.stdout);
    assert.equal(
      pruneJson.file,
      path.join(pruneState, "knowledge.sqlite"),
      "prune.cjs honors HARNESS_HOME even when HOME and USERPROFILE are unset",
    );

    // ── 7. scripts/sync-skills.cjs ────────────────────────────────────────
    const { syncSkills } = require("../scripts/sync-skills.cjs");
    const srcSkills = path.join(work, "src-skills");
    const dstSkills = path.join(work, "dst-skills");
    fs.mkdirSync(path.join(srcSkills, "harness-demo", "references"), { recursive: true });
    fs.writeFileSync(path.join(srcSkills, "harness-demo", "SKILL.md"), "# Demo v1\n");
    fs.writeFileSync(path.join(srcSkills, "harness-demo", "references", "ref.md"), "Ref\n");
    fs.writeFileSync(path.join(srcSkills, "harness-demo", "state.sqlite"), "ignore-runtime");
    fs.mkdirSync(path.join(dstSkills, "custom-operator-skill"), { recursive: true });
    fs.writeFileSync(path.join(dstSkills, "custom-operator-skill", "SKILL.md"), "# Keep me\n");

    const dry = syncSkills({ src: srcSkills, dest: dstSkills, dryRun: true });
    assert.equal(dry.inSync, false);
    assert.equal(fs.existsSync(path.join(dstSkills, "harness-demo")), false, "--dry-run writes nothing");

    const chkBefore = spawnSync(
      process.execPath,
      [path.join(CORE, "scripts", "sync-skills.cjs"), "--src", srcSkills, "--dest", dstSkills, "--check"],
      { encoding: "utf8" },
    );
    assert.equal(chkBefore.status, 1, "--check exits 1 when out of sync");

    const synced = syncSkills({ src: srcSkills, dest: dstSkills });
    assert.equal(synced.created.length, 2, "copies SKILL.md and reference, excluding state.sqlite");
    assert.equal(fs.existsSync(path.join(dstSkills, "harness-demo", "state.sqlite")), false);
    assert.equal(fs.existsSync(path.join(dstSkills, "custom-operator-skill", "SKILL.md")), true);

    const chkAfter = spawnSync(
      process.execPath,
      [path.join(CORE, "scripts", "sync-skills.cjs"), "--src", srcSkills, "--dest", dstSkills, "--check"],
      { encoding: "utf8" },
    );
    assert.equal(chkAfter.status, 0, "--check exits 0 when in sync");

    // ── 8. bin/harness.mjs CLI ────────────────────────────────────────────
    const cliState = path.join(work, "cli-state");
    const engRoot = path.join(work, "cli-engagement");
    fs.mkdirSync(path.join(engRoot, "preuves", "captures", "nested-dir"), { recursive: true });
    fs.writeFileSync(path.join(engRoot, "preuves", "captures", "cap-1.png"), TINY_PNG);

    const { scopeFor } = jiti(path.join(CORE, "src", "util.ts"));
    const cliScope = scopeFor(engRoot);
    const kStore = new KnowledgeStore(path.join(cliState, "knowledge.sqlite"));
    kStore.upsertSession({
      id: "ses_cli_1",
      scope: cliScope,
      cwd: engRoot,
      status: "completed",
      updatedAt: new Date().toISOString(),
    });
    const obs1 = kStore.recordObservation({
      id: "obs-cli-1",
      sessionId: "ses_cli_1",
      scope: cliScope,
      tool: "shell",
      input: {},
      output: "repro output distinct",
      success: true,
      timestamp: new Date().toISOString(),
    });
    const obs2 = kStore.recordObservation({
      id: "obs-cli-2",
      sessionId: "ses_cli_1",
      scope: cliScope,
      tool: "shell",
      input: {},
      output: "negative control output distinct",
      success: true,
      timestamp: new Date().toISOString(),
    });
    const { PlatformStore } = jiti(path.join(CORE, "src", "platform-store.ts"));
    const pPlatform = new PlatformStore(path.join(cliState, "platform.sqlite"), kStore);
    const mission = pPlatform.createMission(cliScope, "CLI Mission", "Local test", undefined, engRoot);
    pPlatform.approveScope(cliScope, mission.id);
    const chunk = pPlatform.ingest(cliScope, "src-1", "test://1", "Ref", "Reference evidence chunk.")[0];
    pPlatform.createFinding(cliScope, {
      missionId: mission.id,
      title: "Informational CLI Finding",
      severity: "informational",
      description: "Desc",
      limitations: "None",
      evidence: [obs1.id, obs2.id],
      sources: [chunk.id],
      checks: [
        { purpose: "reproduction", observationId: obs1.id, contains: "repro output" },
        { purpose: "negative-control", observationId: obs2.id, contains: "negative control" },
      ],
    });
    pPlatform.close();
    kStore.close();

    const runCli = (args, stateDir = cliState) =>
      spawnSync(process.execPath, [path.join(CORE, "bin", "harness.mjs"), ...args], {
        encoding: "utf8",
        cwd: work,
        env: { ...process.env, HARNESS_STATE_ROOT: stateDir },
      });

    const capturesRes = runCli(["captures"]);
    assert.equal(capturesRes.status, 0, capturesRes.stderr);
    assert.match(capturesRes.stdout, /cap-1\.png/, "cmdCaptures without --mission inspects mission_roots");

    const findingsRes = runCli(["findings", "--mission", mission.id]);
    assert.equal(findingsRes.status, 0, findingsRes.stderr);
    assert.match(findingsRes.stdout, /informational/, "severityColor renders informational");
    assert.match(findingsRes.stdout, /unverified/, "statusBadge renders unverified");

    const badPosExport = runCli(["export", "nonexistent-mission-id"]);
    assert.notEqual(badPosExport.status, 0, "harness export <missing-id> fails instead of treating id as outDir");
    assert.equal(fs.existsSync(path.join(work, "nonexistent-mission-id")), false);

    const exportDir = path.join(work, "exported-bundle");
    const exportRes = runCli(["export", mission.id, exportDir]);
    assert.equal(exportRes.status, 0, exportRes.stderr);
    assert.ok(fs.existsSync(path.join(exportDir, "mission.json")));
    assert.ok(fs.existsSync(path.join(exportDir, "observations.json")));
    assert.ok(fs.existsSync(path.join(exportDir, "captures", "cap-1.png")));
    assert.match(exportRes.stdout, /observations\.json/);
    if (process.platform !== "win32") {
      assert.equal(fs.statSync(exportDir).mode & 0o777, 0o700);
      assert.equal(fs.statSync(path.join(exportDir, "mission.json")).mode & 0o777, 0o600);
    }

    // Export without knowledge.sqlite omits observations.json from disk and output.
    const noKnowState = path.join(work, "no-know-state");
    fs.mkdirSync(noKnowState, { recursive: true });
    fs.copyFileSync(path.join(cliState, "platform.sqlite"), path.join(noKnowState, "platform.sqlite"));
    const exportNoKnowDir = path.join(work, "exported-no-know");
    const exportNoKnow = runCli(["export", mission.id, exportNoKnowDir], noKnowState);
    assert.equal(exportNoKnow.status, 0, exportNoKnow.stderr);
    assert.equal(fs.existsSync(path.join(exportNoKnowDir, "observations.json")), false);
    assert.equal(exportNoKnow.stdout.includes("observations.json"), false);
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
};
