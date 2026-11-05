/**
 * The visual attestation, on the OpenCode surface.
 *
 * A capture shows one window, never the desktop, and it is linked to the
 * observation it attests. The rules are checked on their own, and then against
 * a real window of the display when there is one.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { makeContext } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");
const PLUGIN = path.join(CORE, "opencode", "plugin.ts");

module.exports = async ({ assert, jiti }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-capture-"));
  const state = path.join(workspace, "state");
  fs.mkdirSync(state, { recursive: true });
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;

  const plugin = jiti(PLUGIN).default;
  const {
    assertNotRoot,
    captureDestination,
    captureLink,
    captureName,
    isFramed,
    selectWindow,
    selectWindowById,
  } = jiti(path.join(CORE, "src", "capture.ts"));

  // The window is chosen by its exact title, and the choice must be unique.
  const windows = [
    { id: "1", title: "Firefox" },
    { id: "2", title: "Terminal" },
    { id: "3", title: "Terminal" },
  ];
  assert.equal(
    selectWindow(windows, "Firefox").id,
    "1",
    "the window is chosen by its title",
  );
  assert.throws(
    () => selectWindow(windows, "Absent"),
    /No window carries that title/,
    "a window that is not there is refused",
  );
  assert.throws(
    () => selectWindow(windows, "Terminal"),
    /Several windows carry that title/,
    "an ambiguous title is refused",
  );
  assert.equal(
    selectWindowById(windows, "2").title,
    "Terminal",
    "the window is chosen by its id",
  );

  // The desktop is never a subject.
  assert.throws(
    () => assertNotRoot("0x4dd", "0x4dd"),
    /desktop is not a subject/,
    "the root window is refused",
  );
  assert.throws(
    () => assertNotRoot("0x4dd", "0x0"),
    /desktop is not a subject/,
    "the zero id is refused",
  );
  assert.doesNotThrow(() => assertNotRoot("0x4dd", "0x4600095"));

  // The capture lands in the capture root and nowhere else.
  const root = path.join(workspace, "captures");
  const dest = captureDestination(root, "obs-12345678");
  assert.equal(path.dirname(dest), path.resolve(root), "the capture stays in its root");
  assert.throws(
    () => captureDestination(root, "../escape"),
    /Invalid capture name/,
    "a name that escapes the root is refused",
  );
  assert.equal(
    captureName("obs-abcdef1234", "Mon Preuve"),
    "obs-abcdef1234-mon-preuve",
    "the name carries the observation it attests",
  );

  // The framing is the point: the picture has the size of the window.
  assert.equal(
    isFramed({ width: 604, height: 264 }, { width: 604, height: 264 }),
    true,
    "a capture of the size of the window is framed",
  );
  assert.equal(
    isFramed({ width: 1920, height: 1080 }, { width: 604, height: 264 }),
    false,
    "a capture of the size of the desktop is not framed",
  );
  assert.equal(
    isFramed({ width: 1, height: 1 }, { width: 1, height: 1 }),
    false,
    "a minimized window is not a subject",
  );
  assert.equal(
    isFramed({ width: 600, height: 264 }, { width: 604, height: 264 }),
    true,
    "a capture within the tolerance is framed",
  );

  // The link carries the observation it attests.
  const link = captureLink(
    "obs-abcdef1234",
    {
      path: dest,
      bytes: 1234,
      window: "0x4600095",
      title: "Firefox",
      width: 604,
      height: 264,
    },
    "2026-10-21T22:00:00.000Z",
  );
  assert.equal(link.observationId, "obs-abcdef1234", "the link names the observation");
  assert.equal(link.width, 604, "the link carries the size of the capture");

  // The tool, on a real display when there is one.
  const fixture = makeContext(workspace);
  const unload = await plugin.setup(fixture.ctx);
  const { observationId } = jiti(path.join(CORE, "src", "observation-id.ts"));
  const captureObservation = observationId("ses_cap", "call-capture-source");
  await fixture.hooks.get("execute.after")({
    tool: "shell", sessionID: "ses_cap", id: "call-capture-source",
    input: { command: "echo marqueur-harness" }, status: "completed",
    result: { content: [{ type: "text", text: "marqueur-harness" }], metadata: { exit: 0 } },
  });
  assert.ok(fixture.tools.has("cyber_capture"), "the plugin exposes the capture");
  const call = (input) =>
    fixture.tools.get("cyber_capture").execute(input, {
      sessionID: "ses_cap",
      agent: "build",
      messageID: "msg_cap",
      id: "call-cap",
      progress: () => {},
      signal: new AbortController().signal,
    });
  // A capture renders the recorded trace of a finished command, and the proof
  // it rests on is the observation of that read, never the launch.
  const command = (input) =>
    fixture.tools.get("cyber_process").execute(input, {
      sessionID: "ses_cap",
      agent: "build",
      messageID: "msg_cap",
      id: "call-process",
      progress: () => {},
      signal: new AbortController().signal,
    });
  const { ProcessRegistry, processStatus } = jiti(
    path.join(CORE, "src", "process.ts"),
  );
  const registry = new ProcessRegistry(state);
  const ran = JSON.parse(
    (
      await command({
        action: "run",
        argv: [process.execPath, "-e", `console.log("marqueur-harness")`],
      })
    ).content,
  );
  const until = async (predicate) => {
    const end = Date.now() + 8000;
    while (!predicate() && Date.now() < end)
      await new Promise((resolve) => setTimeout(resolve, 30));
    assert.ok(predicate(), "the command reached a terminal state");
  };
  await until(() =>
    ["succeeded", "failed", "timed_out", "stopped"].includes(
      processStatus(registry.get(ran.scope, ran.id)),
    ),
  );
  const read = JSON.parse((await command({ action: "read", id: ran.id })).content);
  assert.match(read.trace, /marqueur-harness/, "the trace carries the output");
  await fixture.hooks.get("execute.after")({
    tool: "cyber_process",
    sessionID: "ses_cap",
    id: "call-process-read",
    input: { action: "read", id: ran.id },
    status: "completed",
    result: { content: JSON.stringify(await command({ action: "read", id: ran.id })) },
  });
  const readObservation = observationId("ses_cap", "call-process-read");

  // The observation must be the read of the process that is rendered.
  await assert.rejects(
    () =>
      call({
        action: "evidence",
        processId: ran.id,
        observationId: captureObservation,
      }),
    /observation of this process read/,
    "an unrelated command cannot be rendered as visual evidence",
  );
  await assert.rejects(
    () =>
      call({
        action: "evidence",
        processId: "process-absent",
        observationId: readObservation,
      }),
    /observation of this process read/,
    "another process id does not inherit the read",
  );

  const display = process.env.DISPLAY;
  if (!display) {
    console.log("  note: no display, the capture on a real window is not exercised");
  } else {
    // The windows of the operator, before the harness does anything.
    const before = JSON.parse((await call({ action: "windows" })).content);
    assert.ok(Array.isArray(before), "the windows are listed");
    assert.equal(
      before.filter((window) => window.title === "harness-evidence").length,
      0,
      "the terminal of the harness is not on the display of the operator",
    );

    // The desktop is refused, even when it is asked for by name.
    const rootWindow = /Window id:\s*(0x[0-9a-f]+)/i.exec(
      spawnSync("xwininfo", ["-root"], { encoding: "utf8" }).stdout ?? "",
    );
    if (rootWindow) {
      await assert.rejects(
        () => call({ action: "shot", window: rootWindow[1] }),
        /desktop is not a subject/,
        "the desktop is refused as a subject",
      );
    }

    // The evidence terminal of the harness renders the recorded trace of the
    // finished command, on a display of its own.
    const shot = JSON.parse(
      (
        await call({
          action: "evidence",
          processId: ran.id,
          observationId: readObservation,
        })
      ).content,
    );
    assert.equal(
      shot.observationId,
      readObservation,
      "the capture is linked to the observation it attests",
    );
    assert.equal(shot.processId, ran.id, "the capture names the process it renders");
    assert.match(
      String(shot.traceHash ?? ""),
      /^[0-9a-f]{64}$/,
      "the capture binds the whole recorded trace",
    );
    assert.ok(shot.bytes > 32, "the capture has content");
    assert.ok(
      shot.width >= 16 && shot.height >= 16,
      "the capture has the size of a window",
    );
    assert.ok(fs.existsSync(shot.path), "the capture file exists");
    assert.ok(
      shot.path.startsWith(path.join(state, "captures")),
      "the capture stays in the state of the harness",
    );

    // Nothing appeared on the display of the operator.
    const after = JSON.parse((await call({ action: "windows" })).content);
    assert.equal(
      after.filter((window) => window.title === "harness-evidence").length,
      0,
      "the terminal of the harness stays off the display of the operator",
    );

    // The link is in the store, so a later session can find it.
    const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
    const { scopeFor } = jiti(path.join(CORE, "src", "util.ts"));
    const store = new KnowledgeStore(path.join(state, "knowledge.sqlite"));
    const scope = scopeFor(workspace);
    const audits = store.audits(scope, "capture", 10);
    assert.equal(audits.length, 1, "the capture is recorded in the store");
    assert.match(
      audits[0].detail,
      new RegExp(readObservation),
      "the record names the observation it attests",
    );
    store.close();
  }

  // The private display of the harness goes away with it.
  if (typeof unload === "function") unload();
  fs.rmSync(workspace, { recursive: true, force: true });
};
