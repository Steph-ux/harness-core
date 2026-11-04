/** Real v2 catalog, SDK and private-server permission guard. No external model call. */
const fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path"),
  { spawn, spawnSync } = require("node:child_process"),
  assert = require("node:assert/strict");
const root = path.resolve(__dirname, ".."),
  binary = process.env.OPENCODE_BINARY;
if (!binary)
  throw Error(
    "Set OPENCODE_BINARY to the official OpenCode v2.0.26 executable",
  );
assert.match(
  spawnSync(binary, ["--version"], { encoding: "utf8", timeout: 5000 }).stdout,
  /v2\.0\.26\b/,
);
const work = fs.mkdtempSync(path.join(os.tmpdir(), "harness-native-")),
  resultPath = path.join(work, "result.json");
const env = {
  ...process.env,
  HARNESS_CORE: root,
  HARNESS_STATE_ROOT: path.join(work, "proof"),
  HARNESS_NATIVE_RESULT: resultPath,
  XDG_CONFIG_HOME: path.join(work, "config"),
  XDG_DATA_HOME: path.join(work, "data"),
  XDG_CACHE_HOME: path.join(work, "cache"),
  XDG_STATE_HOME: path.join(work, "state"),
};
const config = path.join(env.XDG_CONFIG_HOME, "opencode");
fs.mkdirSync(config, { recursive: true });
fs.writeFileSync(
  path.join(config, "opencode.json"),
  JSON.stringify({
    plugins: [
      path.join(root, "opencode"),
      path.join(root, "test/fixtures/native-smoke"),
    ],
    permissions: [
      { action: "shell", resource: "*", effect: "deny" },
      { action: "harness_operator", resource: "*", effect: "ask" },
    ],
  }),
);
const child = spawn(
  binary,
  ["serve", "--hostname", "127.0.0.1", "--port", "0"],
  { env, cwd: root, stdio: ["ignore", "pipe", "pipe"] },
);
let log = "";
child.stdout.on("data", (b) => (log += b));
child.stderr.on("data", (b) => (log += b));
const delay = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  try {
    const end = Date.now() + 20000;
    let address, password;
    while (Date.now() < end) {
      address = /server listening on (http:\/\/\S+)/.exec(log)?.[1];
      password = /server password (\S+)/.exec(log)?.[1];
      if (address && password) break;
      await delay(50);
    }
    assert.ok(address && password, "private server started");
    const api = async (method, endpoint, body) => {
      const r = await fetch(address + endpoint, {
        method,
        headers: {
          Authorization:
            "Basic " + Buffer.from("opencode:" + password).toString("base64"),
          "content-type": "application/json",
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(15000),
      });
      assert.equal(r.status, 200);
      return r.json();
    };
    await api("POST", "/api/session", {
      title: "Synthetic registration smoke",
      location: { directory: root },
    });
    let plugins = [];
    const query = "?location[directory]=" + encodeURIComponent(root);
    for (let n = 0; n < 100; n++) {
      plugins = (await api("GET", "/api/plugin" + query)).data;
      if (
        plugins.some(
          (p) => p.id === "harness-core.proof" && p.state.status === "active",
        )
      )
        break;
      await delay(100);
    }
    assert.equal(
      plugins.filter(
        (p) => p.id === "harness-core.proof" && p.state.status === "active",
      ).length,
      1,
    );
    assert.equal(
      plugins.some(
        (p) => p.id === "harness-core.proof" && p.state.status === "failed",
      ),
      false,
    );
    const skills = (await api("GET", "/api/skill" + query)).data.map(
      (s) => s.id,
    );
    for (const name of ["capitaliser-cyber", "rapports-cyber"])
      assert.ok(skills.includes(name));
    for (let n = 0; n < 250 && !fs.existsSync(resultPath); n++)
      await delay(100);
    const result = JSON.parse(fs.readFileSync(resultPath, "utf8"));
    assert.equal(result.error, undefined);
    assert.equal(result.unexpectedLaunch, undefined);
    for (const name of [
      "cyber_report",
      "cyber_capitalise",
      "cyber_cleanup",
      "cyber_verification",
    ])
      assert.ok(result.tools.includes(name));
    assert.deepEqual(result.tasks.tasks, []);
    assert.equal(result.list.metadata.evidenceSuccess, false);
    assert.match(result.refusal, /another server|permission.*denied/i);
    console.log(
      "Native OpenCode 2.0.26 PASS: plugin active, two project procedures, scoped tools and private-server refusal; no model used.",
    );
  } catch (error) {
    console.error(
      log.replace(/server password \S+/g, "server password <hidden>"),
    );
    throw error;
  } finally {
    child.kill("SIGTERM");
    await new Promise((resolve) => {
      if (child.exitCode !== null) return resolve();
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        resolve();
      }, 2000);
      child.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
    });
    spawnSync(binary, ["service", "stop"], {
      env,
      encoding: "utf8",
      timeout: 5000,
    });
    fs.rmSync(work, { recursive: true, force: true });
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
