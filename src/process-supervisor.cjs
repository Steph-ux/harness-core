// One independent owner per command. Arguments are never interpolated into a shell.
const fs = require("node:fs"),
  { spawn } = require("node:child_process"),
  { createHash, randomUUID } = require("node:crypto");
const job = JSON.parse(fs.readFileSync(process.argv[2], "utf8")),
  resultPath = `${job.logPath}.result.json`;
const write = (value) => {
  const temp = `${resultPath}.${randomUUID()}.tmp`;
  fs.writeFileSync(temp, JSON.stringify({ runKey: job.runKey, ...value }), {
    mode: 0o600,
    flag: "wx",
  });
  fs.renameSync(temp, resultPath);
};
const fd = fs.openSync(job.logPath, "a", 0o600);
let stopped = false,
  timedOut = false,
  finishing = false,
  child,
  hardKill;
const posixGroup = process.platform === "linux";
const killTree = (signal) => {
  if (!child?.pid) return;
  if (posixGroup) {
    try {
      process.kill(-child.pid, signal);
    } catch {}
    return;
  }
  try {
    process.kill(child.pid, signal);
  } catch {}
  if (process.platform === "win32" && signal === "SIGKILL") {
    try {
      spawn("taskkill", ["/F", "/T", "/PID", String(child.pid)], {
        stdio: "ignore",
        windowsHide: true,
      });
    } catch {}
  }
};
const stop = (timeout = false) => {
  if (finishing || stopped || timedOut) return;
  timedOut = timeout;
  stopped = !timeout;
  killTree("SIGTERM");
  hardKill = setTimeout(() => killTree("SIGKILL"), 1000);
};
try {
  child = spawn(job.argv[0], job.argv.slice(1), {
    cwd: job.cwd,
    env: process.env,
    detached: true,
    stdio: ["ignore", fd, fd],
    windowsHide: true,
  });
  write({
    status: "running",
    startedAt: new Date().toISOString(),
    supervisorPid: process.pid,
  });
  const deadline = setTimeout(() => stop(true), job.deadlineMs),
    control = setInterval(() => {
      try {
        if (fs.readFileSync(`${resultPath}.stop`, "utf8") === job.runKey)
          stop();
      } catch {}
    }, 30);
  process.on("SIGTERM", () => stop());
  process.on("SIGINT", () => stop());
  const finish = (code, signal, error) => {
    if (finishing) return;
    let descendantsOutlived = false;
    if (posixGroup && !timedOut && !stopped && child.pid) {
      try {
        process.kill(-child.pid, 0);
        descendantsOutlived = true;
      } catch {}
      if (descendantsOutlived) {
        killTree("SIGTERM");
        hardKill = setTimeout(() => killTree("SIGKILL"), 1000);
      }
    }
    finishing = true;
    clearTimeout(deadline);
    clearInterval(control);
    const finalize = () => {
      if (hardKill) {
        clearTimeout(hardKill);
        killTree("SIGKILL");
      }
      if (error)
        fs.writeSync(fd, `Execution failed: ${error.code || "spawn-error"}\n`);
      fs.closeSync(fd);
      const digest = createHash("sha256"),
        input = fs.createReadStream(job.logPath);
      let traceBytes = 0;
      const cleanupStop = () => {
        try {
          fs.unlinkSync(`${resultPath}.stop`);
        } catch {}
      };
      input.on("data", (b) => {
        digest.update(b);
        traceBytes += b.length;
      });
      input.on("error", () => {
        cleanupStop();
        write({
          status: "failed",
          exitCode: code,
          reason: "unreadable-trace",
          finishedAt: new Date().toISOString(),
        });
      });
      input.on("end", () => {
        cleanupStop();
        write({
          status: timedOut
            ? "timed_out"
            : stopped
              ? "stopped"
              : code === 0 && !error && !descendantsOutlived
                ? "succeeded"
                : "failed",
          ...(descendantsOutlived
            ? { reason: "descendants-outlived-command" }
            : error
              ? { reason: error.code || "spawn-error" }
              : {}),
          exitCode: code,
          signal: signal || null,
          finishedAt: new Date().toISOString(),
          traceHash: digest.digest("hex"),
          traceBytes,
        });
      });
    };
    if (timedOut || stopped || descendantsOutlived) setTimeout(finalize, 1050);
    else finalize();
  };
  child.once("error", (e) => finish(null, null, e));
  child.once("exit", (code, signal) => finish(code, signal));
} catch (error) {
  try {
    fs.closeSync(fd);
  } catch {}
  try {
    fs.unlinkSync(`${resultPath}.stop`);
  } catch {}
  write({
    status: "failed",
    exitCode: null,
    reason: error.code || "supervisor-error",
    finishedAt: new Date().toISOString(),
  });
}
