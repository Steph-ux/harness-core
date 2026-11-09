/** Durable command outcomes. A launch is never proof of successful execution. */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { assertPlainPath, atomicWrite, newId, now, redactText } from "./util";
export interface ProcessRecord {
  id: string;
  scope: string;
  sessionId: string;
  command: string;
  cwd: string;
  pid: number;
  logPath: string;
  startedAt: string;
  deadlineMs: number;
  detached: boolean;
  identity?: string;
  runKey?: string;
}
export type ProcessStatus =
  | "running"
  | "succeeded"
  | "failed"
  | "timed_out"
  | "stopped"
  | "unknown";
export interface ProcessOutcome {
  runKey: string;
  status: ProcessStatus;
  exitCode?: number | null;
  signal?: string | null;
  traceHash?: string;
  traceBytes?: number;
  finishedAt?: string;
  reason?: string;
}
export const DEFAULT_DEADLINE_MS = 120000,
  MAX_DEADLINE_MS = 600000;
export function spawnTraced(
  command: string,
  options: {
    cwd: string;
    logPath: string;
    deadlineMs: number;
    env?: Record<string, string>;
    argv?: string[];
  },
): { pid: number; detached: boolean; runKey: string } {
  if (process.platform !== "linux")
    throw new Error("Traced commands require Linux");
  if (
    !Number.isFinite(options.deadlineMs) ||
    options.deadlineMs <= 0 ||
    options.deadlineMs > MAX_DEADLINE_MS
  )
    throw new Error("Invalid deadline");
  const argv = options.argv ?? ["/bin/sh", "-c", command];
  if (
    !argv.length ||
    argv.some((p) => typeof p !== "string" || /[\0\r\n]/.test(p))
  )
    throw new Error("Invalid command arguments");
  assertPlainPath(options.logPath);
  fs.mkdirSync(path.dirname(options.logPath), { recursive: true, mode: 0o700 });
  fs.closeSync(fs.openSync(options.logPath, "ax", 0o600));
  const runKey = newId(),
    jobPath = `${options.logPath}.job.json`;
  atomicWrite(
    jobPath,
    JSON.stringify({
      argv,
      cwd: options.cwd,
      logPath: options.logPath,
      deadlineMs: options.deadlineMs,
      runKey,
    }),
  );
  atomicWrite(
    `${options.logPath}.result.json`,
    JSON.stringify({ runKey, status: "running", startedAt: now() }),
  );
  const child = spawn(
    process.env.HARNESS_NODE || "node",
    [
      fileURLToPath(new URL("./process-supervisor.cjs", import.meta.url)),
      jobPath,
    ],
    {
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
      detached: true,
      stdio: "ignore",
    },
  );
  child.on("error", () =>
    atomicWrite(
      `${options.logPath}.result.json`,
      JSON.stringify({
        runKey,
        status: "failed",
        exitCode: null,
        reason: "supervisor-spawn-error",
        finishedAt: now(),
      }),
    ),
  );
  child.unref();
  if (!child.pid) throw new Error("Unable to start command supervisor");
  return { pid: child.pid, detached: true, runKey };
}
/** Only for a supervisor just started by this caller, never an arbitrary recovered PID. */
export function stopProcess(pid: number) {
  if (pid > 0)
    try {
      process.kill(pid, "SIGTERM");
    } catch {}
}
export function processAlive(pid: number) {
  if (pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}
export function processIdentity(pid: number): string | undefined {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8"),
      boot = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    return `${boot}:${stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19]}`;
  } catch {
    return undefined;
  }
}
export function processOutcome(
  record: ProcessRecord,
): ProcessOutcome | undefined {
  if (!record.runKey) return;
  try {
    const file = `${record.logPath}.result.json`;
    assertPlainPath(file);
    const value = JSON.parse(fs.readFileSync(file, "utf8"));
    if (
      value.runKey !== record.runKey ||
      !["running", "succeeded", "failed", "timed_out", "stopped"].includes(
        value.status,
      )
    )
      return;
    return value;
  } catch {
    return undefined;
  }
}
export function verifiedOutcome(
  record: ProcessRecord,
): ProcessOutcome | undefined {
  const value = processOutcome(record);
  if (!value) return undefined;
  if (value.status === "running") {
    // A stored "running" is only trusted while the supervisor is alive and
    // inside its deadline. Otherwise it died before its terminal write, and
    // the command is unknown, not still running.
    return processStatus(record) === "running" ? value : undefined;
  }
  // A terminal result without its trace hash cannot be verified: it is a
  // legacy or truncated write, so the outcome is unknown, not tampered.
  if (
    typeof value.traceHash !== "string" ||
    !Number.isFinite(value.traceBytes)
  )
    return undefined;
  assertPlainPath(record.logPath);
  const fd = fs.openSync(record.logPath, "r"),
    digest = createHash("sha256");
  let bytes = 0;
  try {
    const buffer = Buffer.alloc(65536);
    for (let n; (n = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0; ) {
      digest.update(buffer.subarray(0, n));
      bytes += n;
    }
  } finally {
    fs.closeSync(fd);
  }
  if (digest.digest("hex") !== value.traceHash || bytes !== value.traceBytes)
    throw new Error("Process trace integrity check failed");
  return value;
}
export function processStatus(record: ProcessRecord): ProcessStatus {
  const outcome = processOutcome(record);
  if (outcome && outcome.status !== "running") return outcome.status;
  if (
    outcome?.status === "running" &&
    processAlive(record.pid) &&
    Date.now() < Date.parse(record.startedAt) + record.deadlineMs + 5000
  )
    return "running";
  if (
    !record.runKey &&
    record.identity &&
    record.identity === processIdentity(record.pid) &&
    processAlive(record.pid)
  )
    return "running";
  return "unknown";
}
export function publicProcess(record: ProcessRecord) {
  const { runKey, ...safe } = record;
  return safe;
}
export function readTrace(logPath: string, tail = 200): string {
  if (!Number.isInteger(tail) || tail < 1 || tail > 2000)
    throw new Error("Invalid trace tail (1..2000 lines)");
  assertPlainPath(logPath);
  try {
    const fd = fs.openSync(logPath, "r");
    try {
      const size = fs.fstatSync(fd).size,
        buffer = Buffer.alloc(Math.min(size, 256000)),
        start = Math.max(0, size - buffer.length),
        n = fs.readSync(fd, buffer, 0, buffer.length, start);
      let value = buffer.subarray(0, n).toString("utf8");
      if (start) value = value.slice(value.indexOf("\n") + 1);
      return redactText(value)
        .split("\n")
        .slice(-tail)
        .join("\n")
        .slice(-24000);
    } finally {
      fs.closeSync(fd);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "";
    throw error;
  }
}
export class ProcessRegistry {
  constructor(private stateRoot: string) {}
  private file() {
    return path.join(this.stateRoot, "processes.json");
  }
  private readAll(): ProcessRecord[] {
    try {
      assertPlainPath(this.file());
      const rows = JSON.parse(fs.readFileSync(this.file(), "utf8"));
      if (!Array.isArray(rows)) throw new Error("Invalid process registry");
      return rows;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }
  list(scope: string) {
    return this.readAll().filter((r) => r.scope === scope);
  }
  get(scope: string, id: string) {
    const row = this.list(scope).find((r) => r.id === id);
    if (!row) throw new Error("Unknown process");
    return row;
  }
  add(record: ProcessRecord) {
    fs.mkdirSync(this.stateRoot, { recursive: true, mode: 0o700 });
    const lock = `${this.file()}.lock`;
    assertPlainPath(lock);
    const fd = fs.openSync(lock, "wx", 0o600);
    try {
      let runKey = record.runKey;
      if (!runKey)
        try {
          runKey = JSON.parse(
            fs.readFileSync(`${record.logPath}.job.json`, "utf8"),
          ).runKey;
        } catch {}
      const stored = {
        ...record,
        command: redactText(record.command),
        identity: processIdentity(record.pid),
        ...(runKey ? { runKey } : {}),
      };
      atomicWrite(
        this.file(),
        JSON.stringify(
          [...this.readAll().filter((r) => r.id !== record.id), stored],
          null,
          1,
        ),
      );
      return stored;
    } finally {
      fs.closeSync(fd);
      fs.unlinkSync(lock);
    }
  }
  tracePath(id: string) {
    if (!/^proc-[A-Za-z0-9-]+$/.test(id)) throw new Error("Invalid process id");
    return path.join(this.stateRoot, "traces", `${id}.log`);
  }
  stop(scope: string, id: string) {
    const row = this.get(scope, id),
      status = processStatus(row);
    if (!["running", "unknown"].includes(status)) return row;
    if (row.runKey) atomicWrite(`${row.logPath}.result.json.stop`, row.runKey);
    else if (row.identity && row.identity === processIdentity(row.pid))
      stopProcess(row.pid);
    else
      throw new Error(
        "Unknown process identity; refusing to signal a recovered PID",
      );
    return row;
  }
  withStatus(scope: string) {
    return this.list(scope).map((row) => ({
      ...row,
      status: processStatus(row),
    }));
  }
  prepare(
    scope: string,
    sessionId: string,
    command: string,
    cwd: string,
    deadlineMs: number,
  ): ProcessRecord {
    if (
      typeof command !== "string" ||
      !command.trim() ||
      command.length > 24000
    )
      throw new Error("Invalid command length");
    if (
      !Number.isFinite(deadlineMs) ||
      deadlineMs <= 0 ||
      deadlineMs > MAX_DEADLINE_MS
    )
      throw new Error("Invalid deadline");
    const id = `proc-${newId().slice(0, 18)}`;
    return {
      id,
      scope,
      sessionId,
      command,
      cwd,
      pid: 0,
      logPath: this.tracePath(id),
      startedAt: now(),
      deadlineMs,
      detached: true,
    };
  }
}
