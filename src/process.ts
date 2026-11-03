/**
 * The commands the harness owns, and the trace they leave.
 *
 * A long command has two problems: the transcript keeps only its tail, and
 * the process dies with the session that started it. The harness therefore
 * owns the command: it writes the whole output to a file it names, and it
 * detaches the process, so a later session can find it, read its trace and
 * stop it.
 */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { assertPlainPath, newId, now, redactText } from "./util";

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
}

export type ProcessStatus = "running" | "finished";

export const DEFAULT_DEADLINE_MS = 120_000;
export const MAX_DEADLINE_MS = 600_000;

/** A command that outlives its session needs a group of its own. */
export function spawnTraced(
  command: string,
  options: {
    cwd: string;
    logPath: string;
    deadlineMs: number;
    env?: Record<string, string>;
    /** Execute these arguments directly. The shell form remains for legacy Pi callers. */
    argv?: string[];
  },
): { pid: number; detached: boolean } {
  if (!Number.isFinite(options.deadlineMs) || options.deadlineMs <= 0 || options.deadlineMs > MAX_DEADLINE_MS)
    throw new Error("Invalid deadline");
  assertPlainPath(options.logPath);
  fs.mkdirSync(path.dirname(options.logPath), { recursive: true, mode: 0o700 });
  const handle = fs.openSync(options.logPath, "ax", 0o600);
  // The deadline belongs to an independent supervisor, not a timer in the host
  // that may crash. GNU timeout also kills children that ignore SIGTERM.
  let child;
  try {
    if (options.argv && (!options.argv.length || options.argv.some((part) => typeof part !== "string" || /[\0\r\n]/.test(part))))
      throw new Error("Invalid command arguments");
    const target = options.argv?.length ? options.argv : ["/bin/sh", "-c", command];
    child = spawn("/usr/bin/timeout", ["--signal=TERM", "--kill-after=1s", `${options.deadlineMs / 1000}s`, ...target], {
    cwd: options.cwd,
    env: { ...process.env, ...(options.env ?? {}) },
    detached: true,
    stdio: ["ignore", handle, handle],
    });
  } finally {
    fs.closeSync(handle);
  }
  child.on("error", (error) => {
    fs.appendFileSync(options.logPath, `Supervisor failed: ${error.message}\n`);
  });
  child.unref();
  const pid = child.pid ?? 0;
  if (!pid) throw new Error("Unable to start command supervisor");
  return { pid, detached: true };
}

/** A process group, then the process itself. */
export function stopProcess(pid: number): void {
  if (!pid || pid <= 0) return;
  try {
    process.kill(-pid, "SIGTERM");
  } catch {
    try {
      process.kill(pid, "SIGTERM");
    } catch {
      /* The process is already gone. */
    }
  }
}

/** Whether the process is still there. */
export function processAlive(pid: number): boolean {
  if (!pid || pid <= 0) return false;
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    if (/^[ZX] /.test(stat.slice(stat.lastIndexOf(")") + 2))) return false;
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export function processIdentity(pid: number): string | undefined {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const boot = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    return `${boot}:${stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19]}`;
  } catch {
    return undefined;
  }
}

/** The status of a record, seen now. */
export function processStatus(record: ProcessRecord): ProcessStatus {
  return record.identity && record.identity === processIdentity(record.pid) && processAlive(record.pid) ? "running" : "finished";
}

/** The tail of a trace, redacted. */
export function readTrace(logPath: string, tail = 200): string {
  if (!Number.isInteger(tail) || tail < 1 || tail > 2000)
    throw new Error("Invalid trace tail (1..2000 lines)");
  assertPlainPath(logPath);
  let content: string;
  try {
    const fd = fs.openSync(logPath, "r");
    try {
      const size = fs.fstatSync(fd).size;
      const buffer = Buffer.alloc(Math.min(size, 256_000));
      const start = Math.max(0, size - buffer.length);
      const count = fs.readSync(fd, buffer, 0, buffer.length, start);
      content = buffer.subarray(0, count).toString("utf8");
      if (start) content = content.slice(content.indexOf("\n") + 1);
    } finally { fs.closeSync(fd); }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "";
    throw error;
  }
  const lines = content.split("\n");
  return redactText(lines.slice(Math.max(0, lines.length - tail)).join("\n")).slice(
    -24000,
  );
}

/**
 * The registry of the commands the harness owns.
 *
 * It is a small file, because it must survive the session that wrote it: it is
 * what a later session reads to find what was still running.
 */
export class ProcessRegistry {
  constructor(private stateRoot: string) {}

  private file(): string {
    return path.join(this.stateRoot, "processes.json");
  }

  private readAll(): ProcessRecord[] {
    try {
      assertPlainPath(this.file());
      const parsed = JSON.parse(fs.readFileSync(this.file(), "utf8"));
      if (!Array.isArray(parsed)) throw new Error("Invalid process registry");
      return parsed as ProcessRecord[];
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
  }

  private writeAll(records: ProcessRecord[]): void {
    fs.mkdirSync(this.stateRoot, { recursive: true });
    const temporary = `${this.file()}.${newId()}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(records, null, 1), {
      mode: 0o600,
    });
    fs.renameSync(temporary, this.file());
  }

  list(scope: string): ProcessRecord[] {
    return this.readAll().filter((record) => record.scope === scope);
  }

  get(scope: string, id: string): ProcessRecord {
    const found = this.list(scope).find((record) => record.id === id);
    if (!found) throw new Error("Unknown process");
    return found;
  }

  add(record: ProcessRecord): ProcessRecord {
    fs.mkdirSync(this.stateRoot, { recursive: true });
    const lock = `${this.file()}.lock`;
    // Fail rather than silently overwrite another host's update.
    const fd = fs.openSync(lock, "wx", 0o600);
    try {
      const records = this.readAll().filter((entry) => entry.id !== record.id);
      const stored = { ...record, command: redactText(record.command), identity: processIdentity(record.pid) };
      records.push(stored);
      this.writeAll(records);
      return stored;
    } finally {
      fs.closeSync(fd);
      fs.unlinkSync(lock);
    }
  }

  /** The trace path of a command, inside the state. */
  tracePath(id: string): string {
    if (!/^proc-[A-Za-z0-9-]+$/.test(id)) throw new Error("Invalid process id");
    return path.join(this.stateRoot, "traces", `${id}.log`);
  }

  /** A command that is still running, stopped. */
  stop(scope: string, id: string): ProcessRecord {
    const record = this.get(scope, id);
    if (processStatus(record) === "running") stopProcess(record.pid);
    return record;
  }

  /** The records of a scope, with the status each has now. */
  withStatus(scope: string): (ProcessRecord & { status: ProcessStatus })[] {
    return this.list(scope).map((record) => ({
      ...record,
      status: processStatus(record),
    }));
  }

  /** A new record for a command that is about to start. */
  prepare(
    scope: string,
    sessionId: string,
    command: string,
    cwd: string,
    deadlineMs: number,
  ): ProcessRecord {
    if (typeof command !== "string" || !command.trim() || command.length > 24000)
      throw new Error("Invalid command length");
    if (!Number.isFinite(deadlineMs) || deadlineMs <= 0 || deadlineMs > MAX_DEADLINE_MS)
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
