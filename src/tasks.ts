/** Ordered, bounded session tasks: the agent's running list of steps.
 *
 * Stored per scope as a small JSON file (atomic write, no new store table),
 * projected into the continuity capsule so every session start sees the list.
 * The status vocabulary and the blocked-needs-a-reason rule are shared with the
 * engagement method, so a blocked task cannot lose its justification.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { assertPlainPath, atomicWrite, newId, now } from "./util";

export type TaskStatus = "pending" | "in-progress" | "completed" | "blocked";
const STATUS: TaskStatus[] = ["pending", "in-progress", "completed", "blocked"];
const MAX_TASKS = 1000;
const MAX_TITLE = 200;
const MAX_REASON = 400;
const MAX_DEPENDS = 10;
const MAX_DEPTH = 6;
const STALE_LOCK_MS = 30000;
const identifier = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(value);
const isPidAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
};
const isStaleLock = (lock: string, stat: fs.Stats): boolean => {
  if (Date.now() - stat.mtimeMs > STALE_LOCK_MS) return true;
  try {
    const raw = fs.readFileSync(lock, "utf8").trim();
    if (!raw) return false;
    const parsed = JSON.parse(raw) as { pid?: unknown };
    if (
      typeof parsed?.pid === "number" &&
      Number.isInteger(parsed.pid) &&
      parsed.pid > 0 &&
      parsed.pid !== process.pid &&
      !isPidAlive(parsed.pid)
    )
      return true;
  } catch {
    /* Unreadable or partial lock relies on the age threshold above. */
  }
  return false;
};

export interface Task {
  id: string;
  title: string;
  status: TaskStatus;
  dependsOn: string[];
  /** The parent task, when this one is a sub-step of a larger one. */
  parentId?: string;
  reason?: string;
  /** Observation ids that close this task. A completed task carries its proof. */
  evidence?: string[];
  createdAt: string;
  updatedAt: string;
}

export interface TaskNode extends Task {
  children: TaskNode[];
}

/** A sub-step is addressed when it closed with proof, or was blocked with a reason. */
export function taskAddressed(task: Task): boolean {
  return (
    task.status === "completed" ||
    (task.status === "blocked" && Boolean(task.reason?.trim()))
  );
}

export class TaskStore {
  constructor(private stateRoot: string) {
    fs.mkdirSync(stateRoot, { recursive: true });
  }

  private file(scope: string): string {
    if (!/^[a-z][a-z0-9-]{0,95}$/.test(scope))
      throw new Error("Invalid task scope");
    return path.join(this.stateRoot, `tasks-${scope}.json`);
  }

  private acquireLock(lock: string): number {
    assertPlainPath(lock);
    try {
      return fs.openSync(lock, "wx", 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    const stat = fs.lstatSync(lock, { throwIfNoEntry: false });
    if (stat?.isSymbolicLink())
      throw new Error("Linked or special harness paths are not allowed");
    if (stat && isStaleLock(lock, stat)) {
      const recovery = `${lock}.recover`;
      assertPlainPath(recovery);
      let recFd: number | undefined;
      try {
        recFd = fs.openSync(recovery, "wx", 0o600);
        const current = fs.lstatSync(lock, { throwIfNoEntry: false });
        if (
          current &&
          !current.isSymbolicLink() &&
          current.dev === stat.dev &&
          current.ino === stat.ino &&
          current.mtimeMs === stat.mtimeMs &&
          isStaleLock(lock, current)
        )
          fs.unlinkSync(lock);
      } catch {
        /* Another worker is already recovering or owns the lock. */
      } finally {
        if (recFd !== undefined) {
          fs.closeSync(recFd);
          try {
            fs.unlinkSync(recovery);
          } catch {
            /* already removed */
          }
        }
      }
      try {
        assertPlainPath(lock);
        return fs.openSync(lock, "wx", 0o600);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST")
          throw new Error("Concurrent task update; retry from the current state");
        throw error;
      }
    }
    throw new Error("Concurrent task update; retry from the current state");
  }

  private mutate<T>(scope: string, fn: () => T): T {
    const lock = `${this.file(scope)}.lock`;
    const fd = this.acquireLock(lock);
    try {
      fs.writeSync(
        fd,
        JSON.stringify({ pid: process.pid, createdAt: Date.now() }),
      );
      return fn();
    } finally {
      const held = fs.fstatSync(fd);
      fs.closeSync(fd);
      const onDisk = fs.lstatSync(lock, { throwIfNoEntry: false });
      if (onDisk && onDisk.dev === held.dev && onDisk.ino === held.ino) {
        try {
          fs.unlinkSync(lock);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        }
      }
    }
  }
  /**
   * The task list is read from the file on every use.
   *
   * Several hosts, and several instances inside one host, share this file. A
   * cached copy would let each of them believe it owns the list, and the last
   * writer would silently drop the tasks of the others. The file is small and
   * bounded, so reading it is cheaper than being wrong.
   */
  private load(scope: string): Task[] {
    let rows: Task[] = [];
    try {
      assertPlainPath(this.file(scope));
      const value = JSON.parse(fs.readFileSync(this.file(scope), "utf8"));
      if (!Array.isArray(value) || !value.every((row) => task(row)))
        throw new Error("Invalid task storage");
      rows = value;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    return rows;
  }

  private save(scope: string, rows: Task[]): Task[] {
    if (rows.length > MAX_TASKS)
      throw new Error(
        "Task capacity reached; archive completed work explicitly",
      );
    const kept = rows;
    atomicWrite(this.file(scope), JSON.stringify(kept, null, 1));
    return kept;
  }

  list(scope: string): Task[] {
    return this.load(scope).map((row) => ({
      ...row,
      dependsOn: [...row.dependsOn],
    }));
  }

  /** The review packet: every task with the observations that close it. */
  review(scope: string): {
    open: Task[];
    closed: { task: Task; evidence: string[] }[];
    unproven: Task[];
  } {
    const rows = this.load(scope);
    const open: Task[] = [];
    const unproven: Task[] = [];
    const closed: { task: Task; evidence: string[] }[] = [];
    for (const row of rows) {
      const copy = { ...row, dependsOn: [...row.dependsOn] };
      if (row.status === "pending" || row.status === "in-progress") {
        open.push(copy);
        continue;
      }
      if (row.status === "completed" && !row.evidence?.length) {
        unproven.push(copy);
        continue;
      }
      closed.push({ task: copy, evidence: row.evidence ?? [] });
    }
    return { open, closed, unproven };
  }

  /**
   * Open tasks that can start now: none of their dependencies is still open.
   * Those are the independent items, the only case where delegation pays.
   */
  delegable(scope: string): Task[] {
    const rows = this.load(scope);
    const open = rows.filter(
      (row) => row.status === "pending" || row.status === "in-progress",
    );
    const completed = new Set(
      rows.filter((row) => row.status === "completed").map((row) => row.id),
    );
    return open
      .filter((row) => row.dependsOn.every((id) => completed.has(id)))
      .map((row) => ({ ...row, dependsOn: [...row.dependsOn] }));
  }

  get(scope: string, id: string): Task {
    const row = this.load(scope).find((entry) => entry.id === id);
    if (!row) throw new Error(`Unknown task ${id}`);
    return { ...row, dependsOn: [...row.dependsOn] };
  }

  add(
    scope: string,
    input: { title: string; dependsOn?: string[]; parent?: string },
  ): Task {
    return this.mutate(scope, () => {
      const title = bounded(input?.title, MAX_TITLE, "task title");
      let dependsOn: string[] = [];
      if (input?.dependsOn !== undefined) {
        if (
          !Array.isArray(input.dependsOn) ||
          !input.dependsOn.every(identifier)
        )
          throw new Error("Invalid task dependency list");
        dependsOn = [...new Set(input.dependsOn)];
        if (dependsOn.length > MAX_DEPENDS)
          throw new Error(
            `A task accepts at most ${MAX_DEPENDS} dependencies`,
          );
      }
      const rows = this.load(scope);
      if (dependsOn.some((id) => !rows.some((r) => r.id === id)))
        throw new Error("Missing task dependency");
      const stamp = now();
      let parentId: string | undefined;
      if (input?.parent !== undefined) {
        if (!identifier(input.parent)) throw new Error("Invalid parent task id");
        const ancestors: Task[] = [];
        const seen = new Set<string>();
        let cursor = rows.find((row) => row.id === input.parent),
          depth = 1;
        if (!cursor) throw new Error("Unknown parent task");
        while (cursor) {
          if (seen.has(cursor.id)) throw new Error("Task tree cycle");
          seen.add(cursor.id);
          ancestors.push(cursor);
          if (!cursor.parentId) break;
          depth += 1;
          if (depth > MAX_DEPTH) throw new Error("Task tree is too deep");
          cursor = rows.find((row) => row.id === cursor!.parentId);
        }
        for (const ancestor of ancestors) {
          if (
            ancestor.status === "completed" &&
            rows.some(
              (r) =>
                r.dependsOn.includes(ancestor.id) &&
                ["in-progress", "completed"].includes(r.status),
            )
          )
            throw new Error(
              "Cannot add subtask to a completed task while dependent tasks are active or completed",
            );
        }
        for (const ancestor of ancestors) {
          if (ancestor.status === "completed" || ancestor.status === "blocked") {
            ancestor.status = "pending";
            delete ancestor.reason;
            delete ancestor.evidence;
            ancestor.updatedAt = stamp;
          }
        }
        parentId = input.parent;
      }
      const task: Task = {
        id: newId(),
        title,
        status: "pending",
        dependsOn,
        ...(parentId ? { parentId } : {}),
        createdAt: stamp,
        updatedAt: stamp,
      };
      this.save(scope, [...rows, task]);
      return { ...task, dependsOn: [...task.dependsOn] };
    });
  }

  /** The list as a forest, newest branch last. */
  tree(scope: string): TaskNode[] {
    const rows = this.load(scope);
    const nodes = new Map<string, TaskNode>();
    for (const row of rows)
      nodes.set(row.id, {
        ...row,
        dependsOn: [...row.dependsOn],
        children: [],
      });
    const roots: TaskNode[] = [];
    for (const row of rows) {
      const node = nodes.get(row.id)!;
      const parent = row.parentId ? nodes.get(row.parentId) : undefined;
      if (parent) parent.children.push(node);
      else roots.push(node);
    }
    return roots;
  }

  /** A Markdown outline a person can read, and an editor like CherryTree can import. */
  markdown(scope: string): string {
    const lines = ["# Coverage map", ""];
    const walk = (nodes: TaskNode[], depth: number) => {
      for (const node of nodes) {
        const mark =
          node.status === "completed"
            ? "x"
            : node.status === "in-progress"
              ? "~"
              : node.status === "blocked"
                ? "!"
                : " ";
        const evidence = node.evidence?.length
          ? ` — ${node.evidence.join(", ")}`
          : "";
        const reason = node.reason ? ` — blocked: ${node.reason}` : "";
        lines.push(
          `${"  ".repeat(depth)}- [${mark}] ${node.title}${evidence}${reason}`,
        );
        walk(node.children, depth + 1);
      }
    };
    walk(this.tree(scope), 0);
    return lines.join("\n") + "\n";
  }

  private transition(
    scope: string,
    id: string,
    status: TaskStatus,
    reason?: string,
    evidence?: string[],
  ): Task {
    if (!identifier(id)) throw new Error("Invalid task id");
    return this.mutate(scope, () => {
      const rows = this.load(scope);
      const row = rows.find((entry) => entry.id === id);
      if (!row) throw new Error(`Unknown task ${id}`);
      if (
        ["in-progress", "completed"].includes(status) &&
        row.dependsOn.some(
          (dep) => !rows.some((r) => r.id === dep && r.status === "completed"),
        )
      )
        throw new Error("Task dependency is not completed");
      // A branch is not done while a sub-step under it is still open.
      // A blocked child with a reason is addressed: the step was looked at.
      if (
        status === "completed" &&
        rows.some((r) => r.parentId === id && !taskAddressed(r))
      )
        throw new Error("A task closes only after its subtasks");
      if (row.status === "completed" && status !== "completed") {
        if (
          rows.some(
            (r) =>
              r.dependsOn.includes(id) &&
              ["in-progress", "completed"].includes(r.status),
          )
        )
          throw new Error(
            "Cannot reopen a completed task while dependent tasks are active or completed",
          );
        if (
          row.parentId &&
          rows.some((r) => r.id === row.parentId && r.status === "completed")
        )
          throw new Error(
            "Cannot reopen a completed subtask while its parent task is completed",
          );
      }
      if (
        status === "in-progress" &&
        row.parentId &&
        rows.some((r) => r.id === row.parentId && r.status === "completed")
      )
        throw new Error(
          "Cannot reopen a subtask while its parent task is completed",
        );
      row.status = status;
      row.updatedAt = now();
      if (status === "blocked")
        row.reason = bounded(reason, MAX_REASON, "blocked reason");
      else delete row.reason;
      if (status === "completed") row.evidence = evidence;
      else delete row.evidence;
      this.save(scope, rows);
      return { ...row, dependsOn: [...row.dependsOn] };
    });
  }

  start(scope: string, id: string): Task {
    return this.transition(scope, id, "in-progress");
  }

  /** A task closes with the observation that proves it, or it does not close. */
  complete(scope: string, id: string, evidence: string[]): Task {
    if (!Array.isArray(evidence) || !evidence.length)
      throw new Error(
        "A completed task requires the observation that proves it",
      );
    const ids = [...new Set(evidence)];
    if (ids.length > 20 || !ids.every(identifier))
      throw new Error(
        "A completed task accepts at most 20 valid observation ids",
      );
    return this.transition(scope, id, "completed", undefined, ids);
  }

  block(scope: string, id: string, reason: string): Task {
    if (typeof reason !== "string" || !reason.trim())
      throw new Error("A blocked task requires a reason");
    return this.transition(scope, id, "blocked", reason);
  }

  remove(scope: string, id: string): void {
    this.mutate(scope, () => {
      const rows = this.load(scope);
      if (rows.some((r) => r.dependsOn.includes(id)))
        throw new Error("Task is still a dependency");
      if (rows.some((r) => r.parentId === id))
        throw new Error("Task still has subtasks");
      this.save(
        scope,
        rows.filter((r) => r.id !== id),
      );
    });
  }
  clear(scope: string): void {
    this.mutate(scope, () => this.save(scope, []));
  }
}

const bounded = (value: unknown, max: number, label: string): string => {
  if (typeof value !== "string" || !value.trim())
    throw new Error(`Invalid ${label}`);
  const text = value.trim().slice(0, max);
  if (/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/u.test(text))
    throw new Error(
      `Invisible control characters are not accepted in a ${label}`,
    );
  return text;
};

const task = (value: unknown): boolean =>
  typeof value === "object" &&
  value !== null &&
  identifier((value as Task).id) &&
  typeof (value as Task).title === "string" &&
  STATUS.includes((value as Task).status) &&
  Array.isArray((value as Task).dependsOn) &&
  ((value as Task).parentId === undefined ||
    identifier((value as Task).parentId)) &&
  ((value as Task).evidence === undefined ||
    (Array.isArray((value as Task).evidence) &&
      (value as Task).evidence!.every((id) => identifier(id))));
