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
const identifier = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(value);

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

export class TaskStore {
  constructor(private stateRoot: string) {
    fs.mkdirSync(stateRoot, { recursive: true });
  }

  private file(scope: string): string {
    if (!/^[a-z][a-z0-9-]{0,95}$/.test(scope))
      throw new Error("Invalid task scope");
    return path.join(this.stateRoot, `tasks-${scope}.json`);
  }

  private mutate<T>(scope: string, fn: () => T): T {
    const lock = `${this.file(scope)}.lock`;
    assertPlainPath(lock);
    let fd: number;
    try {
      fd = fs.openSync(lock, "wx", 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST")
        throw new Error("Concurrent task update; retry from the current state");
      throw error;
    }
    try {
      return fn();
    } finally {
      fs.closeSync(fd);
      fs.unlinkSync(lock);
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
      const dependsOn = Array.isArray(input?.dependsOn)
        ? [
            ...new Set(input.dependsOn.filter((v) => typeof v === "string")),
          ].slice(0, MAX_DEPENDS)
        : [];
      const rows = this.load(scope);
      if (dependsOn.some((id) => !rows.some((r) => r.id === id)))
        throw new Error("Missing task dependency");
      let parentId: string | undefined;
      if (input?.parent !== undefined) {
        if (!identifier(input.parent)) throw new Error("Invalid parent task id");
        let cursor = rows.find((row) => row.id === input.parent),
          depth = 1;
        if (!cursor) throw new Error("Unknown parent task");
        while (cursor?.parentId) {
          depth += 1;
          if (depth > MAX_DEPTH) throw new Error("Task tree is too deep");
          cursor = rows.find((row) => row.id === cursor!.parentId);
        }
        parentId = input.parent;
      }
      const stamp = now();
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
      return { ...task };
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
      if (
        status === "completed" &&
        rows.some((r) => r.parentId === id && r.status !== "completed")
      )
        throw new Error("A task closes only after its subtasks");
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
