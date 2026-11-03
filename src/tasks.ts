/** Ordered, bounded session tasks: the agent's running list of steps.
 *
 * Stored per scope as a small JSON file (atomic write, no new store table),
 * projected into the continuity capsule so every session start sees the list.
 * The status vocabulary and the blocked-needs-a-reason rule are shared with the
 * engagement method, so a blocked task cannot lose its justification.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { atomicWrite, newId, now } from "./util";

export type TaskStatus = "pending" | "in-progress" | "completed" | "blocked";
const STATUS: TaskStatus[] = ["pending", "in-progress", "completed", "blocked"];
const MAX_TASKS = 20;
const MAX_TITLE = 200;
const MAX_REASON = 400;
const MAX_DEPENDS = 10;
const identifier = (value: unknown): value is string =>
  typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(value);

export interface Task {
  id: string;
  title: string;
  status: TaskStatus;
  dependsOn: string[];
  reason?: string;
  /** Observation ids that close this task. A completed task carries its proof. */
  evidence?: string[];
  createdAt: string;
  updatedAt: string;
}

export class TaskStore {
  constructor(private stateRoot: string) {
    fs.mkdirSync(stateRoot, { recursive: true });
  }

  private file(scope: string): string {
    return path.join(this.stateRoot, `tasks-${scope}.json`);
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
    const kept = rows.slice(-MAX_TASKS);
    atomicWrite(this.file(scope), JSON.stringify(kept, null, 1));
    return kept;
  }

  list(scope: string): Task[] {
    return this.load(scope).map((row) => ({ ...row, dependsOn: [...row.dependsOn] }));
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
    const openIds = new Set(open.map((row) => row.id));
    return open
      .filter((row) => !row.dependsOn.some((id) => openIds.has(id)))
      .map((row) => ({ ...row, dependsOn: [...row.dependsOn] }));
  }

  get(scope: string, id: string): Task {
    const row = this.load(scope).find((entry) => entry.id === id);
    if (!row) throw new Error(`Unknown task ${id}`);
    return { ...row, dependsOn: [...row.dependsOn] };
  }

  add(scope: string, input: { title: string; dependsOn?: string[] }): Task {
    const title = bounded(input?.title, MAX_TITLE, "task title");
    const dependsOn = Array.isArray(input?.dependsOn)
      ? [...new Set(input.dependsOn.filter((v) => typeof v === "string"))].slice(0, MAX_DEPENDS)
      : [];
    const stamp = now();
    const task: Task = {
      id: newId(), title, status: "pending", dependsOn, createdAt: stamp, updatedAt: stamp,
    };
    this.save(scope, [...this.load(scope), task]);
    return { ...task };
  }

  private transition(
    scope: string,
    id: string,
    status: TaskStatus,
    reason?: string,
    evidence?: string[],
  ): Task {
    identifier(id);
    const rows = this.load(scope);
    const row = rows.find((entry) => entry.id === id);
    if (!row) throw new Error(`Unknown task ${id}`);
    row.status = status;
    row.updatedAt = now();
    if (status === "blocked") row.reason = bounded(reason, MAX_REASON, "blocked reason");
    else delete row.reason;
    if (status === "completed") row.evidence = evidence;
    else delete row.evidence;
    this.save(scope, rows);
    return { ...row, dependsOn: [...row.dependsOn] };
  }

  start(scope: string, id: string): Task {
    return this.transition(scope, id, "in-progress");
  }

  /** A task closes with the observation that proves it, or it does not close. */
  complete(scope: string, id: string, evidence: string[]): Task {
    if (!Array.isArray(evidence) || !evidence.length)
      throw new Error("A completed task requires the observation that proves it");
    const ids = [...new Set(evidence)];
    if (ids.length > 20 || !ids.every(identifier))
      throw new Error("A completed task accepts at most 20 valid observation ids");
    return this.transition(scope, id, "completed", undefined, ids);
  }

  block(scope: string, id: string, reason: string): Task {
    if (typeof reason !== "string" || !reason.trim())
      throw new Error("A blocked task requires a reason");
    return this.transition(scope, id, "blocked", reason);
  }

  remove(scope: string, id: string): void {
    this.save(
      scope,
      this.load(scope).filter((entry) => entry.id !== id),
    );
  }

  clear(scope: string): void {
    this.save(scope, []);
  }
}

const bounded = (value: unknown, max: number, label: string): string => {
  if (typeof value !== "string" || !value.trim())
    throw new Error(`Invalid ${label}`);
  const text = value.trim().slice(0, max);
  if (/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/u.test(text))
    throw new Error(`Invisible control characters are not accepted in a ${label}`);
  return text;
};

const task = (value: unknown): boolean =>
  typeof value === "object" &&
  value !== null &&
  identifier((value as Task).id) &&
  typeof (value as Task).title === "string" &&
  STATUS.includes((value as Task).status) &&
  Array.isArray((value as Task).dependsOn) &&
  ((value as Task).evidence === undefined ||
    (Array.isArray((value as Task).evidence) &&
      (value as Task).evidence!.every((id) => identifier(id))));
