/**
 * The state a session finds when it comes back.
 *
 * A capsule carries the running step list and the observations that close it.
 * It is not a narration: a task that cannot justify itself is left out, so a
 * later session finds the exact state or nothing at all.
 *
 * The rules are the same on every host: a blocked task without a reason is
 * dropped, because the reason is what makes a block auditable, and a
 * completed task without evidence is dropped, because a task closed without
 * proof is a claim, not a fact.
 */
import type { KnowledgeStore } from "./store";
import type { Task, TaskStore } from "./tasks";
import { CONCLUSION_THRESHOLD } from "./investigation";
import { json } from "./util";

export type CapsuleTaskStatus =
  | "pending"
  | "in-progress"
  | "completed"
  | "blocked";

export interface CapsuleTask {
  id: string;
  title: string;
  status: CapsuleTaskStatus;
  dependsOn: string[];
  reason?: string;
  evidence?: string[];
}

export interface CapsuleObservation {
  id: string;
  tool: string;
  success: boolean;
  timestamp: string;
  output: string;
}

export interface Capsule {
  scope: string;
  sessionID: string;
  tasks: CapsuleTask[];
  open: number;
  blocked: number;
  observations: CapsuleObservation[];
  /** The engagement the scope is in, if there is one. */
  mission?: {
    id: string;
    title: string;
    boundaries: string;
    state: string;
    /** Present when the operator closed the engagement before its stages ran. */
    closed?: { reason: string; timestamp: string };
    stages: { id: string; state: string }[];
  };
  workflow?: {
    /** Newest first: `reports[0]` is the current snapshot. */
    reports: { id: string; reviewed: number }[];
    restitutions: { reportId?: string }[];
    capitalizations: unknown[];
    cleanup: { id: string; status: string }[];
    cleanupPolicy: string;
  };
  /** The actions that wait for the operator. */
  approvals?: { id: string; action: string; justification: string }[];
  /** The commands the harness still owns. */
  processes?: { id: string; command: string; status: string }[];
  /** What was read and found, that a later session may need. */
  references?: { kind: string; id: string; hash: string }[];
  /** The investigation arbiter's reading of the declared work. */
  investigation?: {
    /** Surfaces declared but never tested nor blocked. */
    untested: number;
    /** Hypotheses left untouched past the stale window. */
    staleHypotheses: number;
    /** Addressed coverage (tested + blocked), or null when nothing declared. */
    coveragePct: number | null;
  };
}

const MAX_TITLE = 200;
const MAX_REASON = 400;
const MAX_EVIDENCE = 20;
const MAX_OBSERVATIONS = 20;
const MAX_OUTPUT = 600;

/** How many recently completed tasks travel in the compact text. */
const MAX_COMPLETED_IN_TEXT = 5;

const identifier = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(value);

/**
 * One task, or nothing.
 *
 * The filter is the discipline: a block without a reason and a closure
 * without evidence do not travel.
 */
export function capsuleTask(input: {
  id: unknown;
  title: unknown;
  status: unknown;
  dependsOn?: unknown;
  reason?: unknown;
  evidence?: unknown;
}): CapsuleTask | undefined {
  if (!identifier(input.id)) return undefined;
  if (typeof input.title !== "string" || !input.title.trim()) return undefined;
  if (
    !["pending", "in-progress", "completed", "blocked"].includes(
      String(input.status),
    )
  )
    return undefined;
  const dependsOn = Array.isArray(input.dependsOn)
    ? [...new Set(input.dependsOn.filter((d) => identifier(d)))].slice(0, 10)
    : [];
  const status = input.status as CapsuleTaskStatus;
  if (status === "blocked") {
    if (typeof input.reason !== "string" || !input.reason.trim())
      return undefined;
    return {
      id: input.id,
      title: input.title.slice(0, MAX_TITLE),
      status,
      dependsOn,
      reason: input.reason.slice(0, MAX_REASON),
    };
  }
  const evidence = Array.isArray(input.evidence)
    ? [...new Set(input.evidence.filter((e) => identifier(e)))].slice(
        0,
        MAX_EVIDENCE,
      )
    : [];
  if (status === "completed" && !evidence.length) return undefined;
  return {
    id: input.id,
    title: input.title.slice(0, MAX_TITLE),
    status,
    dependsOn,
    ...(evidence.length ? { evidence } : {}),
  };
}

/** The task list, filtered by the rules of the capsule. */
export function capsuleTasks(tasks: readonly Task[]): CapsuleTask[] {
  return tasks
    .map((task) =>
      capsuleTask({
        id: task.id,
        title: task.title,
        status: task.status,
        dependsOn: task.dependsOn,
        reason: task.reason,
        evidence: task.evidence,
      }),
    )
    .filter((task): task is CapsuleTask => task !== undefined);
}

/**
 * The state of a scope, for a session that resumes.
 *
 * The proofs of the closed tasks travel with it, so the resumed session can
 * check a claim instead of trusting it. A closed task whose proof cannot be
 * resolved does not travel either: a claim nobody can check is not a state.
 */
export function capsule(
  taskStore: TaskStore,
  knowledge: KnowledgeStore,
  scope: string,
  sessionID: string,
  options: {
    observations?: number;
    mission?: Capsule["mission"];
    workflow?: Capsule["workflow"];
    approvals?: Capsule["approvals"];
    processes?: Capsule["processes"];
    references?: Capsule["references"];
    investigation?: Capsule["investigation"];
  } = {},
): Capsule {
  const wanted = [
    ...new Set(
      taskStore
        .list(scope)
        .flatMap((task) => (Array.isArray(task.evidence) ? task.evidence : [])),
    ),
  ];
  const proofs = new Map<string, CapsuleObservation>();
  for (const id of wanted) {
    try {
      const [item] = knowledge.evidence(scope, [id]);
      if (!item) continue;
      proofs.set(item.id, {
        id: item.id,
        tool: item.tool,
        success: item.success,
        timestamp: item.timestamp,
        output: item.output.slice(0, MAX_OUTPUT),
      });
    } catch {
      /* A proof that is gone proves nothing. */
    }
  }
  const tasks = taskStore
    .list(scope)
    .map(
      (task) =>
        capsuleTask(task) ?? {
          id: task.id,
          title: task.title,
          status: "blocked" as const,
          dependsOn: task.dependsOn,
          reason:
            "Stored task cannot justify its state; repair it before closure",
        },
    )
    .map((task) => {
      if (task.status !== "completed" || !task.evidence) return task;
      const evidence = task.evidence.filter((id) => proofs.has(id));
      if (
        evidence.length !== task.evidence.length ||
        evidence.some((id) => !proofs.get(id)?.success)
      )
        return {
          ...task,
          status: "blocked" as const,
          reason: "Completion evidence is missing or unsuccessful",
        };
      return { ...task, evidence };
    })
    .filter((task): task is CapsuleTask => task !== undefined);
  let recent: CapsuleObservation[] = [];
  try {
    recent = knowledge
      .observationsForSession(
        sessionID,
        scope,
        options.observations ?? MAX_OBSERVATIONS,
      )
      .map((item) => ({
        id: item.id,
        tool: item.tool,
        success: item.success,
        timestamp: item.timestamp,
        output: item.output.slice(0, MAX_OUTPUT),
      }));
  } catch {
    /* A session that has no row yet has no observation. */
  }
  const proofList = [...proofs.values()];
  return {
    scope,
    sessionID,
    tasks,
    open: tasks.filter((task) => task.status !== "completed").length,
    blocked: tasks.filter((task) => task.status === "blocked").length,
    observations: [...proofList, ...recent].slice(-MAX_OBSERVATIONS * 2),
    ...(options.mission ? { mission: options.mission } : {}),
    ...(options.workflow ? { workflow: options.workflow } : {}),
    ...(options.approvals?.length ? { approvals: options.approvals } : {}),
    ...(options.processes?.length ? { processes: options.processes } : {}),
    ...(options.references?.length ? { references: options.references } : {}),
    ...(options.investigation ? { investigation: options.investigation } : {}),
  };
}

/** The capsule as the text a host injects. */
export function capsuleText(value: Capsule): string {
  if (
    !value.tasks.length &&
    !value.observations.length &&
    !value.mission &&
    !value.approvals?.length &&
    !value.processes?.length &&
    !value.references?.length
  )
    return "";
  return compactCapsuleText(value);
}

/**
 * The raw JSON capsule, for hosts that consume it programmatically.
 *
 * Tests and the closing gate still read the full Capsule object; this is only
 * for callers that need the wire format.
 */
export function capsuleJson(value: Capsule): string {
  return [
    "Continuity. This is the state of the work, not a report about it: the running step list, and the observations that close it.",
    "",
    json(value),
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Compact text — what the model actually sees
// ---------------------------------------------------------------------------

function taskLine(task: CapsuleTask): string {
  const tag = task.status === "blocked" ? `blocked: ${task.reason ?? "?"}` : task.status;
  return `  [${tag}] ${task.title.slice(0, 120)}`;
}

function observationLine(obs: CapsuleObservation): string {
  const ok = obs.success ? "ok" : "FAIL";
  return `  ${obs.id} ${obs.tool} ${ok}`;
}

function compactCapsuleText(value: Capsule): string {
  const lines: string[] = [
    "Continuity. Running state — act on open/blocked steps, not on completed ones.",
  ];

  // ---- mission (if any) ----
  if (value.mission) {
    const m = value.mission;
    const stages = m.stages
      .filter((s) => s.state !== "COMPLETED")
      .map((s) => `${s.id}(${s.state})`)
      .join(", ");
    lines.push("");
    lines.push(`Mission ${m.id} "${m.title}" [${m.state}]${stages ? ` — open: ${stages}` : ""}`);
    if (m.closed) lines.push(`  closed: ${m.closed.reason}`);
  }

  // ---- tasks: open/blocked first, then a few recent completed ----
  const open = value.tasks.filter((t) => t.status !== "completed");
  const completed = value.tasks.filter((t) => t.status === "completed");
  const recentCompleted = completed.slice(-MAX_COMPLETED_IN_TEXT);
  const hiddenCompleted = completed.length - recentCompleted.length;

  if (open.length || recentCompleted.length) {
    lines.push("");
    lines.push(`Steps: ${value.tasks.length} total, ${open.length} open/blocked, ${completed.length} completed`);
    for (const t of open) lines.push(taskLine(t));
    if (hiddenCompleted > 0)
      lines.push(`  ... ${hiddenCompleted} earlier completed steps omitted`);
    for (const t of recentCompleted) lines.push(taskLine(t));
  }

  // ---- observations: one line each, no output blobs ----
  if (value.observations.length) {
    lines.push("");
    lines.push(`Recent observations (${value.observations.length}):`);
    for (const obs of value.observations) lines.push(observationLine(obs));
  }

  // ---- approvals ----
  if (value.approvals?.length) {
    lines.push("");
    lines.push("Waiting for operator:");
    for (const a of value.approvals)
      lines.push(`  ${a.id} ${a.action}: ${a.justification.slice(0, 100)}`);
  }

  // ---- processes ----
  if (value.processes?.length) {
    lines.push("");
    lines.push("Owned commands:");
    for (const p of value.processes)
      lines.push(`  ${p.id} [${p.status}] ${p.command.slice(0, 100)}`);
  }

  // ---- references ----
  if (value.references?.length) {
    lines.push("");
    lines.push("References:");
    for (const r of value.references)
      lines.push(`  ${r.id} [${r.kind}] hash=${r.hash}`);
  }

  // ---- investigation summary ----
  if (value.investigation) {
    const inv = value.investigation;
    lines.push("");
    lines.push(`Investigation: ${inv.coveragePct ?? 0}% coverage, ${inv.untested} untested surface(s), ${inv.staleHypotheses} stale hypothesis(es)`);
  }

  return lines.join("\n");
}

export const GATE_MARKER = "Closing gate.";

/**
 * What still stands between the work and a finished report.
 *
 * A model that is asked "are we done?" answers from its own story. The gate
 * answers from the state: an engagement with a stage still open, a step still
 * running, a command the harness still owns, or an action waiting for the
 * operator. Silence means the state records no blocker, not that the operator
 * asked for a summary.
 */
export function closingGate(value: Capsule): string {
  const blockers: string[] = [];
  const mission = value.mission;
  // A closed engagement is over by decision, with its reason in the capsule:
  // its unrun stages are a fact about the past, not work still to do.
  if (mission && mission.state !== "CLOSED") {
    const pending = mission.stages
      .filter((stage) => stage.state !== "COMPLETED")
      .map((stage) => `${stage.id} (${stage.state})`);
    if (mission.state !== "COMPLETED" && pending.length)
      blockers.push(
        `engagement ${mission.id} is ${mission.state}: ${pending.join(", ")} not closed`,
      );
  }
  const running = value.tasks.filter(
    (task) => task.status === "pending" || task.status === "in-progress",
  ).length;
  if (running) blockers.push(`${running} step(s) still open`);
  if (value.blocked) blockers.push(`${value.blocked} step(s) blocked`);
  if (value.approvals?.length)
    blockers.push(`${value.approvals.length} action(s) wait for the operator`);
  if (value.processes?.length)
    blockers.push(`${value.processes.length} command(s) still owned`);
  const pendingCleanup =
    value.workflow?.cleanup.filter((c) => c.status !== "completed") ?? [];
  if (pendingCleanup.length)
    blockers.push(
      `${pendingCleanup.length} post-restitution cleanup action(s) not verified`,
    );
  // A report that is not reviewed, or an approved report that was never
  // restituted, is the same kind of blocker as an open stage: the work is not
  // done, even when the stage list says otherwise.
  const report = value.workflow?.reports[0];
  if (report && !report.reviewed)
    blockers.push(`report ${report.id} waits for the visual review`);
  if (
    report?.reviewed &&
    !value.workflow?.restitutions.some((r) => r.reportId === report.id)
  )
    blockers.push(`approved report ${report.id} is not restituted`);
  // A lesson that was never recorded is the same kind of gap as a missing
  // restitution: the next mission starts from zero. A closure is a decision
  // not to finish, so it does not owe one. An explicit "none" still counts:
  // the pass happened, there was nothing to keep.
  if (
    mission &&
    mission.state !== "CLOSED" &&
    value.workflow &&
    !value.workflow.capitalizations?.length
  )
    blockers.push(
      `engagement ${mission.id} has no recorded capitalization`,
    );
  // The investigation arbiter blocks a conclusion the same way an open stage
  // does: a declared surface never touched, a hypothesis left stale, or
  // coverage under the threshold is work still standing. A closed engagement
  // is over by decision, so it owes none of this.
  const inv = value.investigation;
  if (inv && (!mission || mission.state !== "CLOSED")) {
    if (inv.untested > 0)
      blockers.push(`${inv.untested} declared surface(s) never tested nor blocked`);
    if (inv.staleHypotheses > 0)
      blockers.push(`${inv.staleHypotheses} hypothesis(es) left stale`);
    if (inv.coveragePct !== null && inv.coveragePct < CONCLUSION_THRESHOLD)
      blockers.push(
        `investigation coverage is ${inv.coveragePct}%, under the ${CONCLUSION_THRESHOLD}% conclusion threshold`,
      );
  }
  if (!blockers.length) return "";
  return [
    `${GATE_MARKER} The work is not finished:`,
    ...blockers.map((blocker) => `- ${blocker}`),
    "A step closes only against a successful observation. Do not report the mission done while a blocker stands, and do not present a plan as a result.",
  ].join("\n");
}
