/**
 * Autonomous investigation engine.
 *
 * Analyses observations, tasks and timing to detect stagnation, loops,
 * uncovered surfaces, and premature conclusions.  It produces directives —
 * short imperative sentences injected into the context — not suggestions.
 *
 * The signal functions are pure: they read the observation stream, the task
 * tree and the clock, and never write.  `InvestigationStore` persists the two
 * things the model declares — hypotheses and surface coverage — so a resumed
 * session finds them, and the host assembles the state on every turn.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { assertPlainPath, atomicWrite, newId, now } from "./util";
import { phaseDirective, detectPhase, counterLogicGauntlet, type PhaseInput, EXPLOIT_TOOLS_SET } from "./phases";

// ---------------------------------------------------------------------------
// Hypothesis tracker
// ---------------------------------------------------------------------------

export type HypothesisState =
  | "proposed"
  | "testing"
  | "confirmed"
  | "refuted"
  | "stale";

export interface Hypothesis {
  id: string;
  text: string;
  state: HypothesisState;
  /** Observation ids of the reproduction — the claim firing. */
  evidence: string[];
  /** Observation ids of the negative control — the claim not firing. */
  control: string[];
  /** Output fingerprints keyed by observation id. Compared, not the ids. */
  outputs: Record<string, string>;
  /** Observation ids that refute this hypothesis. */
  counterEvidence: string[];
  createdAt: string;
  updatedAt: string;
}

const STALE_MS = 30 * 60 * 1000;
const HYPOTHESIS_STATES: HypothesisState[] = [
  "proposed",
  "testing",
  "confirmed",
  "refuted",
  "stale",
];
const SURFACE_STATES: SurfaceState[] = [
  "untested",
  "in-progress",
  "tested",
  "blocked",
];
const identifier = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(value);
const assertTimestamp = (value: string): number => {
  if (typeof value !== "string") throw new Error("Invalid timestamp");
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) throw new Error("Invalid timestamp");
  return ms;
};

function normalizeHypothesis(h: Hypothesis): Hypothesis {
  return {
    ...h,
    evidence: [...(h.evidence ?? [])],
    control: [...(h.control ?? [])],
    outputs: { ...(h.outputs ?? {}) },
    counterEvidence: [...(h.counterEvidence ?? [])],
  };
}

/**
 * A hypothesis confirms only with a reproduction and a negative control that
 * observe different outputs. A successful observation alone is not a claim.
 */
export function canConfirmHypothesis(h: Hypothesis): boolean {
  const control = h.control ?? [];
  const outputs = h.outputs ?? {};
  if (h.evidence.length === 0 || control.length === 0) return false;
  for (const eid of h.evidence) {
    if (!outputs[eid]) return false;
    if (control.includes(eid)) return false;
  }
  for (const cid of control) {
    if (!outputs[cid]) return false;
    if (h.evidence.includes(cid)) return false;
    for (const eid of h.evidence) {
      if (outputs[cid] === outputs[eid]) return false;
    }
  }
  return true;
}

export function advanceHypothesis(
  h: Hypothesis,
  now: number,
): HypothesisState {
  if (h.state === "confirmed" || h.state === "refuted") return h.state;
  if (h.counterEvidence.length > 0) return "refuted";
  const fresh = now - Date.parse(h.updatedAt) <= STALE_MS;
  if (
    (h.state === "testing" || (h.state === "stale" && fresh)) &&
    canConfirmHypothesis(h)
  )
    return "confirmed";
  if (!fresh) return "stale";
  if (h.state === "stale") return "testing";
  return h.state;
}

function bindObservation(
  h: Hypothesis,
  list: "evidence" | "control",
  observationId: string,
  outputHash: string,
): void {
  const fingerprint = outputHash.trim();
  if (!fingerprint)
    throw new Error("A bound observation needs the output fingerprint");
  const other = list === "evidence" ? h.control : h.evidence;
  if (other.includes(observationId))
    throw new Error("A negative control cannot be the reproduction");
  for (const id of other) {
    if (h.outputs[id] && h.outputs[id] === fingerprint)
      throw new Error(
        "A negative control must observe a different output than the reproduction",
      );
  }
  if (!h[list].includes(observationId)) h[list].push(observationId);
  h.outputs[observationId] = fingerprint;
}

export class HypothesisTracker {
  private items: Hypothesis[] = [];

  constructor(initial?: readonly Hypothesis[]) {
    if (initial) this.items = initial.map((h) => normalizeHypothesis(h));
  }

  propose(id: string, text: string, timestamp: string): Hypothesis {
    if (!identifier(id)) throw new Error("Invalid hypothesis id");
    if (typeof text !== "string" || !text.trim())
      throw new Error("Hypothesis text is required");
    assertTimestamp(timestamp);
    if (this.items.some((h) => h.id === id))
      throw new Error(`Hypothesis ${id} already exists`);
    const h: Hypothesis = {
      id,
      text: text.trim(),
      state: "proposed",
      evidence: [],
      control: [],
      outputs: {},
      counterEvidence: [],
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    this.items.push(h);
    return normalizeHypothesis(h);
  }

  test(id: string, timestamp: string): Hypothesis {
    const ms = assertTimestamp(timestamp);
    const h = this.find(id);
    if (h.state !== "proposed" && h.state !== "stale")
      throw new Error(`Hypothesis ${id} is ${h.state}, cannot start testing`);
    h.state = "testing";
    h.updatedAt = timestamp;
    h.state = advanceHypothesis(h, ms);
    return normalizeHypothesis(h);
  }

  addEvidence(
    id: string,
    observationId: string,
    timestamp: string,
    outputHash: string,
  ): Hypothesis {
    const ms = assertTimestamp(timestamp);
    const h = this.find(id);
    if (h.state === "confirmed" || h.state === "refuted")
      throw new Error(`Hypothesis ${id} is already ${h.state}`);
    bindObservation(h, "evidence", observationId, outputHash);
    h.updatedAt = timestamp;
    h.state = advanceHypothesis(h, ms);
    return normalizeHypothesis(h);
  }

  addControl(
    id: string,
    observationId: string,
    timestamp: string,
    outputHash: string,
  ): Hypothesis {
    const ms = assertTimestamp(timestamp);
    const h = this.find(id);
    if (h.state === "confirmed" || h.state === "refuted")
      throw new Error(`Hypothesis ${id} is already ${h.state}`);
    bindObservation(h, "control", observationId, outputHash);
    h.updatedAt = timestamp;
    h.state = advanceHypothesis(h, ms);
    return normalizeHypothesis(h);
  }

  refute(id: string, observationId: string, timestamp: string): Hypothesis {
    assertTimestamp(timestamp);
    const h = this.find(id);
    if (h.state === "confirmed")
      throw new Error(`Hypothesis ${id} is confirmed; open a new one`);
    if (!h.counterEvidence.includes(observationId))
      h.counterEvidence.push(observationId);
    h.updatedAt = timestamp;
    h.state = "refuted";
    return normalizeHypothesis(h);
  }

  /** Advance all non-terminal hypotheses and return the ones that became stale. */
  tick(now: number): Hypothesis[] {
    const stale: Hypothesis[] = [];
    for (const h of this.items) {
      const next = advanceHypothesis(h, now);
      if (next !== h.state) {
        h.state = next;
        h.updatedAt = new Date(now).toISOString();
        if (next === "stale") stale.push(normalizeHypothesis(h));
      }
    }
    return stale;
  }

  list(): readonly Hypothesis[] {
    return this.items.map((h) => normalizeHypothesis(h));
  }

  active(): Hypothesis[] {
    return this.items
      .filter((h) => h.state === "proposed" || h.state === "testing")
      .map((h) => normalizeHypothesis(h));
  }

  refuted(): Hypothesis[] {
    return this.items
      .filter((h) => h.state === "refuted")
      .map((h) => normalizeHypothesis(h));
  }

  private find(id: string): Hypothesis {
    const h = this.items.find((item) => item.id === id);
    if (!h) throw new Error(`Unknown hypothesis ${id}`);
    return h;
  }
}

// ---------------------------------------------------------------------------
// Stagnation detector
// ---------------------------------------------------------------------------

export interface ToolCall {
  tool: string;
  outputHash: string;
  success: boolean;
  timestamp: string;
  input?: unknown;
}

export interface StagnationSignal {
  kind: "tool-loop" | "output-repeat" | "no-progress" | "same-failure";
  detail: string;
  severity: "warning" | "critical";
}

const WINDOW_SIZE = 10;
const LOOP_THRESHOLD = 3;
const NO_PROGRESS_MINUTES = 15;
const PROCESS_BOOKKEEPING_ACTIONS = new Set(["run", "list", "stop", "prune"]);

function isNonReadProcessAction(call: ToolCall): boolean {
  if (call.tool !== "cyber_process") return false;
  const action =
    call.input && typeof call.input === "object"
      ? (call.input as Record<string, unknown>).action
      : undefined;
  return (
    typeof action === "string" && PROCESS_BOOKKEEPING_ACTIONS.has(action)
  );
}

export function detectStagnation(
  calls: readonly ToolCall[],
  openTaskCount: number,
  completedRecently: number,
  nowMs: number,
): StagnationSignal[] {
  const signals: StagnationSignal[] = [];
  if (calls.length < 3) return signals;

  const recent = calls.slice(-WINDOW_SIZE);
  // Intentional non-"read" cyber_process calls carry success:false per
  // DECISIONS.md ("launch is not a proof outcome"), so exclude them from
  // tool-loop, output-repeat, and same-failure signals.
  const recentActionable = calls
    .filter((call) => !isNonReadProcessAction(call))
    .slice(-WINDOW_SIZE);

  // Tool loop: same tool called N+ times in the window
  const toolCounts = new Map<string, number>();
  for (const call of recentActionable)
    toolCounts.set(call.tool, (toolCounts.get(call.tool) ?? 0) + 1);
  for (const [tool, count] of toolCounts) {
    if (count >= LOOP_THRESHOLD) {
      signals.push({
        kind: "tool-loop",
        detail: `${tool} called ${count} times in last ${recentActionable.length} calls`,
        severity: count >= LOOP_THRESHOLD + 2 ? "critical" : "warning",
      });
    }
  }

  // Output repeat: same output hash appearing 3+ times
  const hashCounts = new Map<string, number>();
  for (const call of recentActionable)
    hashCounts.set(call.outputHash, (hashCounts.get(call.outputHash) ?? 0) + 1);
  for (const [h, count] of hashCounts) {
    if (count >= LOOP_THRESHOLD) {
      signals.push({
        kind: "output-repeat",
        detail: `Same output hash ${h.slice(0, 8)} seen ${count} times`,
        severity: "critical",
      });
    }
  }

  // Same failure: same tool failing repeatedly
  const failCounts = new Map<string, number>();
  for (const call of recentActionable) {
    if (!call.success)
      failCounts.set(call.tool, (failCounts.get(call.tool) ?? 0) + 1);
  }
  for (const [tool, count] of failCounts) {
    if (count >= LOOP_THRESHOLD) {
      signals.push({
        kind: "same-failure",
        detail: `${tool} failed ${count} times in last ${recentActionable.length} calls`,
        severity: "critical",
      });
    }
  }

  // No progress: tasks open but nothing completed in a while
  if (openTaskCount > 0 && completedRecently === 0 && recent.length >= 5) {
    const oldest = Date.parse(recent[0].timestamp);
    if (nowMs - oldest > NO_PROGRESS_MINUTES * 60 * 1000) {
      signals.push({
        kind: "no-progress",
        detail: `${openTaskCount} tasks open, none completed in ${NO_PROGRESS_MINUTES}+ minutes`,
        severity: "critical",
      });
    }
  }

  return signals;
}

// ---------------------------------------------------------------------------
// Coverage state machine
// ---------------------------------------------------------------------------

export type SurfaceState = "untested" | "in-progress" | "tested" | "blocked";

export interface SurfaceCoverage {
  id: string;
  label: string;
  state: SurfaceState;
  evidence: string[];
  reason?: string;
}

function cloneSurface(s: SurfaceCoverage): SurfaceCoverage {
  return {
    ...s,
    evidence: [...(s.evidence ?? [])],
  };
}

export class CoverageMap {
  private surfaces: Map<string, SurfaceCoverage> = new Map();

  constructor(entries?: readonly { id: string; label: string }[]) {
    if (entries) {
      for (const entry of entries) {
        this.surfaces.set(entry.id, {
          id: entry.id,
          label: entry.label,
          state: "untested",
          evidence: [],
        });
      }
    }
  }

  add(id: string, label: string): void {
    if (!identifier(id)) throw new Error("Invalid surface id");
    if (typeof label !== "string" || !label.trim())
      throw new Error("Surface label is required");
    if (!this.surfaces.has(id)) {
      this.surfaces.set(id, {
        id,
        label: label.trim(),
        state: "untested",
        evidence: [],
      });
    }
  }

  start(id: string): void {
    const s = this.get(id);
    if (s.state === "untested") s.state = "in-progress";
  }

  complete(id: string, evidence: string[]): void {
    const s = this.get(id);
    if (!evidence.length)
      throw new Error("A tested surface needs at least one observation");
    s.state = "tested";
    s.evidence = [...new Set([...s.evidence, ...evidence])];
    delete s.reason;
  }

  block(id: string, reason: string): void {
    if (typeof reason !== "string" || !reason.trim())
      throw new Error("A blocked surface requires a reason");
    const s = this.get(id);
    s.state = "blocked";
    s.reason = reason.trim();
  }

  summary(): {
    total: number;
    tested: number;
    inProgress: number;
    blocked: number;
    untested: number;
    surfaces: SurfaceCoverage[];
  } {
    const all = [...this.surfaces.values()];
    return {
      total: all.length,
      tested: all.filter((s) => s.state === "tested").length,
      inProgress: all.filter((s) => s.state === "in-progress").length,
      blocked: all.filter((s) => s.state === "blocked").length,
      untested: all.filter((s) => s.state === "untested").length,
      surfaces: all.map((s) => cloneSurface(s)),
    };
  }

  untested(): SurfaceCoverage[] {
    return [...this.surfaces.values()]
      .filter((s) => s.state === "untested")
      .map((s) => cloneSurface(s));
  }

  /** Every surface, for persistence. */
  entries(): SurfaceCoverage[] {
    return [...this.surfaces.values()].map((s) => cloneSurface(s));
  }

  /** Rebuild a map from persisted surfaces, keeping their states. */
  static fromEntries(entries: readonly SurfaceCoverage[]): CoverageMap {
    const map = new CoverageMap();
    for (const entry of entries) {
      map.surfaces.set(entry.id, cloneSurface(entry));
    }
    return map;
  }

  private get(id: string): SurfaceCoverage {
    const s = this.surfaces.get(id);
    if (!s) throw new Error(`Unknown surface ${id}`);
    return s;
  }
}

// ---------------------------------------------------------------------------
// Investigation directives
// ---------------------------------------------------------------------------

export interface InvestigationState {
  hypotheses: readonly Hypothesis[];
  stagnation: readonly StagnationSignal[];
  coverage: ReturnType<CoverageMap["summary"]>;
  /** Tasks completed with evidence in this session. */
  completedWithEvidence: number;
  /** Total observations in this session. */
  observationCount: number;
  /** Tools used in the observation window, for proactive directives. */
  toolsUsed?: readonly string[];
  /** Consecutive failed exploit-class tool calls (for 3-failure backtrack). */
  consecutiveExploitFailures?: number;
}

export interface Directive {
  priority: "mandatory" | "recommended";
  text: string;
}

const HTTP_FLOW_TOOLS = new Set([
  "curl",
  "httpx",
  "wget",
  "fetch",
  "webfetch",
  "web_fetch",
  "burp",
  "mitmproxy",
  "zap",
  "ffuf",
  "gobuster",
  "dirsearch",
  "feroxbuster",
  "wfuzz",
  "nuclei",
  "sqlmap",
  "dalfox",
  "katana",
  "hakrawler",
  "arjun",
  "paramspider",
  "nikto",
  "whatweb",
  "cariddi",
  "commix",
  "tplmap",
  "ssrfmap",
  "nosqlmap",
  "xsstrike",
]);

const RECON_TOOLS = [
  "nmap",
  "httpx",
  "whatweb",
  "wappalyzer",
  "nuclei",
  "nikto",
  "wafw00f",
  "curl",
  "gobuster",
  "feroxbuster",
  "dirsearch",
];

/**
 * Produce directives from the investigation state.
 *
 * The directives are imperative: they tell the model what to do, not what
 * it should consider.  A model that ignores a mandatory directive is in
 * violation — the harness can flag it on the next turn.
 */
export function directives(state: InvestigationState): Directive[] {
  const result: Directive[] = [];

  // Stagnation directives — highest priority
  for (const signal of state.stagnation) {
    if (signal.severity === "critical") {
      if (signal.kind === "tool-loop" || signal.kind === "output-repeat") {
        result.push({
          priority: "mandatory",
          text: `STAGNATION: ${signal.detail}. Stop repeating. Change approach: different tool, different parameter, different surface.`,
        });
      } else if (signal.kind === "same-failure") {
        result.push({
          priority: "mandatory",
          text: `REPEATED FAILURE: ${signal.detail}. This tool is not working for this case. Record the failure, block the task, and move to another surface.`,
        });
      } else if (signal.kind === "no-progress") {
        result.push({
          priority: "mandatory",
          text: `NO PROGRESS: ${signal.detail}. Step back. Review what has been tried, what failed, and pick an untested surface or a new hypothesis.`,
        });
      }
    } else {
      result.push({
        priority: "recommended",
        text: `Warning: ${signal.detail}. Consider changing approach before this becomes a loop.`,
      });
    }
  }

  // Hypothesis discipline
  const activeH = state.hypotheses.filter(
    (h) => h.state === "proposed" || h.state === "testing",
  );
  const staleH = state.hypotheses.filter((h) => h.state === "stale");
  const refutedH = state.hypotheses.filter((h) => h.state === "refuted");

  if (staleH.length > 0) {
    result.push({
      priority: "recommended",
      text: `Stale hypotheses: ${staleH.map((h) => h.id).join(", ")} have not been tested in 30+ minutes. When you have a moment, refute or replace them — but finish your current offensive work first.`,
    });
  }

  if (
    state.observationCount > 5 &&
    activeH.length === 0 &&
    state.coverage.untested > 0
  ) {
    result.push({
      priority: "recommended",
      text: `No active hypothesis. Formulate one before continuing: what do you expect to find, and how will you test it?`,
    });
  }

  if (refutedH.length > 0 && activeH.length === 0) {
    result.push({
      priority: "recommended",
      text: `All hypotheses refuted (${refutedH.map((h) => h.id).join(", ")}). Do not revisit them. Formulate a new hypothesis from a different angle.`,
    });
  }

  // Coverage discipline
  const cov = state.coverage;
  if (cov.total > 0) {
    const pct = Math.round((cov.tested / cov.total) * 100);
    if (cov.untested > 0 && cov.inProgress === 0 && state.observationCount > 10) {
      result.push({
        priority: "recommended",
        text: `Coverage: ${pct}% (${cov.tested}/${cov.total}). ${cov.untested} surfaces untested: ${state.coverage.surfaces
          .filter((s) => s.state === "untested")
          .slice(0, 5)
          .map((s) => s.label)
          .join(", ")}${cov.untested > 5 ? "..." : ""}. Pick one.`,
      });
    }
    if (cov.blocked > 0) {
      result.push({
        priority: "recommended",
        text: `${cov.blocked} surface(s) blocked. Review if the blocker is still valid or if a workaround exists.`,
      });
    }
  }

  // Deepening discipline — a confirmed finding is a lead, not a conclusion.
  // If the model confirmed a hypothesis but has no active follow-up, push it
  // to explore the adjacent attack surface that the finding opens.
  const confirmedH = state.hypotheses.filter((h) => h.state === "confirmed");
  if (confirmedH.length > 0 && activeH.length === 0 && cov.untested > 0) {
    const latest = confirmedH[confirmedH.length - 1];
    const entry = escalationFor(latest.text);
    const specific = entry
      ? ` Escalation paths: ${entry.paths.slice(0, 3).join("; ")}. Load: ${entry.skills.slice(0, 2).join(", ")}.`
      : "";
    result.push({
      priority: "recommended",
      text: `DEEPEN: ${confirmedH.length} confirmed finding(s) but no active hypothesis.${specific} A confirmed vulnerability opens adjacent surfaces: escalation, lateral (same flaw on other endpoints), and chaining (combine with another finding). Formulate a deepening hypothesis.`,
    });
  }

  // Cross-referencing: when multiple findings are confirmed, the model should
  // look for chains, not just collect isolated bugs.
  if (confirmedH.length >= 2 && activeH.length === 0) {
    result.push({
      priority: "recommended",
      text: `CROSS-REFERENCE: ${confirmedH.length} confirmed findings. Look for attack chains: can finding A enable or amplify finding B? Document any chain as a new hypothesis.`,
    });
  }

  // Shallow testing guard: a surface tested with a single observation and no
  // deepening hypothesis is likely superficial. Only fire when there's room
  // to deepen (other surfaces are covered, so this isn't a breadth problem).
  if (cov.total > 0 && cov.tested > 0 && cov.untested === 0 && activeH.length === 0) {
    const shallow = cov.surfaces.filter(
      (s) => s.state === "tested" && s.evidence.length === 1,
    );
    if (shallow.length > 0 && shallow.length >= cov.tested / 2) {
      result.push({
        priority: "recommended",
        text: `SHALLOW TESTING: ${shallow.length} surface(s) tested with a single observation each (${shallow.slice(0, 3).map((s) => s.label).join(", ")}). Depth matters: a surface tested once may hide subtler vulnerabilities. Pick the highest-value one and test it with a different technique.`,
      });
    }
  }

  // Data flow analysis nudge: if the model is making HTTP requests but has
  // not recorded any hypothesis about parameter→sink flows, it may be testing
  // blindly. Guarded on HTTP/web tool usage when toolsUsed is known so
  // non-HTTP sessions (ICS/OT, firmware, VoIP, mainframe) are not spammed.
  const used = new Set(state.toolsUsed ?? []);
  const hasHttpTools =
    state.toolsUsed === undefined ||
    [...used].some(
      (t) =>
        HTTP_FLOW_TOOLS.has(t) ||
        t.startsWith("chrome-devtools.") ||
        t.startsWith("rea."),
    );
  const httpObs =
    state.stagnation.length === 0 && state.observationCount > 8 && hasHttpTools;
  if (httpObs && activeH.length === 0 && confirmedH.length === 0 && cov.untested > 0) {
    const hasFlowHypothesis = state.hypotheses.some((h) =>
      /sink|source|parameter|flow|taint|inject|input.*reach/i.test(h.text),
    );
    if (!hasFlowHypothesis) {
      result.push({
        priority: "recommended",
        text: "DATA FLOW: Multiple observations but no hypothesis about input→sink flows. Before throwing payloads, map which parameters reach which sinks (SQL, shell, template, file, reflection). A flow hypothesis guides targeted testing.",
      });
    }
  }

  // CVE lookup nudge: when recon tools ran but no CVE lookup was performed,
  // the model is missing known vulnerabilities on the discovered stack.
  const hasRecon = RECON_TOOLS.some((t) => used.has(t));
  const hasCveLookup = used.has("cyber_cve") || used.has("trivy") || used.has("retire");
  if (hasRecon && !hasCveLookup && state.observationCount > 5) {
    result.push({
      priority: "recommended",
      text: 'CVE CHECK: Reconnaissance tools ran but no CVE lookup was performed. Use cyber_cve action="lookup"/"batch" for OSV packages and cyber_cve action="search" (NVD + searchsploit) for services, servers, CMS, appliances, or firmware (or run trivy/retire on collected artifacts). Known CVEs are low-hanging fruit.',
    });
  }

  // Premature conclusion guard
  const pct = addressedPct(cov);
  if (
    cov.total > 0 &&
    cov.untested > 0 &&
    (state.completedWithEvidence > 0 || used.has("cyber_report")) &&
    pct !== null &&
    pct < CONCLUSION_THRESHOLD
  ) {
    result.push({
      priority: "mandatory",
      text: `PREMATURE CONCLUSION GUARD: Coverage is only ${pct}%. Do not conclude the engagement or write a report until at least ${CONCLUSION_THRESHOLD}% of surfaces are tested or explicitly blocked with a reason.`,
    });
  }

  // Phase-aware directive with counter-logic vectors.
  // Uses tool usage, surface state, and confirmed findings to detect the
  // current offensive phase and emit transition or deepening directives.
  const pd = phaseDirective(
    {
      toolsUsed: state.toolsUsed ?? [],
      observationCount: state.observationCount,
      surfacesTotal: cov.total,
      surfacesTested: cov.tested,
      surfacesUntested: cov.untested,
      surfacesInProgress: cov.inProgress,
      confirmedFindings: confirmedH.length,
      consecutiveExploitFailures: state.consecutiveExploitFailures ?? 0,
    },
    cov.surfaces
      .filter((s) => s.state === "untested" || s.state === "in-progress")
      .map((s) => s.label),
  );
  if (pd) {
    result.push({ priority: pd.priority, text: pd.text });
  }

  // Counter-Logic Gauntlet — permanent adversarial reasoning protocol.
  // Fires every turn, unconditionally.  It is a cognitive protocol that
  // forces the model to invert assumptions, adopt adversarial personas,
  // trace blast radius, and prescribe hardening on every action.
  const phaseInput: PhaseInput = {
    toolsUsed: state.toolsUsed ?? [],
    observationCount: state.observationCount,
    surfacesTotal: cov.total,
    surfacesTested: cov.tested,
    surfacesUntested: cov.untested,
    surfacesInProgress: cov.inProgress,
    confirmedFindings: confirmedH.length,
    consecutiveExploitFailures: state.consecutiveExploitFailures ?? 0,
  };
  const gauntlet = counterLogicGauntlet({
    currentPhase: detectPhase(phaseInput),
    hasConfirmedFindings: confirmedH.length > 0,
    hasActiveHypothesis: activeH.length > 0,
    surfacesTested: cov.tested,
    surfacesTotal: cov.total,
  });
  result.push({ priority: "mandatory", text: gauntlet });

  return result;
}

/** The share of surfaces addressed: tested, or blocked with a reason. */
export const CONCLUSION_THRESHOLD = 60;

/**
 * Addressed coverage, or null when no surface was declared.
 *
 * A surface blocked with a reason is addressed: the model looked at it and
 * recorded why it cannot be tested. Only an untouched surface is a gap.
 */
export function addressedPct(cov: {
  total: number;
  tested: number;
  blocked: number;
}): number | null {
  if (cov.total === 0) return null;
  return Math.round(((cov.tested + cov.blocked) / cov.total) * 100);
}

/**
 * The investigation block injected into context.
 *
 * Returns empty string when there is nothing to say — the model proceeds
 * without interference when it is making progress.
 */
export function investigationBlock(ds: readonly Directive[]): string {
  if (!ds.length) return "";
  const isGauntlet = (d: Directive) => d.text.startsWith("COUNTER-LOGIC PROTOCOL");
  const gauntlet = ds.filter(isGauntlet);
  const mandatory = ds.filter((d) => d.priority === "mandatory" && !isGauntlet(d));
  const recommended = ds.filter((d) => d.priority === "recommended");
  const lines = [
    "Investigation directives. These are enforced by the harness, not suggestions.",
  ];
  if (mandatory.length) {
    lines.push("");
    for (const d of mandatory) lines.push(`[MANDATORY] ${d.text}`);
  }
  if (recommended.length) {
    lines.push("");
    for (const d of recommended) lines.push(`[RECOMMENDED] ${d.text}`);
  }
  if (gauntlet.length) {
    lines.push("");
    for (const d of gauntlet) lines.push(d.text);
  }
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Escalation knowledge — what a confirmed finding opens
// ---------------------------------------------------------------------------

/** When a hypothesis is confirmed, the finding type hints at what to try next. */
interface EscalationEntry {
  paths: string[];
  skills: string[];
}

const ESCALATION_PATHS: Record<string, EscalationEntry> = {
  sqli: {
    paths: [
      "file read (LOAD_FILE, INTO OUTFILE)",
      "RCE via stacked queries or UDF",
      "data exfiltration (dump credentials, PII)",
      "lateral: same parameter on other endpoints",
    ],
    skills: ["harness-sqli", "harness-web-deep", "harness-source-deep"],
  },
  xss: {
    paths: [
      "session hijacking (steal httpOnly cookie via DOM clobbering or CSP bypass)",
      "account takeover via stored XSS in admin panel",
      "chaining with CSRF for state-changing actions",
      "DOM sink analysis for client-side prototype pollution",
    ],
    skills: ["harness-xss", "harness-source-deep", "harness-headers"],
  },
  ssrf: {
    paths: [
      "cloud metadata (169.254.169.254, metadata.google.internal)",
      "internal port scan via response timing",
      "file read via file:// protocol",
      "chaining with deserialization on internal services",
    ],
    skills: ["harness-web-deep", "harness-cloud-enum"],
  },
  idor: {
    paths: [
      "privilege escalation (access admin objects)",
      "mass data harvesting (enumerate all IDs)",
      "lateral: same pattern on other object types",
      "chaining with information disclosure for targeted attacks",
    ],
    skills: ["harness-idor", "harness-access-control", "harness-api-testing"],
  },
  auth: {
    paths: [
      "token forging (JWT none/weak secret, session fixation)",
      "privilege escalation via role parameter tampering",
      "account takeover via password reset flow",
      "lateral: same auth flaw on API vs web vs mobile",
    ],
    skills: ["harness-jwt", "harness-oauth2", "harness-iam", "harness-credential-spray"],
  },
  rce: {
    paths: [
      "persistence (cron, systemd, registry)",
      "lateral movement (pivot to internal hosts)",
      "data exfiltration (sensitive files, credentials)",
      "container/cloud escape if sandboxed",
    ],
    skills: ["harness-red-team", "harness-network-pivot", "harness-container"],
  },
  lfi: {
    paths: [
      "RCE via log poisoning or PHP wrappers",
      "source code disclosure for further vulns",
      "credential harvesting (/etc/shadow, .env, config files)",
      "chaining with SSRF for internal file read",
    ],
    skills: ["harness-web-deep", "harness-file-upload", "harness-source-deep"],
  },
  deserialization: {
    paths: [
      "RCE via gadget chain",
      "DoS via resource exhaustion",
      "lateral: same library on other endpoints",
      "chaining with SSRF to reach internal deserializers",
    ],
    skills: ["harness-deserialization", "harness-web-deep"],
  },
};

/**
 * Match a confirmed hypothesis text to known escalation paths.
 *
 * The match is by keyword in the hypothesis text, not by a formal category.
 * A miss means no specific guidance — the generic deepen directive still fires.
 */
function escalationFor(hypothesisText: string): EscalationEntry | null {
  const lower = hypothesisText.toLowerCase();
  for (const [key, entry] of Object.entries(ESCALATION_PATHS)) {
    if (lower.includes(key)) return entry;
  }
  if (lower.includes("injection") && lower.includes("sql")) return ESCALATION_PATHS.sqli;
  if (lower.includes("redirect") || lower.includes("ssrf")) return ESCALATION_PATHS.ssrf;
  if (lower.includes("file") && lower.includes("include")) return ESCALATION_PATHS.lfi;
  if (lower.includes("remote code") || lower.includes("command injection")) return ESCALATION_PATHS.rce;
  if (lower.includes("deseriali")) return ESCALATION_PATHS.deserialization;
  if (lower.includes("access control") || lower.includes("authorization")) return ESCALATION_PATHS.idor;
  if (lower.includes("authentication") || lower.includes("login") || lower.includes("bypass")) return ESCALATION_PATHS.auth;
  return null;
}

export const INVESTIGATION_MARKER = "Investigation directives.";

// ---------------------------------------------------------------------------
// Persistence — what the model declares, kept across sessions
// ---------------------------------------------------------------------------

interface InvestigationData {
  hypotheses: Hypothesis[];
  surfaces: SurfaceCoverage[];
}

const MAX_HYPOTHESES = 200;
const MAX_SURFACES = 500;
const MAX_TEXT = 400;
const STALE_LOCK_MS = 30000;

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

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item) => typeof item === "string");

const isValidHypothesis = (value: unknown): value is Hypothesis => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const h = value as Record<string, unknown>;
  if (
    !identifier(h.id) ||
    typeof h.text !== "string" ||
    !HYPOTHESIS_STATES.includes(h.state as HypothesisState) ||
    !isStringArray(h.evidence) ||
    typeof h.createdAt !== "string" ||
    typeof h.updatedAt !== "string"
  )
    return false;
  if (h.control !== undefined && !isStringArray(h.control)) return false;
  if (h.counterEvidence !== undefined && !isStringArray(h.counterEvidence))
    return false;
  if (
    h.outputs !== undefined &&
    (!h.outputs ||
      typeof h.outputs !== "object" ||
      Array.isArray(h.outputs) ||
      !Object.values(h.outputs).every((v) => typeof v === "string"))
  )
    return false;
  return true;
};

const isValidSurface = (value: unknown): value is SurfaceCoverage => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const s = value as Record<string, unknown>;
  if (
    !identifier(s.id) ||
    typeof s.label !== "string" ||
    !SURFACE_STATES.includes(s.state as SurfaceState) ||
    !isStringArray(s.evidence)
  )
    return false;
  if (s.reason !== undefined && typeof s.reason !== "string") return false;
  return true;
};

/**
 * Hypotheses and surface coverage, per scope, in a small JSON file.
 *
 * The same discipline as the task store: a lock for the whole update, an
 * atomic write, and a read on every use so two hosts never believe they own
 * the list alone.  The signal functions stay pure; this is the only part that
 * touches the disk.
 */
export class InvestigationStore {
  constructor(private stateRoot: string) {
    fs.mkdirSync(stateRoot, { recursive: true });
  }

  private file(scope: string): string {
    if (!/^[a-z][a-z0-9-]{0,95}$/.test(scope))
      throw new Error("Invalid investigation scope");
    return path.join(this.stateRoot, `investigation-${scope}.json`);
  }

  private load(scope: string): InvestigationData {
    try {
      assertPlainPath(this.file(scope));
      const value = JSON.parse(fs.readFileSync(this.file(scope), "utf8"));
      if (
        !value ||
        typeof value !== "object" ||
        Array.isArray(value) ||
        !Array.isArray(value.hypotheses) ||
        !Array.isArray(value.surfaces) ||
        !value.hypotheses.every(isValidHypothesis) ||
        !value.surfaces.every(isValidSurface)
      )
        throw new Error("Invalid investigation storage");
      return {
        hypotheses: value.hypotheses.map((h: Hypothesis) =>
          normalizeHypothesis(h),
        ),
        surfaces: value.surfaces.map((s: SurfaceCoverage) => cloneSurface(s)),
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      return { hypotheses: [], surfaces: [] };
    }
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
          throw new Error(
            "Concurrent investigation update; retry from the current state",
          );
        throw error;
      }
    }
    throw new Error(
      "Concurrent investigation update; retry from the current state",
    );
  }

  private mutate<T>(scope: string, fn: (data: InvestigationData) => T): T {
    const lock = `${this.file(scope)}.lock`;
    const fd = this.acquireLock(lock);
    try {
      fs.writeSync(
        fd,
        JSON.stringify({ pid: process.pid, createdAt: Date.now() }),
      );
      const data = this.load(scope);
      const result = fn(data);
      if (data.hypotheses.length > MAX_HYPOTHESES)
        throw new Error("Hypothesis capacity reached");
      if (data.surfaces.length > MAX_SURFACES)
        throw new Error("Surface capacity reached");
      atomicWrite(this.file(scope), JSON.stringify(data, null, 1));
      return result;
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

  hypotheses(scope: string): Hypothesis[] {
    return this.load(scope).hypotheses.map((h) => normalizeHypothesis(h));
  }

  coverage(scope: string): SurfaceCoverage[] {
    return this.load(scope).surfaces.map((s) => cloneSurface(s));
  }

  proposeHypothesis(scope: string, text: string, id?: string): Hypothesis {
    if (typeof text !== "string" || !text.trim())
      throw new Error("Hypothesis text is required");
    const trimmed = text.trim().slice(0, MAX_TEXT);
    return this.mutate(scope, (data) => {
      const tracker = new HypothesisTracker(data.hypotheses);
      const h = tracker.propose(id ?? newId(), trimmed, now());
      data.hypotheses = [...tracker.list()];
      return h;
    });
  }

  testHypothesis(scope: string, id: string): Hypothesis {
    return this.mutate(scope, (data) => {
      const tracker = new HypothesisTracker(data.hypotheses);
      const h = tracker.test(id, now());
      data.hypotheses = [...tracker.list()];
      return h;
    });
  }

  evidenceHypothesis(
    scope: string,
    id: string,
    observationId: string,
    outputHash: string,
  ): Hypothesis {
    return this.mutate(scope, (data) => {
      const tracker = new HypothesisTracker(data.hypotheses);
      const h = tracker.addEvidence(id, observationId, now(), outputHash);
      data.hypotheses = [...tracker.list()];
      return h;
    });
  }

  controlHypothesis(
    scope: string,
    id: string,
    observationId: string,
    outputHash: string,
  ): Hypothesis {
    return this.mutate(scope, (data) => {
      const tracker = new HypothesisTracker(data.hypotheses);
      const h = tracker.addControl(id, observationId, now(), outputHash);
      data.hypotheses = [...tracker.list()];
      return h;
    });
  }

  refuteHypothesis(scope: string, id: string, observationId: string): Hypothesis {
    return this.mutate(scope, (data) => {
      const tracker = new HypothesisTracker(data.hypotheses);
      const h = tracker.refute(id, observationId, now());
      data.hypotheses = [...tracker.list()];
      return h;
    });
  }

  /** Advance stale hypotheses and persist the transition. */
  tick(scope: string, nowMs: number): Hypothesis[] {
    return this.mutate(scope, (data) => {
      const tracker = new HypothesisTracker(data.hypotheses);
      const stale = tracker.tick(nowMs);
      data.hypotheses = [...tracker.list()];
      return stale;
    });
  }

  addSurface(scope: string, id: string, label: string): void {
    if (typeof label !== "string" || !label.trim())
      throw new Error("Surface label is required");
    const trimmed = label.trim().slice(0, MAX_TEXT);
    this.mutate(scope, (data) => {
      const map = CoverageMap.fromEntries(data.surfaces);
      map.add(id, trimmed);
      data.surfaces = map.entries();
    });
  }

  startSurface(scope: string, id: string): void {
    this.mutate(scope, (data) => {
      const map = CoverageMap.fromEntries(data.surfaces);
      map.start(id);
      data.surfaces = map.entries();
    });
  }

  completeSurface(scope: string, id: string, evidence: string[]): void {
    this.mutate(scope, (data) => {
      const map = CoverageMap.fromEntries(data.surfaces);
      map.complete(id, evidence);
      data.surfaces = map.entries();
    });
  }

  blockSurface(scope: string, id: string, reason: string): void {
    if (typeof reason !== "string" || !reason.trim())
      throw new Error("A blocked surface requires a reason");
    const trimmed = reason.trim().slice(0, MAX_TEXT);
    this.mutate(scope, (data) => {
      const map = CoverageMap.fromEntries(data.surfaces);
      map.block(id, trimmed);
      data.surfaces = map.entries();
    });
  }

  coverageSummary(scope: string): ReturnType<CoverageMap["summary"]> {
    return CoverageMap.fromEntries(this.load(scope).surfaces).summary();
  }
}

// ---------------------------------------------------------------------------
// Coverage from the task tree — so the gate cannot be dodged by omission
// ---------------------------------------------------------------------------

/**
 * Derive surfaces from the root branches of the task tree.
 *
 * A model that never declares surfaces still plans work as tasks. Those root
 * branches are the surfaces it intended to cover, so the arbiter tracks them
 * without a parallel declaration. A completed branch counts as tested only
 * with evidence; an unproven completion is still a gap. Sub-steps are not
 * surfaces: the branch is the unit of coverage.
 */
export function surfacesFromTasks(
  tasks: readonly {
    id: string;
    title: string;
    status: string;
    parentId?: string;
    evidence?: string[];
    reason?: string;
  }[],
): SurfaceCoverage[] {
  return tasks
    .filter((t) => !t.parentId)
    .map((t) => {
      const proven = t.status === "completed" && (t.evidence?.length ?? 0) > 0;
      const reason = typeof t.reason === "string" ? t.reason.trim() : "";
      const blocked = t.status === "blocked" && reason.length > 0;
      const state: SurfaceState = proven
        ? "tested"
        : blocked
          ? "blocked"
          : t.status === "in-progress"
            ? "in-progress"
            : "untested";
      return {
        id: t.id,
        label: t.title,
        state,
        evidence: [...(t.evidence ?? [])],
        ...(blocked ? { reason } : {}),
      };
    });
}

/** The coverage summary of a task tree, for a scope that declared no surface. */
export function taskCoverageSummary(
  tasks: readonly {
    id: string;
    title: string;
    status: string;
    parentId?: string;
    evidence?: string[];
    reason?: string;
  }[],
): ReturnType<CoverageMap["summary"]> {
  return CoverageMap.fromEntries(surfacesFromTasks(tasks)).summary();
}

// ---------------------------------------------------------------------------
// Assembly — the state the host computes on every turn
// ---------------------------------------------------------------------------

/**
 * Build the investigation state from the observation stream, the task tree
 * and the declared hypotheses/coverage.  Pure: the host passes what it read.
 */
export function assembleInvestigation(opts: {
  observations: readonly {
    tool: string;
    hash: string;
    success: boolean;
    timestamp: string;
    input?: unknown;
  }[];
  tasks: readonly { status: string; evidence?: string[]; updatedAt: string }[];
  hypotheses: readonly Hypothesis[];
  coverage: ReturnType<CoverageMap["summary"]>;
  nowMs: number;
}): InvestigationState {
  const calls: ToolCall[] = opts.observations.map((o) => ({
    tool: o.tool,
    outputHash: o.hash,
    success: o.success,
    timestamp: o.timestamp,
    ...(o.input !== undefined ? { input: o.input } : {}),
  }));
  const openTaskCount = opts.tasks.filter(
    (t) => t.status === "pending" || t.status === "in-progress",
  ).length;
  const completedRecently = opts.tasks.filter(
    (t) =>
      t.status === "completed" &&
      opts.nowMs - Date.parse(t.updatedAt) <= NO_PROGRESS_MINUTES * 60 * 1000,
  ).length;
  const completedWithEvidence = opts.tasks.filter(
    (t) => t.status === "completed" && (t.evidence?.length ?? 0) > 0,
  ).length;
  const stagnation = detectStagnation(
    calls,
    openTaskCount,
    completedRecently,
    opts.nowMs,
  );
  // Count consecutive exploit-tool failures at the tail of observations.
  let consecutiveExploitFailures = 0;
  for (let i = opts.observations.length - 1; i >= 0; i--) {
    const obs = opts.observations[i];
    if (EXPLOIT_TOOLS_SET.has(obs.tool) && !obs.success) {
      consecutiveExploitFailures++;
    } else {
      break;
    }
  }

  const toolSet = new Set<string>();
  for (const o of opts.observations) {
    toolSet.add(o.tool);
    if (
      o.tool === "cyber_process" &&
      o.input &&
      typeof o.input === "object" &&
      (o.input as Record<string, unknown>).action === "run" &&
      Array.isArray((o.input as Record<string, unknown>).argv)
    ) {
      const bin = (o.input as Record<string, unknown>).argv[0];
      if (typeof bin === "string" && bin.trim()) {
        const base = path.posix.basename(bin.trim().replace(/\\/g, "/"));
        if (base) toolSet.add(base);
      }
    }
  }

  return {
    hypotheses: opts.hypotheses,
    stagnation,
    coverage: opts.coverage,
    completedWithEvidence,
    observationCount: opts.observations.length,
    toolsUsed: [...toolSet],
    consecutiveExploitFailures,
  };
}
