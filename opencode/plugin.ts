/**
 * Proof layer for OpenCode.
 *
 * Two guarantees, both enforced by the harness core rather than by prompt:
 *
 *  - every tool call leaves an immutable observation, so a claim about what
 *    was done can be replayed and checked;
 *  - a task closes only against a successful observation, so a task list cannot
 *    be satisfied by narration.
 *
 * The store is the same file the Pi harness writes to, so evidence collected on
 * one host stays reachable from the other. The core is host-neutral: this
 * adapter is the only part that knows about OpenCode.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { coreRoot } from "./paths";
import {
  assertOperatorDecision,
  assertProcessPermission,
} from "./permissions";
import {
  captureBrowserIsolated,
  captureWindow,
  commandArguments,
  listWindows,
  quoteArgument,
  renderTrace,
  rootWindowId,
  windowGeometry,
} from "./display";

export { assertOperatorDecision, assertProcessPermission } from "./permissions";

/**
 * Where the shared state lives.
 *
 * The location is the core's, because the store is shared: it must not live
 * inside the directory of a host that can go away. Until the core is loaded,
 * this is the same default; setup replaces it with the core's own function.
 */
let stateDir = () =>
  path.join(os.homedir(), ".local", "share", "harness-core", "state");
const stateRoot = () => stateDir();
const DEBUG = process.env.HARNESS_PROOF_DEBUG === "1";

/** Bookkeeping cannot prove itself; operational harness tools still leave observations. */
const OWN_TOOL =
  /^(?:cyber_tasks|cyber_mission|cyber_approval|cyber_finding|cyber_review|cyber_memory|cyber_method|cyber_lessons|cyber_verification|cyber_report|cyber_capitalise|cyber_cleanup|cyber_toolbox|cyber_entity|cyber_investigation)$/;

/** The first words of the injected operator block, used to detect a duplicate. */
const OPERATOR_MARKER = "Operator rules.";

/** The prefix of the skills that the harness learned from the work. */
const LEARNED_PREFIX = "harness.learned.";

/**
 * How many sessions are read at once.
 *
 * The extraction is a model call per session. A burst of them would hold the
 * provider and would spend the budget of the operator without being asked.
 */
const LESSON_BATCH = 3;

/**
 * A session is read once it has been quiet for this long. A host that never
 * marked it closed leaves it "active" forever, so time — not status — is what
 * tells a session in flight from a session abandoned.
 */
const LESSON_IDLE_MS = 10 * 60_000;

/**
 * The verdict of a review.
 *
 * The verifier is another model: it can be wrong, so its answer is checked
 * before it is recorded. A confirmation that cites nothing, or that cites an
 * observation nobody provided, is not a confirmation.
 */
function parseVerdict(
  text: string,
  allowed: string[],
): { verdict: string; reason: string; evidence: string[] } {
  let parsed: any;
  try {
    const start = text.indexOf("{");
    const end = text.lastIndexOf("}");
    if (start < 0 || end <= start) throw new Error("no object in the answer");
    parsed = JSON.parse(text.slice(start, end + 1));
  } catch {
    throw new Error("the verifier did not answer with a verdict");
  }
  const evidence = Array.isArray(parsed?.evidence)
    ? parsed.evidence.filter(
        (id: unknown): id is string =>
          typeof id === "string" && allowed.includes(id),
      )
    : [];
  let verdict = ["confirmed", "unsupported", "contradicted"].includes(
    parsed?.verdict,
  )
    ? parsed.verdict
    : "unsupported";
  if (verdict === "confirmed" && !evidence.length) verdict = "unsupported";
  return {
    verdict,
    reason:
      typeof parsed?.reason === "string" ? parsed.reason.slice(0, 500) : "",
    evidence,
  };
}

function debug(line: string): void {
  if (!DEBUG) return;
  try {
    fs.appendFileSync(
      path.join(stateRoot(), "opencode-proof-debug.log"),
      `${new Date().toISOString()} ${line}\n`,
    );
  } catch {
    /* A diagnostic file must never break a tool call. */
  }
}

/** The rendered result of a tool call, as the model saw it. */
function outputText(result: any): string {
  if (result === undefined || result === null) return "";
  const parts: string[] = [];
  if (Array.isArray(result.content))
    for (const part of result.content)
      if (part && part.type === "text" && typeof part.text === "string")
        parts.push(part.text);
  if (!parts.length && result.output && typeof result.output === "object")
    if (typeof result.output.output === "string")
      parts.push(result.output.output);
  if (!parts.length && typeof result.output === "string")
    parts.push(result.output);
  if (!parts.length) {
    try {
      return JSON.stringify(result) ?? "";
    } catch {
      return "";
    }
  }
  return parts.join("\n");
}

/**
 * Whether the work actually succeeded.
 *
 * A tool call that threw is a failure. A tool call that ran but reported a
 * failed outcome is also a failure: the shell tool reports a non-zero exit as
 * a completed call with an exit code, and the Pi harness records the same
 * situation as an unsuccessful observation. The two hosts must agree.
 */
function succeeded(event: any): boolean {
  if (event.status !== "completed") return false;
  const metadata = event.result?.metadata ?? {};
  if (metadata.evidenceSuccess === false) return false;
  if (event.tool === "cyber_process") return metadata.evidenceSuccess === true;
  if (metadata.status === "error" || metadata.status === "failed") return false;
  if (typeof metadata.exit === "number" && metadata.exit !== 0) return false;
  const output = event.result?.output;
  if (output && typeof output === "object") {
    if (output.status === "error" || output.status === "failed") return false;
    if (typeof output.exit === "number" && output.exit !== 0) return false;
  }
  if (metadata.exit === 0) return true;
  const match = /Exited with code (\d+)/.exec(outputText(event.result));
  if (match && Number(match[1]) !== 0) return false;
  return true;
}

/**
 * The plugin definition.
 *
 * It is a plain object on purpose: the loader reads the id and the setup
 * function, and a definition that imports nothing can also be loaded and
 * exercised outside the host, which is how the proof is tested.
 */
export default {
  id: "harness-core.proof",
  async setup(ctx: any) {
    const { KnowledgeStore } = await import(
      path.join(coreRoot(), "src", "store.ts")
    );
    const { TaskStore } = await import(
      path.join(coreRoot(), "src", "tasks.ts")
    );
    const { observationId } = await import(
      path.join(coreRoot(), "src", "observation-id.ts")
    );
    const { assertPlainPath, hash, redactText, scopeFor } = await import(
      path.join(coreRoot(), "src", "util.ts")
    );
    const { operatorContext } = await import(
      path.join(coreRoot(), "src", "context.ts")
    );
    const {
      applyLessonProposal,
      lessonPrompt,
      parseLessonProposal,
      publishToolImprovements,
    } = await import(path.join(coreRoot(), "src", "lessons.ts"));
    const { capsule, capsuleText, closingGate, GATE_MARKER } = await import(
      path.join(coreRoot(), "src", "capsule.ts")
    );
    const {
      InvestigationStore,
      assembleInvestigation,
      addressedPct,
      taskCoverageSummary,
      directives,
      investigationBlock,
      INVESTIGATION_MARKER,
    } = await import(path.join(coreRoot(), "src", "investigation.ts"));
    const { ROUTES, routeFor, requestText, ROUTER_MARKER } = await import(
      path.join(coreRoot(), "src", "routing.ts")
    );
    const {
      DEFAULT_DEADLINE_MS,
      MAX_DEADLINE_MS,
      ProcessRegistry,
      processOutcome,
      processStatus,
      verifiedOutcome,
      publicProcess,
      readTrace,
      spawnTraced,
      stopProcess,
    } = await import(path.join(coreRoot(), "src", "process.ts"));
    const { GLOBAL_SCOPE, SkillUpdater } = await import(
      path.join(coreRoot(), "src", "skills.ts")
    );
    const { ToolRegistry } = await import(
      path.join(coreRoot(), "src", "tool-registry.ts")
    );
    const { identifyToolGaps } = await import(
      path.join(coreRoot(), "src", "tool-gap.ts")
    );
    const { PlatformStore } = await import(
      path.join(coreRoot(), "src", "platform-store.ts")
    );
    const { OSV_ECOSYSTEMS, summarizeOsv } = await import(
      path.join(coreRoot(), "src", "osv.ts")
    );
    const { multiSourceLookup } = await import(
      path.join(coreRoot(), "src", "cve-sources.ts")
    );
    const { assetSteps } = await import(
      path.join(coreRoot(), "src", "coverage-roles.ts")
    );
    const { planIngest } = await import(
      path.join(coreRoot(), "src", "osint-ingest.ts")
    );
    const { COVERAGE_PROFILES, coverageContract, coverageProfile } = await import(
      path.join(coreRoot(), "src", "coverage-profiles.ts")
    );
    const { techniqueCard, techniqueCards, techniqueGaps } = await import(
      path.join(coreRoot(), "src", "techniques.ts")
    );
    const {
      assertNotRoot,
      captureDestination,
      captureName,
      isFramed,
      selectWindow,
      selectWindowById,
    } = await import(path.join(coreRoot(), "src", "capture.ts"));
    const { DEFAULT_CONFIG } = await import(
      path.join(coreRoot(), "src", "types.ts")
    );
    // The location of the shared store is the core's, not the plugin's.
    const { stateRoot: sharedStateRoot } = await import(
      path.join(coreRoot(), "src", "paths.ts")
    );
    stateDir = sharedStateRoot;

    fs.mkdirSync(stateRoot(), { recursive: true, mode: 0o700 });
    const knowledge = new KnowledgeStore(
      path.join(stateRoot(), "knowledge.sqlite"),
    );
    const taskStore = new TaskStore(stateRoot());
    const investigation = new InvestigationStore(stateRoot());
    const skills = new SkillUpdater(stateRoot(), knowledge, DEFAULT_CONFIG);
    const toolRegistry = new ToolRegistry(stateRoot());
    // The engagement ledger. It is the same file the Pi harness writes to, so
    // both hosts share one engagement state.
    const platform = new PlatformStore(
      path.join(stateRoot(), "platform.sqlite"),
      knowledge,
    );
    // The commands the harness owns, and the trace they leave.
    const processes = new ProcessRegistry(stateRoot());
    const { EngagementWorkflow } = await import(
      path.join(coreRoot(), "src", "engagement-workflow.ts")
    );
    const workflow = new EngagementWorkflow(stateRoot(), platform, knowledge);

    const instanceCwd: string = ctx?.location?.directory ?? process.cwd();
    const scopeCache = new Map<string, string>();
    const sessionCwd = new Map<string, string>();
    const registered = new Map<string, string>();
    // The skills the current turn routed to, per session, grouped by enforced route.
    // A finding for that request needs >= 1 loaded method per matched enforced route.
    const routedRequiredGroups = new Map<string, string[][]>();
    const loadedMethodsBySession = new Map<string, Set<string>>();
    const requestBySession = new Map<string, string>();
    const isRouterOff = () =>
      (process.env.HARNESS_ROUTER ?? "").trim().toLowerCase() === "off";
    const enforcedGroups = (routing: { ids: string[] }): string[][] =>
      routing.ids
        .map((id) => ROUTES.find((route) => route.id === id))
        .filter(
          (route): route is (typeof ROUTES)[number] =>
            Boolean(route?.enforce && route.skills.length),
        )
        .map((route) => [...route.skills]);
    const recordLoadedMethod = (
      scope: string,
      proofSessionID: string,
      name: string,
    ) => {
      const key = `${proofSessionID}\0${scope}`;
      let set = loadedMethodsBySession.get(key);
      if (!set) {
        set = new Set<string>();
        loadedMethodsBySession.set(key, set);
      }
      set.add(name);
      set.add(`${LEARNED_PREFIX}${name}`);
      try {
        knowledge.audit(scope, "skill.loaded", {
          sessionID: proofSessionID,
          name,
        });
      } catch {
        /* Audit failure must not block skill loading. */
      }
    };
    // Host-provided tools are discovered through the host, not invented in a prompt.
    const hostTools = async () => {
      try {
        const list = await ctx.tool.list();
        return Array.isArray(list)
          ? list.map((entry: any) => ({
              name: String(entry.name ?? entry.id ?? ""),
              description: String(entry.description ?? "").slice(0, 300),
            })).filter((entry: any) => entry.name)
          : [];
      } catch {
        return [];
      }
    };
    const lifecycleController = new AbortController();
    // A different session must never change this request's verifier provider.
    const liveModels = new Map<string, { providerID: string; id: string }>();
    // The sessions whose lessons were already extracted, and the ones being
    // extracted now.
    const lessonChecked = new Map<string, number>();
    let lessonRunning = false;

    function sessionSnapshot(scope: string, sessionID: string) {
      const observations = knowledge.observationsForSession(
        sessionID,
        scope,
        100,
      );
      const digest = hash(
        JSON.stringify({
          scope,
          sessionID,
          observations: observations.map((item: any) => [item.id, item.hash]),
        }),
      );
      return { observations, digest };
    }

    /**
     * What a session teaches.
     *
     * The extractor is a model without tools: it reads the observations and
     * proposes, it does not act. The proposals then go through the ordinary
     * mechanisms, so one that is not backed by a successful observation is
     * refused like any other.
     */
    async function extractLessons(
      scope: string,
      sessionID: string,
      requestSessionID: string,
    ): Promise<{
      facts: number;
      skills: number;
      rejected: string[];
    }> {
      const { observations, digest } = sessionSnapshot(scope, sessionID);
      if (!observations.length) {
        // Nothing to read. It is written down anyway, so the session is not
        // read again and again.
        knowledge.recordReview({
          sessionId: sessionID,
          scope,
          digest,
          status: "completed",
          detail: JSON.stringify({
            facts: 0,
            skills: 0,
            rejected: [],
            empty: true,
          }),
        });
        knowledge.audit(scope, "lessons.extracted", {
          sessionID,
          digest,
          empty: true,
        });
        return { facts: 0, skills: 0, rejected: [] };
      }
      const known = skills.list(scope);
      const prompt = lessonPrompt(
        {
          sessionId: sessionID,
          scope,
          observations,
          knownSkills: known,
        },
        DEFAULT_CONFIG.reviewMaxChars,
      );
      // The candidates are tried in order: a provider that refuses a direct
      // call must not stop the loop that learns from the work.
      let answer: any;
      let lastError: unknown;
      let asked: { providerID: string; id: string } | null = null;
      for (const candidate of await verifierCandidates(
        undefined,
        requestSessionID,
      )) {
        try {
          answer = await boundedGenerate(candidate, prompt);
          asked = candidate;
          break;
        } catch (error) {
          lastError = error;
          debug(
            `lessons model ${candidate.providerID}/${candidate.id} refused: ${String(error).slice(0, 200)}`,
          );
        }
      }
      if (!answer)
        throw lastError ?? new Error("no model answered the lesson extraction");
      const proposal = parseLessonProposal(answer?.text ?? "");
      const outcome = applyLessonProposal(
        knowledge,
        skills as any,
        scope,
        proposal,
      );
      try {
        publishToolImprovements(outcome.analysis, sessionID);
      } catch {
        // Journal write failure must not block lesson recording.
      }
      for (const item of outcome.analysis.toolImprovements ?? []) {
        try {
          const slug = "tool-improve-" + item.lesson
            .toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 60)
            .replace(/-+$/, "");
          knowledge.proposeKnowledge(scope, {
            key: slug,
            kind: "workflow",
            content: item.lesson.slice(0, 2000),
            evidence: item.evidence,
          });
        } catch {
          // A rejected improvement is still in LEÇONS.md.
        }
      }
      if (outcome.skills && typeof ctx.skill?.reload === "function")
        await ctx.skill.reload();
      knowledge.recordReview({
        sessionId: sessionID,
        scope,
        digest,
        status: "completed",
        detail: JSON.stringify({
          facts: outcome.facts,
          skills: outcome.skills,
          rejected: outcome.rejected,
          analysis: outcome.analysis,
          model: asked,
        }),
      });
      knowledge.audit(scope, "lessons.extracted", {
        sessionID,
        digest,
        facts: outcome.facts,
        skills: outcome.skills,
        rejected: outcome.rejected,
        model: asked,
      });
      return outcome;
    }

    /**
     * The sessions of the scope that taught something and were not read yet.
     *
     * The session in flight is never among them: it is still running, its
     * observations are not complete, and a session is read by the next one.
     */
    function pendingLessons(scope: string, current?: string): string[] {
      const reviewed = new Set(
        knowledge
          .audits(scope, "lessons.extracted", 200)
          .flatMap((row: any) => {
            try {
              return [JSON.parse(row.detail).digest];
            } catch {
              return [];
            }
          }),
      );
      // A session is read by a later one. "Later" is a matter of time, not of
      // status: a host that never marked a session closed leaves it active
      // forever, and its work stays unread.
      const cutoff = Date.now() - LESSON_IDLE_MS;
      return knowledge
        .sessionsForScope(scope, 100)
        .filter(
          (row: any) =>
            row.id !== current &&
            !reviewed.has(sessionSnapshot(scope, row.id).digest) &&
            Date.now() - (lessonChecked.get(row.id) ?? 0) > 60000 &&
            Number.isFinite(Date.parse(row.updatedAt)) &&
            Date.parse(row.updatedAt) < cutoff,
        )
        .map((row: any) => row.id);
    }

    // Which host wrote to the store is part of the proof, so it is recorded.
    try {
      knowledge.audit(scopeFor(instanceCwd), "host.attached", {
        host: "opencode",
        cwd: instanceCwd,
        version: ctx?.app?.version ?? "unknown",
      });
    } catch (error) {
      debug(`attach audit failed: ${String(error)}`);
    }

    // A learned method nobody used is archived, like on the Pi host.
    for (const targetScope of [scopeFor(instanceCwd), GLOBAL_SCOPE]) {
      try {
        const archived = skills.archiveUnused(
          targetScope,
          knowledge.audits(targetScope, "skills.exposure", 200),
        );
        if (archived.length)
          debug(`archived learned methods (${targetScope}): ${archived.join(", ")}`);
      } catch (error) {
        debug(`archive failed (${targetScope}): ${String(error)}`);
      }
    }

    /**
     * The directory a session document records.
     *
     * The host nests it under `location`; a document older than that shape
     * carries it at the root. Anything else is unresolvable, never guessed.
     */
    function sessionDirectory(document: any): string | undefined {
      const directory = document?.location?.directory ?? document?.directory;
      return typeof directory === "string" && path.isAbsolute(directory)
        ? directory
        : undefined;
    }

    /**
     * The scope of a session.
     *
     * A session can live in a different directory than the instance that hosts
     * it, so the session record is the authority. The instance directory is
     * only a fallback.
     */
    async function scopeOf(sessionID: string): Promise<string> {
      if (!ctx?.session?.get) throw new Error("Session client unavailable");
      const found = await ctx.session.get({ sessionID });
      const directory = sessionDirectory(found);
      if (!directory)
        throw new Error(
          "Session directory unavailable; scoped operation refused",
        );
      const scope = scopeFor(directory);
      scopeCache.set(sessionID, scope);
      sessionCwd.set(sessionID, directory);
      return scope;
    }

    /**
     * The models that could serve a harness request, best first.
     *
     * A review or a lesson extraction is a request of its own, and some
     * providers refuse those outright (the OpenCode free tier, the Go models
     * until a region is chosen). The harness therefore keeps a list and tries
     * it in order, instead of pinning one provider and failing the loop.
     */
    async function verifierCandidates(
      requested: { providerID: string; id: string } | undefined,
      sessionID: string,
    ): Promise<{ providerID: string; id: string }[]> {
      const liveModel = liveModels.get(sessionID);
      const out: { providerID: string; id: string }[] = [];
      const add = (model?: { providerID?: string; id?: string } | null) => {
        if (!model?.providerID || !model?.id) return;
        if (
          out.some(
            (row) => row.providerID === model.providerID && row.id === model.id,
          )
        )
          return;
        out.push({ providerID: model.providerID, id: model.id });
      };

      // The operator can pin the model that serves the harness: the host's own
      // default may refuse a request of its own, or cost more than the call is
      // worth. The environment wins; the file is how the choice survives a
      // restart.
      const pinned = (() => {
        const env = process.env.HARNESS_VERIFIER?.trim();
        if (env) return env;
        try {
          return fs
            .readFileSync(path.join(stateRoot(), "verifier"), "utf8")
            .trim();
        } catch {
          return "";
        }
      })();
      const allowed = new Set(
        (process.env.HARNESS_VERIFIER_PROVIDERS ?? "")
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      );
      if (pinned) {
        const cut = pinned.indexOf("/");
        if (cut < 1 || cut === pinned.length - 1)
          throw new Error("Invalid pinned verifier");
        const model = {
          providerID: pinned.slice(0, cut),
          id: pinned.slice(cut + 1),
        };
        if (
          requested &&
          (requested.providerID !== model.providerID ||
            requested.id !== model.id)
        )
          throw new Error("Requested model conflicts with pinned verifier");
        return [model];
      }
      if (requested) {
        if (
          requested.providerID !== liveModel?.providerID &&
          !allowed.has(requested.providerID)
        )
          throw new Error("Verifier provider is outside the operator policy");
        return [requested];
      }
      if (liveModel) add(liveModel);
      const models = await ctx.model.list();
      const listed = Array.isArray(models) ? models : (models?.data ?? []);
      if (allowed.size) {
        for (const model of listed)
          if (allowed.has(model.providerID)) add(model);
      } else {
        for (const model of listed) add(model);
      }
      // An empty list is a refusal with a reason, not a silent no-op: the
      // caller reports it instead of recording a review that never ran.
      if (!out.length)
        throw new Error(
          "no model can serve the harness: no active session model or configured provider is available",
        );
      return out.slice(0, 3);
    }

    // The pinned API accepts model/prompt only. No server-side token cap is claimed.
    async function boundedGenerate(model: any, prompt: string) {
      const controller = new AbortController(),
        signal = AbortSignal.any([
          controller.signal,
          lifecycleController.signal,
        ]);
      let timer: any;
      try {
        const deadline = new Promise((_, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            reject(new Error("Verifier deadline exceeded"));
          }, 30000);
        });
        const value: any = await Promise.race([
          ctx.generate.text({ model, prompt }, { signal }),
          deadline,
        ]);
        if (typeof value?.text !== "string" || value.text.length > 24000)
          throw new Error("Invalid or oversized verifier output");
        return value;
      } finally {
        clearTimeout(timer);
        controller.abort();
      }
    }
    /**
     * The observation ids of a session.
     *
     * A session that has no row yet has no observation, and that is not an
     * error: it simply has nothing to show.
     */
    function recentObservations(scope: string, sessionID: string): string[] {
      try {
        const storedID = registered.get(`${sessionID}\0${scope}`) ?? sessionID;
        return knowledge
          .observationsForSession(storedID, scope, 20)
          .map((item: any) => item.id);
      } catch {
        return [];
      }
    }

    /**
     * The session row.
     *
     * The Pi harness records a run, which ends. An OpenCode session is a
     * conversation that can be resumed days later, so there is no terminal
     * event to mirror: the row states that this conversation is attached to
     * the proof store, and stays "active" for as long as the host observes it.
     */
    function ensureSession(
      sessionID: string,
      scope: string,
      status: "active" | "completed" = "active",
    ): string {
      const key = `${sessionID}\0${scope}`;
      const known = registered.get(key);
      if (known) {
        knowledge.upsertSession({
          id: known,
          scope,
          cwd: sessionCwd.get(sessionID) ?? instanceCwd,
          status,
          updatedAt: new Date().toISOString(),
        });
        return known;
      }
      let storedID = sessionID;
      try {
        knowledge.upsertSession({
          id: storedID,
          scope,
          cwd: sessionCwd.get(sessionID) ?? instanceCwd,
          status,
          updatedAt: new Date().toISOString(),
        });
      } catch (error) {
        if (!String(error).includes("scope collision")) throw error;
        storedID = `${sessionID}:${scope.slice(-24)}`;
        knowledge.upsertSession({
          id: storedID,
          scope,
          cwd: sessionCwd.get(sessionID) ?? instanceCwd,
          status,
          updatedAt: new Date().toISOString(),
        });
      }
      registered.set(key, storedID);
      return storedID;
    }

    if (typeof ctx.event?.subscribe === "function")
      void (async () => {
        try {
          for await (const event of ctx.event.subscribe({
            signal: lifecycleController.signal,
          })) {
            const sessionID = event?.data?.sessionID;
            if (
              !sessionID ||
              (event.type !== "session.idle" && event.type !== "session.status")
            )
              continue;
            const status =
              event.type === "session.idle" ||
              event.data?.status?.type === "idle"
                ? "completed"
                : event.data?.status?.type === "busy"
                  ? "active"
                  : undefined;
            if (!status) continue;
            try {
              ensureSession(sessionID, await scopeOf(sessionID), status);
            } catch (error) {
              debug(
                `session lifecycle failed for ${sessionID}: ${String(error)}`,
              );
            }
          }
        } catch (error) {
          if (!lifecycleController.signal.aborted)
            debug(`session event stream failed: ${String(error)}`);
        }
      })();

    /**
     * The operator rules, injected on every turn.
     *
     * They are the authority, so they go into the system prompt, ahead of
     * anything else the harness would add. Learned knowledge is deliberately
     * absent: it is unproven by definition, and it never shares this block.
     */
    const budget = {
      operatorModelChars: Number(
        process.env.HARNESS_OPERATOR_CHARS ?? DEFAULT_CONFIG.operatorModelChars,
      ),
      memoryMaxChars: Number(
        process.env.HARNESS_MEMORY_CHARS ?? DEFAULT_CONFIG.memoryMaxChars,
      ),
    };
    await ctx.session.hook("prompt", async (event: any) => {
      const text = requestText(event);
      if (text) requestBySession.set(event.sessionID, text);
    });
    await ctx.session.hook("context", async (event: any) => {
      if (!Array.isArray(event.system)) return;
      const scope = await scopeOf(event.sessionID);
      // Mandatory authority is independent of optional continuity storage.
      const authority = operatorContext(knowledge, scope, budget);
      if (
        authority.block &&
        !event.system.some(
          (block: any) =>
            typeof block?.text === "string" &&
            block.text.startsWith(OPERATOR_MARKER),
        )
      ) {
        event.system.splice(1, 0, { type: "text", text: authority.block });
        knowledge.audit(scope, "context.injected", {
          sessionID: event.sessionID,
          agent: event.agent,
          rules: authority.entries.map((entry: any) => entry.key),
          chars: authority.block.length,
        });
      }
      try {
        if (event?.model?.providerID && event?.model?.id) {
          liveModels.set(event.sessionID, {
            providerID: event.model.providerID,
            id: event.model.id,
          });
        }
        if (!Array.isArray(event.system)) return;
        // The state of the work, for a session that resumes. It carries the
        // running step list and the observations that close it, so a resumed
        // session finds the exact state instead of a narration about it.
        const proofSessionID = ensureSession(event.sessionID, scope);
        const mission = platform.active(scope);
        // The investigation arbiter reads the state once per turn. The summary
        // gates the conclusion; the assembled state drives the injected block.
        // A read failure here must never hold the turn.
        const invNowMs = Date.now();
        let invState: any;
        let invSummary: any;
        try {
          investigation.tick(scope, invNowMs);
          const explicitCov = investigation.coverageSummary(scope);
          const tasks = taskStore.list(scope);
          const coverage = explicitCov.total > 0
            ? explicitCov
            : taskCoverageSummary(tasks);
          invState = assembleInvestigation({
            observations: knowledge.observationsForSession(proofSessionID, scope, 30),
            tasks,
            hypotheses: investigation.hypotheses(scope),
            coverage,
            nowMs: invNowMs,
          });
          invSummary = {
            untested: invState.coverage.untested,
            staleHypotheses: invState.hypotheses.filter((h: any) => h.state === "stale").length,
            coveragePct: addressedPct(invState.coverage),
          };
        } catch {
          /* The arbiter reads; a read failure is not a reason to stop the turn. */
        }
        const state = capsule(taskStore, knowledge, scope, proofSessionID, {
          investigation: invSummary,
          mission: mission
            ? {
                id: mission.id,
                title: mission.title,
                boundaries: mission.boundaries,
                state: mission.state,
                ...(mission.closed ? { closed: mission.closed } : {}),
                stages: mission.nodes.map(({ id, state }: any) => ({
                  id,
                  state,
                })),
              }
            : undefined,
          workflow: mission ? workflow.status(scope, mission.id) : undefined,
          approvals: platform
            .approvals(scope, "pending", 20)
            .map(({ id, action, justification }: any) => ({
              id,
              action: action.slice(0, 200),
              justification: justification.slice(0, 400),
            })),
          processes: processes
            .withStatus(scope)
            .filter((entry) => ["running", "unknown"].includes(entry.status))
            .map((entry) => ({
              id: entry.id,
              command: entry.command.slice(0, 500),
              status: entry.status,
            })),
          references: platform
            .memoryUses(scope, event.sessionID)
            .slice(-20)
            .map((entry: any) => ({
              kind: entry.kind,
              id: entry.referenceId,
              hash: entry.hash,
            })),
        });
        const continuity = capsuleText(state);

        if (continuity) {
          const at = event.system.findIndex(
            (block: any) =>
              typeof block?.text === "string" &&
              block.text.startsWith(OPERATOR_MARKER),
          );
          event.system.splice(at >= 0 ? at + 1 : 1, 0, {
            type: "text",
            text: continuity,
          });
          knowledge.audit(scope, "context.continuity", {
            sessionID: event.sessionID,
            tasks: state.tasks.length,
            open: state.open,
            blocked: state.blocked,
            observations: state.observations.length,
          });
        }

        // The method that covers this request. The route is decided by a
        // keyword matcher, never by a model: a model that is handed sixty
        // skills picks the tool it already knows, which is the whole problem.
        const routing = routeFor(
          requestText(event) || requestBySession.get(event.sessionID) || "",
        );
        // HARNESS_ROUTER=off is the control arm of the A/B: the same request
        // without the map, and without the load the map would require.
        const routerOff = isRouterOff();
        // The methods this turn must have loaded before a finding is recorded.
        routedRequiredGroups.set(
          event.sessionID,
          routerOff ? [] : enforcedGroups(routing),
        );
        if (
          !routerOff &&
          !event.system.some(
            (block: any) =>
              typeof block?.text === "string" &&
              block.text.startsWith(ROUTER_MARKER),
          )
        ) {
          const at = event.system.findIndex(
            (block: any) =>
              typeof block?.text === "string" &&
              block.text.startsWith(OPERATOR_MARKER),
          );
          event.system.splice(at >= 0 ? at + 1 : 1, 0, {
            type: "text",
            text: routing.block,
          });
          knowledge.audit(scope, "context.routing", {
            sessionID: event.sessionID,
            agent: event.agent,
            matched: routing.ids,
            chars: routing.block.length,
          });
        }

        // Recompute on each context injection, including the same running
        // session after a tool is activated. This is a hint, never a proof.
        const capabilities = toolRegistry.context(
          scope,
          requestText(event) || requestBySession.get(event.sessionID) || "",
          await hostTools(),
        );
        const capabilityMarker = "Harness capabilities.";
        const existingCapability = event.system.findIndex(
          (block: any) => typeof block?.text === "string" &&
            block.text.startsWith(capabilityMarker),
        );
        if (existingCapability >= 0)
          event.system.splice(existingCapability, 1);
        // Keep the immutable authority order: host -> operator -> route.
        // Capabilities are advisory and must never precede operator rules.
        const routeAt = event.system.findIndex(
          (block: any) => typeof block?.text === "string" &&
            block.text.startsWith(ROUTER_MARKER),
        );
        const operatorAt = event.system.findIndex(
          (block: any) => typeof block?.text === "string" &&
            block.text.startsWith(OPERATOR_MARKER),
        );
        const position = routeAt >= 0 ? routeAt + 1 :
          operatorAt >= 0 ? operatorAt + 1 : 1;
        event.system.splice(position, 0, { type: "text", text: capabilities });

        // The closing gate. It answers "are we done?" from the state, not
        // from the model's story: whatever still stands is named, and a plan
        // is not a result.
        const gate = closingGate(state);
        if (
          gate &&
          !event.system.some(
            (block: any) =>
              typeof block?.text === "string" &&
              block.text.startsWith(GATE_MARKER),
          )
        ) {
          const anchor = event.system.findLastIndex(
            (block: any) =>
              typeof block?.text === "string" &&
              (block.text.startsWith("Continuity.") ||
                block.text.startsWith(ROUTER_MARKER) ||
                block.text.startsWith("Harness capabilities.")),
          );
          event.system.splice(anchor >= 0 ? anchor + 1 : 1, 0, {
            type: "text",
            text: gate,
          });
          knowledge.audit(scope, "context.gate", {
            sessionID: event.sessionID,
            open: state.open,
            blocked: state.blocked,
            stages:
              state.mission?.stages
                .filter((stage) => stage.state !== "COMPLETED")
                .map((stage) => stage.id) ?? [],
            chars: gate.length,
          });
        }

        // The investigation arbiter's injected block, from the state read above.
        // It tells the model when it is looping, leaving surfaces untested, or
        // concluding too early, and stays silent while the work progresses.
        try {
          const invDirectives = invState ? directives(invState) : [];
          const invBlock = investigationBlock(invDirectives);
          if (
            invBlock &&
            !event.system.some(
              (block: any) =>
                typeof block?.text === "string" &&
                block.text.startsWith(INVESTIGATION_MARKER),
            )
          ) {
            const anchor = event.system.findLastIndex(
              (block: any) =>
                typeof block?.text === "string" &&
                (block.text.startsWith(GATE_MARKER) ||
                  block.text.startsWith("Continuity.") ||
                  block.text.startsWith(ROUTER_MARKER) ||
                  block.text.startsWith("Harness capabilities.")),
            );
            event.system.splice(anchor >= 0 ? anchor + 1 : 1, 0, {
              type: "text",
              text: invBlock,
            });
            knowledge.audit(scope, "context.investigation", {
              sessionID: event.sessionID,
              directives: invDirectives.length,
              mandatory: invDirectives.filter((d: any) => d.priority === "mandatory").length,
              chars: invBlock.length,
            });
          }
        } catch {
          /* The arbiter reads; a read failure is not a reason to stop the turn. */
        }

        // What the learned methods offered this turn. It is what tells the
        // curator which methods are still used.
        const activeLearned = skills.active(scope);
        const learned = activeLearned.map((entry) => ({
          name: entry.revision.name,
          file: entry.filePath,
        }));
        if (learned.length)
          knowledge.audit(scope, "skills.exposure", {
            sessionID: event.sessionID,
            skills: learned,
          });
        const globalLearned = activeLearned
          .filter((entry) => entry.revision.scope === GLOBAL_SCOPE)
          .map((entry) => ({
            name: entry.revision.name,
            file: entry.filePath,
          }));
        if (globalLearned.length)
          knowledge.audit(GLOBAL_SCOPE, "skills.exposure", {
            sessionID: event.sessionID,
            projectScope: scope,
            skills: globalLearned,
          });

        // What the previous sessions of this scope taught, read once. The
        // extraction runs apart: it must never hold a turn. If the process
        // goes away before it finishes, the session stays unreviewed and the
        // next session reads it.
        if (!lessonRunning) {
          const pending = pendingLessons(scope, event.sessionID).slice(
            0,
            LESSON_BATCH,
          );
          if (pending.length) {
            lessonRunning = true;
            void (async () => {
              try {
                for (const sessionID of pending) {
                  lessonChecked.set(sessionID, Date.now());
                  try {
                    const outcome = await extractLessons(
                      scope,
                      sessionID,
                      event.sessionID,
                    );
                    debug(
                      `lessons ${sessionID}: ${outcome.facts} faits, ${outcome.skills} methodes`,
                    );
                  } catch (error) {
                    try {
                      knowledge.audit(scope, "lessons.failed", {
                        sessionID,
                        error: String(error).slice(0, 300),
                      });
                      // A model-not-found or provider error is permanent: mark
                      // the session as extracted so pendingLessons stops
                      // retrying it on every turn.
                      if (
                        /model.not.found|provider.*not.*configured|no model can serve/i.test(
                          String(error),
                        )
                      ) {
                        knowledge.audit(scope, "lessons.extracted", {
                          sessionID,
                          digest: sessionSnapshot(scope, sessionID).digest,
                          skipped: String(error).slice(0, 200),
                        });
                      }
                    } catch {
                      /* The store may be closing. */
                    }
                    debug(
                      `lesson extraction failed for ${sessionID}: ${String(error)}`,
                    );
                  }
                }
              } finally {
                lessonRunning = false;
              }
            })();
          }
        }
      } catch (error) {
        debug(`context injection failed: ${String(error)}`);
        event.system.push({
          type: "text",
          text: "Harness continuity unavailable. Do not infer task, approval, or process state; read the scoped stores before acting.",
        });
      }
    });

    /**
     * The proof itself: a tool call becomes an immutable observation.
     *
     * A failure to write the proof never breaks the tool call that was being
     * proven; it is recorded as an audit entry instead.
     */
    /**
     * The learned methods, served as skills.
     *
     * A method that was learned from the work is a skill like any other: the
     * host loads it, and it is selected like any other. What the harness
     * owns is the promotion: a method becomes active when a successful
     * observation supports it, a later correction replaces it, and a method
     * nobody used is archived.
     */
    await ctx.skill.transform((editor: any) => {
      const skillsDir = path.join(coreRoot(), ".opencode", "skills");
      const unquoteYaml = (value: string) => {
        if (
          value.startsWith('"') &&
          value.endsWith('"') &&
          value.length >= 2
        ) {
          try {
            return String(JSON.parse(value));
          } catch {
            return value.slice(1, -1);
          }
        }
        if (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
          return value.slice(1, -1).replace(/''/g, "'");
        return value;
      };
      if (fs.existsSync(skillsDir)) {
        const dirs = fs
          .readdirSync(skillsDir, { withFileTypes: true })
          .filter((entry) => entry.isDirectory())
          .sort((a, b) => a.name.localeCompare(b.name));
        for (const entry of dirs) {
          const file = path.join(skillsDir, entry.name, "SKILL.md");
          if (!fs.existsSync(file)) continue;
          try {
            if (!fs.statSync(file).isFile()) continue;
          } catch {
            continue;
          }
          const raw = fs.readFileSync(file, "utf8").replace(/\r\n/g, "\n");
          const fm = /^---\n([\s\S]*?)\n---(?:\n|$)/.exec(raw);
          if (!fm) continue;
          const frontmatter = fm[1];
          const rawName = /^name:\s*(.+)$/m.exec(frontmatter)?.[1]?.trim();
          if (!rawName) continue;
          const id = unquoteYaml(rawName) || entry.name;
          const rawDesc = /^description:\s*(.+)$/m
            .exec(frontmatter)?.[1]
            ?.trim();
          const description = rawDesc ? unquoteYaml(rawDesc) : id;
          editor.add({
            id,
            name: id,
            description,
            path: file,
            content: raw.slice(fm[0].length).replace(/^\s+/, ""),
          });
        }
      }
      const scopes = new Set<string>([
        ...scopeCache.values(),
        scopeFor(instanceCwd),
      ]);
      const wanted = new Map<
        string,
        { scope: string; entry: ReturnType<typeof skills.active>[number] }
      >();
      for (const scope of scopes) {
        for (const entry of skills.active(scope)) {
          const id = `${LEARNED_PREFIX}${entry.revision.name}`;
          if (!wanted.has(id)) wanted.set(id, { scope, entry });
        }
      }
      for (const existing of editor.list()) {
        const id = String(existing.id ?? "");
        if (id.startsWith(LEARNED_PREFIX) && !wanted.has(id))
          editor.remove(id);
      }
      for (const [id, { scope, entry }] of wanted) {
        const loaded = skills.load(scope, entry.revision.name);
        editor.add({
          id,
          name: entry.revision.name,
          description: entry.revision.description,
          path: entry.filePath,
          content: loaded.content,
        });
      }
    });

    await ctx.tool.hook("execute.after", async (event: any) => {
      try {
        if (OWN_TOOL.test(String(event.tool ?? ""))) return;
        const scope = await scopeOf(event.sessionID);
        const proofSessionID = ensureSession(event.sessionID, scope);
        const observation = knowledge.recordObservation({
          id: observationId(event.sessionID, event.id),
          sessionId: proofSessionID,
          scope,
          tool: String(event.tool ?? "unknown"),
          input: event.input ?? {},
          output: outputText(event.result ?? event.error),
          success: succeeded(event),
          timestamp: new Date().toISOString(),
        });
        // The immutable observation is the usage record. Do not duplicate
        // every tool invocation in the unbounded audit log.
        debug(
          `observed ${observation.id} tool=${observation.tool} success=${observation.success} scope=${scope}`,
        );
      } catch (error) {
        debug(`observation failed: ${String(error)}`);
        try {
          knowledge.audit(
            scopeCache.get(event.sessionID) ?? "project-unknown",
            "observation.error",
            {
              tool: event.tool,
              error: String(error).slice(0, 300),
            },
          );
        } catch {
          /* The audit must not raise either. */
        }
      }
    });

    const { addWorkflowTools } = await import(
      path.join(coreRoot(), "opencode", "workflow-tools.ts")
    );
    const { addLedgerTools } = await import(
      path.join(coreRoot(), "opencode", "ledger-tools.ts")
    );
    await ctx.tool.transform((editor: any) => {
      editor.add({
        name: "cyber_toolbox",
        description: "Discover actual host/CLI/managed capabilities; ensure installs a catalogued tool only after an operator once-decision; knowledge-search reads the configured reference database without making findings; propose and validate scripts, activate instantly, and roll back. Native shell permissions still apply. Launching a command never installs one.",
        input: {
          type: "object",
          properties: {
            action: { type: "string", enum: ["discover", "knowledge-search", "plan", "ensure", "usage", "list", "propose", "validate", "activate", "promote", "rollback", "retire", "prune"] },
            query: { type: "string" },
            refresh: { type: "boolean" },
            global: { type: "boolean" },
            objectives: { type: "array", items: { type: "string" }, maxItems: 25 },
            names: { type: "array", items: { type: "string" }, maxItems: 10 },
            offset: { type: "integer", minimum: 0 },
            limit: { type: "integer", minimum: 1, maximum: 40 },
            name: { type: "string" },
            description: { type: "string" },
            language: { type: "string", enum: ["mjs", "py", "sh"] },
            source: { type: "string" },
            candidateId: { type: "string" },
            version: { type: "integer", minimum: 1 },
            provenance: {
              type: "object",
              properties: {
                url: { type: "string" },
                commit: { type: "string" },
                license: { type: "string" },
              },
              required: ["url"],
              additionalProperties: false,
            },
            days: { type: "integer", minimum: 0, maximum: 3650 },
            candidateIds: { type: "array", items: { type: "string" }, maxItems: 100 },
            tests: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  observationId: { type: "string" },
                  contains: { type: "string" },
                  kind: { type: "string", enum: ["positive", "negative"] },
                },
                required: ["observationId", "contains", "kind"],
                additionalProperties: false,
              },
            },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          const scope = await scopeOf(context.sessionID);
          ensureSession(context.sessionID, scope);
          const action = String(input.action);
          if (action === "discover")
            return { content: JSON.stringify(toolRegistry.discover(
              scope, input.query ?? "", await hostTools(), input.offset, input.limit, input.refresh === true,
            )) };
          if (action === "knowledge-search") {
            const { searchReference } = await import(path.join(coreRoot(), "src", "reference-search.ts"));
            return { content: JSON.stringify(searchReference(input.query, input.limit)) };
          }
          if (action === "plan") {
            // A bounded top-level inventory can be insufficient: scan the complete
            // CLI list once and combine it with the full managed registry.
            const inventory = toolRegistry.inventory(scope, await hostTools(), true);
            const gaps = identifyToolGaps(input.objectives ?? [], inventory);
            // An explicit plan is a read: no extra audit row per query.
            return { content: JSON.stringify(gaps) };
          }
          if (action === "ensure") {
            const { ensureMany } = await import(
              path.join(coreRoot(), "src", "installable.ts")
            );
            const names: string[] = Array.isArray(input.names)
              ? input.names.slice(0, 10).map(String)
              : typeof input.name === "string" ? [input.name] : [];
            if (!names.length) throw new Error("Provide name or names to ensure");
            await assertOperatorDecision(
              ctx,
              context,
              "ensure-tool:" + names.join(","),
            );
            const results = ensureMany(names);
            for (const r of results) {
              knowledge.audit(scope, "tools.ensure", {
                sessionID: context.sessionID,
                name: r.name,
                wasPresent: r.wasPresent,
                installed: r.installed,
                method: r.method,
                error: r.error,
              });
            }
            return { content: JSON.stringify(results) };
          }
          if (action === "list")
            return { content: JSON.stringify(toolRegistry.list(scope, true)) };
          if (action === "usage") {
            const storedID = registered.get(`${context.sessionID}\0${scope}`) ?? context.sessionID;
            const rows = knowledge.observationsForSession(storedID, scope, 200);
            return { content: JSON.stringify(rows.map((row: any) => ({
              observationId: row.id,
              tool: row.tool,
              success: row.success,
              candidateManagedCommand: toolRegistry.matchExecution(scope, row.input, row.tool),
            }))) };
          }
          if (action === "propose") {
            const candidate = toolRegistry.propose(scope, input);
            knowledge.audit(scope, "tools.proposed", {
              sessionID: context.sessionID, id: candidate.id, name: candidate.name,
              version: candidate.version, sha256: candidate.sha256,
            });
            return { content: JSON.stringify(candidate) };
          }
          if (action === "validate") {
            const candidate = toolRegistry.validate(
              scope, input.candidateId, input.tests,
              (ids: string[]) => knowledge.evidence(scope, ids),
            );
            knowledge.audit(scope, "tools.validated", {
              sessionID: context.sessionID, id: candidate.id, tests: candidate.tests,
            });
            return { content: JSON.stringify(candidate) };
          }
          if (action === "activate" || action === "promote") {
            if (typeof input.candidateId !== "string" || !input.candidateId.trim())
              throw new Error(`${action} requires a candidateId`);
            if (action === "promote")
              await assertOperatorDecision(ctx, context, "promote-tool:" + input.candidateId);
            const active = toolRegistry.activate(scope, input.candidateId, action === "promote");
            knowledge.audit(scope, "tools.activated", {
              sessionID: context.sessionID, id: active.id, scope: active.scope,
              name: active.name, version: active.version,
            });
            return { content: JSON.stringify({
              ...active, availability: "immediate via permissioned shell/process",
            }) };
          }
          if (action === "rollback") {
            if (typeof input.name !== "string" || !input.name.trim())
              throw new Error("rollback requires a tool name");
            if (!Number.isInteger(input.version) || input.version < 1)
              throw new Error("rollback requires a positive integer version");
            await assertOperatorDecision(ctx, context, "rollback-tool:" + input.name);
            const restored = toolRegistry.rollback(
              scope, input.name, input.version, input.global === true,
            );
            knowledge.audit(scope, "tools.rolled-back", {
              sessionID: context.sessionID, name: restored.name,
              version: restored.version,
            });
            return { content: JSON.stringify(restored) };
          }
          if (action === "prune") {
            const result = toolRegistry.prune(scope, input.candidateIds ?? [], input.days ?? 30);
            if (result.removed.length)
              knowledge.audit(scope, "tools.pruned", {
                sessionID: context.sessionID,
                removed: result.removed,
              });
            return { content: JSON.stringify(result) };
          }
          if (action === "retire") {
            if (typeof input.name !== "string" || !input.name.trim())
              throw new Error("retire requires a tool name");
            await assertOperatorDecision(
              ctx, context, "retire-tool:" + (input.global ? "global:" : "local:") + input.name,
            );
            const retired = toolRegistry.retire(scope, input.name, input.global === true);
            knowledge.audit(scope, "tools.retired", {
              sessionID: context.sessionID, name: retired.name,
              scope: retired.scope, version: retired.version,
            });
            return { content: JSON.stringify(retired) };
          }
          throw new Error("Unknown toolbox action");
        },
      });
      addWorkflowTools(editor, {
        ctx,
        workflow,
        platform,
        knowledge,
        processes,
        scopeOf,
        ensureSession,
        assertOperatorDecision,
        assertProcessPermission,
        spawnTraced,
        stopProcess,
        verifiedOutcome,
        processStatus,
        publicProcess,
        instanceCwd,
        sessionCwd,
      });
      editor.add({
        name: "cyber_verification",
        description:
          "Bind fresh reproduction and negative-control observations from this independent session to the finding revision.",
        input: {
          type: "object",
          properties: {
            action: { type: "string", enum: ["attest"] },
            findingId: { type: "string" },
            checks: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  observationId: { type: "string" },
                  contains: { type: "string" },
                  purpose: {
                    type: "string",
                    enum: [
                      "reproduction",
                      "positive-control",
                      "negative-control",
                    ],
                  },
                },
                required: ["observationId", "contains", "purpose"],
                additionalProperties: false,
              },
            },
          },
          required: ["action", "findingId", "checks"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          if (input.action !== "attest")
            throw new Error("Invalid verification action");
          const scope = await scopeOf(context.sessionID),
            sessionId = ensureSession(context.sessionID, scope),
            payload = platform.verificationPayload(
              scope,
              input.findingId,
              sessionId,
              input.checks,
            );
          return {
            content: JSON.stringify(
              knowledge.recordObservation({
                id: observationId(
                  context.sessionID,
                  `${context.id}:verification`,
                ),
                sessionId,
                scope,
                tool: "harness:verification",
                input: { findingId: input.findingId, runId: payload.runId },
                output: JSON.stringify(payload),
                success: true,
                timestamp: new Date().toISOString(),
              }),
            ),
          };
        },
      });

      editor.add({
        name: "cyber_cve",
        description:
          "Look up known vulnerabilities. Use lookup for a single OSV package, batch for multiple OSV packages (up to 20), and search for services/servers/technologies not in an OSV ecosystem (queries NVD + searchsploit). The investigation arbiter nudges you to run this after reconnaissance.",
        input: {
          type: "object",
          properties: {
            action: { type: "string", enum: ["lookup", "batch", "search"] },
            technology: {
              type: "string",
              description: "For search: the technology name (e.g. 'Apache', 'OpenSSH', 'WordPress').",
            },
            ecosystem: {
              type: "string",
              enum: [
                "PyPI", "npm", "Go", "Debian", "Ubuntu", "Alpine", "Packagist",
                "Maven", "NuGet", "RubyGems", "crates.io", "Hex", "GitHub Actions",
              ],
            },
            package: {
              type: "string",
              description: "The package name, as the ecosystem writes it.",
            },
            version: { type: "string", description: "The version to test." },
            packages: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  ecosystem: { type: "string" },
                  package: { type: "string" },
                  version: { type: "string" },
                },
                required: ["ecosystem", "package"],
              },
              description: "For batch: up to 20 packages to check at once.",
            },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any) => {
          const validPackageName = (pkg: string) =>
            /^[A-Za-z0-9@][A-Za-z0-9._/@+-]{0,200}$/.test(pkg);
          const validPackageVersion = (ver: string) =>
            Boolean(ver.trim()) &&
            ver.length <= 100 &&
            !/[\s\u0000-\u001f]/.test(ver);
          if (input.action === "search") {
            const tech =
              typeof input.technology === "string"
                ? input.technology.trim()
                : "";
            if (!tech || tech.length > 200)
              throw new Error(
                "search requires a technology name (max 200 chars)",
              );
            if (/[\u0000-\u001f\u007f]/.test(tech))
              throw new Error("Invalid search technology characters");
            const techTokens = tech.split(/\s+/).filter(Boolean);
            if (
              techTokens.length > 15 ||
              techTokens.some((t) => t.startsWith("-"))
            )
              throw new Error(
                "Search technology tokens cannot start with '-'",
              );
            let version: string | undefined;
            if (input.version !== undefined) {
              const rawVer = String(input.version).trim();
              if (rawVer) {
                if (
                  rawVer.length > 100 ||
                  /[\u0000-\u001f\u007f]/.test(rawVer)
                )
                  throw new Error("Invalid search version");
                const verTokens = rawVer.split(/\s+/).filter(Boolean);
                if (
                  verTokens.length > 10 ||
                  verTokens.some((t) => t.startsWith("-"))
                )
                  throw new Error("Search version tokens cannot start with '-'");
                version = rawVer;
              }
            }
            const result = await multiSourceLookup(tech, version);
            return { content: JSON.stringify(result) };
          }
          if (input.action === "batch") {
            const items = Array.isArray(input.packages) ? input.packages : [];
            if (!items.length) throw new Error("batch requires a packages array");
            if (items.length > 20) throw new Error("batch is limited to 20 packages");
            const formatBatchError = (err: unknown): string => {
              const raw =
                err instanceof Error
                  ? err.message
                    ? err.name && err.name !== "Error"
                      ? `${err.name}: ${err.message}`
                      : err.message
                    : err.name || "lookup-failed"
                  : typeof err === "string"
                    ? err
                    : (() => {
                        try {
                          return JSON.stringify(err) ?? String(err);
                        } catch {
                          return String(err);
                        }
                      })();
              const noStack = raw
                .replace(/\r?\n\s*at\s+[\s\S]*/g, "")
                .replace(/[\r\n]+/g, " ")
                .trim();
              return redactText(noStack).slice(0, 200) || "lookup-failed";
            };
            const results = [];
            for (const item of items) {
              if (!item || typeof item !== "object") {
                results.push({ ecosystem: "", package: "", version: null, error: "invalid" });
                continue;
              }
              const eco = String(item.ecosystem ?? "");
              const pkg = String(item.package ?? "").trim();
              const ver =
                item.version === undefined ? undefined : String(item.version);
              if (
                !OSV_ECOSYSTEMS.includes(eco as any) ||
                !validPackageName(pkg) ||
                (ver !== undefined && !validPackageVersion(ver))
              ) {
                results.push({
                  ecosystem: eco,
                  package: pkg,
                  version: ver ?? null,
                  error: "invalid",
                });
                continue;
              }
              try {
                const resp = await fetch("https://api.osv.dev/v1/query", {
                  method: "POST",
                  headers: { "content-type": "application/json" },
                  body: JSON.stringify({
                    package: { ecosystem: eco, name: pkg },
                    ...(ver ? { version: ver } : {}),
                  }),
                  signal: AbortSignal.timeout(10000),
                });
                if (!resp.ok) {
                  results.push({ ecosystem: eco, package: pkg, version: ver ?? null, error: `osv-${resp.status}` });
                  continue;
                }
                const declared = Number(resp.headers?.get?.("content-length") ?? 0);
                if (Number.isFinite(declared) && declared > 512000) {
                  results.push({ ecosystem: eco, package: pkg, version: ver ?? null, error: "osv-too-large" });
                  continue;
                }
                const text = await resp.text();
                if (Buffer.byteLength(text, "utf8") > 512000) {
                  results.push({ ecosystem: eco, package: pkg, version: ver ?? null, error: "osv-too-large" });
                  continue;
                }
                results.push({
                  ecosystem: eco,
                  package: pkg,
                  version: ver ?? null,
                  vulnerabilities: summarizeOsv(JSON.parse(text)),
                });
              } catch (err) {
                results.push({
                  ecosystem: eco,
                  package: pkg,
                  version: ver ?? null,
                  error: formatBatchError(err),
                });
              }
            }
            return { content: JSON.stringify({ batch: results }) };
          }
          if (input.action !== "lookup") throw new Error("Unknown CVE action");
          const ecosystem = String(input.ecosystem ?? "");
          if (!OSV_ECOSYSTEMS.includes(ecosystem as any))
            throw new Error("Unsupported OSV ecosystem");
          const name = String(input.package ?? "").trim();
          if (!validPackageName(name))
            throw new Error("Invalid package name");
          const version =
            input.version === undefined ? undefined : String(input.version);
          if (version !== undefined && !validPackageVersion(version))
            throw new Error("Invalid package version");
          const response = await fetch("https://api.osv.dev/v1/query", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              package: { ecosystem, name },
              ...(version ? { version } : {}),
            }),
            signal: AbortSignal.timeout(15000),
          });
          if (!response.ok)
            throw new Error(`OSV refused the lookup (${response.status})`);
          const text = await response.text();
          if (Buffer.byteLength(text, "utf8") > 512000)
            throw new Error("OSV response is too large");
          return {
            content: JSON.stringify({
              ecosystem,
              package: name,
              version: version ?? null,
              vulnerabilities: summarizeOsv(JSON.parse(text)),
            }),
          };
        },
      });

      addLedgerTools(editor, {
        scopeOf,
        taskStore,
        platform,
        knowledge,
        investigation,
        assetSteps,
        coverageProfile,
        coverageContract,
        COVERAGE_PROFILES,
        hash,
        assembleInvestigation,
        taskCoverageSummary,
        directives,
      });

      editor.add({
        name: "cyber_mission",
        description:
          "Drive an engagement: declare its scope, have it approved, take the stages in order and record what each one produced. The scope is a gate: nothing is dispatched before the operator approves it.",
        input: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: [
                "create",
                "status",
                "approve-scope",
                "claim",
                "finish",
                "checkpoints",
                "resume",
                "retry",
                "reopen-validation",
                "close",
              ],
              description: "What to do with the engagement.",
            },
            id: {
              type: "string",
              description:
                "The mission id. The active mission is used when it is absent.",
            },
            title: {
              type: "string",
              description: "The title of the engagement, for create.",
            },
            boundaries: {
              type: "string",
              description:
                "What is in scope and what is not, in the operator's own words, for create.",
            },
            root: {
              type: "string",
              description:
                "The engagement directory that owns this mission's artifacts and captures, for create. An absolute path to an existing directory; evidence outside it is refused.",
            },
            reason: {
              type: "string",
              description: "Why a completed validation must be reopened.",
            },
            node: {
              type: "string",
              description:
                "The stage to take or to close, for claim and finish.",
            },
            owner: {
              type: "string",
              description: "Who takes the stage, for claim.",
            },
            findingIds: {
              type: "array",
              items: { type: "string" },
              description:
                "The findings the verification stage covers, for claim. A finding can only be verified if the stage covered it.",
            },
            lease: {
              type: "string",
              description: "The lease returned by claim, for finish.",
            },
            results: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  role: {
                    type: "string",
                    enum: [
                      "recon-agent",
                      "web-agent",
                      "network-agent",
                      "windows-agent",
                      "linux-agent",
                      "code-agent",
                      "threat-intel-agent",
                      "forensics-agent",
                      "report-agent",
                      "verification-agent",
                    ],
                  },
                  status: {
                    type: "string",
                    enum: ["completed", "error", "aborted", "budget-exceeded"],
                  },
                  summary: { type: "string" },
                  evidence: { type: "array", items: { type: "string" } },
                  observationIds: {
                    type: "array",
                    items: { type: "string" },
                    description:
                      "The observations that prove the work. They must exist in this scope.",
                  },
                },
                required: ["role", "status", "summary"],
                additionalProperties: false,
              },
              description: "What the stage produced, for finish.",
            },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          const scope = await scopeOf(context.sessionID);
          if (input.action === "create") {
            if (!input.title || !input.boundaries)
              throw new Error(
                "an engagement needs a title and explicit boundaries",
              );
            return {
              content: JSON.stringify(
                platform.createMission(
                  scope,
                  input.title,
                  input.boundaries,
                  undefined,
                  input.root,
                ),
              ),
            };
          }
          const id = input.id ?? platform.active(scope)?.id;
          if (!id) throw new Error("a mission id is required");
          if (input.action === "status")
            return {
              content: JSON.stringify({
                mission: platform.mission(scope, id),
                findings: platform.findings(scope, id),
                checkpoints: platform.checkpoints(scope, id),
              }),
            };
          if (input.action === "approve-scope") {
            // The scope gate. It is closed until the operator opens it.
            await assertOperatorDecision(ctx, context, `approve-scope:${id}`);
            platform.approveScope(scope, id);
            return { content: JSON.stringify(platform.mission(scope, id)) };
          }
          if (input.action === "reopen-validation") {
            if (!input.reason?.trim())
              throw new Error("Reopening validation needs a reason");
            const current = platform.mission(scope, id);
            if (
              current.nodes.some((n) => n.state === "RUNNING") ||
              !current.nodes.some(
                (n) => n.id === "validation" && n.state === "COMPLETED",
              )
            )
              throw new Error("Validation cannot be reopened in this state");
            await assertOperatorDecision(
              ctx,
              context,
              `reopen-validation:${id}`,
            );
            return {
              content: JSON.stringify(
                platform.reopenValidation(
                  scope,
                  id,
                  input.reason,
                  `operator:${context.sessionID}`,
                ),
              ),
            };
          }
          if (input.action === "close") {
            // Ending an engagement is an operator decision, and it is a
            // closure, not a completion: the stages that never ran stay
            // visible as they are.
            if (!input.reason?.trim())
              throw new Error("Closing an engagement needs a written reason");
            await assertOperatorDecision(ctx, context, `close:${id}`);
            return {
              content: JSON.stringify(platform.closeMission(scope, id, input.reason)),
            };
          }
          if (input.action === "checkpoints")
            return { content: JSON.stringify(platform.checkpoints(scope, id)) };
          if (input.action === "resume")
            return { content: JSON.stringify(platform.resume(scope, id)) };
          if (!input.node) throw new Error("the stage is required");
          if (input.action === "retry")
            return {
              content: JSON.stringify(platform.retry(scope, id, input.node)),
            };
          if (input.action === "claim") {
            if (!input.owner)
              throw new Error("the owner of the stage is required");
            return {
              content: JSON.stringify(
                platform.claim(
                  scope,
                  id,
                  input.node,
                  input.owner,
                  input.findingIds ?? [],
                ),
              ),
            };
          }
          if (!input.lease)
            throw new Error("the lease is required to close a stage");
          if (!input.results?.length)
            throw new Error("closing a stage needs what it produced");
          return {
            content: JSON.stringify(
              platform.finish(
                scope,
                id,
                input.node,
                input.lease,
                input.results.map((result: any) => ({
                  role: result.role,
                  status: result.status,
                  summary: result.summary,
                  evidence: result.evidence ?? [],
                  observationIds: result.observationIds ?? [],
                })),
              ),
            ),
          };
        },
      });

      editor.add({
        name: "cyber_approval",
        description:
          "The queue of actions that wait for the operator. An action that the engagement forbids unattended is requested here and stops until the operator decides. The decision is written down.",
        input: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["request", "list", "decide"],
              description: "What to do with the queue.",
            },
            id: {
              type: "string",
              description: "The approval id, for decide.",
            },
            missionId: {
              type: "string",
              description: "The engagement the action belongs to, for request.",
            },
            requestedAction: {
              type: "string",
              description: "The action that waits, for request.",
            },
            justification: {
              type: "string",
              description: "Why it needs the operator, for request.",
            },
            requestedBy: {
              type: "string",
              description: "Who asks, for request.",
            },
            approve: {
              type: "boolean",
              description: "The decision, for decide.",
            },
            decidedBy: {
              type: "string",
              description: "Who decides, for decide.",
            },
            status: {
              type: "string",
              enum: ["pending", "approved", "denied"],
              description: "Filter, for list.",
            },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          const scope = await scopeOf(context.sessionID);
          if (input.action === "list")
            return {
              content: JSON.stringify(platform.approvals(scope, input.status)),
            };
          if (input.action === "request") {
            if (
              !input.missionId ||
              !input.requestedAction ||
              !input.justification
            )
              throw new Error(
                "an approval needs the engagement, the action and why it needs the operator",
              );
            return {
              content: JSON.stringify(
                platform.requestApproval(
                  scope,
                  input.missionId,
                  input.requestedAction,
                  input.justification,
                  input.requestedBy ?? "specialist",
                ),
              ),
            };
          }
          if (!input.id) throw new Error("an approval id is required");
          if (typeof input.approve !== "boolean")
            throw new Error("the decision is required");
          await assertOperatorDecision(
            ctx,
            context,
            `approval:${input.id}:${input.approve ? "approve" : "deny"}`,
          );
          return {
            content: JSON.stringify(
              platform.decideApproval(
                scope,
                input.id,
                input.approve,
                input.decidedBy ?? "operator",
              ),
            ),
          };
        },
      });

      editor.add({
        name: "cyber_source",
        description:
          "Register what was read, so a finding can cite it. A source is cut into chunks that the ledger cites by id.",
        input: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["ingest", "get", "list", "search"],
              description: "What to do with the sources.",
            },
            sourceId: {
              type: "string",
              description: "The source the document belongs to, for ingest.",
            },
            uri: {
              type: "string",
              description: "Where the document comes from, for ingest.",
            },
            title: {
              type: "string",
              description: "The title of the document, for ingest.",
            },
            body: {
              type: "string",
              description: "The text of the document, for ingest.",
            },
            id: { type: "string", description: "The chunk id, for get." },
            query: { type: "string", description: "The search, for search." },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          const scope = await scopeOf(context.sessionID);
          if (input.action === "ingest") {
            if (!input.sourceId || !input.uri || !input.title || !input.body)
              throw new Error(
                "a source needs its id, where it comes from, a title and its text",
              );
            return {
              content: JSON.stringify(
                platform.ingest(
                  scope,
                  input.sourceId,
                  input.uri,
                  input.title,
                  input.body,
                ),
              ),
            };
          }
          if (input.action === "list")
            return { content: JSON.stringify(platform.sources(scope)) };
          if (input.action === "search")
            return {
              content: JSON.stringify(
                platform.search(scope, "source", input.query ?? "", 20),
              ),
            };
          if (!input.id) throw new Error("a chunk id is required");
          return { content: JSON.stringify(platform.chunk(scope, input.id)) };
        },
      });

      editor.add({
        name: "cyber_finding",
        description:
          "Record a claim with the observations that back it. A finding carries its evidence, its source citations, the controls that were observed and its limitations. It stays unverified until an independent verification stage says otherwise.",
        input: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["create", "get", "verify", "reject", "search", "evidence"],
              description: "What to do with the ledger.",
            },
            id: {
              type: "string",
              description: "The finding id, for get, verify and reject.",
            },
            missionId: {
              type: "string",
              description: "The mission the finding belongs to, for create.",
            },
            title: {
              type: "string",
              description: "The title of the finding, for create.",
            },
            severity: {
              type: "string",
              enum: ["informational", "low", "medium", "high", "critical"],
              description: "The severity, for create.",
            },
            description: {
              type: "string",
              description: "What was found, for create.",
            },
            limitations: {
              type: "string",
              description: "What the finding does not show, for create.",
            },
            evidence: {
              type: "array",
              items: { type: "string" },
              description:
                "The observation ids that back the finding, for create. They must exist in this scope.",
            },
            sources: {
              type: "array",
              items: { type: "string" },
              description: "The source chunk ids cited, for create.",
            },
            checks: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  observationId: { type: "string" },
                  contains: { type: "string" },
                  purpose: {
                    type: "string",
                    enum: [
                      "reproduction",
                      "positive-control",
                      "negative-control",
                    ],
                  },
                },
                required: ["observationId", "contains", "purpose"],
                additionalProperties: false,
              },
              description:
                "The controls that were observed, for create. Each one points at a successful observation whose output carries the text.",
            },
            kind: {
              type: "string",
              enum: [
                "all",
                "mission",
                "evidence",
                "finding",
                "source",
                "knowledge",
              ],
              description: "What to search, for search.",
            },
            query: { type: "string", description: "The search, for search." },
            ids: {
              type: "array",
              items: { type: "string" },
              description: "The observation ids to index, for evidence.",
            },
            verificationId: {
              type: "string",
              description:
                "The observation of the independent verification, for action verify. It must come from the verification stage, and it must not be the evidence of the finding itself.",
            },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          const scope = await scopeOf(context.sessionID);
          if (input.action === "create") {
            if (!input.missionId)
              throw new Error("a finding belongs to a mission");
            if (!input.title || !input.severity || !input.description)
              throw new Error(
                "a finding needs a title, a severity and a description",
              );
            if (!input.limitations?.trim())
              throw new Error("a finding states what it does not show");
            // The method that covers this request must have been loaded in the
            // session: recording a finding is where the harness refuses to take
            // the model's memory for a procedure. The host hands the context
            // hook no request text, so the finding's own content is routed too.
            if (!isRouterOff()) {
              const routed = routeFor(
                [input.title, input.description, input.limitations]
                  .filter((value: unknown) => typeof value === "string")
                  .join("\n"),
              );
              const rawGroups = [
                ...(routedRequiredGroups.get(context.sessionID) ?? []),
                ...enforcedGroups(routed),
              ];
              const seenGroupKeys = new Set<string>();
              const groups: string[][] = [];
              for (const group of rawGroups) {
                const key = group.join("\0");
                if (!key || seenGroupKeys.has(key)) continue;
                seenGroupKeys.add(key);
                groups.push(group);
              }
              if (groups.length) {
                const proofSessionID = ensureSession(context.sessionID, scope);
                const loaded = new Set<string>();
                let cursor = 0;
                for (;;) {
                  const page = knowledge.observationsAfter(scope, cursor, 200);
                  if (!page.length) break;
                  for (const { observation: row } of page) {
                    if (row.sessionId !== proofSessionID || !row.success)
                      continue;
                    if (
                      row.tool === "skill" &&
                      row.input &&
                      typeof row.input === "object"
                    ) {
                      const id = String(
                        (row.input as any).id ?? (row.input as any).name ?? "",
                      );
                      if (id) loaded.add(id);
                    } else if (
                      row.tool === "cyber_method" &&
                      row.input &&
                      typeof row.input === "object" &&
                      (row.input as any).action === "load"
                    ) {
                      const name = String((row.input as any).name ?? "");
                      if (name) {
                        loaded.add(name);
                        loaded.add(`${LEARNED_PREFIX}${name}`);
                      }
                    }
                  }
                  if (page.length < 200) break;
                  cursor = page[page.length - 1].cursor;
                }
                for (const id of loadedMethodsBySession.get(
                  `${proofSessionID}\0${scope}`,
                ) ?? [])
                  loaded.add(id);
                for (const row of knowledge.audits(scope, "skill.loaded", 200)) {
                  try {
                    const detail = JSON.parse(row.detail);
                    if (
                      detail?.sessionID === proofSessionID &&
                      typeof detail.name === "string" &&
                      detail.name
                    ) {
                      loaded.add(detail.name);
                      loaded.add(`${LEARNED_PREFIX}${detail.name}`);
                    }
                  } catch {
                    /* ignore malformed audit detail */
                  }
                }
                const unsatisfied = groups.filter(
                  (group) => !group.some((id) => loaded.has(id)),
                );
                // Each matched enforced route requires >= 1 of its skills loaded;
                // an unrelated skill loaded earlier never satisfies a new route.
                if (unsatisfied.length > 0)
                  throw new Error(
                    `The method ${unsatisfied.map((g) => g.join(" or ")).join(" and ")} covers this request and none of them was loaded in this session. Call the skill tool with id ${unsatisfied[0][0]} first, then record the finding from what it had you observe.`,
                  );
              }
            }
            return {
              content: JSON.stringify(
                platform.createFinding(scope, {
                  missionId: input.missionId,
                  title: input.title,
                  severity: input.severity,
                  description: input.description,
                  limitations: input.limitations,
                  evidence: input.evidence ?? [],
                  sources: input.sources ?? [],
                  checks: input.checks ?? [],
                }),
              ),
            };
          }
          if (input.action === "search")
            return {
              content: JSON.stringify(
                platform.search(
                  scope,
                  input.kind ?? "all",
                  input.query ?? "",
                  20,
                ),
              ),
            };
          if (input.action === "evidence") {
            if (!input.ids?.length)
              throw new Error("the observation ids are required");
            platform.indexEvidence(scope, input.ids);
            return {
              content: JSON.stringify(platform.evidence(scope, input.ids)),
            };
          }
          if (!input.id) throw new Error("a finding id is required");
          if (input.action === "get") {
            const finding = platform.finding(scope, input.id);
            return {
              content: JSON.stringify({
                finding,
                sources: finding.sources,
                evidence: platform.evidence(scope, finding.evidence),
              }),
            };
          }
          if (input.action === "verify")
            return {
              content: JSON.stringify(
                platform.verifyFinding(scope, input.id, input.verificationId),
              ),
            };
          return {
            content: JSON.stringify(platform.rejectFinding(scope, input.id)),
          };
        },
      });

      editor.add({
        name: "cyber_entity",
        description:
          "Record what the engagement learned as typed entities and relations, then query them or find the shortest pivot path. Every fact carries the observations it was read from; a second read merges into the same entity.",
        input: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["upsert", "relate", "get", "query", "path", "import"],
              description:
                "Record an entity, link two entities, read one with its relations, list or search, or compute a path.",
            },
            type: {
              type: "string",
              enum: [
                "domain", "host", "ip", "url", "org", "person", "account", "repo",
                "secret", "certificate", "service", "technology", "vulnerability",
                "other",
              ],
            },
            key: {
              type: "string",
              description:
                "The identity inside the type (a domain, an IP, github:user, an email).",
            },
            label: { type: "string" },
            attributes: { type: "object", additionalProperties: true },
            observationIds: {
              type: "array",
              items: { type: "string" },
              description: "The observations this fact was read from.",
            },
            from: { type: "string", description: "Source entity id, for relate and path." },
            to: { type: "string", description: "Target entity id, for relate and path." },
            kind: {
              type: "string",
              description: "The relation kind, for relate (owns, resolves-to, member-of, uses, leaks).",
            },
            id: { type: "string", description: "The entity id, for get." },
            path: {
              type: "string",
              description: "A collected dump to ingest, for import.",
            },
            format: {
              type: "string",
              enum: ["lines", "httpx", "json"],
              description:
                "lines: one host or URL per line; httpx: JSON lines from httpx; json: an array of {type,key} facts.",
            },
            query: { type: "string", description: "A substring of the key or label, for query." },
            limit: { type: "integer", minimum: 1, maximum: 500 },
            maxDepth: { type: "integer", minimum: 1, maximum: 6 },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          const scope = await scopeOf(context.sessionID);
          ensureSession(context.sessionID, scope);
          if (input.action === "import") {
            if (!input.path) throw new Error("import requires a dump path");
            const format = String(input.format ?? "lines");
            if (!["lines", "httpx", "json"].includes(format))
              throw new Error("Invalid dump format");
            if (!Array.isArray(input.observationIds) || !input.observationIds.length)
              throw new Error(
                "An import needs the observation that produced the dump",
              );
            const file = path.resolve(String(input.path));
            assertPlainPath(file);
            let stat;
            try {
              stat = fs.statSync(file);
            } catch {
              throw new Error("The dump is missing");
            }
            if (!stat.isFile() || stat.size < 1 || stat.size > 5000000)
              throw new Error("Invalid dump size");
            const mission = platform.active(scope),
              root = mission
                ? platform.missionRoot(scope, mission.id)
                : undefined;
            if (root) {
              assertPlainPath(root);
              const allowed = fs.realpathSync.native(root);
              if (
                !fs.realpathSync
                  .native(file)
                  .startsWith(allowed + path.sep)
              )
                throw new Error("The dump must stay inside the engagement");
            }
            knowledge.evidence(scope, input.observationIds);
            const plan = planIngest(
              format as any,
              fs.readFileSync(file, "utf8"),
            );
            const ids = new Map<string, string>();
            for (const entity of plan.entities)
              ids.set(
                `${entity.type}:${entity.key}`,
                platform.upsertEntity(scope, {
                  ...entity,
                  observationIds: input.observationIds,
                }).id,
              );
            const done = new Set<string>();
            let relations = 0;
            for (const relation of plan.relations) {
              const from = ids.get(
                  `${relation.source.type}:${relation.source.key}`,
                ),
                to = ids.get(`${relation.target.type}:${relation.target.key}`);
              if (!from || !to) continue;
              const key = `${from}|${to}|${relation.kind}`;
              if (done.has(key)) continue;
              done.add(key);
              platform.relate(scope, {
                from,
                to,
                kind: relation.kind,
                observationIds: input.observationIds,
              });
              relations += 1;
            }
            return {
              content: JSON.stringify({
                entities: plan.entities.length,
                relations,
                skipped: plan.skipped,
              }),
            };
          }
          if (input.action === "upsert")
            return { content: JSON.stringify(platform.upsertEntity(scope, input)) };
          if (input.action === "relate")
            return { content: JSON.stringify(platform.relate(scope, input)) };
          if (input.action === "get")
            return {
              content: JSON.stringify({
                entity: platform.entity(scope, input.id),
                relations: platform.relations(scope, input.id),
              }),
            };
          if (input.action === "query")
            return {
              content: JSON.stringify(
                platform.entities(scope, {
                  type: input.type,
                  query: input.query,
                  limit: input.limit,
                }),
              ),
            };
          if (input.action === "path")
            return {
              content: JSON.stringify(
                platform.path(scope, input.from, input.to, input.maxDepth ?? 4),
              ),
            };
          throw new Error("Unknown entity action");
        },
      });

      editor.add({
        name: "cyber_process",
        description:
          "Run a command the harness owns, or look at the ones it already owns. The whole output goes to a trace file, and the command is detached: it keeps running even if the session dies, and a later session can find it, read its trace and stop it.",
        input: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["run", "list", "read", "stop", "prune"],
              description:
                "Run a command, list them, read a trace, stop one, or archive the rows whose process is gone.",
            },
            argv: {
              type: "array",
              items: { type: "string" },
              description:
                "The executable and its arguments. Shell syntax is intentionally not accepted.",
            },
            timeout: {
              type: "number",
              description:
                "The deadline of the command, in seconds. 120 by default, 600 at most.",
            },
            id: {
              type: "string",
              description: "The command id, for action read and stop.",
            },
            tail: {
              type: "number",
              description:
                "How many lines of the trace to read, for action read.",
            },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          const scope = await scopeOf(context.sessionID);
          if (!["run", "list", "read", "stop", "prune"].includes(input.action))
            throw new Error("Invalid process action");
          if (input.action === "list")
            return {
              content: JSON.stringify(
                processes.withStatus(scope).map(publicProcess),
              ),
              metadata: { evidenceSuccess: false },
            };
          if (input.action === "run") {
            const argv = commandArguments(input.argv);
            const seconds = input.timeout ?? DEFAULT_DEADLINE_MS / 1000;
            if (
              !Number.isFinite(seconds) ||
              seconds <= 0 ||
              seconds * 1000 > MAX_DEADLINE_MS
            )
              throw new Error("Invalid timeout (0..600 seconds)");

            const command = argv.map(quoteArgument).join(" ");
            await assertProcessPermission(ctx, context, command);
            context.signal?.throwIfAborted();
            const cwd =
              sessionCwd.get(context.sessionID) ??
              sessionDirectory(
                await ctx.session.get({ sessionID: context.sessionID }),
              ) ??
              instanceCwd;
            const record = processes.prepare(
              scope,
              context.sessionID,
              command,
              cwd,
              seconds * 1000,
            );
            const started = spawnTraced(command, {
              cwd,
              logPath: record.logPath,
              deadlineMs: seconds * 1000,
              argv,
            });
            let stored;
            try {
              stored = processes.add({ ...record, ...started });
            } catch (error) {
              stopProcess(started.pid);
              throw error;
            }
            return {
              content: JSON.stringify({
                ...publicProcess(stored),
                trace: record.logPath,
                note: "Launch is not proof of success. Read after termination to obtain the exit code and verified trace.",
              }),
              metadata: { evidenceSuccess: false },
            };
          }
          if (input.action === "prune") {
            const pruned = processes.prune(scope);
            return {
              content: JSON.stringify({
                ...pruned,
                note: "Each archived row keeps its last known status; the trace files stay on disk. A running command is never archived.",
              }),
              metadata: { evidenceSuccess: false },
            };
          }
          if (!input.id) throw new Error("a command id is required");
          if (input.action === "stop") {
            const record = processes.get(scope, input.id);
            await assertProcessPermission(
              ctx,
              context,
              process.platform === "win32"
                ? `taskkill /PID ${record.pid}`
                : `kill -TERM -- -${record.pid}`,
            );
            const stopped = processes.stop(scope, input.id);
            return {
              content: JSON.stringify(publicProcess(stopped)),
              metadata: { evidenceSuccess: false },
            };
          }
          const record = processes.get(scope, input.id);
          const proofSessionID = ensureSession(context.sessionID, scope);
          let outcome: ReturnType<typeof verifiedOutcome> | undefined;
          let integrityError: string | undefined;
          try {
            outcome = verifiedOutcome(record);
          } catch (error) {
            integrityError =
              error instanceof Error ? error.message : String(error);
          }
          if (integrityError) {
            return {
              content: JSON.stringify({
                ...publicProcess(record),
                status: "unknown",
                observationId: observationId(context.sessionID, context.id),
                diagnosis: `Trace integrity check failed: ${integrityError}`,
                trace: "",
              }),
              metadata: { evidenceSuccess: false },
            };
          }
          const { runKey, ...result } = outcome ?? ({} as any);
          const trace = readTrace(record.logPath, input.tail ?? 200),
            seen = outcome ?? processOutcome(record);
          // A missing binary is not always an ENOENT: a wrapper such as nice,
          // mono or bash exits 127 with an empty trace, and an empty success is
          // not a result. Say which case it is, from the recorded outcome.
          const diagnosis =
            seen?.exitCode === 127
              ? "exit 127: a binary the command calls is missing (often a wrapper such as nice, mono or bash); an empty output is not a success"
              : /ENOENT|EACCES|spawn-error/.test(String(seen?.reason ?? "")) ||
                  /^Execution failed: (ENOENT|EACCES)/.test(trace)
                ? "the executable itself is missing or not executable"
                : seen?.status === "failed" && seen?.exitCode == null
                  ? "the command failed without an exit code; the executable may not have started"
                  : outcome?.status === "succeeded" && !trace.trim()
                  ? "the command succeeded but printed nothing; that is not a result"
                  : undefined;
          return {
            content: JSON.stringify({
              ...publicProcess(record),
              ...result,
              status: outcome?.status ?? processStatus(record),
              // The capture binds to the observation of this read, so name it
              // here: the model should not have to guess its own call id.
              observationId: observationId(context.sessionID, context.id),
              ...(diagnosis ? { diagnosis } : {}),
              trace,
            }),
            metadata: {
              evidenceSuccess:
                outcome?.status === "succeeded" && outcome.exitCode === 0,
            },
          };
        },
      });

      editor.add({
        name: "cyber_lessons",
        description:
          "Read what a previous inactive session taught. The extractor is a model without tools: it reads the observations and proposes durable facts and reusable methods, which the store then accepts only if a successful observation backs them.",
        input: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["run", "pending"],
              description:
                "Extract the lessons of a session, or list what is waiting.",
            },
            sessionId: {
              type: "string",
              description:
                "The previous inactive session to read. It is required for run.",
            },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          const scope = await scopeOf(context.sessionID);
          if (input.action === "pending")
            return {
              content: JSON.stringify({
                pending: pendingLessons(scope, context.sessionID),
                reviews: knowledge.reviews(scope, 20),
              }),
            };
          const sessionID = input.sessionId;
          if (!sessionID || sessionID === context.sessionID)
            throw new Error(
              "lessons are extracted only from a previous inactive session",
            );
          const target = knowledge
            .sessionsForScope(scope, 200)
            .find((row: any) => row.id === sessionID);
          if (!target)
            throw new Error(
              "lessons are extracted only from an inactive scoped session",
            );
          if (target.status === "active") {
            const updated = Date.parse(target.updatedAt);
            const isIdle =
              Number.isFinite(updated) &&
              Date.now() - updated >= LESSON_IDLE_MS;
            if (!isIdle)
              throw new Error(
                "lessons are extracted only from an inactive scoped session",
              );
          }
          const outcome = await extractLessons(
            scope,
            sessionID,
            context.sessionID,
          );
          return { content: JSON.stringify(outcome) };
        },
      });

      // A capture belongs to the engagement that owns it. Without a declared
      // root, it keeps the historical location under the harness state.
      const captureRoot = (scope: string) => {
        const mission = platform.active(scope);
        const engagement = mission
          ? platform.missionRoot(scope, mission.id)
          : undefined;
        const root = engagement
          ? path.join(engagement, "preuves", "captures")
          : path.join(stateRoot(), "captures");
        fs.mkdirSync(root, { recursive: true, mode: 0o700 });
        return root;
      };

      editor.add({
        name: "cyber_capture",
        description:
          "Take a visual attestation of a window. The capture shows one window, never the desktop, and it is linked to the observation it attests.",
        input: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["windows", "shot", "evidence", "browser"],
              description:
                "List the windows of the display, capture one of them, capture the terminal of the harness, or capture a browser page via CDP (no automation banner).",
            },
            processId: {
              type: "string",
              description:
                "The finished process whose verified recorded trace is rendered. No command is rerun.",
            },
            window: {
              type: "string",
              description:
                "The id or the title of the window to capture, for action shot.",
            },
            observationId: {
              type: "string",
              description:
                "The observation the capture attests, for action shot.",
            },
            label: {
              type: "string",
              description: "A short label for the file, for action shot.",
            },
            url: {
              type: "string",
              description:
                "URL substring to match the browser tab, for action browser. Without it, the first tab is captured.",
            },
            port: {
              type: "number",
              description:
                "Chrome DevTools port, for action browser. Default 9222.",
            },
            file: {
              type: "string",
              description:
                "Path to an existing screenshot PNG to register as evidence, for action browser. When set, no CDP call is made.",
            },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          const scope = await scopeOf(context.sessionID);
          if (input.action === "windows") {
            const list = listWindows();
            return { content: JSON.stringify(list) };
          }
          if (input.action === "evidence") {
            // The command runs in the terminal of the harness, on its own
            // display. The desktop of the operator is not touched, and neither
            // is the terminal of the operator.
            if (!input.observationId)
              throw new Error(
                "an evidence capture needs the observation it attests",
              );
            const proof = knowledge.evidence(scope, [input.observationId])[0];
            if (
              !input.processId ||
              proof.tool !== "cyber_process" ||
              proof.input?.action !== "read" ||
              proof.input?.id !== input.processId
            )
              throw new Error(
                "Capture requires the observation of this process read",
              );
            const record = processes.get(scope, input.processId);
            let outcome: ReturnType<typeof verifiedOutcome> | undefined;
            try {
              outcome = verifiedOutcome(record);
            } catch (error) {
              throw new Error(
                `A capture requires an untampered verified trace (${error instanceof Error ? error.message : String(error)})`,
              );
            }
            if (!outcome || outcome.status === "running")
              throw new Error("A capture requires a finished, verified trace");
            const name = captureName(
              input.observationId,
              `${input.label ?? "evidence"}-${randomUUID().slice(0, 8)}`,
            );
            const root = captureRoot(scope);
            const dest = captureDestination(root, name);
            // The image is the terminal view of the recorded trace: the command
            // and its output. Provenance stays in the audit link, not burned
            // into the page that goes to the client.
            const body = readTrace(record.logPath, 2000)
              .replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\)/g, "")
              .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
              .replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "")
              .replace(/\s+$/, "");
            const lines = body.split("\n"),
              shown = lines.slice(0, 40);
            if (lines.length > shown.length) shown.push("…");
            const home = os.homedir(),
              cwd = sessionCwd.get(context.sessionID) ?? instanceCwd,
              title = cwd.startsWith(home)
                ? "~" + cwd.slice(home.length)
                : cwd;
            const renderer = renderTrace(
              shown.join("\n"),
              dest,
              title,
              record.command,
              cwd,
            );
            const image = fs.readFileSync(dest);
            const link = {
              kind: "rendered-trace",
              processId: input.processId,
              traceHash: outcome.traceHash,
              observationId: input.observationId ?? "",
              path: dest,
              renderer,
              width: image.readUInt32BE(16),
              height: image.readUInt32BE(20),
              bytes: image.length,
              sha256: createHash("sha256").update(image).digest("hex"),
              takenAt: new Date().toISOString(),
            };
            knowledge.audit(scope, "capture", link);
            return { content: JSON.stringify(link) };
          }
          if (input.action === "browser") {
            if (!input.observationId)
              throw new Error("a browser capture needs the observation it attests");
            knowledge.evidence(scope, [input.observationId]);
            const name = captureName(
              input.observationId,
              `${input.label ?? "browser"}-${randomUUID().slice(0, 8)}`,
            );
            const root = captureRoot(scope);
            const dest = captureDestination(root, name);
            const hasValidPng = (buf: Buffer) =>
              buf.length >= 24 &&
              buf[0] === 0x89 &&
              buf[1] === 0x50 &&
              buf[2] === 0x4e &&
              buf[3] === 0x47 &&
              buf[4] === 0x0d &&
              buf[5] === 0x0a &&
              buf[6] === 0x1a &&
              buf[7] === 0x0a &&
              buf.readUInt32BE(8) === 13 &&
              buf.subarray(12, 16).toString("ascii") === "IHDR" &&
              buf.readUInt32BE(16) > 0 &&
              buf.readUInt32BE(20) > 0;
            let isolated = false;
            let image: Buffer;
            try {
              if (input.file) {
                // Register an existing screenshot file as evidence.
                const src = path.resolve(String(input.file));
                assertPlainPath(src);
                let stat: fs.Stats;
                try {
                  stat = fs.statSync(src);
                } catch {
                  throw new Error("the file does not exist: " + src);
                }
                if (!stat.isFile())
                  throw new Error("the file is not a regular file: " + src);
                if (stat.size > 25 * 1024 * 1024)
                  throw new Error("the browser capture file exceeds 25 MB limit");
                if (stat.size < 24)
                  throw new Error("the file is not a valid PNG");
                const header = Buffer.alloc(24);
                const fd = fs.openSync(src, "r");
                let bytesRead = 0;
                try {
                  bytesRead = fs.readSync(fd, header, 0, 24, 0);
                } finally {
                  fs.closeSync(fd);
                }
                if (!hasValidPng(header.subarray(0, bytesRead)))
                  throw new Error("the file is not a valid PNG");
                fs.copyFileSync(src, dest);
              } else if (input.port !== undefined) {
                const port = Number(input.port);
                if (!Number.isInteger(port) || port < 1 || port > 65535)
                  throw new Error("Invalid CDP port (must be integer 1..65535)");
                const script = path.join(coreRoot(), "scripts", "capture_browser.mjs");
                const args = [script, dest, "--port", String(port)];
                if (input.url) args.push("--url", String(input.url));
                await new Promise<void>((resolve, reject) => {
                  const child = spawn(process.execPath, args, {
                    stdio: ["ignore", "pipe", "pipe"],
                    signal: context?.signal,
                  });
                  let output = "";
                  const timer = setTimeout(() => {
                    child.kill("SIGTERM");
                  }, 25000);
                  child.stdout?.on("data", (chunk) => {
                    output += String(chunk);
                  });
                  child.stderr?.on("data", (chunk) => {
                    output += String(chunk);
                  });
                  child.on("error", (error) => {
                    clearTimeout(timer);
                    reject(new Error(`${process.execPath} failed: ${error.message}`));
                  });
                  child.on("close", (code) => {
                    clearTimeout(timer);
                    if (code === 0) return resolve();
                    reject(new Error(`${process.execPath} failed: ${output.slice(0, 300)}`));
                  });
                });
              } else if (typeof input.url === "string" && input.url.trim()) {
                captureBrowserIsolated({
                  url: input.url.trim(),
                  dest,
                  timeoutMs: 25000,
                });
                isolated = true;
              } else {
                throw new Error(
                  "a browser capture requires file, url (for isolated capture), or port",
                );
              }
              if (!fs.existsSync(dest) || fs.statSync(dest).size < 32) {
                throw new Error("the browser capture is empty or failed");
              }
              image = fs.readFileSync(dest);
              if (!hasValidPng(image)) {
                throw new Error("the browser capture is not a valid PNG");
              }
            } catch (error) {
              try {
                fs.rmSync(dest, { force: true });
              } catch {}
              throw error;
            }
            const link = {
              kind: "browser-capture",
              observationId: input.observationId ?? "",
              path: dest,
              url: input.url ?? "",
              ...(isolated ? { isolated: true } : {}),
              width: image.readUInt32BE(16),
              height: image.readUInt32BE(20),
              bytes: image.length,
              sha256: createHash("sha256").update(image).digest("hex"),
              takenAt: new Date().toISOString(),
            };
            knowledge.audit(scope, "capture", link);
            return { content: JSON.stringify(link) };
          }
          if (!input.window) throw new Error("a capture needs a window");
          // The desktop is refused before every other requirement: it is never
          // a subject, even when the rest of the request is incomplete.
          const rootId = rootWindowId();
          assertNotRoot(rootId, input.window);
          if (!input.observationId)
            throw new Error("a capture needs the observation it attests");
          knowledge.evidence(scope, [input.observationId]);
          const list = listWindows();
          const target = /^[0-9]+$/.test(input.window.trim())
            ? selectWindowById(list, input.window)
            : selectWindow(list, input.window);
          assertNotRoot(rootId, target.id);
          const geometry = windowGeometry(target.id);
          const name = captureName(
            input.observationId,
            `${input.label ?? "capture"}-${randomUUID().slice(0, 8)}`,
          );
          const root = captureRoot(scope);
          const dest = captureDestination(root, name);
          const capture = captureWindow(target.id, dest);
          if (!isFramed(capture, geometry)) {
            try {
              fs.rmSync(dest, { force: true });
            } catch {}
            throw new Error(
              "the capture does not match the window it claims to show, so it is refused",
            );
          }
          const link = {
            observationId: input.observationId ?? "",
            path: dest,
            window: target.id,
            title: target.title,
            width: capture.width,
            height: capture.height,
            bytes: capture.bytes,
            sha256: createHash("sha256")
              .update(fs.readFileSync(dest))
              .digest("hex"),
            takenAt: new Date().toISOString(),
          };
          knowledge.audit(scope, "capture", link);
          return { content: JSON.stringify(link) };
        },
      });

      editor.add({
        name: "cyber_method",
        description:
          "Propose a reusable method learned from the work, and list the methods already learned. A method needs evidence: the observations that show it works. A method the operator states is taken as given.",
        input: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["propose", "list", "load", "promote", "technique", "gaps"],
              description:
                "Propose a method, list them, read one, share one with every project, read a technique card, or list the technique gaps.",
            },
            phase: {
              type: "string",
              enum: [
                "recon",
                "access",
                "identity",
                "execution",
                "lateral",
                "collection",
                "impact",
              ],
              description:
                "Restrict technique cards to one phase, for action technique without a name.",
            },
            name: {
              type: "string",
              description:
                "The name of the method, for propose, load and promote.",
            },
            description: {
              type: "string",
              description: "What the method is for, for propose.",
            },
            category: {
              type: "string",
              enum: [
                "false-positive-patterns",
                "tool-usage-patterns",
                "investigation-patterns",
                "environment-patterns",
              ],
              description: "The kind of method, for propose.",
            },
            procedure: {
              type: "array",
              items: { type: "string" },
              description: "The steps of the method, for propose.",
            },
            validation: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  observationId: { type: "string" },
                  contains: { type: "string" },
                },
                required: ["observationId", "contains"],
                additionalProperties: false,
              },
              description:
                "The checks that show the method works, each pointing at an observation, for propose.",
            },
            evidence: {
              type: "array",
              items: { type: "string" },
              description:
                "The observation ids that support the method, for propose.",
            },
            stated: {
              type: "string",
              description:
                "The operator's own words. A method the operator states is taken as given.",
            },
            contains: {
              type: "string",
              description:
                "What the output of the method must show. Without a validation, the check is built against the most recent successful observation.",
            },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          const scope = await scopeOf(context.sessionID);
          if (input.action === "gaps")
            return { content: JSON.stringify(techniqueGaps()) };
          if (input.action === "technique") {
            if (!input.name)
              return {
                content: JSON.stringify(
                  techniqueCards(input.phase ?? undefined),
                ),
              };
            return { content: JSON.stringify(techniqueCard(input.name)) };
          }
          if (input.action === "list")
            return { content: JSON.stringify(skills.list(scope)) };
          if (input.action === "load") {
            if (typeof input.name !== "string" || !input.name.trim())
              throw new Error("load requires a method name");
            const loaded = skills.load(scope, input.name);
            const proofSessionID = ensureSession(context.sessionID, scope);
            recordLoadedMethod(scope, proofSessionID, input.name);
            return { content: JSON.stringify(loaded) };
          }
          if (input.action === "promote") {
            if (typeof input.name !== "string" || !input.name.trim())
              throw new Error("promote requires a method name");
            await assertOperatorDecision(
              ctx,
              context,
              `promote-global:${input.name}`,
            );
            const revision = skills.promote(scope, input.name);
            if (typeof ctx.skill?.reload === "function")
              await ctx.skill.reload();
            return { content: JSON.stringify(revision) };
          }
          if (!input.name || !input.description || !input.category)
            throw new Error(
              "propose requires a name, a description and a category",
            );
          if (!input.procedure?.length)
            throw new Error("propose requires the steps of the method");
          // Without named evidence, the method leans on the observations of
          // the session. The check it states still has to be there: a method
          // must say how it is verified.
          const evidence = input.evidence?.length
            ? input.evidence
            : recentObservations(scope, context.sessionID);
          if (!evidence.length)
            throw new Error(
              "a method needs evidence: name the observations that show it works",
            );
          let validation = input.validation ?? [];
          if (!validation.length && input.contains?.trim()) {
            // The method says what it looks for; the check is built against
            // the observation that produced it.
            for (const id of evidence) {
              const found = knowledge.evidence(scope, [id])[0];
              if (
                found?.success &&
                found.output.includes(input.contains.trim())
              ) {
                validation = [
                  { observationId: id, contains: input.contains.trim() },
                ];
                break;
              }
            }
            if (!validation.length)
              throw new Error(
                "no observation of this session shows the text the method looks for",
              );
          }
          if (input.stated?.trim())
            await assertOperatorDecision(
              ctx,
              context,
              `operator-method:${input.name}`,
            );
          const revision = skills.propose(
            scope,
            {
              name: input.name,
              description: input.description,
              category: input.category,
              prerequisites: [],
              procedure: input.procedure,
              validation,
              evidence,
            },
            input.stated,
          );
          if (typeof ctx.skill?.reload === "function") await ctx.skill.reload();
          return { content: JSON.stringify(revision) };
        },
      });

      editor.add({
        name: "cyber_review",
        description:
          "Check a claim against the evidence. A review needs observations, and it is checked by a separate model that cannot use tools and cannot see this session. It never confirms a claim on its own authority.",
        input: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["run", "list"],
              description:
                "Run a review, or list the reviews already recorded.",
            },
            claim: {
              type: "string",
              description: "The claim to check, for action run.",
            },
            observationIds: {
              type: "array",
              items: { type: "string" },
              description:
                "The observations to check the claim against. Without them, the recent observations of the session are used.",
            },
            model: {
              type: "object",
              properties: {
                providerID: { type: "string" },
                id: { type: "string" },
              },
              required: ["providerID", "id"],
              additionalProperties: false,
              description: "The verifier to use, for action run.",
            },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          const scope = await scopeOf(context.sessionID);
          if (input.action === "list")
            return {
              content: JSON.stringify(knowledge.reviews(scope, 50)),
            };
          if (!input.claim?.trim())
            throw new Error("a review needs a claim to check");
          const ids = input.observationIds?.length
            ? input.observationIds
            : recentObservations(scope, context.sessionID);
          if (!ids.length)
            throw new Error(
              "a review needs an observation: there is nothing to check the claim against",
            );
          const observations = knowledge.evidence(scope, ids);
          const candidates = await verifierCandidates(input.model, context.sessionID);
          const digest = hash(
            JSON.stringify({
              scope,
              claim: input.claim,
              observations: observations.map((item: any) => [
                item.id,
                item.hash,
              ]),
            }),
          );
          const proofSessionID = ensureSession(context.sessionID, scope);
          knowledge.recordReview({
            sessionId: proofSessionID,
            scope,
            digest,
            status: "running",
            detail: `Checking a claim against ${observations.length} observation(s)`,
          });
          const prompt = [
            "You are checking a claim against tool observations. You have no tools and you cannot see the session that produced them.",
            "Answer only with one JSON object:",
            '{"verdict":"confirmed|unsupported|contradicted","reason":"one sentence","evidence":["observation ids you actually used"]}',
            "Rules:",
            "- Confirm only what the observations show. A claim about a result that is not in the observations is unsupported.",
            "- Cite only observation ids that are listed below.",
            "- Never state a confidence you cannot justify.",
            "",
            `CLAIM: ${input.claim}`,
            "",
            "OBSERVATIONS:",
            ...observations.map(
              (item: any) =>
                `- ${item.id} tool=${item.tool} success=${item.success}\n  ${String(item.output).slice(0, 1500)}`,
            ),
          ].join("\n");
          try {
            // The same list as the lessons: a provider that refuses a direct
            // call must not decide that the claim goes unchecked.
            let answer: any;
            let lastError: unknown;
            for (const candidate of candidates) {
              try {
                answer = await boundedGenerate(candidate, prompt);
                break;
              } catch (error) {
                lastError = error;
                debug(
                  `review model ${candidate.providerID}/${candidate.id} refused: ${String(error).slice(0, 200)}`,
                );
              }
            }
            if (!answer)
              throw lastError ?? new Error("no model answered the review");
            const verdict = parseVerdict(
              answer?.text ?? "",
              observations.map((o: any) => o.id),
            );
            knowledge.recordReview({
              sessionId: proofSessionID,
              scope,
              digest,
              status: "completed",
              detail: JSON.stringify(verdict),
            });
            return { content: JSON.stringify(verdict) };
          } catch (error) {
            knowledge.recordReview({
              sessionId: proofSessionID,
              scope,
              digest,
              status: "error",
              detail: String(error).slice(0, 300),
            });
            throw error;
          }
        },
      });

      editor.add({
        name: "cyber_memory",
        description:
          "Read the scoped proof store: recent tool evidence, facts learned from it, and the rules the operator stated. A fact needs successful evidence. An operator rule outranks anything learned.",
        input: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: [
                "recent",
                "facts",
                "evidence",
                "operator",
                "remember",
                "forget",
              ],
              description: "What to read or change.",
            },
            limit: {
              type: "integer",
              minimum: 1,
              maximum: 200,
              description: "How many observations to list, for action recent.",
            },
            ids: {
              type: "array",
              items: { type: "string" },
              description: "Observation ids, for action evidence.",
            },
            query: { type: "string", description: "Filter, for action facts." },
            key: {
              type: "string",
              description: "Rule key, for remember and forget.",
            },
            content: {
              type: "string",
              description: "Rule text, for remember.",
            },
            stated: {
              type: "string",
              description: "The operator's own words, for remember and forget.",
            },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          const scope = await scopeOf(context.sessionID);
          const action = String(input.action);
          if (action === "evidence") {
            if (!input.ids?.length) throw new Error("evidence requires ids");
            return {
              content: JSON.stringify(knowledge.evidence(scope, input.ids)),
            };
          }
          if (action === "operator")
            return { content: JSON.stringify(knowledge.operatorModel(scope)) };
          if (action === "remember") {
            if (!input.key || !input.content || !input.stated?.trim())
              throw new Error("remember requires key, content and stated");
            await assertOperatorDecision(
              ctx,
              context,
              `remember-rule:${input.key}`,
            );
            const rule = knowledge.setOperatorRule(scope, {
              key: input.key,
              content: input.content,
            });
            knowledge.audit(scope, "operator.remember", {
              key: rule.key,
              id: rule.id,
              stated: input.stated,
              origin: "agent",
            });
            return { content: JSON.stringify(rule) };
          }
          if (action === "forget") {
            if (!input.key || !input.stated?.trim())
              throw new Error("forget requires key and stated");
            await assertOperatorDecision(
              ctx,
              context,
              `forget-rule:${input.key}`,
            );
            const existing = knowledge
              .operatorModel(scope)
              .find((rule: any) => rule.key === input.key);
            if (!existing)
              throw new Error(`No active operator rule named ${input.key}`);
            knowledge.resolveKnowledge(scope, existing.id, false);
            knowledge.audit(scope, "operator.forget", {
              key: input.key,
              id: existing.id,
              stated: input.stated ?? "",
              origin: "agent",
            });
            return { content: JSON.stringify({ retracted: input.key }) };
          }
          if (action === "facts")
            return {
              content: JSON.stringify(
                knowledge.getKnowledge(scope, input.query),
              ),
            };
          const proofSessionID = ensureSession(context.sessionID, scope);
          const recent = knowledge.observationsForSession(
            proofSessionID,
            scope,
            input.limit ?? 20,
          );
          return {
            content: JSON.stringify(
              recent.map((item: any) => ({
                id: item.id,
                tool: item.tool,
                success: item.success,
                timestamp: item.timestamp,
                output: item.output.slice(0, 600),
              })),
            ),
          };
        },
      });
    });

    debug(`plugin ready scope=${scopeFor(instanceCwd)} cwd=${instanceCwd}`);
    let unloaded = false;
    return () => {
      if (unloaded) return;
      unloaded = true;
      lifecycleController.abort();
      // The stores hold open handles on the SQLite files. A plugin that is
      // unloaded leaves them behind: the state directory cannot be removed
      // and the next load opens a second handle on the same file.
      try {
        workflow.close();
      } catch {
        /* already closed */
      }
      try {
        platform.close();
      } catch {
        /* already closed */
      }
      try {
        knowledge.close();
      } catch {
        /* already closed */
      }
      debug("plugin unloaded");
    };
  },
};
