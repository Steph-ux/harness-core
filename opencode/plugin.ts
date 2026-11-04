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
 * one host stays reachable from the other. The core is host-neutral: this file
 * is the only part that knows about OpenCode.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";

/** Use the official client's discovery and authentication, never a guessed URL. */
async function localApi(args: string[], signal?: AbortSignal): Promise<any> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["api", ...args], {
      stdio: ["ignore", "pipe", "pipe"], signal,
    });
    let output = "";
    const timer = setTimeout(() => child.kill("SIGTERM"), 15000);
    child.stdout.on("data", (chunk) => { output += chunk; });
    // API errors may contain a command or credentials; do not echo stderr.
    child.stderr.resume();
    child.on("error", (error) => { clearTimeout(timer); reject(error); });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error("OpenCode permission API request failed"));
      try { resolve(JSON.parse(output)); }
      catch { reject(new Error("Invalid OpenCode permission API response")); }
    });
  });
}

/** 2.0.26 exposes permission.create over HTTP, but not assert in the plugin. */
export async function assertProcessPermission(
  ctx: any,
  context: any,
  command: string,
  request = localApi,
): Promise<void> {
  const input = {
    sessionID: context.sessionID, agent: context.agent,
    source: { type: "tool", messageID: context.messageID, id: context.id },
    action: "shell", resources: [command],
  };
  if (typeof ctx.permission?.assert === "function") {
    await ctx.permission.assert(input);
    return;
  }
  context.signal?.throwIfAborted();
  const info = await request(["get", "/api/info"], context.signal);
  if (info.pid !== process.pid)
    throw new Error("Permission API belongs to another server; command refused");
  if (typeof ctx.event?.subscribe !== "function")
    throw new Error("Permission event stream unavailable; command refused");

  const id = `per_${randomUUID()}`;
  const controller = new AbortController();
  const signal = context.signal
    ? AbortSignal.any([controller.signal, context.signal]) : controller.signal;
  // Listen before creating the request so a fast human response is not lost.
  const decision = (async () => {
    try {
      for await (const event of ctx.event.subscribe({ signal })) {
        if (event.type === "permission.replied" &&
            event.data?.sessionID === context.sessionID && event.data.requestID === id)
          return { reply: event.data.reply };
      }
      return { error: new Error("Permission event stream closed; command refused") };
    } catch (error) { return { error }; }
  })();
  try {
    const { sessionID, ...payload } = input;
    const response = await request([
      "post", `/api/session/${encodeURIComponent(sessionID)}/permission`,
      "--data", JSON.stringify({ ...payload, id }),
    ], signal);
    const result = response.data ?? response;
    if (result.id !== id) throw new Error("Permission request identity mismatch");
    if (result.effect === "allow") return;
    if (result.effect !== "ask") throw new Error("Shell permission denied");
    const outcome = await decision;
    signal.throwIfAborted();
    if (outcome.error) throw outcome.error;
    if (outcome.reply !== "once" && outcome.reply !== "always")
      throw new Error("Shell permission rejected");
  } finally {
    controller.abort();
    await decision;
  }
}

/** Operator-only transitions require a fresh interactive answer, never a saved allow. */
export async function assertOperatorDecision(
  ctx: any,
  context: any,
  resource: string,
  request = localApi,
): Promise<void> {
  if (typeof ctx.permission?.explicit === "function") {
    const reply = await ctx.permission.explicit({ context, resource });
    if (reply !== "once") throw new Error("An explicit operator decision is required");
    return;
  }
  context.signal?.throwIfAborted();
  const info = await request(["get", "/api/info"], context.signal);
  if (info.pid !== process.pid)
    throw new Error("Permission API belongs to another server; decision refused");
  if (typeof ctx.event?.subscribe !== "function")
    throw new Error("Permission event stream unavailable; decision refused");
  const id = `per_${randomUUID()}`;
  const controller = new AbortController();
  const signal = context.signal
    ? AbortSignal.any([controller.signal, context.signal]) : controller.signal;
  const decision = (async () => {
    try {
      for await (const event of ctx.event.subscribe({ signal })) {
        if (event.type === "permission.replied" &&
            event.data?.sessionID === context.sessionID && event.data.requestID === id)
          return { reply: event.data.reply };
      }
      return { error: new Error("Permission event stream closed; decision refused") };
    } catch (error) { return { error }; }
  })();
  try {
    const response = await request([
      "post", `/api/session/${encodeURIComponent(context.sessionID)}/permission`,
      "--data", JSON.stringify({
        id, agent: context.agent,
        source: { type: "tool", messageID: context.messageID, id: context.id },
        action: "harness_operator", resources: [resource],
      }),
    ], signal);
    const result = response.data ?? response;
    if (result.id !== id) throw new Error("Permission request identity mismatch");
    // The base policy allows unknown actions. That is not a human decision.
    if (result.effect !== "ask")
      throw new Error("harness_operator must be configured as ask; decision refused");
    const outcome = await decision;
    signal.throwIfAborted();
    if (outcome.error) throw outcome.error;
    if (outcome.reply !== "once")
      throw new Error("The operator must approve this transition once");
  } finally {
    controller.abort();
    await decision;
  }
}

/** A command of the host, with its output. */
function runCommand(
  command: string,
  args: string[],
  timeout = 10000,
  env?: Record<string, string>,
  allowFailure = false,
): string {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    timeout,
    env: env ? { ...process.env, ...env } : process.env,
  });
  if (result.error) throw new Error(`${command} failed: ${result.error.message}`);
  if (result.status !== 0 && !allowFailure)
    throw new Error(
      `${command} failed: ${String(result.stderr || result.stdout || "")
        .slice(0, 300)}`,
    );
  return result.stdout ?? "";
}

function commandArguments(value: unknown): string[] {
  if (!Array.isArray(value) || !value.length || value.length > 256 ||
      value.some((part) => typeof part !== "string" || part.length > 32768 || /[\0\r\n]/.test(part)))
    throw new Error("argv must contain 1..256 valid command arguments");
  return value;
}

function waitForTerminalCommand(session: string, marker: string): void {
  for (let attempt = 0; attempt < 300; attempt++) {
    const pane = runCommand("tmux", ["capture-pane", "-p", "-t", session], 10000);
    if(pane.split("\n").some(line=>line.trim()===`${marker}:0`))return;
    spawnSync("sleep", ["0.1"]);
  }
  throw new Error("the evidence command did not finish within 30 seconds");
}

/**
 * The harness core lives outside this file, and this file may be loaded from a
 * copy, a link or a package directory. The core is therefore reached by an
 * absolute path rather than a relative one, so the loader never decides where
 * the proof comes from.
 *
 * The locations are read when the plugin starts, not when it is loaded: a
 * module loaded once can then serve two stores, which is what the tests need.
 */
const coreRoot = () =>
  process.env.HARNESS_CORE?.trim() ||
  path.join(os.homedir(), "hacking", "lab", "harness-core");

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
const OWN_TOOL = /^(?:cyber_tasks|cyber_mission|cyber_approval|cyber_finding|cyber_review|cyber_memory|cyber_method|cyber_lessons|cyber_verification|cyber_report|cyber_capitalise|cyber_cleanup)$/;

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
        (id: unknown): id is string => typeof id === "string" && allowed.includes(id),
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
    if (typeof result.output.output === "string") parts.push(result.output.output);
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
  if(metadata.evidenceSuccess===false)return false;
  if(event.tool==="cyber_process")return metadata.evidenceSuccess===true;
  if (metadata.status === "error" || metadata.status === "failed") return false;
  if (typeof metadata.exit === "number" && metadata.exit !== 0) return false;
  const output = event.result?.output;
  if (output && typeof output === "object")
    if (output.status === "error" || output.status === "failed") return false;
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
/**
 * The windows the display shows.
 *
 * The titles are read one by one and paired with the ids, because a title
 * search in the display tool does not accept a partial name.
 */
function listWindows(display?: string): { id: string; title: string }[] {
  const env = display ? { DISPLAY: display } : undefined;
  const ids = runCommand(
    "xdotool",
    ["search", "--onlyvisible", "--name", "."],
    10000,
    env,
    true,
  )
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const windows: { id: string; title: string }[] = [];
  for (const id of ids) {
    let title = "";
    try {
      title = runCommand("xdotool", ["getwindowname", id], 5000, env).trim();
    } catch {
      continue;
    }
    windows.push({ id, title });
  }
  return windows;
}

/** The id of the root window: the desktop itself. */
function rootWindowId(display?: string): string {
  const out = runCommand("xwininfo", ["-root"], 10000, display ? { DISPLAY: display } : undefined);
  const match = /Window id:\s*(0x[0-9a-f]+)/i.exec(out);
  return match ? match[1] : "";
}

/** The size of a window, as the display tool reports it. */
function windowGeometry(id: string, display?: string): { width: number; height: number } {
  const out = runCommand(
    "xwininfo",
    ["-id", id],
    10000,
    display ? { DISPLAY: display } : undefined,
  );
  const width = Number(/Width:\s*(\d+)/.exec(out)?.[1]);
  const height = Number(/Height:\s*(\d+)/.exec(out)?.[1]);
  return { width, height };
}

/**
 * The picture of one window.
 *
 * The capture is taken of that window and of nothing else, so the desktop
 * never appears in it.
 */
function captureWindow(
  id: string,
  dest: string,
  display?: string,
): { width: number; height: number; bytes: number } {
  runCommand("import", ["-window", id, dest], 20000, display ? { DISPLAY: display } : undefined);
  const stat = fs.statSync(dest);
  if (!stat.isFile() || stat.size < 32)
    throw new Error("the capture file is empty");
  const size = runCommand("identify", ["-format", "%w %h", dest], 10000).trim();
  const [width, height] = size.split(" ").map((value) => Number(value));
  return { width, height, bytes: stat.size };
}

/**
 * The private display of the harness.
 *
 * The harness renders its terminal on a display of its own, the way a browser
 * of a test runner opens its own window instead of taking over the one of the
 * operator. Nothing appears on the desktop of the operator, and the terminal of
 * the operator is never touched.
 */
let privateDisplay: { number: number; pid: number } | undefined;

function freeDisplay(): number {
  for (let number = 99; number >= 90; number -= 1) {
    if (
      !fs.existsSync(`/tmp/.X${number}-lock`) &&
      !fs.existsSync(`/tmp/.X11-unix/X${number}`)
    )
      return number;
  }
  throw new Error("no free display for the evidence terminal");
}

function ensurePrivateDisplay(): string {
  if (privateDisplay) return `:${privateDisplay.number}`;
  const number = freeDisplay();
  const child = spawn(
    "Xvfb",
    [`:${number}`, "-screen", "0", "1280x800x24", "-nolisten", "tcp"],
    { detached: true, stdio: "ignore" },
  );
  child.unref();
  privateDisplay = { number, pid: child.pid ?? 0 };
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    if (fs.existsSync(`/tmp/.X11-unix/X${number}`)) return `:${number}`;
    spawnSync("sleep", ["0.2"]);
  }
  throw new Error("the private display of the harness did not start");
}

function stopPrivateDisplay(): void {
  // The terminal of the harness goes with its display. The session is the
  // harness's own, and the display it lived in is gone.
  try {
    spawnSync("tmux", ["kill-session", "-t", EVIDENCE_SESSION], {
      encoding: "utf8",
    });
  } catch {
    /* The session is already gone. */
  }
  if (!privateDisplay) return;
  try {
    process.kill(privateDisplay.pid, "SIGTERM");
  } catch {
    /* The display is already gone. */
  }
  privateDisplay = undefined;
}

/** The title of the window the harness owns, on its own display. */
const EVIDENCE_TITLE = "harness-evidence";

/** The session of the terminal the harness owns. */
const EVIDENCE_SESSION = "harness-evidence";

/** A path, quoted for the shell of the evidence terminal. */
function shellQuote(value: string): string {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

/**
 * The window of the harness, on its private display.
 *
 * It is a real terminal rendering of a real execution, and it lives where the
 * operator cannot see it.
 */
function ensureEvidenceWindow(
  display: string,
  session: string,
): { id: string; title: string } {
  const found = listWindows(display).find(
    (window) => window.title === EVIDENCE_TITLE,
  );
  if (found) return found;
  const child = spawn(
    "xterm",
    [
      "-T",
      EVIDENCE_TITLE,
      "-geometry",
      "120x32",
      "-e",
      "tmux",
      "attach-session",
      "-t",
      session,
    ],
    { detached: true, stdio: "ignore", env: { ...process.env, DISPLAY: display } },
  );
  child.unref();
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    const window = listWindows(display).find(
      (candidate) => candidate.title === EVIDENCE_TITLE,
    );
    if (window) return window;
    spawnSync("sleep", ["0.3"]);
  }
  throw new Error("the terminal of the harness did not open");
}

export default {
  id: "harness-core.proof",
  async setup(ctx: any) {
    const { KnowledgeStore } = await import(path.join(coreRoot(), "src", "store.ts"));
    const { TaskStore } = await import(path.join(coreRoot(), "src", "tasks.ts"));
    const { observationId } = await import(
      path.join(coreRoot(), "src", "observation-id.ts"),
    );
    const { scopeFor, hash } = await import(path.join(coreRoot(), "src", "util.ts"));
    const { operatorContext } = await import(path.join(coreRoot(), "src", "context.ts"));
    const {
      applyLessonProposal,
      lessonPrompt,
      parseLessonProposal,
    } = await import(path.join(coreRoot(), "src", "lessons.ts"));
    const { capsule, capsuleText, closingGate, GATE_MARKER } = await import(
      path.join(coreRoot(), "src", "capsule.ts"),
    );
    const { routeFor, requestText, ROUTER_MARKER } = await import(
      path.join(coreRoot(), "src", "routing.ts"),
    );
    const {
      DEFAULT_DEADLINE_MS,
      MAX_DEADLINE_MS,
      ProcessRegistry,
      processStatus, verifiedOutcome, publicProcess,
      readTrace,
      spawnTraced,
      stopProcess,
    } = await import(path.join(coreRoot(), "src", "process.ts"));
    const { SkillUpdater } = await import(
      path.join(coreRoot(), "src", "skills.ts"),
    );
    const { PlatformStore } = await import(
      path.join(coreRoot(), "src", "platform-store.ts"),
    );
    const {
      assertNotRoot,
      captureDestination,
      captureName,
      isFramed,
      selectWindow,
      selectWindowById,
    } = await import(path.join(coreRoot(), "src", "capture.ts"));
    const { DEFAULT_CONFIG } = await import(path.join(coreRoot(), "src", "types.ts"));
    // The location of the shared store is the core's, not the plugin's.
    const { stateRoot: sharedStateRoot } = await import(
      path.join(coreRoot(), "src", "paths.ts"),
    );
    stateDir = sharedStateRoot;

    fs.mkdirSync(stateRoot(), { recursive: true, mode: 0o700 });
    const knowledge = new KnowledgeStore(path.join(stateRoot(), "knowledge.sqlite"));
    const taskStore = new TaskStore(stateRoot());
    const skills = new SkillUpdater(stateRoot(), knowledge, DEFAULT_CONFIG);
    // The engagement ledger. It is the same file the Pi harness writes to, so
    // both hosts share one engagement state.
    const platform = new PlatformStore(
      path.join(stateRoot(), "platform.sqlite"),
      knowledge,
    );
    // The commands the harness owns, and the trace they leave.
    const processes = new ProcessRegistry(stateRoot());

    const instanceCwd: string = ctx?.location?.directory ?? process.cwd();
    const scopeCache = new Map<string, string>();
    const sessionCwd = new Map<string, string>();
    const registered = new Map<string, string>();
    // The skills the current turn routed to, per session. A finding for that
    // request needs the method loaded, not merely named in the prompt.
    const routedRequired = new Map<string, string[]>();
    const requestBySession=new Map<string,string>();
    const lifecycleController = new AbortController();
    // The model of the request in flight, used by the independent verifier.
    let liveModel: { providerID: string; id: string } | undefined;
    // The sessions whose lessons were already extracted, and the ones being
    // extracted now.
    const lessonChecked=new Map<string,number>();
    let lessonRunning = false;

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
    ): Promise<{
      facts: number;
      skills: number;
      rejected: string[];
    }> {
      const observations = knowledge.observationsForSession(
        sessionID,
        scope,
        100,
      );
      const digest = hash(
        JSON.stringify({
          scope,
          sessionID,
          observations: observations.map((item: any) => [item.id,item.hash]),
        }),
      );
      if (!observations.length) {
        // Nothing to read. It is written down anyway, so the session is not
        // read again and again.
        knowledge.recordReview({
          sessionId: sessionID,
          scope,
          digest,
          status: "completed",
          detail: JSON.stringify({ facts: 0, skills: 0, rejected: [], empty: true }),
        });
        knowledge.audit(scope, "lessons.extracted", { sessionID, digest, empty: true });
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
      for (const candidate of await verifierCandidates()) {
        try {
          answer = await boundedGenerate(candidate,prompt);
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
      const reviewed=new Set(knowledge.audits(scope,"lessons.extracted",200).flatMap((row:any)=>{try{return [JSON.parse(row.detail).digest];}catch{return [];}}));
      const snapshotDigest=(id:string)=>hash(JSON.stringify({scope,sessionID:id,observations:knowledge.observationsForSession(id,scope,100).map((o:any)=>[o.id,o.hash])}));
      // A session is read by a later one. "Later" is a matter of time, not of
      // status: a host that never marked a session closed leaves it active
      // forever, and its work stays unread.
      const cutoff = Date.now() - LESSON_IDLE_MS;
      return knowledge
        .sessionsForScope(scope, 100)
        .filter(
          (row: any) =>
            row.id !== current &&
            !reviewed.has(snapshotDigest(row.id)) &&
            Date.now()-(lessonChecked.get(row.id)??0)>60000 &&
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
    try {
      const archived = skills.archiveUnused(
        scopeFor(instanceCwd),
        knowledge.audits(scopeFor(instanceCwd), "skills.exposure", 200),
      );
      if (archived.length) debug(`archived learned methods: ${archived.join(", ")}`);
    } catch (error) {
      debug(`archive failed: ${String(error)}`);
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
        throw new Error("Session directory unavailable; scoped operation refused");
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
      requested?: { providerID: string; id: string },
    ): Promise<{ providerID: string; id: string }[]> {
      const out: { providerID: string; id: string }[] = [];
      const add = (model?: { providerID?: string; id?: string } | null) => {
        if (!model?.providerID || !model?.id) return;
        if (out.some((row) => row.providerID === model.providerID && row.id === model.id)) return;
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
          return fs.readFileSync(path.join(stateRoot(), "verifier"), "utf8").trim();
        } catch {
          return "";
        }
      })();
      const allowed=new Set((process.env.HARNESS_VERIFIER_PROVIDERS??"").split(",").map(s=>s.trim()).filter(Boolean));
      if(pinned){const cut=pinned.indexOf("/");if(cut<1||cut===pinned.length-1)throw new Error("Invalid pinned verifier");const model={providerID:pinned.slice(0,cut),id:pinned.slice(cut+1)};if(requested&&(requested.providerID!==model.providerID||requested.id!==model.id))throw new Error("Requested model conflicts with pinned verifier");return [model];}
      if(requested){if(requested.providerID!==liveModel?.providerID&&!allowed.has(requested.providerID))throw new Error("Verifier provider is outside the operator policy");return [requested];}
      if(liveModel&&!["opencode","opencode-go"].includes(liveModel.providerID))add(liveModel);
      if(allowed.size){const models=await ctx.model.list();for(const model of Array.isArray(models)?models:models?.data??[])if(allowed.has(model.providerID))add(model);}
      // An empty list is a refusal with a reason, not a silent no-op: the
      // caller reports it instead of recording a review that never ran.
      if (!out.length)
        throw new Error(
          "no model can serve the harness: the OpenCode free tier refuses the requests the harness makes, and no other provider is configured",
        );
      return out.slice(0, 3);
    }

    // The pinned API accepts model/prompt only. No server-side token cap is claimed.
    async function boundedGenerate(model:any,prompt:string){
      const controller=new AbortController(),signal=AbortSignal.any([controller.signal,lifecycleController.signal]);let timer:any;
      try{const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new Error("Verifier deadline exceeded"));},30000);});const value:any=await Promise.race([ctx.generate.text({model,prompt},{signal}),deadline]);if(typeof value?.text!=="string"||value.text.length>24000)throw new Error("Invalid or oversized verifier output");return value;}finally{clearTimeout(timer);controller.abort();}
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
    function ensureSession(sessionID: string, scope: string, status: "active" | "completed" = "active"): string {
      const key = `${sessionID}\0${scope}`;
      const known = registered.get(key);
      if (known) {
        knowledge.upsertSession({ id: known, scope, cwd: sessionCwd.get(sessionID) ?? instanceCwd, status, updatedAt: new Date().toISOString() });
        return known;
      }
      let storedID = sessionID;
      try {
        knowledge.upsertSession({ id: storedID, scope, cwd: sessionCwd.get(sessionID) ?? instanceCwd, status, updatedAt: new Date().toISOString() });
      } catch (error) {
        if (!String(error).includes("scope collision")) throw error;
        storedID = `${sessionID}:${scope.slice(-24)}`;
        knowledge.upsertSession({ id: storedID, scope, cwd: sessionCwd.get(sessionID) ?? instanceCwd, status, updatedAt: new Date().toISOString() });
      }
      registered.set(key, storedID);
      return storedID;
    }

    if (typeof ctx.event?.subscribe === "function") void (async () => {
      try {
        for await (const event of ctx.event.subscribe({ signal: lifecycleController.signal })) {
          const sessionID = event?.data?.sessionID;
          if (!sessionID || (event.type !== "session.idle" && event.type !== "session.status")) continue;
          const status = event.type === "session.idle" || event.data?.status?.type === "idle"
            ? "completed" : event.data?.status?.type === "busy" ? "active" : undefined;
          if (!status) continue;
          try { ensureSession(sessionID, await scopeOf(sessionID), status); }
          catch (error) { debug(`session lifecycle failed for ${sessionID}: ${String(error)}`); }
        }
      } catch (error) {
        if (!lifecycleController.signal.aborted) debug(`session event stream failed: ${String(error)}`);
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
    await ctx.session.hook("prompt",async(event:any)=>{const text=requestText(event);if(text)requestBySession.set(event.sessionID,text);});
    await ctx.session.hook("context", async (event: any) => {
      if (!Array.isArray(event.system)) return;
      const scope = await scopeOf(event.sessionID);
      // Mandatory authority is independent of optional continuity storage.
      const authority = operatorContext(knowledge, scope, budget);
      if (authority.block && !event.system.some((block: any) =>
        typeof block?.text === "string" && block.text.startsWith(OPERATOR_MARKER))) {
        event.system.splice(1, 0, { type: "text", text: authority.block });
        knowledge.audit(scope, "context.injected", {
          sessionID: event.sessionID, agent: event.agent,
          rules: authority.entries.map((entry: any) => entry.key), chars: authority.block.length,
        });
      }
      try {
        if (event?.model?.providerID && event?.model?.id) {
          liveModel = {
            providerID: event.model.providerID,
            id: event.model.id,
          };
        }
        if (!Array.isArray(event.system)) return;
        // The state of the work, for a session that resumes. It carries the
        // running step list and the observations that close it, so a resumed
        // session finds the exact state instead of a narration about it.
        const proofSessionID = ensureSession(event.sessionID, scope);
        const mission = platform.active(scope);
        const state = capsule(taskStore, knowledge, scope, proofSessionID, {
          mission: mission ? {
            id: mission.id, title: mission.title, boundaries: mission.boundaries,
            state: mission.state,
            stages: mission.nodes.map(({ id, state }: any) => ({ id, state })),
          } : undefined,
          approvals: platform.approvals(scope, "pending", 20).map(({ id, action, justification }: any) => ({ id, action: action.slice(0, 200), justification: justification.slice(0, 400) })),
          processes: processes
            .withStatus(scope).filter(entry=>["running","unknown"].includes(entry.status))
            .map((entry) => ({
              id: entry.id,
              command: entry.command.slice(0, 500),
              status: entry.status,
            })),
          references: platform.memoryUses(scope, event.sessionID).slice(-20).map((entry: any) => ({
            kind: entry.kind, id: entry.referenceId, hash: entry.hash,
          })),
        });
        const continuity = capsuleText(state);

        // The block is injected once per request. If the host ever hands over
        // a prompt that already carries it, it is left alone.
        const carried = event.system.filter(
          (block: any) =>
            typeof block?.text === "string" &&
            block.text.startsWith(OPERATOR_MARKER),
        ).length;
        if (carried) {
          debug(`context block already present (carried})`);
        } else {
          const { entries, block } = operatorContext(knowledge, scope, budget);
          if (block) {
            // The block goes right after the host prompt, so it precedes every
            // other block the harness, the skills or the memory plugin add.
            event.system.splice(1, 0, { type: "text", text: block });
            knowledge.audit(scope, "context.injected", {
              sessionID: event.sessionID,
              agent: event.agent,
              rules: entries.map((entry) => entry.key),
              chars: block.length,
            });
          }
        }

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
        const routing = routeFor(requestText(event)||requestBySession.get(event.sessionID)||"");
        // HARNESS_ROUTER=off is the control arm of the A/B: the same request
        // without the map, and without the load the map would require.
        const routerOff = (process.env.HARNESS_ROUTER ?? "").toLowerCase() === "off";
        // The methods this turn must have loaded before a finding is recorded.
        routedRequired.set(event.sessionID, routerOff ? [] : routing.required);
        if (
          !routerOff &&
          !event.system.some(
            (block: any) =>
              typeof block?.text === "string" &&
              block.text.startsWith(ROUTER_MARKER),
          )
        ) {
          const at = event.system.findIndex((block: any) =>
            typeof block?.text === "string" && block.text.startsWith(OPERATOR_MARKER),
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

        // The closing gate. It answers "are we done?" from the state, not
        // from the model's story: whatever still stands is named, and a plan
        // is not a result.
        const gate = closingGate(state);
        if (
          gate &&
          !event.system.some(
            (block: any) =>
              typeof block?.text === "string" && block.text.startsWith(GATE_MARKER),
          )
        ) {
          const anchor = event.system.findIndex(
            (block: any) =>
              typeof block?.text === "string" &&
              (block.text.startsWith("Continuity.") ||
                block.text.startsWith(ROUTER_MARKER)),
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

        // What the learned methods offered this turn. It is what tells the
        // curator which methods are still used.
        const learned = skills
          .active(scope)
          .map((entry) => ({ name: entry.revision.name, file: entry.filePath }));
        if (learned.length)
          knowledge.audit(scope, "skills.exposure", {
            sessionID: event.sessionID,
            skills: learned,
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
                  lessonChecked.set(sessionID,Date.now());
                  try {
                    const outcome = await extractLessons(scope, sessionID);
                    debug(
                      `lessons ${sessionID}: ${outcome.facts} faits, ${outcome.skills} methodes`,
                    );
                  } catch (error) {
                    // A failed extraction leaves a trace: a session that was
                    // not read must not look like one that taught nothing.
                    try {
                      knowledge.audit(scope, "lessons.failed", {
                        sessionID,
                        error: String(error).slice(0, 300),
                      });
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
        event.system.push({ type: "text", text: "Harness continuity unavailable. Do not infer task, approval, or process state; read the scoped stores before acting." });
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
      const scope = scopeFor(instanceCwd);
      const active = skills.active(scope);
      const wanted = new Set(active.map((entry) => entry.revision.name));
      for (const existing of editor.list()) {
        const id = String(existing.id ?? "");
        if (id.startsWith(LEARNED_PREFIX) && !wanted.has(id.slice(LEARNED_PREFIX.length)))
          editor.remove(id);
      }
      for (const entry of active) {
        const loaded = skills.load(scope, entry.revision.name);
        editor.add({
          id: `${LEARNED_PREFIX}${entry.revision.name}`,
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
        debug(
          `observed ${observation.id} tool=${observation.tool} success=${observation.success} scope=${scope}`,
        );
      } catch (error) {
        debug(`observation failed: ${String(error)}`);
        try {
          knowledge.audit(scopeCache.get(event.sessionID) ?? "project-unknown", "observation.error", {
            tool: event.tool,
            error: String(error).slice(0, 300),
          });
        } catch {
          /* The audit must not raise either. */
        }
      }
    });

    await ctx.tool.transform((editor: any) => {
      editor.add({name:"cyber_verification",description:"Bind fresh reproduction and negative-control observations from this independent session to the finding revision.",input:{type:"object",properties:{action:{type:"string",enum:["attest"]},findingId:{type:"string"},checks:{type:"array",items:{type:"object",properties:{observationId:{type:"string"},contains:{type:"string"},purpose:{type:"string",enum:["reproduction","positive-control","negative-control"]}},required:["observationId","contains","purpose"],additionalProperties:false}}},required:["action","findingId","checks"],additionalProperties:false},execute:async(input:any,context:any)=>{
        if(input.action!=="attest")throw new Error("Invalid verification action");
        const scope=await scopeOf(context.sessionID),sessionId=ensureSession(context.sessionID,scope),payload=platform.verificationPayload(scope,input.findingId,sessionId,input.checks);
        return{content:JSON.stringify(knowledge.recordObservation({id:observationId(context.sessionID,`${context.id}:verification`),sessionId,scope,tool:"harness:verification",input:{findingId:input.findingId,runId:payload.runId},output:JSON.stringify(payload),success:true,timestamp:new Date().toISOString()}))};
      }});

      editor.add({
        name: "cyber_tasks",
        description:
          "Keep the running step list. A task closes only against a successful observation. A blocked task must give its reason. Use the cyber_memory action recent to obtain the observation ids that prove the work.",
        input: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["add", "start", "complete", "block", "remove", "list", "review"],
              description: "What to do with the task list.",
            },
            title: { type: "string", description: "Task title, for add." },
            id: {
              type: "string",
              description: "Task id, for start, complete, block and remove.",
            },
            reason: { type: "string", description: "Why the task is blocked." },
            evidence: {
              type: "array",
              items: { type: "string" },
              description: "Observation ids that close the task.",
            },
            dependsOn: {
              type: "array",
              items: { type: "string" },
              description: "Tasks that must close first.",
            },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          const scope = await scopeOf(context.sessionID);
          const action = String(input.action);
          if (action === "add") {
            if (!input.title) throw new Error("add requires a title");
            return {
              content: JSON.stringify(
                taskStore.add(scope, {
                  title: input.title,
                  dependsOn: input.dependsOn,
                }),
              ),
            };
          }
          if (action === "list") {
            return {
              content: JSON.stringify({
                tasks: taskStore.list(scope),
                delegable: taskStore.delegable(scope),
              }),
            };
          }
          if (action === "review") {
            const packet = taskStore.review(scope);
            const ids = [...new Set(packet.closed.flatMap((entry: any) => entry.evidence))];
            return {
              content: JSON.stringify({
                ...packet,
                observations: knowledge.evidence(scope, ids).map((item: any) => ({
                  id: item.id,
                  tool: item.tool,
                  success: item.success,
                  output: item.output.slice(0, 2000),
                })),
              }),
            };
          }
          if (!input.id) throw new Error(`${action} requires a task id`);
          if (action === "start")
            return { content: JSON.stringify(taskStore.start(scope, input.id)) };
          if (action === "remove") {
            taskStore.remove(scope, input.id);
            return {
              content: JSON.stringify({
                removed: input.id,
                tasks: taskStore.list(scope),
              }),
            };
          }
          if (action === "block") {
            if (!input.reason) throw new Error("a blocked task requires a reason");
            return {
              content: JSON.stringify(taskStore.block(scope, input.id, input.reason)),
            };
          }
          if (!input.evidence?.length)
            throw new Error(
              "a completed task requires the observation ids that prove it",
            );
          const proven = knowledge.evidence(scope, input.evidence);
          if (!proven.some((item: any) => item.success))
            throw new Error("task evidence must include a successful observation");
          return {
            content: JSON.stringify(
              taskStore.complete(scope, input.id, input.evidence),
            ),
          };
        },
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
            node: {
              type: "string",
              description: "The stage to take or to close, for claim and finish.",
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
              throw new Error("an engagement needs a title and explicit boundaries");
            return {
              content: JSON.stringify(
                platform.createMission(scope, input.title, input.boundaries),
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
          if (input.action === "checkpoints")
            return { content: JSON.stringify(platform.checkpoints(scope, id)) };
          if (input.action === "resume")
            return { content: JSON.stringify(platform.resume(scope, id)) };
          if (!input.node) throw new Error("the stage is required");
          if (input.action === "claim") {
            if (!input.owner) throw new Error("the owner of the stage is required");
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
          if (!input.lease) throw new Error("the lease is required to close a stage");
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
            if (!input.missionId || !input.requestedAction || !input.justification)
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
            ctx, context, `approval:${input.id}:${input.approve ? "approve" : "deny"}`,
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
                platform.ingest(scope, input.sourceId, input.uri, input.title, input.body),
              ),
            };
          }
          if (input.action === "list") return { content: JSON.stringify(platform.sources(scope)) };
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
            id: { type: "string", description: "The finding id, for get, verify and reject." },
            missionId: {
              type: "string",
              description: "The mission the finding belongs to, for create.",
            },
            title: { type: "string", description: "The title of the finding, for create." },
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
                    enum: ["reproduction", "positive-control", "negative-control"],
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
              enum: ["all", "mission", "evidence", "finding", "source", "knowledge"],
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
            if (!input.missionId) throw new Error("a finding belongs to a mission");
            if (!input.title || !input.severity || !input.description)
              throw new Error("a finding needs a title, a severity and a description");
            if (!input.limitations?.trim())
              throw new Error("a finding states what it does not show");
            // The method that covers this request must have been loaded in the
            // session: recording a finding is where the harness refuses to take
            // the model's memory for a procedure. The host hands the context
            // hook no request text, so the finding's own content is routed too.
            const routed = routeFor(
              [input.title, input.description, input.limitations]
                .filter((value: unknown) => typeof value === "string")
                .join("\n"),
            );
            const required = [
              ...new Set([
                ...(routedRequired.get(context.sessionID) ?? []),
                ...routed.required,
              ]),
            ];
            if (required.length) {
              const proofSessionID = ensureSession(context.sessionID, scope);
              const seen = knowledge.observationsForSession(
                proofSessionID,
                scope,
                200,
              );
              const loaded = new Set(
                seen
                  .filter((row: any) => row.tool === "skill"&&row.success)
                  .map((row: any) => String(row.input?.id ?? "")),
              );
              const missing = required.filter((id) => !loaded.has(id));
              // A row may name two methods that cover the same request; one of
              // them loaded is what the ledger needs.
              if (missing.length === required.length)
                throw new Error(
                  `The method ${required.join(" or ")} covers this request and none of them was loaded in this session. Call the skill tool with id ${required[0]} first, then record the finding from what it had you observe.`,
                );
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
                platform.search(scope, input.kind ?? "all", input.query ?? "", 20),
              ),
            };
          if (input.action === "evidence") {
            if (!input.ids?.length) throw new Error("the observation ids are required");
            platform.indexEvidence(scope, input.ids);
            return { content: JSON.stringify(platform.evidence(scope, input.ids)) };
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
          return { content: JSON.stringify(platform.rejectFinding(scope, input.id)) };
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
              enum: ["run", "list", "read", "stop"],
              description: "Run a command, list them, read a trace, or stop one.",
            },
            argv: {
              type: "array",
              items: { type: "string" },
              description: "The executable and its arguments. Shell syntax is intentionally not accepted.",
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
              description: "How many lines of the trace to read, for action read.",
            },
          },
          required: ["action"],
          additionalProperties: false,
        },
        execute: async (input: any, context: any) => {
          const scope = await scopeOf(context.sessionID);
          if (!["run", "list", "read", "stop"].includes(input.action))
            throw new Error("Invalid process action");
          if (input.action === "list")
            return {content:JSON.stringify(processes.withStatus(scope).map(publicProcess)),metadata:{evidenceSuccess:false}};
          if (input.action === "run") {
            const argv = commandArguments(input.argv);
            const command = argv.map(shellQuote).join(" ");
            const seconds = input.timeout ?? DEFAULT_DEADLINE_MS / 1000;
            if (!Number.isFinite(seconds) || seconds <= 0 || seconds * 1000 > MAX_DEADLINE_MS)
              throw new Error("Invalid timeout (0..600 seconds)");
            await assertProcessPermission(ctx, context, command);
            context.signal?.throwIfAborted();
            const session = await ctx.session.get({ sessionID: context.sessionID });
            const cwd = sessionDirectory(session) ?? instanceCwd;
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
              metadata:{evidenceSuccess:false},
            };
          }
          if (!input.id) throw new Error("a command id is required");
          if (input.action === "stop") {
            const record = processes.get(scope, input.id);
            await assertProcessPermission(ctx, context, `kill -TERM -- -${record.pid}`);
            const stopped = processes.stop(scope, input.id);
            return { content: JSON.stringify(publicProcess(stopped)),metadata:{evidenceSuccess:false} };
          }
          const record=processes.get(scope,input.id),outcome=verifiedOutcome(record);
          const {runKey,...result}=outcome??{} as any;
          return {content:JSON.stringify({...publicProcess(record),...result,status:outcome?.status??processStatus(record),trace:readTrace(record.logPath,input.tail??200)}),metadata:{evidenceSuccess:outcome?.status==="succeeded"&&outcome.exitCode===0}};

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
              description: "Extract the lessons of a session, or list what is waiting.",
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
            throw new Error("lessons are extracted only from a previous inactive session");
          const target = knowledge.sessionsForScope(scope, 100)
            .find((row: any) => row.id === sessionID);
          if (!target || target.status === "active")
            throw new Error("lessons are extracted only from an inactive scoped session");
          const outcome = await extractLessons(scope, sessionID);
          return { content: JSON.stringify(outcome) };
        },
      });

      editor.add({
        name: "cyber_capture",
        description:
          "Take a visual attestation of a window. The capture shows one window, never the desktop, and it is linked to the observation it attests.",
        input: {
          type: "object",
          properties: {
            action: {
              type: "string",
              enum: ["windows", "shot", "evidence"],
              description:
                "List the windows of the display, capture one of them, or capture the terminal of the harness.",
            },
            processId:{type:"string",description:"The finished process whose verified recorded trace is rendered. No command is rerun."},
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
              throw new Error("an evidence capture needs the observation it attests");
            const proof=knowledge.evidence(scope,[input.observationId])[0];
            if(!input.processId||proof.tool!=="cyber_process"||proof.input?.action!=="read"||proof.input?.id!==input.processId)throw new Error("Capture requires the observation of this process read");
            const record=processes.get(scope,input.processId),outcome=verifiedOutcome(record);
            if(!outcome||outcome.status==="running")throw new Error("A capture requires a finished, verified trace");
            const rendered=path.join(stateRoot(),"captures",`trace-${randomUUID()}.txt`);fs.mkdirSync(path.dirname(rendered),{recursive:true,mode:0o700});
            fs.writeFileSync(rendered,`RECORDED TRACE / ${record.id} / ${outcome.status} / ${outcome.finishedAt}\n${readTrace(record.logPath,2000)}`.replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\)/g,"").replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,"").replace(/[\x00-\x08\x0b-\x1f\x7f]/g,""),{mode:0o600});
            const line=`cat -- ${shellQuote(rendered)}`;
            const display = ensurePrivateDisplay();
            const session = EVIDENCE_SESSION;
            const alive =
              spawnSync("tmux", ["has-session", "-t", session]).status === 0;
            if (!alive)
              spawnSync("tmux", [
                "new-session",
                "-d",
                "-s",
                session,
                "-x",
                "120",
                "-y",
                "32",
                "-c",
                sessionCwd.get(context.sessionID) ?? instanceCwd,
              ]);
            const window = ensureEvidenceWindow(display, session);
            // The attestation shows where the command ran.
            runCommand(
              "tmux",
              ["send-keys", "-t", session, `cd ${shellQuote(sessionCwd.get(context.sessionID) ?? instanceCwd)}`, "C-m"],
              10000,
            );
            const marker = `__HARNESS_DONE_${randomUUID().replaceAll("-", "")}__`;
            runCommand(
              "tmux",
              ["send-keys", "-t", session, `${line}; printf '\\n${marker}:%s\\n' "$?"`, "C-m"],
              10000,
            );
            waitForTerminalCommand(session, marker);
            const geometry = windowGeometry(window.id, display);
            const name = captureName(
              input.observationId,
              `${input.label ?? "evidence"}-${randomUUID().slice(0, 8)}`,
            );
            const root = path.join(stateRoot(), "captures");
            fs.mkdirSync(root, { recursive: true, mode: 0o700 });
            const dest = captureDestination(root, name);
            const capture = captureWindow(window.id, dest, display);
            if (!isFramed(capture, geometry))
              throw new Error(
                "the capture does not match the window it claims to show, so it is refused",
              );
            const link = {
              kind:"rendered-trace",processId:input.processId,traceHash:outcome.traceHash,
              observationId: input.observationId ?? "",
              path: dest,
              window: window.id,
              title: window.title,
              width: capture.width,
              height: capture.height,
              bytes: capture.bytes,
              sha256: createHash("sha256").update(fs.readFileSync(dest)).digest("hex"),
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
          const root = path.join(stateRoot(), "captures");
          fs.mkdirSync(root, { recursive: true, mode: 0o700 });
          const dest = captureDestination(root, name);
          const capture = captureWindow(target.id, dest);
          if (!isFramed(capture, geometry))
            throw new Error(
              "the capture does not match the window it claims to show, so it is refused",
            );
          const link = {
            observationId: input.observationId ?? "",
            path: dest,
            window: target.id,
            title: target.title,
            width: capture.width,
            height: capture.height,
            bytes: capture.bytes,
            sha256: createHash("sha256").update(fs.readFileSync(dest)).digest("hex"),
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
              enum: ["propose", "list", "load", "promote"],
              description:
                "Propose a method, list them, read one, or share one with every project.",
            },
            name: {
              type: "string",
              description: "The name of the method, for propose, load and promote.",
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
              description: "The observation ids that support the method, for propose.",
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
          if (input.action === "list")
            return { content: JSON.stringify(skills.list(scope)) };
          if (input.action === "load") {
            if (!input.name) throw new Error("load requires a method name");
            const loaded = skills.load(scope, input.name);
            return { content: JSON.stringify(loaded) };
          }
          if (input.action === "promote") {
            await assertOperatorDecision(ctx,context,`promote-global:${input.name}`);
            if (!input.name) throw new Error("promote requires a method name");
            const revision = skills.promote(scope, input.name);
            if (typeof ctx.skill?.reload === "function") await ctx.skill.reload();
            return { content: JSON.stringify(revision) };
          }
          if (!input.name || !input.description || !input.category)
            throw new Error("propose requires a name, a description and a category");
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
              if (found?.success && found.output.includes(input.contains.trim())) {
                validation = [{ observationId: id, contains: input.contains.trim() }];
                break;
              }
            }
            if (!validation.length)
              throw new Error(
                "no observation of this session shows the text the method looks for",
              );
          }
          if (input.stated?.trim())
            await assertOperatorDecision(ctx, context, `operator-method:${input.name}`);
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
              description: "Run a review, or list the reviews already recorded.",
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
          const candidates = await verifierCandidates(input.model);
          const digest = hash(
            JSON.stringify({
              scope,
              claim: input.claim,
              observations: observations.map((item: any) => [item.id,item.hash]),
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
                answer = await boundedGenerate(candidate,prompt);
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
            const verdict = parseVerdict(answer?.text ?? "", observations.map((o: any) => o.id));
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
              enum: ["recent", "facts", "evidence", "operator", "remember", "forget"],
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
            key: { type: "string", description: "Rule key, for remember and forget." },
            content: { type: "string", description: "Rule text, for remember." },
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
            return { content: JSON.stringify(knowledge.evidence(scope, input.ids)) };
          }
          if (action === "operator")
            return { content: JSON.stringify(knowledge.operatorModel(scope)) };
          if (action === "remember") {
            if (!input.key || !input.content || !input.stated?.trim())
              throw new Error("remember requires key, content and stated");
            await assertOperatorDecision(ctx, context, `remember-rule:${input.key}`);
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
            await assertOperatorDecision(ctx, context, `forget-rule:${input.key}`);
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
            return { content: JSON.stringify(knowledge.getKnowledge(scope, input.query)) };
          const recent = knowledge.observationsForSession(
            registered.get(`${context.sessionID}\0${scope}`) ?? context.sessionID,
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
    return () => {
      lifecycleController.abort();
      // The private display of the harness goes away with it. The terminal of
      // the operator was never touched.
      stopPrivateDisplay();
      debug("plugin unloaded");
    };
  },
};
