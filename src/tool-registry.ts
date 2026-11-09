/**
 * Live, host-neutral registry of reusable scripts. No candidate is executable
 * through this API: execution remains behind the host's normal shell/process
 * permission boundary. Indexes are re-read on each call so a running session
 * sees an independently promoted tool without restarting its model.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { assertPlainPath, atomicWrite, hash, redactText } from "./util";

export type ToolLanguage = "mjs" | "py" | "sh";
export type ToolStatus = "candidate" | "validated" | "active" | "retired";
export interface ToolTest {
  observationId: string;
  contains: string;
  kind: "positive" | "negative";
}
export interface ToolRevision {
  id: string;
  scope: string;
  name: string;
  version: number;
  description: string;
  language: ToolLanguage;
  file: string;
  sha256: string;
  status: ToolStatus;
  createdAt: string;
  tests: ToolTest[];
}
interface RegistryState { schema: 1; revisions: ToolRevision[] }
export interface ToolCapability {
  name: string;
  origin: "path" | "managed" | "host";
  description: string;
  command?: string;
  scope?: string;
  version?: number;
}
const VALID_SCOPE = /^(?:global|project-[a-f0-9]{24})$/;
const VALID_NAME = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const LANG: Record<ToolLanguage, string> = {
  mjs: "node", py: "python3", sh: "bash",
};
const MAX_SCAN = 8000;
const MAX_PER_DIRECTORY = 3000;
const MAX_DIRECTORY_COUNT = 40;
const STOP = new Set(["the", "and", "for", "with", "from", "dans", "pour", "une", "les", "des", "avec", "sur", "de", "du", "un", "la", "le", "tool", "outil", "run", "use"]);

function checkScope(scope: string): void {
  if (!VALID_SCOPE.test(scope)) throw new Error("Invalid tool scope");
}
function checkName(name: string): void {
  if (!VALID_NAME.test(name) || name.length > 48 || name.includes(".."))
    throw new Error("Invalid tool name");
}
function terms(text: string): string[] {
  return [...new Set(text.normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .toLowerCase().split(/[^a-z0-9]+/).filter((word) => word.length > 2 && !STOP.has(word)))];
}
function relevance(query: string, item: ToolCapability): number {
  if (!query.trim()) return 1;
  const tokens = terms(query);
  const title = terms(item.name);
  const description = terms(item.description);
  return tokens.reduce((score, word) => score +
    (title.includes(word) ? 5 : title.some((t) => t.startsWith(word)) ? 3 :
      description.includes(word) ? 1 : 0), 0);
}
function commandFor(item: ToolRevision): string {
  return LANG[item.language] + " " + JSON.stringify(item.file);
}
function safeSource(source: string): void {
  if (typeof source !== "string" || !source.trim() || source.length > 80000 ||
      source.includes("\0") || redactText(source) !== source)
    throw new Error("Invalid script source or possible credential");
}
function globallyReusable(source: string): void {
  if (/(?:https?:\/\/|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b|\/home\/[^/\s]+\/|\/Users\/[^/\s]+\/)/i.test(source))
    throw new Error("Global scripts must not contain target/customer identifiers or user-specific paths");
}

export class ToolRegistry {
  private readonly root: string;
  private readonly index: string;
  private readonly lock: string;
  constructor(stateRoot: string) {
    this.root = path.resolve(stateRoot, "capabilities");
    this.index = path.join(this.root, "registry.json");
    this.lock = path.join(this.root, ".lock");
    assertPlainPath(this.root);
    fs.mkdirSync(this.root, { recursive: true, mode: 0o700 });
  }
  private read(): RegistryState {
    assertPlainPath(this.index);
    if (!fs.existsSync(this.index)) return { schema: 1, revisions: [] };
    const value = JSON.parse(fs.readFileSync(this.index, "utf8"));
    if (value.schema !== 1 || !Array.isArray(value.revisions))
      throw new Error("Unsupported tool registry schema");
    return value;
  }
  private mutate<T>(fn: (state: RegistryState) => T): T {
    assertPlainPath(this.lock);
    let fd: number;
    try { fd = fs.openSync(this.lock, "wx", 0o600); }
    catch { throw new Error("Tool registry busy; retry instead of removing the lock"); }
    try {
      const current = this.read();
      const result = fn(current);
      atomicWrite(this.index, JSON.stringify(current, null, 2) + "\n");
      return result;
    } finally {
      fs.closeSync(fd);
      fs.unlinkSync(this.lock);
    }
  }
  private verifyFile(item: ToolRevision): void {
    assertPlainPath(item.file);
    if (!item.file.startsWith(this.root + path.sep))
      throw new Error("Tool file escapes the registry");
    if (!fs.existsSync(item.file) ||
        hash(fs.readFileSync(item.file, "utf8")) !== item.sha256)
      throw new Error("Tool source changed since proposal; validation invalid");
  }
  private syntax(item: ToolRevision): void {
    this.verifyFile(item);
    let args: string[];
    let binary: string;
    if (item.language === "mjs") { binary = process.execPath; args = ["--check", item.file]; }
    else if (item.language === "py") { binary = "python3"; args = ["-c", "import ast,sys; ast.parse(open(sys.argv[1], encoding='utf-8').read())", item.file]; }
    else { binary = "bash"; args = ["-n", item.file]; }
    const run = spawnSync(binary, args, { timeout: 5000, maxBuffer: 65536, encoding: "utf8" });
    if (run.error || run.status !== 0)
      throw new Error("Static syntax check failed: " + String(run.error?.message ?? run.stderr ?? "unknown").slice(0, 250));
    this.verifyFile(item);
  }
  private available(scope: string): ToolRevision[] {
    checkScope(scope);
    const all = this.read().revisions;
    const chosen = new Map<string, ToolRevision>();
    for (const item of all.filter((entry) =>
      entry.status === "active" && (entry.scope === "global" || entry.scope === scope))) {
      if (!chosen.has(item.name) || item.scope === scope) chosen.set(item.name, item);
    }
    return [...chosen.values()].filter((item) => {
      try { this.verifyFile(item); return true; } catch { return false; }
    });
  }
  list(scope: string, includeCandidates = false): ToolRevision[] {
    checkScope(scope);
    if (!includeCandidates) return this.available(scope);
    return this.read().revisions.filter((item) => item.scope === scope || item.scope === "global");
  }
  propose(scope: string, input: { name: string; description: string; language: ToolLanguage; source: string }): ToolRevision {
    checkScope(scope);
    if (scope === "global") throw new Error("A global tool requires validated promotion");
    checkName(input.name);
    if (!(input.language in LANG)) throw new Error("Unsupported tool language");
    if (!input.description?.trim() || input.description.length > 500 ||
        redactText(input.description) !== input.description)
      throw new Error("Invalid tool description");
    safeSource(input.source);
    return this.mutate((state) => {
      const prior = state.revisions.filter((item) => item.scope === scope && item.name === input.name);
      const version = Math.max(0, ...prior.map((entry) => entry.version)) + 1;
      const id = randomUUID();
      const folder = path.join(this.root, "staging", scope, input.name, "v" + version + "-" + id);
      const file = path.join(folder, "tool." + input.language);
      assertPlainPath(file);
      fs.mkdirSync(folder, { recursive: true, mode: 0o700 });
      const source = input.source.endsWith("\n") ? input.source : input.source + "\n";
      fs.writeFileSync(file, source, { mode: 0o600, flag: "wx" });
      const entry: ToolRevision = {
        id, scope, name: input.name, version, description: input.description,
        language: input.language, file, sha256: hash(source),
        status: "candidate", createdAt: new Date().toISOString(), tests: [],
      };
      state.revisions.push(entry);
      return { ...entry };
    });
  }
  validate(scope: string, id: string, tests: ToolTest[], evidence: (ids: string[]) => {
    id: string; success: boolean; output: string; input: unknown; scope: string;
  }[]): ToolRevision {
    checkScope(scope);
    if (!Array.isArray(tests) || tests.length < 2 || tests.length > 12 ||
        !tests.some((test) => test.kind === "positive") ||
        !tests.some((test) => test.kind === "negative") ||
        new Set(tests.map((test) => test.observationId)).size !== tests.length)
      throw new Error("Distinct positive and negative observations are required");
    const item = this.read().revisions.find((entry) => entry.id === id && entry.scope === scope);
    if (!item || item.status !== "candidate") throw new Error("Tool candidate not found");
    this.syntax(item);
    const proofs = evidence(tests.map((test) => test.observationId));
    for (const test of tests) {
      const proof = proofs.find((entry) => entry.id === test.observationId);
      if (!proof || proof.scope !== scope || !proof.success ||
          typeof test.contains !== "string" || test.contains.trim().length < 4 ||
          !proof.output.includes(test.contains) ||
          !JSON.stringify(proof.input).includes(item.file))
        throw new Error("Test lacks successful, scope-bound execution of the exact candidate: " + test.observationId);
    }
    return this.mutate((state) => {
      const actual = state.revisions.find((entry) => entry.id === id && entry.scope === scope);
      if (!actual || actual.status !== "candidate") throw new Error("Candidate state changed");
      this.verifyFile(actual);
      actual.tests = tests.map((test) => ({ ...test }));
      actual.status = "validated";
      return { ...actual };
    });
  }
  activate(scope: string, id: string, global = false): ToolRevision {
    checkScope(scope);
    return this.mutate((state) => {
      const item = state.revisions.find((entry) => entry.id === id && entry.scope === scope);
      if (!item || item.status !== "validated") throw new Error("Validated candidate required");
      this.verifyFile(item);
      if (global) globallyReusable(fs.readFileSync(item.file, "utf8"));
      const targetScope = global ? "global" : scope;
      const targetVersion = global
        ? Math.max(0, ...state.revisions.filter((entry) => entry.scope === "global" && entry.name === item.name).map((entry) => entry.version)) + 1
        : item.version;
      for (const entry of state.revisions)
        if (entry.scope === targetScope && entry.name === item.name && entry.status === "active")
          entry.status = "retired";
      if (!global) {
        item.status = "active";
        return { ...item };
      }
      const idGlobal = randomUUID();
      const folder = path.join(this.root, "published", "global", item.name, "v" + targetVersion + "-" + idGlobal);
      const file = path.join(folder, "tool." + item.language);
      assertPlainPath(file);
      fs.mkdirSync(folder, { recursive: true, mode: 0o700 });
      fs.writeFileSync(file, fs.readFileSync(item.file, "utf8"), { mode: 0o600, flag: "wx" });
      const shared = { ...item, scope: "global", id: idGlobal, version: targetVersion, file, status: "active" as const };
      state.revisions.push(shared);
      return { ...shared };
    });
  }
  rollback(scope: string, name: string, version: number): ToolRevision {
    checkScope(scope); checkName(name);
    return this.mutate((state) => {
      const candidate = state.revisions.find((item) => item.scope === scope && item.name === name && item.version === version);
      if (!candidate || !["active", "retired"].includes(candidate.status) || !candidate.tests.length)
        throw new Error("Only a previously validated active revision can be restored");
      this.verifyFile(candidate);
      for (const item of state.revisions)
        if (item.scope === scope && item.name === name && item.status === "active")
          item.status = "retired";
      candidate.status = "active";
      return { ...candidate };
    });
  }
  /** Enumerate PATH and configured tool directories, never recursively execute or probe binaries. */
  scan(): ToolCapability[] {
    const home = process.env.HARNESS_TOOL_HOME || path.join(os.homedir(), "hacking", "Mes-outils");
    const dirs = [...new Set([
      ...(process.env.PATH ?? "").split(path.delimiter),
      home,
      ...(process.env.HARNESS_TOOL_PATHS ?? "").split(path.delimiter),
    ].filter(Boolean).map((entry) => path.resolve(entry)))].slice(0, MAX_DIRECTORY_COUNT);
    const found = new Map<string, ToolCapability>();
    for (const directory of dirs) {
      try {
        assertPlainPath(directory);
        const entries = fs.readdirSync(directory, { withFileTypes: true }).slice(0, MAX_PER_DIRECTORY);
        for (const entry of entries) {
          if (found.size >= MAX_SCAN) break;
          if (!entry.isFile() || !/^[A-Za-z0-9][A-Za-z0-9_.+-]{0,100}$/.test(entry.name))
            continue;
          const file = path.join(directory, entry.name);
          const stat = fs.statSync(file);
          if (!(stat.mode & 0o111)) continue;
          found.set(entry.name, { name: entry.name, origin: "path", description: "Executable on PATH or configured tool directory", command: file });
        }
      } catch { /* A missing, protected or linked directory is not trusted. */ }
    }
    return [...found.values()];
  }
  discover(scope: string, query: string, host: { name: string; description?: string }[] = [], offset = 0, limit = 15) {
    checkScope(scope);
    const managed: ToolCapability[] = this.available(scope).map((item) => ({
      name: item.name, origin: "managed", description: item.description, command: commandFor(item),
      scope: item.scope, version: item.version,
    }));
    const hosted: ToolCapability[] = host.filter((item) => typeof item?.name === "string").map((item) => ({
      name: item.name, origin: "host", description: String(item.description ?? "").slice(0, 300),
    }));
    const entries = [...managed, ...hosted, ...this.scan()];
    const scored = entries.map((item) => ({ item, score: relevance(query, item) }))
      .filter((entry) => !query.trim() || entry.score > 0)
      .sort((a, b) => b.score - a.score || a.item.name.localeCompare(b.item.name));
    const start = Number.isSafeInteger(offset) ? Math.max(0, offset) : 0;
    const size = Number.isSafeInteger(limit) ? Math.max(1, Math.min(40, limit)) : 15;
    return { query, total: scored.length, offset: start, tools: scored.slice(start, start + size).map((entry) => entry.item) };
  }
  context(scope: string, query: string, host: { name: string; description?: string }[] = []): string {
    const result = this.discover(scope, query, host, 0, 6);
    const rows = result.tools.map((item) => "- " + item.name + " [" + item.origin + "]: " +
      (item.command ?? item.description).slice(0, 140));
    return [
      "Harness capabilities. The inventory is live and is not proof of tool use.",
      "Before acting, compare applicable tools with cyber_toolbox discover; do not claim unavailable tools were executed.",
      ...rows,
      result.total === 0 ? "No indexed match. Use cyber_toolbox discover with another query or propose an improvement after checking existing tools." : "",
      "A validated managed script is immediately callable via the normal permissioned shell/process tool; no new session required.",
    ].filter(Boolean).join("\n").slice(0, 1500);
  }
  matchExecution(scope: string, input: unknown): { name: string; version: number; scope: string } | null {
    const raw = JSON.stringify(input ?? {});
    for (const entry of this.available(scope))
      if (raw.includes(entry.file)) return { name: entry.name, version: entry.version, scope: entry.scope };
    return null;
  }
}
