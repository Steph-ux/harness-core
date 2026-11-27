/**
 * Live, host-neutral registry of reusable scripts. No candidate is executable
 * through this API: execution remains behind the host's normal shell/process
 * permission boundary. Indexes are re-read on each call so a running session
 * sees an independently promoted tool without restarting its model.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { assertPlainPath, atomicWrite, hash, redactText } from "./util";
import { expandSecurityTerms, SECURITY_SHORT_TERMS, toolNote } from "./tool-catalog";

export type ToolLanguage = "mjs" | "py" | "sh";
export type ToolStatus = "candidate" | "validated" | "active" | "retired";
/** Where a managed script came from: the repository it was taken from or adapted from. */
export interface ToolProvenance {
  url: string;
  commit?: string;
  license?: string;
}
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
  provenance?: ToolProvenance;
}
interface RegistryState {
  schema: 1;
  revisions: ToolRevision[];
  /** Highest version ever issued per `scope/name`; pruning never lowers it. */
  versions?: Record<string, number>;
}
export interface ToolCapability {
  name: string;
  origin: "path" | "managed" | "host";
  description: string;
  command?: string;
  scope?: string;
  version?: number;
  provenance?: ToolProvenance;
}
const VALID_SCOPE = /^(?:global|project-[a-f0-9]{24})$/;
const VALID_NAME = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const LANG: Record<ToolLanguage, string> = {
  mjs: "node", py: "python3", sh: "bash",
};
const MAX_SCAN = 20000;
/**
 * Whether a file can be run.
 *
 * POSIX carries the permission in the mode, so the mode decides. Windows
 * does not have that bit: every regular file looks non-executable there,
 * and a scan would find no tool at all. On Windows the extension decides,
 * and a file without one is taken as a script the interpreter runs.
 */
function isExecutable(name: string, stat: fs.Stats): boolean {
  if (process.platform !== "win32") return Boolean(stat.mode & 0o111);
  return /\.(?:exe|com|bat|cmd|ps1)$/i.test(name) || !/\.[A-Za-z0-9]+$/.test(name);
}
/** A file whose header can describe it. Binaries are not read. */
const SCRIPT_HEADER = /\.(?:py|sh|bash|js|mjs|cjs|ts|rb|pl|ps1)$/i;
const MAX_DESCRIPTION_BYTES = 4096;
const MAX_TOOL_SUBDIRECTORIES = 64;
/**
 * The purpose of a script, read from its own header.
 *
 * A collection documents each script at the top: a module docstring in Python,
 * a comment block in shell or JavaScript. That header — not the file name — is
 * what lets a semantic query find the script, and it is the only description
 * the registry can obtain without running it. Nothing is executed: the first
 * kilobytes are read and the first paragraph is kept.
 */
function scriptDescription(file: string): string | undefined {
  if (!SCRIPT_HEADER.test(file)) return undefined;
  let head: string;
  try {
    const fd = fs.openSync(file, "r");
    try {
      const buffer = Buffer.alloc(MAX_DESCRIPTION_BYTES);
      head = buffer
        .subarray(0, fs.readSync(fd, buffer, 0, buffer.length, 0))
        .toString("utf8");
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return undefined;
  }
  // A shebang and a coding declaration precede the header they belong to.
  const kept = head
    .replace(/^\uFEFF/, "")
    .split("\n")
    .filter(
      (line, index) =>
        !(index === 0 && line.startsWith("#!")) &&
        !(index < 3 && /^#.*coding[:=]/.test(line)),
    );
  const body = kept.join("\n").trimStart();
  const collected: string[] = [];
  const quote = body.startsWith('"""')
    ? '"""'
    : body.startsWith("'''")
      ? "'''"
      : "";
  if (quote) {
    const end = body.indexOf(quote, quote.length);
    if (end > quote.length) collected.push(body.slice(quote.length, end));
  } else if (body.startsWith("/*")) {
    const end = body.indexOf("*/", 2);
    if (end > 2) {
      for (const rawLine of body.slice(2, end).split(/\r?\n/)) {
        const cleaned = rawLine.replace(/^\s*\*\s?/, "").trim();
        if (!cleaned) {
          if (collected.length) break;
          continue;
        }
        if (cleaned.startsWith("@") && collected.length) break;
        collected.push(cleaned);
      }
    }
  }
  if (!collected.length)
    for (const line of kept) {
      const comment = line.match(/^\s*(?:#|\/\/)\s?(.*)$/);
      if (comment) {
        const text = comment[1].trim();
        if (!text && collected.length) break;
        if (text) collected.push(text);
      } else if (line.trim()) break;
      else if (collected.length) break;
    }
  const description = collected.join(" ").replace(/\s+/g, " ").trim();
  return description ? description.slice(0, 300) : undefined;
}
/**
 * The directories a scan may read.
 *
 * The work of a scan is bounded by MAX_SCAN, which counts the executables
 * it keeps; the count of directories only bounds the readdir calls. A
 * machine with a long PATH (Windows carries many entries, one per tool)
 * has to be scannable, so the limit is generous and configurable.
 */
const MAX_DIRECTORY_COUNT = 256;
const MAX_REVISIONS = 2000;
const MAX_SCOPE_REVISIONS = 250;
const MAX_SCOPE_CANDIDATES = 25;
const CLI_CACHE_MS = 60_000;
const STOP = new Set(["the", "and", "for", "with", "from", "dans", "pour", "une", "les", "des", "avec", "sur", "de", "du", "un", "la", "le", "tool", "outil", "run", "use"]);

function checkScope(scope: string): void {
  if (!VALID_SCOPE.test(scope)) throw new Error("Invalid tool scope");
}
function checkName(name: string): void {
  if (!VALID_NAME.test(name) || name.length > 48 || name.includes(".."))
    throw new Error("Invalid tool name");
}
const GENERIC_PATH_DESC = "Executable from PATH or explicitly configured directory";
function terms(text: string): string[] {
  return [
    ...new Set(
      text
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .split(/[^a-z0-9]+/)
        .filter(
          (word) =>
            (word.length > 2 || SECURITY_SHORT_TERMS.has(word)) &&
            !STOP.has(word),
        ),
    ),
  ];
}
function relevance(query: string, item: ToolCapability): number {
  if (!query.trim()) {
    return item.description && item.description !== GENERIC_PATH_DESC ? 2 : 1;
  }
  const normalized = query
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/\bsous[\s-]+domaines?\b|\bsubdomains?\b/g, "subdomain");
  const tokens = terms(normalized);
  const title = terms(item.name);
  const description = terms(item.description);
  let score = tokens.reduce(
    (sum, word) =>
      sum +
      (title.includes(word)
        ? 5
        : title.some((t) => t.startsWith(word))
          ? 3
          : description.includes(word)
            ? 2
            : word === "subdomain" &&
                description.some((t) => t.startsWith("transparen"))
              ? 1
              : 0),
    0,
  );
  if (score === 0) {
    const aliases = expandSecurityTerms(tokens);
    for (const alias of aliases) {
      if (tokens.includes(alias)) continue;
      if (title.includes(alias)) score += 2;
      else if (description.includes(alias)) score += 1;
    }
  }
  return score;
}
function commandFor(item: ToolRevision): string {
  return LANG[item.language] + " " + JSON.stringify(item.file);
}
function splitCommandArgs(line: string): string[] | null {
  const args: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  let hasToken = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      hasToken = true;
      continue;
    }
    if (/\s/.test(ch)) {
      if (hasToken) {
        args.push(current);
        current = "";
        hasToken = false;
      }
      continue;
    }
    current += ch;
    hasToken = true;
  }
  if (quote !== null) return null;
  if (hasToken) args.push(current);
  return args;
}
function invocationFromInput(input: unknown): unknown {
  if (!input || typeof input !== "object" || Array.isArray(input))
    return undefined;
  const source = input as Record<string, unknown>;
  if (Array.isArray(source.argv)) return source.argv;
  return source.command ?? source.cmd;
}
/** Conservative direct invocation check (not proof of successful effects). */
function directInvocation(invocation: unknown, script: string): boolean {
  let args: string[];
  if (Array.isArray(invocation)) {
    if (
      !invocation.length ||
      invocation.length > 256 ||
      !invocation.every((part) => typeof part === "string")
    )
      return false;
    if (
      invocation.some(
        (part) =>
          /[\0\r\n<>]/.test(part) ||
          part.includes("$(") ||
          part.includes("${"),
      )
    )
      return false;
    args = invocation;
  } else if (typeof invocation === "string") {
    if (/[\0\r\n]/.test(invocation)) return false;
    const line = invocation.trim();
    if (
      !line ||
      /[;|&\x60<>]/.test(line) ||
      line.includes("$(") ||
      line.includes("${")
    )
      return false;
    const parsed = splitCommandArgs(line);
    if (!parsed) return false;
    args = parsed;
  } else {
    return false;
  }
  if (args.length < 2) return false;
  const runner = path.basename(args[0]).toLowerCase();
  if (!/^(?:node|nodejs|python|python3|bash|sh)(?:\.exe)?$/.test(runner))
    return false;
  let targetIndex = 1;
  if (args[1] === "--") {
    if (args.length < 3) return false;
    targetIndex = 2;
  }
  const executed = args[targetIndex];
  if (executed === "-e" || executed === "-c" || executed.startsWith("-"))
    return false;
  return executed === script;
}
function safeSource(source: string): void {
  if (typeof source !== "string" || !source.trim() || source.length > 80000 ||
      source.includes("\0") || redactText(source) !== source)
    throw new Error("Invalid script source or possible credential");
}
function checkProvenance(value: unknown): ToolProvenance | undefined {
  if (value === undefined) return undefined;
  const input = value as Record<string, unknown>;
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw new Error("Invalid tool provenance");
  let url: URL;
  try {
    url = new URL(String(input.url));
  } catch {
    throw new Error("Invalid tool provenance URL");
  }
  if (url.protocol !== "https:")
    throw new Error("Tool provenance must be an https URL");
  if (url.username || url.password)
    throw new Error("Tool provenance URL must not carry credentials");
  const field = (key: string, max: number) => {
    const text = input[key];
    if (text === undefined) return undefined;
    if (
      typeof text !== "string" ||
      !text.trim() ||
      text.length > max ||
      redactText(text) !== text
    )
      throw new Error("Invalid tool provenance field");
    return text.trim();
  };
  return {
    url: url.toString(),
    commit: field("commit", 64),
    license: field("license", 80),
  };
}

const GLOBAL_URL = /\b[a-z][a-z0-9+.-]*:\/\//i;
const GLOBAL_WWW = /(?<![a-z0-9-])www\.[a-z0-9-]+/i;
const GLOBAL_IPV4 = /\b\d{1,3}(?:\.\d{1,3}){3}\b/;
const GLOBAL_IPV6 =
  /(?<![0-9A-Za-z:])(?:\[(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?|:(?::[0-9a-fA-F]{1,4}){1,7})(?:%[A-Za-z0-9._-]+)?\]|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){0,6})?|:(?::[0-9a-fA-F]{1,4}){1,7})(?![0-9A-Za-z:])/;
const GLOBAL_EMAIL = /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/i;
const GLOBAL_LOCAL_PATH =
  /\/home\/[^/\s]+\/|\/Users\/[^/\s]+\/|\b[A-Za-z]:\\[^\s"']+|\\\\[A-Za-z0-9._-]+\\[^\s"']+/i;
const GLOBAL_HASH = /\b[A-Fa-f0-9]{32,}\b/;
const GLOBAL_TOKEN = /\b[A-Za-z0-9+/_-]{32,}={0,2}\b/g;
const DOMAIN_TLDS = new Set([
  "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name",
  "pro", "arpa", "local", "internal", "corp", "lan", "home", "test", "example",
  "invalid", "onion", "cloud", "dev", "app", "tech", "online", "site", "store",
  "xyz", "io", "ai", "co", "uk", "de", "fr", "ca", "au", "jp", "cn", "ru",
  "br", "in", "nl", "se", "no", "fi", "dk", "ch", "at", "be", "es", "it",
  "pt", "pl", "cz", "ua", "ro", "hu", "gr", "tr", "za", "ng", "ke", "gh",
  "ci", "sn", "bj", "tg", "ml", "bf", "ne", "cm", "ma", "tn", "dz", "eg",
  "ae", "sa", "il", "sg", "hk", "tw", "kr", "id", "my", "th", "vn", "ph",
  "mx", "ar", "cl", "pe", "ve", "nz", "ie", "eu", "us", "rs", "py", "sh",
]);
const BARE_DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24})\b/gi;

function isIdentifierOrHeader(token: string): boolean {
  if (/^[A-Z0-9_]+$/.test(token) && token.includes("_")) return true;
  if (/[\d_+=]/.test(token)) return false;
  const parts = token.split(/[-/]/);
  return (
    parts.length >= 3 &&
    parts.every((part) => /^(?:[a-z]{1,24}|[A-Z][a-z]{1,24}|[A-Z]{1,10})$/.test(part))
  );
}

function globallyReusable(
  source: string,
  description = "",
  tests: readonly ToolTest[] = [],
): void {
  const combined = [source, description, ...tests.map((test) => test.contains)].join("\n");
  if (
    GLOBAL_URL.test(combined) ||
    GLOBAL_WWW.test(combined) ||
    GLOBAL_IPV4.test(combined) ||
    GLOBAL_IPV6.test(combined) ||
    GLOBAL_EMAIL.test(combined) ||
    GLOBAL_LOCAL_PATH.test(combined) ||
    GLOBAL_HASH.test(combined) ||
    redactText(combined) !== combined
  )
    throw new Error(
      "Global scripts must not contain target/customer identifiers, tokens or user-specific paths",
    );
  for (const match of combined.matchAll(GLOBAL_TOKEN)) {
    if (!isIdentifierOrHeader(match[0]))
      throw new Error(
        "Global scripts must not contain target/customer identifiers, tokens or user-specific paths",
      );
  }
  for (const match of combined.matchAll(BARE_DOMAIN)) {
    const token = match[0];
    const tld = match[1].toLowerCase();
    const index = match.index ?? 0;
    const after = combined.slice(index + token.length, index + token.length + 12);
    const before = combined.slice(Math.max(0, index - 40), index);
    if (/^[([\s]*=/.test(after) || after.startsWith("(") || after.startsWith("["))
      continue;
    if (/^(?:e\.g|i\.e)$/i.test(token)) continue;
    if (["rs", "py", "sh"].includes(tld)) {
      const hostCtx =
        /^:\d{1,5}(?:\b|$)/.test(after) ||
        (/^\/[A-Za-z0-9_.-]/.test(after) && !/[\\/~.]$/.test(before)) ||
        /(?:^|[\s(,;])(?:host(?:name)?|domain|fqdn|vhost|cname|dig|curl)\s*(?:[:=]\s*|\s+(?:is|at|on|to)\s+|\s+)$/i.test(before) ||
        /(?:^|[\s(,;])(?:server|origin|endpoint|target|url|uri)\s*[:=]\s*$/i.test(before);
      if (!hostCtx) continue;
    }
    if (DOMAIN_TLDS.has(tld))
      throw new Error(
        "Global scripts must not contain target/customer identifiers, tokens or user-specific paths",
      );
  }
}

export class ToolRegistry {
  private readonly root: string;
  private readonly index: string;
  private readonly lock: string;
  private cliCache: { key: string; expires: number; entries: ToolCapability[] } | null = null;
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
    if (value.versions !== undefined &&
        (typeof value.versions !== "object" || value.versions === null ||
          Array.isArray(value.versions)))
      throw new Error("Unsupported tool registry counters");
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
      if (current.revisions.length > MAX_REVISIONS)
        throw new Error("Tool registry at capacity; prune old candidates");
      this.cliCache = null;
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
    const pyArgs = [
      "-c",
      "import ast,sys; ast.parse(open(sys.argv[1], encoding='utf-8').read())",
      item.file,
    ];
    const candidates: [string, string[]][] =
      item.language === "mjs"
        ? [[process.execPath, ["--check", item.file]]]
        : item.language === "py"
          ? (process.platform === "win32" ? ["python", "python3"] : ["python3", "python"]).map(
              (bin) => [bin, pyArgs],
            )
          : [["bash", ["-n", item.file]]];
    let lastError = "unknown";
    for (let i = 0; i < candidates.length; i += 1) {
      const [binary, args] = candidates[i];
      const run = spawnSync(binary, args, {
        timeout: 5000,
        maxBuffer: 65536,
        encoding: "utf8",
      });
      if (!run.error && run.status === 0) {
        this.verifyFile(item);
        return;
      }
      const errCode = (run.error as NodeJS.ErrnoException | undefined)?.code;
      const missingBinary =
        errCode === "ENOENT" ||
        (process.platform === "win32" && run.status === 9009 && !String(run.stderr ?? "").trim());
      lastError = String(run.error?.message ?? run.stderr ?? "unknown").slice(0, 250);
      if (!missingBinary || i === candidates.length - 1) break;
    }
    throw new Error("Static syntax check failed: " + lastError);
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
  propose(scope: string, input: { name: string; description: string; language: ToolLanguage; source: string; provenance?: unknown }): ToolRevision {
    checkScope(scope);
    if (scope === "global") throw new Error("A global tool requires validated promotion");
    checkName(input.name);
    if (!Object.hasOwn(LANG, input.language)) throw new Error("Unsupported tool language");
    if (!input.description?.trim() || input.description.length > 500 ||
        redactText(input.description) !== input.description)
      throw new Error("Invalid tool description");
    safeSource(input.source);
    const provenance = checkProvenance(input.provenance);
    // Candidates abandoned for 30 days are cleaned before new proposals.
    this.prune(scope);
    return this.mutate((state) => {
      if (state.revisions.length >= MAX_REVISIONS)
        throw new Error("Tool registry at capacity; prune unused candidates");
      const inScope = state.revisions.filter((item) => item.scope === scope);
      if (inScope.length >= MAX_SCOPE_REVISIONS)
        throw new Error("Scope revision quota reached; prune unused candidates");
      if (inScope.filter((item) => item.status === "candidate").length >= MAX_SCOPE_CANDIDATES)
        throw new Error("Candidate quota reached; prune or validate candidates");
      const prior = inScope.filter((item) => item.name === input.name);
      const counter = scope + "/" + input.name;
      const version = Math.max(
        state.versions?.[counter] ?? 0,
        ...prior.map((entry) => entry.version),
      ) + 1;
      // Pruned candidates must not give their number to a later script.
      state.versions = { ...(state.versions ?? {}), [counter]: version };
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
        ...(provenance ? { provenance } : {}),
      };
      state.revisions.push(entry);
      return { ...entry };
    });
  }
  validate(scope: string, id: string, tests: ToolTest[], evidence: (ids: string[]) => {
    id: string; success: boolean; output: string; input: unknown; scope: string;
    tool?: string;
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
    const positiveOutputs: string[] = [];
    const negativeOutputs: string[] = [];
    for (const test of tests) {
      const proof = proofs.find((entry) => entry.id === test.observationId);
      const executable = directInvocation(
        invocationFromInput(proof?.input),
        item.file,
      );
      const executionTool = /(?:shell|bash|process|exec|terminal|command)/i.test(proof?.tool ?? "");
      const meaningful =
        typeof test.contains === "string" ? test.contains.trim() : "";
      const nonTrivial =
        meaningful.length >= 4 &&
        (meaningful.match(/[\p{L}\p{N}]/gu) ?? []).length >= 3 &&
        !/^(?:ok|true|false|null|undefined|success|done|pass|fail|failed|error)$/i.test(
          meaningful,
        );
      if (!proof || proof.scope !== scope || !proof.success ||
          !nonTrivial ||
          !proof.output.includes(test.contains) ||
          !executable || !executionTool)
        throw new Error("Test lacks successful, scope-bound execution of the exact candidate: " + test.observationId);
      if (test.kind === "positive") positiveOutputs.push(proof.output);
      else negativeOutputs.push(proof.output);
    }
    for (const pos of positiveOutputs) {
      for (const neg of negativeOutputs) {
        if (pos === neg)
          throw new Error("Positive and negative tests must observe different outputs");
      }
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
      if (!item || (item.status !== "validated" && !(global && item.status === "active")))
        throw new Error("Validated candidate required");
      this.verifyFile(item);
      if (global)
        globallyReusable(
          fs.readFileSync(item.file, "utf8"),
          item.description,
          item.tests,
        );
      const targetScope = global ? "global" : scope;
      const globalCounter = "global/" + item.name;
      const targetVersion = global
        ? Math.max(
            state.versions?.[globalCounter] ?? 0,
            ...state.revisions
              .filter((entry) => entry.scope === "global" && entry.name === item.name)
              .map((entry) => entry.version),
          ) + 1
        : item.version;
      if (global)
        state.versions = { ...(state.versions ?? {}), [globalCounter]: targetVersion };
      for (const entry of state.revisions)
        if (entry.scope === targetScope && entry.name === item.name && entry.status === "active")
          entry.status = "retired";
      if (!global) {
        item.status = "active";
        return { ...item };
      }
      if (state.revisions.length >= MAX_REVISIONS)
        throw new Error("Tool registry at capacity; prune unused candidates");
      const idGlobal = randomUUID();
      const folder = path.join(this.root, "published", "global", item.name, "v" + targetVersion + "-" + idGlobal);
      const file = path.join(folder, "tool." + item.language);
      assertPlainPath(file);
      fs.mkdirSync(folder, { recursive: true, mode: 0o700 });
      fs.writeFileSync(file, fs.readFileSync(item.file, "utf8"), { mode: 0o600, flag: "wx" });
      const shared: ToolRevision = {
        ...item,
        scope: "global",
        id: idGlobal,
        version: targetVersion,
        file,
        status: "active",
        tests: [],
      };
      state.revisions.push(shared);
      return { ...shared };
    });
  }
  rollback(scope: string, name: string, version: number, global = false): ToolRevision {
    checkScope(scope); checkName(name);
    const targetScope = global ? "global" : scope;
    return this.mutate((state) => {
      const candidate = state.revisions.find((item) => item.scope === targetScope && item.name === name && item.version === version);
      if (
        !candidate ||
        !["active", "retired"].includes(candidate.status) ||
        (candidate.scope !== "global" && !candidate.tests.length)
      )
        throw new Error("Only a previously validated active revision can be restored");
      this.verifyFile(candidate);
      for (const item of state.revisions)
        if (item.scope === targetScope && item.name === name && item.status === "active")
          item.status = "retired";
      candidate.status = "active";
      return { ...candidate };
    });
  }
  /** Retire one active version, including a global one if explicitly requested. */
  retire(scope: string, name: string, global = false): ToolRevision {
    checkScope(scope); checkName(name);
    const targetScope = global ? "global" : scope;
    return this.mutate((state) => {
      const active = state.revisions.find((item) =>
        item.scope === targetScope && item.name === name && item.status === "active");
      if (!active) throw new Error("No active version to retire");
      active.status = "retired";
      return { ...active };
    });
  }
  /**
   * Remove stale or explicitly selected unvalidated candidates only.
   * Never delete validated, active or retired code here: rollback and
   * evidence records must remain intact.
   */
  prune(scope: string, ids: string[] = [], days = 30): { removed: string[] } {
    checkScope(scope);
    if (!Number.isFinite(days) || days < 0 || days > 3650 ||
        !Array.isArray(ids) || ids.length > 100)
      throw new Error("Invalid prune request");
    const cutoff = Date.now() - days * 86400_000;
    const selected = this.mutate((state) => {
      const removed: ToolRevision[] = [];
      state.revisions = state.revisions.filter((item) => {
        const eligible = item.scope === scope && item.status === "candidate" &&
          (ids.includes(item.id) ||
            (ids.length === 0 && Date.parse(item.createdAt) < cutoff));
        if (eligible) removed.push(item);
        return !eligible;
      });
      return removed;
    });
    for (const item of selected) {
      try {
        assertPlainPath(item.file);
        if (!item.file.startsWith(this.root + path.sep))
          throw new Error("Candidate is outside the registry");
        fs.unlinkSync(item.file);
        fs.rmdirSync(path.dirname(item.file));
      } catch {
        // Index cleanup has already committed. No validated/active tool
        // is touched, and a failed filesystem cleanup is safe to retry.
      }
    }
    return { removed: selected.map((item) => item.id) };
  }

  /**
   * Do not probe/exe CLI commands. PATH is environment configuration;
   * explicit custom tool directories must exist and be ordinary directories.
   * Readdir is cached and never performed for routine context injection.
   */
  scan(refresh = false): ToolCapability[] {
    const configured = [
      process.env.HARNESS_TOOL_HOME,
      ...(process.env.HARNESS_TOOL_PATHS ?? "").split(path.delimiter),
    ].filter((v): v is string => Boolean(v?.trim()));
    const inherited = (process.env.PATH ?? "").split(path.delimiter).filter(Boolean);
    const explicitSet = new Set(configured.map((entry) => path.resolve(entry)));
    const dirs = [...new Set([...configured, ...inherited].map((entry) => path.resolve(entry)))];
    const key = JSON.stringify({ dirs, explicit: [...explicitSet].sort() });
    if (!refresh && this.cliCache?.key === key && this.cliCache.expires > Date.now())
      return [...this.cliCache.entries];
    if (dirs.length > MAX_DIRECTORY_COUNT)
      throw new Error("Too many tool directories; restrict PATH or HARNESS_TOOL_PATHS");
    const explicit = explicitSet;
    const found = new Map<string, ToolCapability>();
    const indexFile = (directory: string, name: string, category?: string) => {
      if (found.size >= MAX_SCAN) return;
      if (!/^[A-Za-z0-9][A-Za-z0-9_.+-]{0,100}$/.test(name)) return;
      const file = path.join(directory, name);
      let stat;
      try {
        stat = fs.statSync(file);
      } catch {
        return;
      }
      if (!stat.isFile() || !isExecutable(name, stat) || found.has(name)) return;
      const header = scriptDescription(file) ?? toolNote(name);
      found.set(name, {
        name, origin: "path",
        // The category is part of the description: a query for the kind of
        // work matches the folder even when the file name does not.
        description: header
          ? (category ? `${category}: ${header}` : header)
          : "Executable from PATH or explicitly configured directory",
        command: file,
      });
    };
    for (const directory of dirs) {
      try {
        // A PATH entry may itself be a symlink (`/bin` -> `/usr/bin` on
        // merged-/usr systems): resolve it, then check the real directory.
        const real = fs.realpathSync(directory);
        assertPlainPath(real);
        if (!fs.statSync(real).isDirectory()) throw new Error("Not a directory");
        const descend = explicit.has(directory);
        const entries = fs.readdirSync(real, { withFileTypes: true });
        let subdirs = 0;
        for (const entry of entries) {
          if (found.size >= MAX_SCAN) break;
          // A configured toolbox is categories (`01-enumeration/*.py`), not a
          // flat bin. Descend one level there only. PATH stays flat: /usr/bin
          // has subdirectories that are not the operator's tools, and a name
          // starting with "_" is a library, not a tool.
          if (descend && (entry.isDirectory() || entry.isSymbolicLink())) {
            if (
              entry.name.startsWith(".") ||
              entry.name.startsWith("_") ||
              !/^[A-Za-z0-9][A-Za-z0-9_.+-]{0,100}$/.test(entry.name) ||
              subdirs >= MAX_TOOL_SUBDIRECTORIES
            ) {
              if (!entry.isSymbolicLink()) continue;
            } else {
              const child = path.join(directory, entry.name);
              let childReal = "";
              try {
                childReal = fs.realpathSync(child);
                assertPlainPath(childReal);
                if (
                  childReal.startsWith(real + path.sep) &&
                  fs.statSync(childReal).isDirectory()
                ) {
                  subdirs++;
                  for (const nested of fs.readdirSync(childReal, { withFileTypes: true })) {
                    if (!nested.isFile() && !nested.isSymbolicLink()) continue;
                    indexFile(child, nested.name, entry.name);
                  }
                  continue;
                }
              } catch {
                if (entry.isDirectory()) continue;
              }
              if (entry.isDirectory()) continue;
            }
          }
          // Kali ships many tools as symlinks (msfconsole, msfvenom). Follow a
          // link to a regular executable, and ignore directories and dangling
          // links.
          if (!entry.isFile() && !entry.isSymbolicLink()) continue;
          indexFile(directory, entry.name);
        }
      } catch (error) {
        if (explicit.has(directory))
          throw new Error("Configured tool directory is unavailable: " + directory +
            " (" + String(error).slice(0, 100) + ")");
        // Inherited PATH directories may disappear during a session.
      }
    }
    const entries = [...found.values()];
    this.cliCache = { key, expires: Date.now() + CLI_CACHE_MS, entries };
    return [...entries];
  }
  /** Prefer the managed/host capability over duplicate CLI names. */
  inventory(scope: string, host: { name: string; description?: string }[] = [], includePath = true): ToolCapability[] {
    checkScope(scope);
    const managed: ToolCapability[] = this.available(scope).map((item) => ({
      name: item.name, origin: "managed", description: item.description,
      command: commandFor(item), scope: item.scope, version: item.version,
      ...(item.provenance ? { provenance: item.provenance } : {}),
    }));
    const hosted: ToolCapability[] = host.filter((item) =>
      typeof item?.name === "string" && item.name.trim()).map((item) => ({
        name: item.name, origin: "host",
        description: String(item.description ?? "").slice(0, 300),
      }));
    const unique = new Map<string, ToolCapability>();
    for (const entry of [...managed, ...hosted, ...(includePath ? this.scan() : [])]) {
      if (!unique.has(entry.name)) unique.set(entry.name, entry);
    }
    return [...unique.values()];
  }
  discover(scope: string, query: string, host: { name: string; description?: string }[] = [],
    offset = 0, limit = 15, refresh = false, includePath = true) {
    checkScope(scope);
    if (refresh) this.cliCache = null;
    const entries = this.inventory(scope, host, includePath);
    const originRank = (origin: ToolCapability["origin"]) =>
      origin === "managed" ? 0 : origin === "path" ? 1 : 2;
    const scored = entries.map((item) => ({ item, score: relevance(query, item) }))
      .filter((entry) => !query.trim() || entry.score > 0)
      .sort(
        (a, b) =>
          b.score - a.score ||
          originRank(a.item.origin) - originRank(b.item.origin) ||
          a.item.name.localeCompare(b.item.name, "en"),
      );
    const start = Number.isSafeInteger(offset) ? Math.max(0, offset) : 0;
    const size = Number.isSafeInteger(limit) ? Math.max(1, Math.min(40, limit)) : 15;
    return {
      query, total: scored.length, offset: start,
      tools: scored.slice(start, start + size).map((entry) => entry.item),
    };
  }
  context(scope: string, query: string, host: { name: string; description?: string }[] = []): string {
    checkScope(scope);
    const base = this.inventory(scope, host, false);
    const seenNames = new Set(base.map((item) => item.name));
    const cachedCli =
      this.cliCache && this.cliCache.expires > Date.now()
        ? this.cliCache.entries.filter((item) => !seenNames.has(item.name))
        : [];
    const allEntries = [...base, ...cachedCli];
    const originRank = (origin: ToolCapability["origin"]) =>
      origin === "managed" ? 0 : origin === "path" ? 1 : 2;
    const rankList = (items: ToolCapability[], q: string) =>
      items
        .map((item) => ({ item, score: relevance(q, item) }))
        .filter((entry) => !q.trim() || entry.score > 0)
        .sort(
          (a, b) =>
            b.score - a.score ||
            originRank(a.item.origin) - originRank(b.item.origin) ||
            a.item.name.localeCompare(b.item.name, "en"),
        )
        .map((entry) => entry.item);
    const matched = rankList(allEntries, query);
    const pool = matched.length ? matched : rankList(allEntries, "");
    const mcpNamespace = (name: string): string | null => {
      const m = /^(?:mcp__([a-z0-9-]+)__|([a-z0-9-]+)\.|([a-z0-9-]+)_)/i.exec(name);
      return m ? (m[1] ?? m[2] ?? m[3]).toLowerCase() : null;
    };
    const selected: ToolCapability[] = [];
    const nsCounts = new Map<string, number>();
    const contextLimit = 10;
    for (const item of pool) {
      if (selected.length >= contextLimit) break;
      const ns = item.origin === "host" ? mcpNamespace(item.name) : null;
      if (ns && (nsCounts.get(ns) ?? 0) >= 2) continue;
      if (ns) nsCounts.set(ns, (nsCounts.get(ns) ?? 0) + 1);
      selected.push(item);
    }
    const header = [
      "Harness capabilities. The inventory is live and is not proof of tool use.",
      "Before acting, compare applicable tools with cyber_toolbox discover; do not claim unavailable tools were executed.",
    ];
    const noMatchNote =
      matched.length === 0
        ? selected.length > 0
          ? "No indexed match for query; top available tools:"
          : "No indexed match. Use cyber_toolbox discover with another query or propose an improvement after checking existing tools."
        : "";
    const footer =
      "A validated managed script is immediately callable via the normal permissioned shell/process tool; no new session required.";
    const rows: string[] = [];
    for (const item of selected) {
      const line =
        "- " +
        item.name +
        (item.version ? " v" + item.version : "") +
        " [" +
        item.origin +
        "]: " +
        (item.description || item.command || "").slice(0, 120);
      const candidate = [...header, ...(noMatchNote ? [noMatchNote] : []), ...rows, line, footer]
        .join("\n");
      if (candidate.length > 1500) break;
      rows.push(line);
    }
    return [...header, ...(noMatchNote ? [noMatchNote] : []), ...rows, footer]
      .join("\n")
      .slice(0, 1500);
  }
  /**
   * A conservative command-line hint. Mentions, comments and echo are never
   * evidence of execution. The caller must also identify an execution tool.
   */
  matchExecution(scope: string, input: unknown, tool = ""):
    { name: string; version: number; scope: string } | null {
    if (!/(?:shell|bash|process|exec|terminal|command)/i.test(tool))
      return null;
    const invocation = invocationFromInput(input);
    if (!invocation) return null;
    for (const entry of this.available(scope)) {
      if (directInvocation(invocation, entry.file))
        return { name: entry.name, version: entry.version, scope: entry.scope };
    }
    return null;
  }
}
