import * as fs from "node:fs";
import * as path from "node:path";
import { createHash, randomUUID } from "node:crypto";
export const now = () => new Date().toISOString();
export const newId = () => randomUUID();
export const hash = (value: string) =>
  createHash("sha256").update(value).digest("hex");
/**
 * Where the workspace aliases live.
 *
 * The alias file maps a current workspace path to the scope it had on the
 * previous operating system, so evidence collected before the move stays
 * reachable. Several hosts share that mapping, so the location is not owned
 * by any one of them: it is resolved from the environment first, then from a
 * shared configuration directory.
 */
export function aliasFilePath(): string {
  const override = process.env.HARNESS_SCOPE_ALIASES;
  if (typeof override === "string" && override.trim())
    return path.resolve(override.trim());
  const home = process.env.USERPROFILE || process.env.HOME || "";
  return path.join(home, ".config", "harness-core", "scope-aliases.json");
}
export function scopeFor(cwd: string, aliasFile = aliasFilePath()): string {
  let canonical = path.resolve(cwd);
  try {
    canonical = fs.realpathSync.native(canonical);
  } catch {
    /* An absent workspace still gets an isolated scope. */
  }
  if (process.platform === "win32") canonical = canonical.toLowerCase();
  if (process.platform !== "win32" && fs.existsSync(aliasFile)) {
    const config = JSON.parse(fs.readFileSync(aliasFile, "utf8"));
    if (config.version !== 1 || !Array.isArray(config.entries))
      throw new Error("Invalid scope alias configuration");
    const paths = new Set<string>(),
      scopes = new Set<string>();
    let matched: string | undefined;
    for (const entry of config.entries) {
      if (
        !entry ||
        typeof entry.linuxCwd !== "string" ||
        !path.isAbsolute(entry.linuxCwd) ||
        typeof entry.historicalCwd !== "string" ||
        !/^[A-Za-z]:\\/.test(entry.historicalCwd) ||
        entry.historicalScope !==
          `project-${hash(entry.historicalCwd.toLowerCase()).slice(0, 24)}`
      )
        throw new Error("Invalid scope alias entry");
      let linuxCwd = path.resolve(entry.linuxCwd);
      try {
        linuxCwd = fs.realpathSync.native(linuxCwd);
      } catch {
        /* Workspace may not exist yet. */
      }
      if (paths.has(linuxCwd) || scopes.has(entry.historicalScope))
        throw new Error("Duplicate scope alias entry");
      paths.add(linuxCwd);
      scopes.add(entry.historicalScope);
      if (canonical === linuxCwd || cwd === entry.historicalCwd)
        matched = entry.historicalScope;
    }
    if (matched) return matched;
  }
  return `project-${hash(canonical).slice(0, 24)}`;
}
export function redactText(text: string): string {
  return text
    .replace(
      /(["'](?:password|passwd|motdepasse|mot_de_passe|pwd|secret|client_secret|api[_-]?key|access[_-]?token|refresh[_-]?token|remember[_-]?token|session[_-]?token|authorization|cookie|set-cookie|private[_-]?key)["']\s*:\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^,}\]\s]+)/gi,
      '$1"<REDACTED>"',
    )
    .replace(
      /^(\s*(?:set-cookie|cookie|authorization|proxy-authorization|x-api-key)\s*:\s*).*$/gim,
      "$1<REDACTED>",
    )
    .replace(
      /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g,
      "<REDACTED PRIVATE KEY>",
    )
    .replace(/\b\d{6,12}:[A-Za-z0-9_-]{30,}\b/g, "<REDACTED BOT TOKEN>")
    .replace(
      /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b/g,
      "<REDACTED TOKEN>",
    )
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer <REDACTED>")
    .replace(
      /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
      "<REDACTED JWT>",
    )
    .replace(
      /((?:password|passwd|motdepasse|mot_de_passe|pwd|client_secret|remember[_-]?token|session[_-]?token|api[_-]?key|access[_-]?token|refresh[_-]?token|botToken|authorization)\s*[=:]\s*["']?)[^\s,"'}]+/gi,
      "$1<REDACTED>",
    )
    .replace(/(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, "$1<REDACTED>@");
}
export function redact(value: unknown, depth = 0): unknown {
  if (depth > 20) return "<MAX DEPTH>";
  if (typeof value === "string") return redactText(value);
  if (Array.isArray(value))
    return value.slice(0, 1000).map((entry) => redact(entry, depth + 1));
  if (value && typeof value === "object") {
    const output: Record<string, unknown> = Object.create(null);
    for (const [key, item] of Object.entries(value).slice(0, 1000)) {
      output[key] =
        /^(?:password|passwd|motdepasse|mot_de_passe|pwd|client_secret|remember[_-]?token|session[_-]?token|api[_-]?key|access[_-]?token|refresh[_-]?token|bottoken|authorization|cookie|set-cookie|secret|private[_-]?key)$/i.test(
          key,
        )
          ? "<REDACTED>"
          : redact(item, depth + 1);
    }
    return output;
  }
  return value;
}
export function json(value: unknown): string {
  return JSON.stringify(redact(value));
}
export function textOf(value: unknown): string {
  if (typeof value === "string") return redactText(value);
  if (
    value &&
    typeof value === "object" &&
    typeof (value as { content?: unknown }).content === "string"
  )
    return redactText((value as { content: string }).content);
  if (
    value &&
    typeof value === "object" &&
    Array.isArray((value as { content?: unknown }).content)
  ) {
    return (value as { content: { type?: string; text?: string }[] }).content
      .filter((part) => part.type === "text" && typeof part.text === "string")
      .map((part) => redactText(part.text!))
      .join("\n");
  }
  return json(value) ?? "";
}
export function assertLearningText(value: string): void {
  if (typeof value !== "string" || !value.trim() || value.length > 24000)
    throw new Error("Invalid learning text length");
  if (/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/u.test(value))
    throw new Error(
      "Invisible control characters are not accepted in learned instructions",
    );
  if (
    /ignore\s+(?:all\s+|the\s+)?(?:previous|system|developer)\s+instructions|(?:disable|bypass)\s+(?:the\s+)?(?:permission|approval|scope)\s+(?:checks?|controls?|guards?)|(?:print|send|upload|reveal)\s+(?:all\s+)?(?:api keys|credentials|auth\.json|bot tokens)/i.test(
      value,
    )
  ) {
    throw new Error(
      "Learned instructions cannot override authority or export credentials",
    );
  }
  if (redactText(value) !== value)
    throw new Error("Credentials must not enter learned knowledge");
}
export function assertPlainPath(file: string): void {
  const absolute = path.resolve(file),
    root = path.parse(absolute).root;
  let current = root;
  for (const segment of [
    "",
    ...path.relative(root, absolute).split(path.sep).filter(Boolean),
  ]) {
    if (segment) current = path.join(current, segment);
    const stat = fs.lstatSync(current, { throwIfNoEntry: false });
    if (!stat) continue;
    if (
      stat.isSymbolicLink() ||
      (!stat.isFile() && !stat.isDirectory()) ||
      (stat.isFile() && stat.nlink > 1)
    )
      throw new Error("Linked or special harness paths are not allowed");
    const normalize = (s: string) =>
      process.platform === "win32"
        ? path.normalize(s).toLowerCase()
        : path.normalize(s);
    // A file can disappear between lstat and realpath: another owner removed
    // it. An absent path is not a redirected one.
    let real: string;
    try {
      real = fs.realpathSync.native(current);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    if (normalize(real) !== normalize(path.resolve(current)))
      throw new Error("Redirected harness paths are not allowed");
  }
}
export function atomicWrite(file: string, content: string): void {
  assertPlainPath(file);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = `${file}.${randomUUID()}.tmp`;
  try {
    assertPlainPath(file);
    fs.writeFileSync(temp, content, { mode: 0o600, flag: "wx" });
    assertPlainPath(file);
    fs.renameSync(temp, file);
  } finally {
    if (fs.existsSync(temp)) fs.unlinkSync(temp);
  }
}
export function parseObject(text: string): Record<string, unknown> {
  const trimmed = text
    .trim()
    .replace(/^```(?:json)?\s*\n/i, "")
    .replace(/\n```\s*$/, "");
  const result: unknown = JSON.parse(trimmed);
  if (!result || typeof result !== "object" || Array.isArray(result))
    throw new Error("Expected one JSON object");
  return result as Record<string, unknown>;
}
