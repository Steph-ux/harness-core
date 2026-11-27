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
  const home = (process.env.USERPROFILE || process.env.HOME || "").trim();
  if (!home) return "";
  return path.join(path.resolve(home), ".config", "harness-core", "scope-aliases.json");
}
export function scopeFor(cwd: string, aliasFile = aliasFilePath()): string {
  let canonical = path.resolve(cwd);
  try {
    canonical = fs.realpathSync.native(canonical);
  } catch {
    /* An absent workspace still gets an isolated scope. */
  }
  if (process.platform === "win32") canonical = canonical.toLowerCase();
  if (process.platform !== "win32" && aliasFile && fs.existsSync(aliasFile)) {
    if (!fs.statSync(aliasFile).isFile())
      throw new Error("Invalid scope alias file");
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
const SECRET_KEY =
  "(?:password|passwd|motdepasse|mot_de_passe|pwd|secret|client_secret|private[_-]?key|remember[_-]?token|session[_-]?token|access[_-]?token|refresh[_-]?token|api[_-]?key|bot[_-]?token|auth[_-]?token|token|authorization|proxy-authorization|x-api-key|set-cookie|cookie)";
const JSON_SECRET_RE = new RegExp(
  `(["']${SECRET_KEY}["']\\s*:\\s*)("(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*'|[^,}\\]\\s]+)`,
  "gi",
);
const HEADER_LINE_RE =
  /^(\s*(?:set-cookie|cookie|authorization|proxy-authorization|x-api-key)\s*:\s*)(.+)$/gim;
const EQ_SECRET_RE = new RegExp(
  `(?<![A-Za-z])(${SECRET_KEY}\\s*=\\s*)("(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*'|[^\\s,"';}]+)`,
  "gi",
);
const COLON_SECRET_RE = new RegExp(
  `(?<![A-Za-z])(${SECRET_KEY}\\s*:)(\\s*)("(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*'|[^\\s,"'}]+)`,
  "gi",
);
const PROSE_CUE_BEFORE =
  /\b(?:test|verify|check|validate|audit|ensure|enforce|review|rotate|expire|require|requires|missing|weak|broken|bypass|for)\s+$/i;

export function redactText(text: string): string {
  return text
    .replace(JSON_SECRET_RE, '$1"<REDACTED>"')
    .replace(HEADER_LINE_RE, (full, prefix: string, val: string) => {
      const trimmed = val.trim();
      const isHeaderSecret =
        /^(?:Bearer|Basic|Digest|Token|AWS4-[A-Z0-9-]+|Negotiate|NTLM)\s+/i.test(
          trimmed,
        ) ||
        trimmed.includes("=") ||
        !/\s/.test(trimmed) ||
        /^["']/.test(trimmed) ||
        /[0-9+/=_$-]/.test(trimmed);
      return isHeaderSecret ? `${prefix}<REDACTED>` : full;
    })
    .replace(
      /-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g,
      "<REDACTED PRIVATE KEY>",
    )
    .replace(
      /-----BEGIN [^-]*PRIVATE KEY-----(?:[ \t]*\r?\n[A-Za-z0-9+/=]{1,120})*/g,
      "<REDACTED PRIVATE KEY>",
    )
    .replace(/\b\d{6,12}:[A-Za-z0-9_-]{30,}\b/g, "<REDACTED BOT TOKEN>")
    .replace(
      /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16})\b/g,
      "<REDACTED TOKEN>",
    )
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer <REDACTED>")
    .replace(
      /((?:authorization|proxy-authorization)\s*[=:]\s*["']?Basic\s+)[A-Za-z0-9+/=]{4,}/gi,
      "$1<REDACTED>",
    )
    .replace(
      /\bBasic\s+(?=[A-Za-z0-9+/=]*(?:\d|[+/=]|[a-z][A-Z]|[A-Z][a-z][A-Z]))[A-Za-z0-9+/]{6,}={0,2}\b/g,
      "Basic <REDACTED>",
    )
    .replace(
      /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
      "<REDACTED JWT>",
    )
    .replace(EQ_SECRET_RE, (_full, prefix: string, val: string) => {
      if (val.startsWith('"')) return `${prefix}"<REDACTED>"`;
      if (val.startsWith("'")) return `${prefix}'<REDACTED>'`;
      return `${prefix}<REDACTED>`;
    })
    .replace(
      COLON_SECRET_RE,
      (full, prefix: string, ws: string, val: string, offset: number, str: string) => {
        if (val.startsWith('"')) return `${prefix}${ws}"<REDACTED>"`;
        if (val.startsWith("'")) return `${prefix}${ws}'<REDACTED>'`;
        if (!ws) return `${prefix}${ws}<REDACTED>`;
        const hasSecretChars = /[0-9_/+=$!@#%^&*~`\\]/.test(val);
        if (!hasSecretChars && /^[A-Za-z.,;!?-]+$/.test(val)) {
          const after = str.slice(offset + full.length);
          const before = str.slice(Math.max(0, offset - 32), offset);
          if (/^[ \t]+[A-Za-z]/.test(after) || PROSE_CUE_BEFORE.test(before))
            return full;
        }
        return `${prefix}${ws}<REDACTED>`;
      },
    )
    .replace(/([a-z][a-z0-9+.-]*:\/\/)[^\s/@]*:[^\s/@]+@/gi, "$1<REDACTED>@");
}
const REDACTED_KEY_RE =
  /^(?:password|passwd|motdepasse|mot_de_passe|pwd|secret|client_secret|private[_-]?key|remember[_-]?token|session[_-]?token|access[_-]?token|refresh[_-]?token|api[_-]?key|bottoken|bot[_-]?token|auth[_-]?token|token|authorization|proxy-authorization|x-api-key|cookie|set-cookie)$/i;
export function redact(value: unknown, depth = 0): unknown {
  if (depth > 20) return "<MAX DEPTH>";
  if (typeof value === "string") return redactText(value);
  if (value instanceof Date)
    return Number.isNaN(value.getTime()) ? "Invalid Date" : value.toISOString();
  if (value instanceof Error) {
    const out: Record<string, unknown> = Object.create(null);
    out.name = value.name;
    out.message = redactText(value.message);
    if (typeof value.stack === "string") out.stack = redactText(value.stack);
    return out;
  }
  if (value instanceof Map) {
    return [...value.entries()].slice(0, 1000).map(([key, item]) => [
      redact(key, depth + 1),
      typeof key === "string" && REDACTED_KEY_RE.test(key)
        ? "<REDACTED>"
        : redact(item, depth + 1),
    ]);
  }
  if (value instanceof Set) {
    return [...value.values()]
      .slice(0, 1000)
      .map((entry) => redact(entry, depth + 1));
  }
  if (Array.isArray(value))
    return value.slice(0, 1000).map((entry) => redact(entry, depth + 1));
  if (value && typeof value === "object") {
    const output: Record<string, unknown> = Object.create(null);
    for (const [key, item] of Object.entries(value).slice(0, 1000)) {
      output[key] = REDACTED_KEY_RE.test(key)
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
  if (
    /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/u.test(
      value,
    )
  )
    throw new Error(
      "Control characters are not accepted in learned instructions",
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
  if (typeof file !== "string" || !file.trim())
    throw new Error("Invalid harness path");
  const absolute = path.resolve(file),
    root = path.parse(absolute).root;
  // The volume must be the one it is named as. A SUBST drive (X:) points at
  // another directory and can be remapped between two runs, so the state
  // would move without the path ever changing.
  let realRoot: string;
  try {
    realRoot = fs.realpathSync.native(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    realRoot = root;
  }
  const normalize = (s: string) =>
    process.platform === "win32"
      ? path.normalize(s).toLowerCase()
      : path.normalize(s);
  if (normalize(realRoot) !== normalize(root))
    throw new Error("Redirected harness paths are not allowed");
  let current = root;
  for (const segment of [
    "",
    ...path.relative(root, absolute).split(path.sep).filter(Boolean),
  ]) {
    if (segment) current = path.join(current, segment);
    const stat = fs.lstatSync(current, { throwIfNoEntry: false });
    if (!stat) continue;
    // A component that is a link points somewhere else: it is refused
    // whether it names a file or a directory, and whether the link is a
    // symbolic link or a Windows junction.
    if (
      stat.isSymbolicLink() ||
      (!stat.isFile() && !stat.isDirectory()) ||
      (stat.isFile() && stat.nlink > 1)
    )
      throw new Error("Linked or special harness paths are not allowed");
    // A short name is an alias, not a redirection: Windows keeps
    // C:\Users\STEPHA~1 for C:\Users\stephanea, where lstat sees a plain
    // directory rather than a symlink. The component is compared by the object
    // it denotes so aliases pass while redirections are refused.
    let real: string, parent: string;
    try {
      real = fs.realpathSync.native(current);
      parent = fs.realpathSync.native(path.dirname(current));
    } catch (error) {
      // A file can disappear between lstat and realpath, or Windows can
      // refuse realpath on an exclusively locked file (EPERM). On POSIX,
      // EPERM/EACCES must fail rather than bypass the redirection check.
      const code = (error as NodeJS.ErrnoException).code;
      if (
        code === "ENOENT" ||
        (process.platform === "win32" && stat.isFile() && code === "EPERM")
      )
        continue;
      throw error;
    }
    const expected = path.join(parent, path.basename(current));
    const held = fs.lstatSync(expected, { throwIfNoEntry: false });
    const resolved = fs.lstatSync(real, { throwIfNoEntry: false });
    if (!held || !resolved) continue;
    // lstat does not follow the last link, so the two differ exactly when
    // the component points elsewhere. The comparison is made on the object
    // the component denotes, not on the way it is spelled.
    if (held.isSymbolicLink() !== resolved.isSymbolicLink())
      throw new Error("Redirected harness paths are not allowed");
    if (
      !held.isSymbolicLink() &&
      (held.dev !== resolved.dev || held.ino !== resolved.ino)
    )
      throw new Error("Redirected harness paths are not allowed");
  }
}
export function atomicWrite(file: string, content: string): void {
  if (typeof file !== "string" || !file.trim())
    throw new Error("Invalid file path");
  assertPlainPath(file);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temp = `${file}.${randomUUID()}.tmp`;
  try {
    assertPlainPath(file);
    fs.writeFileSync(temp, content, { mode: 0o600, flag: "wx" });
    assertPlainPath(file);
    fs.renameSync(temp, file);
  } finally {
    try {
      fs.unlinkSync(temp);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
}
export function parseObject(text: string): Record<string, unknown> {
  const trimmed = text
    .trim()
    .replace(/^```(?:json)?(?:\s*\r?\n|\s*)/i, "")
    .replace(/(?:\r?\n|\s*)```\s*$/, "")
    .trim();
  const result: unknown = JSON.parse(trimmed, (key, value) =>
    key === "__proto__" ? undefined : value,
  );
  if (!result || typeof result !== "object" || Array.isArray(result))
    throw new Error("Expected one JSON object");
  return result as Record<string, unknown>;
}
