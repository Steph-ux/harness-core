#!/usr/bin/env node
/**
 * Sync repository .opencode/skills/* into an OpenCode skills directory
 * (default ~/.config/opencode/skills) without copying runtime state or
 * touching unrelated skills in the destination.
 *
 * Usage:
 *   node scripts/sync-skills.cjs [--dest DIR] [--dry-run] [--check]
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomUUID } = require("node:crypto");

const RUNTIME_EXCLUDED_NAMES = new Set([
  ".git",
  ".DS_Store",
  "node_modules",
  "__pycache__",
  "processes.json",
  "processes-archive.json",
]);

function isExcludedName(name) {
  if (RUNTIME_EXCLUDED_NAMES.has(name)) return true;
  if (name.endsWith(".sqlite") || name.endsWith(".sqlite-wal") || name.endsWith(".sqlite-shm") || name.endsWith(".sqlite-journal"))
    return true;
  if (name.includes(".bak-") || name.endsWith(".pyc") || name.endsWith(".tmp"))
    return true;
  return false;
}

function assertPlainPath(file) {
  const absolute = path.resolve(file);
  const root = path.parse(absolute).root;
  let realRoot;
  try {
    realRoot = fs.realpathSync.native(root);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    realRoot = root;
  }
  const normalize = (s) =>
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
    if (
      stat.isSymbolicLink() ||
      (!stat.isFile() && !stat.isDirectory()) ||
      (stat.isFile() && stat.nlink > 1)
    )
      throw new Error(`Linked or special path is not allowed: ${current}`);
    let real, parent;
    try {
      real = fs.realpathSync.native(current);
      parent = fs.realpathSync.native(path.dirname(current));
    } catch (error) {
      const code = error?.code;
      if (code === "ENOENT" || code === "EPERM" || code === "EACCES") continue;
      throw error;
    }
    const expected = path.join(parent, path.basename(current));
    const held = fs.lstatSync(expected, { throwIfNoEntry: false });
    const resolved = fs.lstatSync(real, { throwIfNoEntry: false });
    if (!held || !resolved) continue;
    if (held.isSymbolicLink() !== resolved.isSymbolicLink())
      throw new Error(`Redirected path is not allowed: ${current}`);
    if (
      !held.isSymbolicLink() &&
      (held.dev !== resolved.dev || held.ino !== resolved.ino)
    )
      throw new Error(`Redirected path is not allowed: ${current}`);
  }
}

function defaultDest() {
  let home = (process.env.HOME || process.env.USERPROFILE || "").trim();
  if (!home) {
    try {
      home = os.homedir();
    } catch {
      home = "";
    }
  }
  if (!home) throw new Error("Cannot determine user home directory; pass --dest");
  return path.join(path.resolve(home), ".config", "opencode", "skills");
}

function collectSkillFiles(dir, relPrefix = "") {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = new Map();
  for (const entry of entries) {
    if (isExcludedName(entry.name)) continue;
    const full = path.join(dir, entry.name);
    const stat = fs.lstatSync(full);
    if (stat.isSymbolicLink()) continue;
    const rel = relPrefix ? path.posix.join(relPrefix, entry.name) : entry.name;
    if (stat.isDirectory()) {
      for (const [childRel, childInfo] of collectSkillFiles(full, rel)) {
        files.set(childRel, childInfo);
      }
    } else if (stat.isFile()) {
      files.set(rel, {
        full,
        mode: (stat.mode & 0o111) !== 0 ? 0o755 : 0o644,
      });
    }
  }
  return files;
}

function collectExistingFiles(dir, relPrefix = "") {
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const stat = fs.lstatSync(full);
    const rel = relPrefix ? path.posix.join(relPrefix, entry.name) : entry.name;
    if (stat.isSymbolicLink()) {
      throw new Error(`Linked destination entry is not allowed: ${full}`);
    }
    if (stat.isDirectory()) {
      out.push(...collectExistingFiles(full, rel));
    } else if (stat.isFile()) {
      out.push({ rel, full });
    }
  }
  return out;
}

function parseArgs(argv) {
  let src = path.resolve(__dirname, "..", ".opencode", "skills");
  let dest = "";
  let dryRun = false;
  let check = false;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--dest") {
      if (i + 1 >= argv.length || !argv[i + 1].trim())
        throw new Error("Missing value for --dest");
      dest = path.resolve(argv[++i]);
    } else if (arg === "--src") {
      if (i + 1 >= argv.length || !argv[i + 1].trim())
        throw new Error("Missing value for --src");
      src = path.resolve(argv[++i]);
    } else if (arg === "--dry-run") {
      dryRun = true;
    } else if (arg === "--check") {
      check = true;
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }
  if (!dest) dest = defaultDest();
  return { src, dest, dryRun, check };
}

function syncSkills(options = {}) {
  const src = path.resolve(
    options.src || path.resolve(__dirname, "..", ".opencode", "skills"),
  );
  const dest = path.resolve(options.dest || defaultDest());
  const dryRun = Boolean(options.dryRun);
  const check = Boolean(options.check);

  assertPlainPath(src);
  assertPlainPath(dest);
  if (!fs.existsSync(src) || !fs.statSync(src).isDirectory())
    throw new Error(`Source skills directory not found: ${src}`);

  const skillDirs = fs
    .readdirSync(src, { withFileTypes: true })
    .filter((entry) => {
      if (isExcludedName(entry.name)) return false;
      const full = path.join(src, entry.name);
      const stat = fs.lstatSync(full);
      if (stat.isSymbolicLink() || !stat.isDirectory()) return false;
      return fs.existsSync(path.join(full, "SKILL.md"));
    })
    .map((entry) => entry.name)
    .sort();

  const created = [];
  const updated = [];
  const removed = [];
  let unchanged = 0;

  if (!dryRun && !check) {
    fs.mkdirSync(dest, { recursive: true, mode: 0o755 });
  }

  for (const skill of skillDirs) {
    const srcSkillDir = path.join(src, skill);
    const destSkillDir = path.join(dest, skill);
    assertPlainPath(destSkillDir);
    const desired = collectSkillFiles(srcSkillDir);
    const existing = collectExistingFiles(destSkillDir);
    const existingMap = new Map(existing.map((e) => [e.rel, e.full]));

    for (const [rel, info] of desired) {
      const target = path.join(destSkillDir, ...rel.split("/"));
      assertPlainPath(target);
      const srcBytes = fs.readFileSync(info.full);
      if (!existingMap.has(rel)) {
        created.push(`${skill}/${rel}`);
        if (!dryRun && !check) {
          fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
          const temp = `${target}.${randomUUID()}.tmp`;
          try {
            fs.writeFileSync(temp, srcBytes, { mode: info.mode, flag: "wx" });
            fs.renameSync(temp, target);
            fs.chmodSync(target, info.mode);
          } finally {
            if (fs.existsSync(temp)) fs.unlinkSync(temp);
          }
        }
      } else {
        const dstBytes = fs.readFileSync(target);
        if (!srcBytes.equals(dstBytes)) {
          updated.push(`${skill}/${rel}`);
          if (!dryRun && !check) {
            const temp = `${target}.${randomUUID()}.tmp`;
            try {
              fs.writeFileSync(temp, srcBytes, { mode: info.mode, flag: "wx" });
              fs.renameSync(temp, target);
              fs.chmodSync(target, info.mode);
            } finally {
              if (fs.existsSync(temp)) fs.unlinkSync(temp);
            }
          }
        } else {
          unchanged++;
        }
      }
    }

    for (const item of existing) {
      if (!desired.has(item.rel)) {
        removed.push(`${skill}/${item.rel}`);
        if (!dryRun && !check) {
          fs.unlinkSync(item.full);
        }
      }
    }
  }

  const inSync =
    created.length === 0 && updated.length === 0 && removed.length === 0;
  return {
    src,
    dest,
    dryRun,
    check,
    skills: skillDirs.length,
    inSync,
    created,
    updated,
    removed,
    unchanged,
  };
}

module.exports = { syncSkills, parseArgs };

if (require.main === module) {
  const opts = parseArgs(process.argv.slice(2));
  const result = syncSkills(opts);
  console.log(JSON.stringify(result, null, 2));
  if (opts.check && !result.inSync) process.exitCode = 1;
}
