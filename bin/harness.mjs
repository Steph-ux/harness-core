#!/usr/bin/env node
/**
 * harness — standalone CLI for the harness-core state.
 *
 * Reads the SQLite stores directly. No OpenCode session needed.
 *
 * Usage:
 *   harness status                        Overall state summary
 *   harness missions [--scope S]          List missions
 *   harness findings [--mission ID]       List findings
 *   harness captures [--mission ID]       List capture files
 *   harness observations [--session ID]   List observations
 *   harness knowledge [--scope S]         List knowledge records
 *   harness export [--mission ID] [DIR]   Export evidence bundle
 */
import { DatabaseSync } from "node:sqlite";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

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
      throw new Error("Linked or special harness paths are not allowed");
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
      throw new Error("Redirected harness paths are not allowed");
    if (
      !held.isSymbolicLink() &&
      (held.dev !== resolved.dev || held.ino !== resolved.ino)
    )
      throw new Error("Redirected harness paths are not allowed");
  }
}

const stateRoot = () => {
  const override = process.env.HARNESS_STATE_ROOT?.trim();
  if (override) return path.resolve(override);
  const home = process.env.HARNESS_HOME?.trim();
  if (home) return path.join(path.resolve(home), "state");
  return path.join(os.homedir(), ".local", "share", "harness-core", "state");
};

const ROOT = stateRoot();
const KNOWLEDGE_DB = path.join(ROOT, "knowledge.sqlite");
const PLATFORM_DB = path.join(ROOT, "platform.sqlite");

function openDb(file) {
  if (!fs.existsSync(file)) return null;
  for (const suffix of ["", "-wal", "-shm"]) assertPlainPath(file + suffix);
  if (!fs.statSync(file).isFile())
    throw new Error(`Database path is not a regular file: ${file}`);
  const db = new DatabaseSync(file, { readOnly: true });
  db.exec("PRAGMA busy_timeout=3000;");
  return db;
}

function fmt(date) {
  if (!date) return "—";
  return date.replace("T", " ").replace(/\.\d+Z$/, "");
}

function pad(str, len) {
  str = String(str);
  return str.length >= len ? str.slice(0, len) : str + " ".repeat(len - str.length);
}

function rpad(str, len) {
  str = String(str);
  return str.length >= len ? str.slice(0, len) : " ".repeat(len - str.length) + str;
}

function severityColor(sev) {
  const colors = {
    critical: "\x1b[91m",
    high: "\x1b[31m",
    medium: "\x1b[33m",
    low: "\x1b[36m",
    informational: "\x1b[90m",
    info: "\x1b[90m",
  };
  return (colors[sev] || "") + sev + "\x1b[0m";
}

function statusBadge(status) {
  const colors = {
    verified: "\x1b[92m",
    unverified: "\x1b[33m",
    disproven: "\x1b[90m",
  };
  return (colors[status] || "") + status + "\x1b[0m";
}

// ─── Subcommands ────────────────────────────────────────────────────────────

function cmdStatus() {
  const knowledge = openDb(KNOWLEDGE_DB);
  const platform = openDb(PLATFORM_DB);
  console.log(`\x1b[1mHarness State\x1b[0m  ${ROOT}\n`);

  if (knowledge) {
    const sessions = knowledge.prepare("SELECT count(*) as c FROM sessions").get();
    const observations = knowledge.prepare("SELECT count(*) as c FROM observations").get();
    const knowledgeRecs = knowledge.prepare("SELECT count(*) as c FROM knowledge WHERE status='active'").get();
    const auditEntries = knowledge.prepare("SELECT count(*) as c FROM audit_log").get();
    console.log(`  Sessions:      ${sessions.c}`);
    console.log(`  Observations:  ${observations.c}`);
    console.log(`  Knowledge:     ${knowledgeRecs.c} active`);
    console.log(`  Audit log:     ${auditEntries.c} entries`);
    knowledge.close();
  } else {
    console.log("  Knowledge DB:  not found");
  }

  if (platform) {
    const missions = platform.prepare("SELECT count(*) as c FROM missions").get();
    const findings = platform.prepare("SELECT count(*) as c FROM findings").get();
    const entities = platform.prepare("SELECT count(*) as c FROM entities").get();
    const active = platform.prepare("SELECT id FROM active_missions LIMIT 1").get();
    console.log(`  Missions:      ${missions.c}`);
    console.log(`  Findings:      ${findings.c}`);
    console.log(`  Entities:      ${entities.c}`);
    if (active) console.log(`  Active:        ${active.id}`);
    platform.close();
  } else {
    console.log("  Platform DB:   not found");
  }

  // Captures
  const captureDir = path.join(ROOT, "captures");
  if (fs.existsSync(captureDir)) {
    assertPlainPath(captureDir);
    if (fs.statSync(captureDir).isDirectory()) {
      const files = fs.readdirSync(captureDir).filter((f) => f.endsWith(".png"));
      console.log(`  Captures:      ${files.length} files`);
    }
  }

  // Processes
  const procFile = path.join(ROOT, "processes.json");
  if (fs.existsSync(procFile)) {
    try {
      assertPlainPath(procFile);
      const procs = JSON.parse(fs.readFileSync(procFile, "utf8"));
      const count = Array.isArray(procs) ? procs.length : Object.keys(procs).length;
      console.log(`  Processes:     ${count} tracked`);
    } catch { /* ignore */ }
  }
  console.log();
}

function cmdMissions(scope) {
  const db = openDb(PLATFORM_DB);
  if (!db) { console.error("Platform DB not found"); process.exit(1); }

  let rows;
  if (scope) {
    rows = db.prepare("SELECT m.*, mc.reason as closure_reason, mc.timestamp as closed_at FROM missions m LEFT JOIN mission_closures mc ON m.id=mc.mission_id AND m.scope=mc.scope WHERE m.scope=? ORDER BY m.created DESC").all(scope);
  } else {
    rows = db.prepare("SELECT m.*, mc.reason as closure_reason, mc.timestamp as closed_at FROM missions m LEFT JOIN mission_closures mc ON m.id=mc.mission_id AND m.scope=mc.scope ORDER BY m.created DESC").all();
  }

  if (!rows.length) { console.log("No missions found."); db.close(); return; }

  console.log(`\x1b[1mMissions\x1b[0m (${rows.length})\n`);
  for (const r of rows) {
    const status = r.closure_reason ? `\x1b[90mclosed\x1b[0m` : `\x1b[92mopen\x1b[0m`;
    console.log(`  \x1b[1m${r.id}\x1b[0m  ${status}  \x1b[90m${r.scope}\x1b[0m`);
    console.log(`    ${r.title}`);
    console.log(`    created ${fmt(r.created)}${r.closed_at ? `  closed ${fmt(r.closed_at)}` : ""}`);

    const fc = db.prepare("SELECT count(*) as c, severity FROM findings WHERE mission_id=? GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END").all(r.id);
    if (fc.length) {
      const summary = fc.map((f) => `${f.c} ${f.severity}`).join(", ");
      console.log(`    findings: ${summary}`);
    }

    const nodes = db.prepare("SELECT state, count(*) as c FROM nodes WHERE mission_id=? GROUP BY state").all(r.id);
    if (nodes.length) {
      const summary = nodes.map((n) => `${n.c} ${n.state}`).join(", ");
      console.log(`    stages: ${summary}`);
    }
    console.log();
  }
  db.close();
}

function cmdFindings(missionId) {
  const db = openDb(PLATFORM_DB);
  if (!db) { console.error("Platform DB not found"); process.exit(1); }

  let rows;
  if (missionId) {
    rows = db.prepare("SELECT * FROM findings WHERE mission_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created DESC").all(missionId);
  } else {
    rows = db.prepare("SELECT * FROM findings ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created DESC").all();
  }

  if (!rows.length) { console.log("No findings found."); db.close(); return; }

  console.log(`\x1b[1mFindings\x1b[0m (${rows.length})\n`);
  for (const r of rows) {
    console.log(`  ${severityColor(r.severity)}  ${statusBadge(r.status)}  \x1b[1m${r.title}\x1b[0m`);
    console.log(`    id: ${r.id}  mission: ${r.mission_id}  confidence: ${(r.confidence * 100).toFixed(0)}%`);
    if (r.description) console.log(`    ${r.description.slice(0, 120)}`);

    const ev = db.prepare("SELECT count(*) as c FROM finding_evidence WHERE finding_id=?").all(r.id);
    if (ev[0]?.c) console.log(`    evidence: ${ev[0].c} observations`);

    const ver = db.prepare("SELECT * FROM finding_verifications WHERE finding_id=?").get(r.id);
    if (ver) console.log(`    verified: ${fmt(ver.timestamp)} (attempt ${ver.attempt})`);
    console.log();
  }
  db.close();
}

function cmdCaptures(missionId) {
  const dirSet = new Set([path.resolve(ROOT, "captures")]);
  const db = openDb(PLATFORM_DB);
  if (db) {
    try {
      const roots = missionId
        ? db.prepare("SELECT root FROM mission_roots WHERE mission_id=?").all(missionId)
        : db.prepare("SELECT DISTINCT root FROM mission_roots").all();
      for (const row of roots) {
        if (row?.root) dirSet.add(path.resolve(row.root, "preuves", "captures"));
      }
    } finally {
      db.close();
    }
  }

  let total = 0;
  for (const dir of dirSet) {
    if (!fs.existsSync(dir)) continue;
    assertPlainPath(dir);
    if (!fs.statSync(dir).isDirectory()) continue;
    const files = fs
      .readdirSync(dir, { withFileTypes: true })
      .filter((entry) => entry.isFile() && !entry.isSymbolicLink() && entry.name.endsWith(".png"))
      .map((entry) => entry.name)
      .sort();
    if (!files.length) continue;

    console.log(`\x1b[1mCaptures\x1b[0m in ${dir} (${files.length})\n`);
    for (const f of files) {
      const filePath = path.join(dir, f);
      assertPlainPath(filePath);
      const stat = fs.statSync(filePath);
      if (!stat.isFile()) continue;
      const kb = (stat.size / 1024).toFixed(1);
      console.log(`  ${pad(f, 60)}  ${rpad(kb + " KB", 10)}  ${fmt(stat.mtime.toISOString())}`);
      total++;
    }
    console.log();
  }
  if (!total) console.log("No captures found.");
}

function cmdObservations(sessionId) {
  const db = openDb(KNOWLEDGE_DB);
  if (!db) { console.error("Knowledge DB not found"); process.exit(1); }

  let rows;
  if (sessionId) {
    rows = db.prepare("SELECT * FROM observations WHERE session_id=? ORDER BY timestamp DESC LIMIT 50").all(sessionId);
  } else {
    rows = db.prepare("SELECT * FROM observations ORDER BY timestamp DESC LIMIT 50").all();
  }

  if (!rows.length) { console.log("No observations found."); db.close(); return; }

  console.log(`\x1b[1mObservations\x1b[0m (showing ${rows.length})\n`);
  for (const r of rows) {
    const success = r.success ? "\x1b[92m✓\x1b[0m" : "\x1b[91m✗\x1b[0m";
    console.log(`  ${success} ${r.id}  \x1b[90m${r.tool}\x1b[0m  ${fmt(r.timestamp)}`);
    if (r.output) {
      const preview = r.output.replace(/\n/g, " ").slice(0, 100);
      console.log(`    ${preview}${r.output.length > 100 ? "…" : ""}`);
    }
  }
  console.log();
  db.close();
}

function cmdKnowledge(scope) {
  const db = openDb(KNOWLEDGE_DB);
  if (!db) { console.error("Knowledge DB not found"); process.exit(1); }

  let rows;
  if (scope) {
    rows = db.prepare("SELECT * FROM knowledge WHERE scope=? AND status='active' ORDER BY created_at DESC").all(scope);
  } else {
    rows = db.prepare("SELECT * FROM knowledge WHERE status='active' ORDER BY created_at DESC").all();
  }

  if (!rows.length) { console.log("No active knowledge records."); db.close(); return; }

  console.log(`\x1b[1mKnowledge\x1b[0m (${rows.length} active)\n`);
  for (const r of rows) {
    console.log(`  \x1b[1m${r.key}\x1b[0m  \x1b[90m${r.kind}\x1b[0m  \x1b[90m${r.scope}\x1b[0m`);
    console.log(`    ${r.content.slice(0, 120)}${r.content.length > 120 ? "…" : ""}`);
    console.log();
  }
  db.close();
}

function writeRestrictedJson(filePath, data) {
  assertPlainPath(filePath);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), { mode: 0o600 });
  if (process.platform !== "win32") fs.chmodSync(filePath, 0o600);
}

function cmdExport(missionId, outDir) {
  const db = openDb(PLATFORM_DB);
  if (!db) { console.error("Platform DB not found"); process.exit(1); }

  const mission = missionId
    ? db.prepare("SELECT * FROM missions WHERE id=?").get(missionId)
    : db.prepare("SELECT m.* FROM missions m JOIN active_missions a ON m.id=a.id LIMIT 1").get();
  if (!mission) { console.error("No mission found"); db.close(); process.exit(1); }

  const dir = path.resolve(
    outDir || path.join(ROOT, "exports", `${mission.id}-${Date.now()}`),
  );
  assertPlainPath(dir);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);

  const findings = db.prepare("SELECT * FROM findings WHERE mission_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END").all(mission.id);
  const nodes = db.prepare("SELECT * FROM nodes WHERE mission_id=? ORDER BY id").all(mission.id);
  const entities = db.prepare("SELECT * FROM entities WHERE scope=?").all(mission.scope);
  const relations = db.prepare("SELECT * FROM relations WHERE scope=?").all(mission.scope);
  const closure = db.prepare("SELECT * FROM mission_closures WHERE mission_id=?").get(mission.id);

  const bundle = {
    mission: { ...mission, closure: closure || null },
    findings,
    nodes,
    entities: entities.length,
    relations: relations.length,
    exportedAt: new Date().toISOString(),
  };

  writeRestrictedJson(path.join(dir, "mission.json"), bundle);
  writeRestrictedJson(path.join(dir, "entities.json"), entities);
  writeRestrictedJson(path.join(dir, "relations.json"), relations);

  let copiedCaptures = 0;
  const root = db.prepare("SELECT root FROM mission_roots WHERE mission_id=?").get(mission.id);
  if (root?.root) {
    const captDir = path.join(root.root, "preuves", "captures");
    if (fs.existsSync(captDir)) {
      assertPlainPath(captDir);
      if (fs.statSync(captDir).isDirectory()) {
        const captOut = path.join(dir, "captures");
        assertPlainPath(captOut);
        const entries = fs.readdirSync(captDir, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isSymbolicLink() || !entry.isFile()) continue;
          const srcFile = path.join(captDir, entry.name);
          assertPlainPath(srcFile);
          if (!copiedCaptures) {
            fs.mkdirSync(captOut, { recursive: true, mode: 0o700 });
            if (process.platform !== "win32") fs.chmodSync(captOut, 0o700);
          }
          const dstFile = path.join(captOut, entry.name);
          assertPlainPath(dstFile);
          fs.copyFileSync(srcFile, dstFile);
          if (process.platform !== "win32") fs.chmodSync(dstFile, 0o600);
          copiedCaptures++;
        }
      }
    }
  }

  let wroteObservations = false;
  const knowledge = openDb(KNOWLEDGE_DB);
  if (knowledge) {
    const obsIds = new Set();
    for (const f of findings) {
      const links = db.prepare("SELECT observation_id FROM finding_evidence WHERE finding_id=?").all(f.id);
      for (const l of links) obsIds.add(l.observation_id);
    }
    const observations = [];
    for (const oid of obsIds) {
      const obs = knowledge.prepare("SELECT * FROM observations WHERE id=?").get(oid);
      if (obs) observations.push(obs);
    }
    writeRestrictedJson(path.join(dir, "observations.json"), observations);
    wroteObservations = true;
    knowledge.close();
  }

  db.close();
  const files = ["mission.json", "entities.json", "relations.json"];
  if (wroteObservations) files.push("observations.json");
  console.log(`\x1b[92mExported\x1b[0m to ${dir}`);
  console.log(`  ${files.join(", ")}`);
  if (copiedCaptures > 0) console.log(`  captures/ copied (${copiedCaptures})`);
}

// ─── Argument parsing ───────────────────────────────────────────────────────

function parseCli(argv) {
  const [subcmd, ...rest] = argv;
  const flags = {};
  const positional = [];
  const VALUE_FLAGS = new Set(["--scope", "--mission", "--session", "--out", "--dir"]);
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (VALUE_FLAGS.has(arg)) {
      if (i + 1 >= rest.length || !rest[i + 1]) {
        console.error(`Missing value for ${arg}`);
        process.exit(1);
      }
      flags[arg.slice(2)] = rest[++i];
    } else if (arg.startsWith("--")) {
      console.error(`Unknown option: ${arg}`);
      process.exit(1);
    } else {
      positional.push(arg);
    }
  }
  return { subcmd, flags, positional };
}

function resolveExportArgs(flags, positional) {
  let missionId = flags.mission;
  let outDir = flags.out || flags.dir;
  if (missionId) {
    if (!outDir && positional.length) outDir = positional[0];
    return { missionId, outDir };
  }
  if (positional.length >= 2) {
    return { missionId: positional[0], outDir: outDir || positional[1] };
  }
  if (positional.length === 1) {
    const single = positional[0];
    if (outDir) return { missionId: single, outDir };
    const looksLikePath =
      single.includes("/") ||
      single.includes("\\") ||
      single === "." ||
      single === ".." ||
      (fs.existsSync(single) && fs.statSync(single).isDirectory());
    if (looksLikePath) return { missionId: undefined, outDir: single };
    return { missionId: single, outDir: undefined };
  }
  return { missionId, outDir };
}

const { subcmd, flags, positional } = parseCli(process.argv.slice(2));

switch (subcmd) {
  case "status":
    cmdStatus();
    break;
  case "missions":
    cmdMissions(flags.scope);
    break;
  case "findings":
    cmdFindings(flags.mission);
    break;
  case "captures":
    cmdCaptures(flags.mission);
    break;
  case "observations":
    cmdObservations(flags.session);
    break;
  case "knowledge":
    cmdKnowledge(flags.scope);
    break;
  case "export": {
    const { missionId, outDir } = resolveExportArgs(flags, positional);
    cmdExport(missionId, outDir);
    break;
  }
  default:
    console.log(`\x1b[1mharness\x1b[0m — CLI for harness-core state

Usage:
  harness status                         Overall state summary
  harness missions [--scope S]           List missions
  harness findings [--mission ID]        List findings
  harness captures [--mission ID]        List capture files
  harness observations [--session ID]    List observations
  harness knowledge [--scope S]          List knowledge records
  harness export [--mission ID] [DIR]    Export evidence bundle

Environment:
  HARNESS_STATE_ROOT    Override state directory
  HARNESS_HOME          Override harness home (~/.local/share/harness-core)

State: ${ROOT}
`);
}
