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
  const db = new DatabaseSync(file);
  db.exec("PRAGMA busy_timeout=3000; PRAGMA journal_mode=WAL;");
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
  const colors = { critical: "\x1b[91m", high: "\x1b[31m", medium: "\x1b[33m", low: "\x1b[36m", info: "\x1b[90m" };
  return (colors[sev] || "") + sev + "\x1b[0m";
}

function statusBadge(status) {
  const colors = { confirmed: "\x1b[92m", draft: "\x1b[33m", rejected: "\x1b[90m", open: "\x1b[36m" };
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
    const files = fs.readdirSync(captureDir).filter((f) => f.endsWith(".png"));
    console.log(`  Captures:      ${files.length} files`);
  }

  // Processes
  const procFile = path.join(ROOT, "processes.json");
  if (fs.existsSync(procFile)) {
    try {
      const procs = JSON.parse(fs.readFileSync(procFile, "utf8"));
      console.log(`  Processes:     ${Object.keys(procs).length} tracked`);
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

    // Finding count for this mission
    const fc = db.prepare("SELECT count(*) as c, severity FROM findings WHERE mission_id=? GROUP BY severity ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END").all(r.id);
    if (fc.length) {
      const summary = fc.map((f) => `${f.c} ${f.severity}`).join(", ");
      console.log(`    findings: ${summary}`);
    }

    // Node progress
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

    // Evidence count
    const ev = db.prepare("SELECT count(*) as c FROM finding_evidence WHERE finding_id=?").all(r.id);
    if (ev[0]?.c) console.log(`    evidence: ${ev[0].c} observations`);

    // Verification
    const ver = db.prepare("SELECT * FROM finding_verifications WHERE finding_id=?").get(r.id);
    if (ver) console.log(`    verified: ${fmt(ver.timestamp)} (attempt ${ver.attempt})`);
    console.log();
  }
  db.close();
}

function cmdCaptures(missionId) {
  // Look in both default capture dir and engagement capture dirs
  const dirs = [path.join(ROOT, "captures")];

  if (missionId) {
    const db = openDb(PLATFORM_DB);
    if (db) {
      const root = db.prepare("SELECT root FROM mission_roots WHERE mission_id=?").get(missionId);
      if (root?.root) dirs.push(path.join(root.root, "preuves", "captures"));
      db.close();
    }
  }

  let total = 0;
  for (const dir of dirs) {
    if (!fs.existsSync(dir)) continue;
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".png")).sort();
    if (!files.length) continue;

    console.log(`\x1b[1mCaptures\x1b[0m in ${dir} (${files.length})\n`);
    for (const f of files) {
      const stat = fs.statSync(path.join(dir, f));
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

function cmdExport(missionId, outDir) {
  const db = openDb(PLATFORM_DB);
  if (!db) { console.error("Platform DB not found"); process.exit(1); }

  const mission = missionId
    ? db.prepare("SELECT * FROM missions WHERE id=?").get(missionId)
    : db.prepare("SELECT m.* FROM missions m JOIN active_missions a ON m.id=a.id LIMIT 1").get();
  if (!mission) { console.error("No mission found"); db.close(); process.exit(1); }

  const dir = outDir || path.join(ROOT, "exports", `${mission.id}-${Date.now()}`);
  fs.mkdirSync(dir, { recursive: true });

  // Mission metadata
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

  fs.writeFileSync(path.join(dir, "mission.json"), JSON.stringify(bundle, null, 2));
  fs.writeFileSync(path.join(dir, "entities.json"), JSON.stringify(entities, null, 2));
  fs.writeFileSync(path.join(dir, "relations.json"), JSON.stringify(relations, null, 2));

  // Copy captures
  const root = db.prepare("SELECT root FROM mission_roots WHERE mission_id=?").get(mission.id);
  if (root?.root) {
    const captDir = path.join(root.root, "preuves", "captures");
    if (fs.existsSync(captDir)) {
      const captOut = path.join(dir, "captures");
      fs.mkdirSync(captOut, { recursive: true });
      for (const f of fs.readdirSync(captDir)) {
        fs.copyFileSync(path.join(captDir, f), path.join(captOut, f));
      }
    }
  }

  // Export observations linked to findings
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
    fs.writeFileSync(path.join(dir, "observations.json"), JSON.stringify(observations, null, 2));
    knowledge.close();
  }

  db.close();
  console.log(`\x1b[92mExported\x1b[0m to ${dir}`);
  console.log(`  mission.json, entities.json, relations.json, observations.json`);
  if (root?.root) console.log(`  captures/ copied`);
}

// ─── Argument parsing ───────────────────────────────────────────────────────

const [subcmd, ...rest] = process.argv.slice(2);

function getArg(name) {
  const i = rest.indexOf(name);
  if (i === -1) return undefined;
  return rest[i + 1];
}

switch (subcmd) {
  case "status":
    cmdStatus();
    break;
  case "missions":
    cmdMissions(getArg("--scope"));
    break;
  case "findings":
    cmdFindings(getArg("--mission"));
    break;
  case "captures":
    cmdCaptures(getArg("--mission"));
    break;
  case "observations":
    cmdObservations(getArg("--session"));
    break;
  case "knowledge":
    cmdKnowledge(getArg("--scope"));
    break;
  case "export":
    cmdExport(getArg("--mission"), rest.find((a) => !a.startsWith("--") && a !== getArg("--mission")));
    break;
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
