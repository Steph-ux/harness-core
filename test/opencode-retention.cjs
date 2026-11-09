/**
 * Retention removes transcripts, never evidence.
 *
 * A message older than the window leaves the store and the search index; an
 * observation of the same session stays, because it is what a claim rests on.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti }) => {
  const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
  const { scopeFor } = jiti(path.join(CORE, "src", "util.ts"));
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "harness-retention-"));
  const scope = scopeFor(base);
  const store = new KnowledgeStore(path.join(base, "knowledge.sqlite"));
  const day = 86400_000;
  const old = new Date(Date.now() - 400 * day).toISOString();
  const fresh = new Date(Date.now() - 10 * day).toISOString();
  try {
    store.upsertSession({
      id: "ses_old",
      scope,
      cwd: base,
      status: "completed",
      updatedAt: old,
    });
    store.upsertSession({
      id: "ses_new",
      scope,
      cwd: base,
      status: "completed",
      updatedAt: fresh,
    });
    store.recordMessage("ses_old", scope, "msg-old", "user", "ancien transcript", old);
    store.recordMessage("ses_new", scope, "msg-new", "user", "transcript recent", fresh);
    const kept = store.recordObservation({
      id: "obs-retention",
      sessionId: "ses_old",
      scope,
      tool: "shell",
      input: {},
      output: "preuve conservee",
      success: true,
      timestamp: old,
    });
    store.audit(scope, "retention.keep", { note: "audit stays" });

    assert.equal(store.pruneMessages(90, true), 1, "one message is out of the window");
    assert.equal(store.pruneMessages(90), 1, "the old transcript is removed");
    assert.equal(store.pruneMessages(90), 0, "the window is idempotent");
    assert.equal(
      store.evidence(scope, [kept.id]).length,
      1,
      "an observation of the pruned session is evidence and stays",
    );
    assert.equal(
      store.audits(scope, "retention.keep", 10).length,
      1,
      "the audit log is append-only and untouched",
    );
    assert.equal(
      store.searchSessions(scope, "ancien").length,
      0,
      "the pruned transcript leaves the search index",
    );
    assert.equal(
      store.searchSessions(scope, "recent").length,
      1,
      "the kept transcript is still searchable",
    );
    assert.throws(() => store.pruneMessages(0), /retention window/);
    store.vacuum();

    // A database tagged version 2 already carries the observation columns.
    // Reopening it must migrate to 3, not replay the column migration.
    const { DatabaseSync } = require("node:sqlite");
    const legacy = path.join(base, "legacy.sqlite");
    const raw = new DatabaseSync(legacy);
    raw.exec(`
      CREATE TABLE observations(id TEXT PRIMARY KEY, session_id TEXT NOT NULL, scope TEXT NOT NULL, tool TEXT NOT NULL, input TEXT NOT NULL, output TEXT NOT NULL, success INTEGER NOT NULL, timestamp TEXT NOT NULL, hash TEXT NOT NULL, raw_hash TEXT, raw_bytes INTEGER, truncated INTEGER);
      CREATE TABLE messages(entry_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, scope TEXT NOT NULL, role TEXT NOT NULL, text TEXT NOT NULL, timestamp TEXT NOT NULL);
      CREATE VIRTUAL TABLE messages_fts USING fts5(entry_id UNINDEXED, scope UNINDEXED, text);
      PRAGMA user_version=2;`);
    raw.close();
    const migrated = new KnowledgeStore(legacy);
    migrated.close();
    const check = new DatabaseSync(legacy);
    assert.equal(
      check.prepare("PRAGMA user_version").get().user_version,
      3,
      "a version 2 database migrates to 3 without replaying a column add",
    );
    check.close();
  } finally {
    store.close();
    fs.rmSync(base, { recursive: true, force: true });
  }
};
