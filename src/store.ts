import * as fs from "node:fs";
import * as path from "node:path";
import { DatabaseSync } from "node:sqlite";
import type {
  KnowledgeProposal,
  KnowledgeRecord,
  Observation,
  OperatorRule,
  ReviewRecord,
  SearchHit,
  SessionRecord,
  StorePort,
} from "./types";
import {
  assertLearningText,
  assertPlainPath,
  hash,
  json,
  newId,
  now,
  redact,
  redactText,
} from "./util";

type Row = Record<string, any>;
function scopeCheck(scope: string): void {
  if (typeof scope !== "string" || !/^[a-z][a-z0-9-]{0,95}$/.test(scope))
    throw new Error("Invalid scope");
}
function idCheck(id: string): void {
  if (typeof id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(id))
    throw new Error("Invalid identifier");
}
function limitCheck(limit: number): void {
  if (!Number.isInteger(limit) || limit < 1 || limit > 200)
    throw new Error("Invalid limit (1..200)");
}
function stable(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, stable(v)]),
    );
  return value;
}
function stamp(value: string): void {
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value)))
    throw new Error("Invalid timestamp");
}

/** Durable, project-scoped evidence and semantic knowledge. SQL is always bound. */
export class KnowledgeStore implements StorePort {
  private db: DatabaseSync;
  private closed = false;
  constructor(private filename: string) {
    assertPlainPath(filename);
    fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
    for (const suffix of ["", "-wal", "-shm"])
      assertPlainPath(filename + suffix);
    this.db = new DatabaseSync(filename);
    this.db.exec(
      "PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL;",
    );
    try {
      this.migrate();
    } catch (e) {
      this.db.close();
      throw e;
    }
  }
  private migrate(): void {
    const version = Number(
      this.db.prepare("PRAGMA user_version").get()!.user_version,
    );
    if (version > 3)
      throw new Error("Knowledge database is newer than this harness");
    if (version === 3) return;
    if (version === 0)
      this.db.exec(`BEGIN IMMEDIATE;
      CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, scope TEXT NOT NULL, cwd TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(id,scope));
      CREATE TABLE IF NOT EXISTS messages (entry_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, scope TEXT NOT NULL, role TEXT NOT NULL, text TEXT NOT NULL, timestamp TEXT NOT NULL, FOREIGN KEY(session_id,scope) REFERENCES sessions(id,scope));
      CREATE INDEX IF NOT EXISTS messages_scope ON messages(scope,session_id,timestamp);
      CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(entry_id UNINDEXED,scope UNINDEXED,text);
      CREATE TRIGGER IF NOT EXISTS messages_fts_insert AFTER INSERT ON messages BEGIN INSERT INTO messages_fts(entry_id,scope,text) VALUES(new.entry_id,new.scope,new.text); END;
      CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY,session_id TEXT NOT NULL,scope TEXT NOT NULL,tool TEXT NOT NULL,input TEXT NOT NULL,output TEXT NOT NULL,success INTEGER NOT NULL,timestamp TEXT NOT NULL,hash TEXT NOT NULL, UNIQUE(id,scope),FOREIGN KEY(session_id,scope) REFERENCES sessions(id,scope));
      CREATE INDEX IF NOT EXISTS observations_session ON observations(scope,session_id,timestamp);
      CREATE TABLE IF NOT EXISTS knowledge (id TEXT PRIMARY KEY,scope TEXT NOT NULL,key TEXT NOT NULL,content TEXT NOT NULL,kind TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(id,scope));
      CREATE UNIQUE INDEX IF NOT EXISTS knowledge_active_key ON knowledge(scope,key) WHERE status='active';
      CREATE INDEX IF NOT EXISTS knowledge_scope ON knowledge(scope,status);
      CREATE TABLE IF NOT EXISTS knowledge_evidence (knowledge_id TEXT NOT NULL,observation_id TEXT NOT NULL,scope TEXT NOT NULL,ordinal INTEGER NOT NULL,PRIMARY KEY(knowledge_id,observation_id),FOREIGN KEY(knowledge_id,scope) REFERENCES knowledge(id,scope),FOREIGN KEY(observation_id,scope) REFERENCES observations(id,scope));
      CREATE TABLE IF NOT EXISTS reviews (session_id TEXT PRIMARY KEY,scope TEXT NOT NULL,digest TEXT NOT NULL,status TEXT NOT NULL,detail TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(session_id,scope) REFERENCES sessions(id,scope));
      CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT,scope TEXT NOT NULL,event TEXT NOT NULL,detail TEXT NOT NULL,timestamp TEXT NOT NULL);
      CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT,'Audit log is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT,'Audit log is append-only'); END;
      DELETE FROM messages_fts;
      INSERT INTO messages_fts(entry_id,scope,text) SELECT entry_id,scope,text FROM messages;
      PRAGMA user_version = 1;
      COMMIT;`);
    if (version < 2) {
      // Idempotent: a database that kept its columns but lost its version tag
      // must migrate, not fail on a duplicate column.
      const columns = new Set(
        this.db
          .prepare("PRAGMA table_info(observations)")
          .all()
          .map((row) => String(row.name)),
      );
      this.db.exec("BEGIN IMMEDIATE;");
      try {
        for (const [name, type] of [
          ["raw_hash", "TEXT"],
          ["raw_bytes", "INTEGER"],
          ["truncated", "INTEGER"],
        ] as const)
          if (!columns.has(name))
            this.db.exec(
              `ALTER TABLE observations ADD COLUMN ${name} ${type};`,
            );
        this.db.exec(`
      CREATE TRIGGER IF NOT EXISTS observations_no_update BEFORE UPDATE ON observations BEGIN SELECT RAISE(ABORT,'Immutable observation'); END;
      CREATE TRIGGER IF NOT EXISTS observations_no_delete BEFORE DELETE ON observations BEGIN SELECT RAISE(ABORT,'Immutable observation'); END;
      PRAGMA user_version=2; COMMIT;`);
      } catch (error) {
        this.db.exec("ROLLBACK");
        throw error;
      }
    }
    if (version < 3)
      this.db.exec(`BEGIN IMMEDIATE;
      CREATE TRIGGER IF NOT EXISTS messages_fts_delete AFTER DELETE ON messages BEGIN DELETE FROM messages_fts WHERE entry_id=old.entry_id; END;
      CREATE INDEX IF NOT EXISTS messages_timestamp ON messages(timestamp);
      PRAGMA user_version=3; COMMIT;`);
  }
  private open(): void {
    if (this.closed) throw new Error("Knowledge store is closed");
  }
  private session(id: string, scope: string): Row {
    this.open();
    scopeCheck(scope);
    idCheck(id);
    const session = this.db
      .prepare("SELECT * FROM sessions WHERE id=?")
      .get(id);
    if (!session) throw new Error("Missing session");
    if (session.scope !== scope) throw new Error("Session scope mismatch");
    return session;
  }
  upsertSession(session: SessionRecord): void {
    this.open();
    scopeCheck(session.scope);
    idCheck(session.id);
    stamp(session.updatedAt);
    if (
      !["active", "completed", "aborted", "error"].includes(session.status) ||
      typeof session.cwd !== "string"
    )
      throw new Error("Invalid session");
    const prior = this.db
      .prepare("SELECT scope FROM sessions WHERE id=?")
      .get(session.id);
    if (prior && prior.scope !== session.scope)
      throw new Error("Session scope collision");
    this.db
      .prepare(
        "INSERT INTO sessions VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at",
      )
      .run(
        session.id,
        session.scope,
        redactText(session.cwd),
        session.status,
        session.updatedAt,
      );
  }
  recordMessage(
    sessionId: string,
    scope: string,
    entryId: string,
    role: string,
    text: string,
    timestamp: string,
  ): void {
    this.session(sessionId, scope);
    idCheck(entryId);
    stamp(timestamp);
    if (
      !["user", "assistant", "toolResult", "custom", "summary"].includes(
        role,
      ) ||
      typeof text !== "string"
    )
      throw new Error("Invalid indexed message");
    const safe = redactText(text).slice(0, 100000);
    const existing = this.db
      .prepare("SELECT * FROM messages WHERE entry_id=?")
      .get(entryId);
    if (existing) {
      if (
        existing.session_id !== sessionId ||
        existing.scope !== scope ||
        existing.role !== role ||
        existing.text !== safe ||
        existing.timestamp !== timestamp
      )
        throw new Error("Message entry collision");
      return;
    }
    this.db
      .prepare(
        "INSERT INTO messages(entry_id,session_id,scope,role,text,timestamp) VALUES(?,?,?,?,?,?)",
      )
      .run(entryId, sessionId, scope, role, safe, timestamp);
  }
  recordObservation(observation: Omit<Observation, "hash">): Observation {
    this.open();
    if ("hash" in observation)
      throw new Error("Unexpected supplied observation hash");
    this.session(observation.sessionId, observation.scope);
    idCheck(observation.id);
    stamp(observation.timestamp);
    if (
      typeof observation.tool !== "string" ||
      !observation.tool ||
      typeof observation.output !== "string" ||
      typeof observation.success !== "boolean"
    )
      throw new Error("Invalid observation");
    // The digest covers content only. The timestamp is metadata: a session
    // resume replays the same tool result with a fresh timestamp, and that
    // must stay idempotent rather than read as tampering.
    const immutable = {
      id: observation.id,
      sessionId: observation.sessionId,
      scope: observation.scope,
      tool: observation.tool,
      input: stable(redact(observation.input)) ?? null,
      output: redactText(observation.output).slice(0, 24000),
      success: observation.success,
      rawHash: hash(observation.output),
      rawBytes: Buffer.byteLength(observation.output, "utf8"),
      truncated: redactText(observation.output).length > 24000,
    };
    const digest = hash(JSON.stringify(immutable));
    const prior = this.db
      .prepare("SELECT * FROM observations WHERE id=?")
      .get(observation.id);
    if (prior) {
      // Compare the stored fields, not the hash. Rows written before the
      // digest dropped the timestamp still match a replay of the same content.
      if (!this.sameObservationContent(prior, immutable))
        throw new Error("Immutable observation collision");
      return this.observation(prior);
    }
    this.db
      .prepare(
        "INSERT INTO observations(id,session_id,scope,tool,input,output,success,timestamp,hash,raw_hash,raw_bytes,truncated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
      )
      .run(
        immutable.id,
        immutable.sessionId,
        immutable.scope,
        immutable.tool,
        JSON.stringify(immutable.input),
        immutable.output,
        immutable.success ? 1 : 0,
        observation.timestamp,
        digest,
        immutable.rawHash,
        immutable.rawBytes,
        immutable.truncated ? 1 : 0,
      );
    return JSON.parse(
      JSON.stringify({
        ...immutable,
        timestamp: observation.timestamp,
        hash: digest,
      }),
    );
  }
  private sameObservationContent(
    row: Row,
    immutable: {
      sessionId: string;
      scope: string;
      tool: string;
      input: unknown;
      output: string;
      success: boolean;
      rawHash?: string;
      truncated?: boolean;
    },
  ): boolean {
    return (
      row.session_id === immutable.sessionId &&
      row.scope === immutable.scope &&
      row.tool === immutable.tool &&
      row.output === immutable.output &&
      (row.success === 1) === immutable.success &&
      row.input === JSON.stringify(immutable.input) &&
      (row.raw_hash ? row.raw_hash === immutable.rawHash : !immutable.truncated)
    );
  }
  private observation(row: Row): Observation {
    return {
      id: row.id,
      sessionId: row.session_id,
      scope: row.scope,
      tool: row.tool,
      input: JSON.parse(row.input),
      output: redactText(row.output),
      success: row.success === 1,
      timestamp: row.timestamp,
      hash: row.hash,
      ...(row.raw_hash
        ? {
            rawHash: String(row.raw_hash),
            rawBytes: Number(row.raw_bytes),
            truncated: Boolean(row.truncated),
          }
        : {}),
    };
  }
  evidence(scope: string, ids: string[]): Observation[] {
    this.open();
    scopeCheck(scope);
    if (!Array.isArray(ids) || ids.length > 200)
      throw new Error("Invalid evidence list");
    return [...new Set(ids)].map((id) => {
      idCheck(id);
      const row = this.db
        .prepare("SELECT * FROM observations WHERE id=?")
        .get(id);
      if (!row) throw new Error("Missing evidence");
      if (row.scope !== scope) throw new Error("Evidence scope mismatch");
      return this.observation(row);
    });
  }
  observationsForSession(
    sessionId: string,
    scope: string,
    limit = 100,
  ): Observation[] {
    this.session(sessionId, scope);
    limitCheck(limit);
    return this.db
      .prepare(
        "SELECT * FROM observations WHERE session_id=? AND scope=? ORDER BY rowid DESC LIMIT ?",
      )
      .all(sessionId, scope, limit)
      .reverse()
      .map((row) => this.observation(row));
  }
  /**
   * The sessions of a scope.
   *
   * A host that starts after a session ended still has to find it, to extract
   * what it taught.
   */
  sessionsForScope(
    scope: string,
    limit = 100,
  ): { id: string; status: string; updatedAt: string }[] {
    this.open();
    scopeCheck(scope);
    limitCheck(limit);
    return this.db
      .prepare(
        "SELECT id,status,updated_at FROM sessions WHERE scope=? ORDER BY updated_at DESC LIMIT ?",
      )
      .all(scope, limit)
      .map((row) => ({
        id: String(row.id),
        status: String(row.status),
        updatedAt: String(row.updated_at),
      }));
  }
  private knowledge(row: Row): KnowledgeRecord {
    const evidence = this.db
      .prepare(
        "SELECT observation_id FROM knowledge_evidence WHERE knowledge_id=? AND scope=? ORDER BY ordinal",
      )
      .all(row.id, row.scope)
      .map((r) => String(r.observation_id));
    return {
      id: row.id,
      scope: row.scope,
      key: row.key,
      content: row.content,
      kind: row.kind,
      status: row.status,
      createdAt: row.created_at,
      evidence,
    };
  }
  observationsAfter(
    scope: string,
    cursor: number,
    limit = 200,
  ): { cursor: number; observation: Observation }[] {
    this.open();
    scopeCheck(scope);
    limitCheck(limit);
    if (!Number.isSafeInteger(cursor) || cursor < 0)
      throw new Error("Invalid observation cursor");
    return this.db
      .prepare(
        "SELECT rowid AS cursor,* FROM observations WHERE scope=? AND rowid>? ORDER BY rowid LIMIT ?",
      )
      .all(scope, cursor, limit)
      .map((row) => ({
        cursor: Number(row.cursor),
        observation: this.observation(row),
      }));
  }
  proposeKnowledge(
    scope: string,
    proposal: KnowledgeProposal,
  ): KnowledgeRecord {
    this.open();
    scopeCheck(scope);
    if (!proposal || typeof proposal !== "object")
      throw new Error("Invalid knowledge proposal");
    if (
      typeof proposal.key !== "string" ||
      !/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/.test(proposal.key) ||
      proposal.key.length > 96
    )
      throw new Error("Invalid knowledge key slug");
    assertLearningText(proposal.content);
    if (
      !["environment", "workflow", "false-positive", "preference"].includes(
        proposal.kind,
      )
    )
      throw new Error("Invalid knowledge kind");
    if (!Array.isArray(proposal.evidence) || !proposal.evidence.length)
      throw new Error("Knowledge requires evidence");
    const evidence = this.evidence(scope, proposal.evidence);
    if (!evidence.some((item) => item.success))
      throw new Error("Knowledge requires successful evidence");
    const duplicate = this.db
      .prepare(
        "SELECT * FROM knowledge WHERE scope=? AND key=? AND content=? AND kind=? AND status IN ('active','pending') ORDER BY created_at DESC LIMIT 1",
      )
      .get(scope, proposal.key, proposal.content, proposal.kind);
    if (duplicate) return this.knowledge(duplicate);
    const conflict = this.db
      .prepare(
        "SELECT id FROM knowledge WHERE scope=? AND key=? AND status='active'",
      )
      .get(scope, proposal.key);
    const id = newId(),
      createdAt = now(),
      status = conflict ? "pending" : "active";
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db
        .prepare("INSERT INTO knowledge VALUES(?,?,?,?,?,?,?)")
        .run(
          id,
          scope,
          proposal.key,
          proposal.content,
          proposal.kind,
          status,
          createdAt,
        );
      evidence.forEach((item, index) =>
        this.db
          .prepare("INSERT INTO knowledge_evidence VALUES(?,?,?,?)")
          .run(id, item.id, scope, index),
      );
      this.db.exec("COMMIT");
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
    return this.knowledge(
      this.db.prepare("SELECT * FROM knowledge WHERE id=?").get(id)!,
    );
  }
  /**
   * Declare an operator rule. Unlike learned knowledge, a rule is stated by the
   * operator rather than inferred from tool runs, so it carries no evidence and
   * becomes active immediately. Setting the same key replaces the rule.
   */
  setOperatorRule(scope: string, rule: OperatorRule): KnowledgeRecord {
    this.open();
    scopeCheck(scope);
    if (!rule || typeof rule !== "object")
      throw new Error("Invalid operator rule");
    if (
      typeof rule.key !== "string" ||
      !/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/.test(rule.key) ||
      rule.key.length > 96
    )
      throw new Error("Invalid knowledge key slug");
    assertLearningText(rule.content);
    const existing = this.db
      .prepare(
        "SELECT * FROM knowledge WHERE scope=? AND key=? AND kind='operator' ORDER BY created_at DESC LIMIT 1",
      )
      .get(scope, rule.key);
    if (
      existing &&
      existing.status === "active" &&
      existing.content === rule.content
    )
      return this.knowledge(existing);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      if (existing)
        this.db
          .prepare(
            "DELETE FROM knowledge WHERE scope=? AND key=? AND kind='operator'",
          )
          .run(scope, rule.key);
      this.db
        .prepare(
          "UPDATE knowledge SET status='retired' WHERE scope=? AND key=? AND status='active' AND kind!='operator'",
        )
        .run(scope, rule.key);
      const id = newId(),
        createdAt = now();
      this.db
        .prepare("INSERT INTO knowledge VALUES(?,?,?,?,?,?,?)")
        .run(
          id,
          scope,
          rule.key,
          rule.content,
          "operator",
          "active",
          createdAt,
        );
      this.db.exec("COMMIT");
      return this.knowledge(
        this.db.prepare("SELECT * FROM knowledge WHERE id=?").get(id)!,
      );
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }
  operatorModel(scope: string): KnowledgeRecord[] {
    this.open();
    scopeCheck(scope);
    // The order is the priority order: the most recent statement comes
    // first, because a later statement corrects an earlier one. The rowid
    // breaks the tie, so two rules stated within the same millisecond keep a
    // stable order instead of an arbitrary one.
    return this.db
      .prepare(
        "SELECT * FROM knowledge WHERE scope=? AND kind='operator' AND status='active' ORDER BY created_at DESC, rowid DESC LIMIT 200",
      )
      .all(scope)
      .map((row) => this.knowledge(row));
  }
  getKnowledge(scope: string, query?: string, limit = 30): KnowledgeRecord[] {
    this.open();
    scopeCheck(scope);
    limitCheck(limit);
    if (query !== undefined && typeof query !== "string")
      throw new Error("Invalid knowledge query");
    return this.db
      .prepare(
        "SELECT * FROM knowledge WHERE scope=? AND status='active' AND (?='' OR instr(lower(content),lower(?))>0 OR instr(lower(key),lower(?))>0) ORDER BY created_at DESC LIMIT ?",
      )
      .all(scope, query ?? "", query ?? "", query ?? "", limit)
      .map((row) => this.knowledge(row));
  }
  pendingKnowledge(scope: string): KnowledgeRecord[] {
    this.open();
    scopeCheck(scope);
    return this.db
      .prepare(
        "SELECT * FROM knowledge WHERE scope=? AND status='pending' ORDER BY created_at LIMIT 200",
      )
      .all(scope)
      .map((row) => this.knowledge(row));
  }
  resolveKnowledge(scope: string, id: string, approve: boolean): void {
    this.open();
    scopeCheck(scope);
    idCheck(id);
    const row = this.db.prepare("SELECT * FROM knowledge WHERE id=?").get(id);
    if (!row) throw new Error("Missing knowledge");
    if (row.scope !== scope) throw new Error("Knowledge scope mismatch");
    // Inferred knowledge waits for review; operator-declared rules are the
    // operator's own state, so retracting or reinstating one is always allowed.
    if (row.status !== "pending" && row.kind !== "operator")
      throw new Error("Knowledge is not pending");
    if (row.kind === "operator" && row.status === "active" && approve) return;
    if (
      approve &&
      row.kind !== "operator" &&
      this.db
        .prepare(
          "SELECT 1 FROM knowledge WHERE scope=? AND key=? AND kind='operator' AND status='active'",
        )
        .get(scope, row.key)
    )
      throw new Error("An inferred fact cannot replace an operator rule");
    this.db.exec("BEGIN IMMEDIATE");
    try {
      if (approve)
        this.db
          .prepare(
            "UPDATE knowledge SET status='retired' WHERE scope=? AND key=? AND status='active'",
          )
          .run(scope, row.key);
      this.db
        .prepare("UPDATE knowledge SET status=? WHERE id=? AND scope=?")
        .run(approve ? "active" : "rejected", id, scope);
      this.db.exec("COMMIT");
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }
  private hit(row: Row): SearchHit {
    return {
      sessionId: row.session_id,
      entryId: row.entry_id,
      role: row.role,
      text: row.text,
      timestamp: row.timestamp,
    };
  }
  searchSessions(scope: string, query: string, limit = 10): SearchHit[] {
    this.open();
    scopeCheck(scope);
    limitCheck(limit);
    if (typeof query !== "string" || query.length > 4000)
      throw new Error("Invalid session query");
    const tokens = query.match(/[\p{L}\p{N}_-]+/gu)?.slice(0, 20) ?? [];
    if (!tokens.length) return [];
    const match = tokens
      .map((token) => `"${token.replace(/"/g, '""')}"`)
      .join(" AND ");
    return this.db
      .prepare(
        "SELECT m.* FROM messages_fts JOIN messages m ON m.entry_id=messages_fts.entry_id WHERE messages_fts MATCH ? AND m.scope=? ORDER BY rank LIMIT ?",
      )
      .all(match, scope, limit)
      .map((row) => this.hit(row));
  }
  browseSession(
    scope: string,
    sessionId: string,
    offset = 0,
    limit = 30,
  ): SearchHit[] {
    this.session(sessionId, scope);
    limitCheck(limit);
    if (!Number.isInteger(offset) || offset < 0 || offset > 1000000)
      throw new Error("Invalid offset");
    return this.db
      .prepare(
        "SELECT * FROM messages WHERE scope=? AND session_id=? ORDER BY rowid LIMIT ? OFFSET ?",
      )
      .all(scope, sessionId, limit, offset)
      .map((row) => this.hit(row));
  }
  recordReview(review: Omit<ReviewRecord, "updatedAt">): void {
    this.session(review.sessionId, review.scope);
    if (
      !["pending", "running", "completed", "cancelled", "error"].includes(
        review.status,
      ) ||
      typeof review.digest !== "string" ||
      typeof review.detail !== "string"
    )
      throw new Error("Invalid review");
    this.db
      .prepare(
        "INSERT INTO reviews VALUES(?,?,?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET digest=excluded.digest,status=excluded.status,detail=excluded.detail,updated_at=excluded.updated_at",
      )
      .run(
        review.sessionId,
        review.scope,
        review.digest,
        review.status,
        redactText(review.detail),
        now(),
      );
  }
  reviews(scope: string, limit = 20): ReviewRecord[] {
    this.open();
    scopeCheck(scope);
    limitCheck(limit);
    return this.db
      .prepare(
        "SELECT * FROM reviews WHERE scope=? ORDER BY updated_at DESC LIMIT ?",
      )
      .all(scope, limit)
      .map((row) => ({
        sessionId: String(row.session_id),
        scope: String(row.scope),
        digest: String(row.digest),
        status: row.status as ReviewRecord["status"],
        detail: String(row.detail),
        updatedAt: String(row.updated_at),
      }));
  }
  audit(scope: string, event: string, detail: unknown): void {
    this.open();
    scopeCheck(scope);
    if (typeof event !== "string" || !event || event.length > 128)
      throw new Error("Invalid audit event");
    this.db
      .prepare(
        "INSERT INTO audit_log(scope,event,detail,timestamp) VALUES(?,?,?,?)",
      )
      .run(scope, event, json(detail) ?? "null", now());
  }
  audits(
    scope: string,
    event: string,
    limit = 10,
  ): { detail: string; timestamp: string }[] {
    this.open();
    scopeCheck(scope);
    limitCheck(limit);
    return this.db
      .prepare(
        "SELECT detail,timestamp FROM audit_log WHERE scope=? AND event=? ORDER BY id DESC LIMIT ?",
      )
      .all(scope, event, limit)
      .map((row) => ({
        detail: String(row.detail),
        timestamp: String(row.timestamp),
      }));
  }
  knowledgeCounts(scope: string): { active: number; pending: number } {
    this.open();
    scopeCheck(scope);
    const result = { active: 0, pending: 0 };
    for (const row of this.db
      .prepare(
        "SELECT status,count(*) AS n FROM knowledge WHERE scope=? GROUP BY status",
      )
      .all(scope)) {
      if (row.status === "active" || row.status === "pending")
        result[row.status] = Number(row.n);
    }
    return result;
  }
  /**
   * Remove transcript messages older than the window. Observations are the
   * evidence a claim rests on and are never pruned; the audit log is
   * append-only by schema. The search rows follow the delete trigger.
   */
  pruneMessages(days: number, dryRun = false): number {
    this.open();
    if (!Number.isFinite(days) || days < 1 || days > 3650)
      throw new Error("Invalid message retention window (1..3650 days)");
    const cutoff = new Date(Date.now() - days * 86400_000).toISOString();
    if (dryRun)
      return Number(
        this.db
          .prepare("SELECT COUNT(*) AS n FROM messages WHERE timestamp < ?")
          .get(cutoff)!.n,
      );
    return Number(
      this.db.prepare("DELETE FROM messages WHERE timestamp < ?").run(cutoff)
        .changes,
    );
  }
  /** Reclaim free pages after a prune. Never runs inside a transaction. */
  vacuum(): void {
    this.open();
    this.db.exec("VACUUM");
    // Fold the rebuilt pages back; otherwise the WAL keeps a second copy of
    // the whole database until the last connection closes.
    try {
      this.db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    } catch {
      /* a reader holds the checkpoint; the next close folds it */
    }
  }
  /** Bytes held by the database and its WAL, for a before/after report. */
  size(): number {
    let total = 0;
    for (const suffix of ["", "-wal", "-shm"])
      try {
        total += fs.statSync(this.filename + suffix).size;
      } catch {
        /* a suffix that does not exist holds no bytes */
      }
    return total;
  }
  close(): void {
    if (!this.closed) {
      this.closed = true;
      this.db.close();
    }
  }
}
