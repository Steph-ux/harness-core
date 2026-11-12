import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import type { StorePort, WorkerResult } from "./types";
import { WORKER_ROLES } from "./types";
import {
  ENTITY_TYPES,
  STAGES,
  type Entity,
  type EntityType,
  type FindingProposal,
  type GraphNode,
  type Mission,
  type Relation,
  type SearchResult,
  type SourceChunk,
  type SourceSpec,
} from "./platform-types";
import { assertPlainPath, hash, json, newId, now, redactText } from "./util";
import { memoryFragment, memoryQuery, rankMemory } from "./memory-ranking";

const identifier = (value: string) => {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value)
  )
    throw new Error("Invalid identifier or scope");
};
const text = (value: string, max = 24000) => {
  if (typeof value !== "string" || !value.trim() || value.length > max)
    throw new Error("Invalid text length");
  return redactText(value);
};
const parse = (value: unknown) => JSON.parse(String(value));
type Row = Record<string, any>;
const STOP = new Set(
  "a an the and or to of in for is it this that have we already seen technique avons nous deja déjà vu cette technique les des une un le la et dans pour que est de du".split(
    " ",
  ),
);
export function searchTokens(query: string): string[] {
  if (typeof query !== "string" || query.length > 4000)
    throw new Error("Invalid query");
  return [
    ...new Set(
      (query.toLowerCase().match(/[\p{L}\p{N}_-]+/gu) ?? []).filter(
        (t) => t.length > 1 && !STOP.has(t),
      ),
    ),
  ].slice(0, 20);
}

/** Sidecar normalized ledger and indexed projections; legacy evidence stays authoritative. */
export class PlatformStore {
  private db: DatabaseSync;
  private closed = false;
  /** The report gate, registered by the engagement workflow that owns it. */
  private reportGuard?: (scope: string, missionId: string) => void;
  constructor(
    filename: string,
    private evidenceStore: StorePort,
  ) {
    assertPlainPath(filename);
    fs.mkdirSync(path.dirname(filename), { recursive: true });
    for (const suffix of ["", "-wal", "-shm"])
      assertPlainPath(filename + suffix);
    this.db = new DatabaseSync(filename);
    this.db.exec(
      "PRAGMA foreign_keys=ON;PRAGMA busy_timeout=5000;PRAGMA journal_mode=WAL",
    );
    try {
      this.migrate();
    } catch (e) {
      this.db.close();
      throw e;
    }
  }
  private migrate() {
    const version = Number(
      this.db.prepare("PRAGMA user_version").get()!.user_version,
    );
    if (version > 6)
      throw new Error("Platform database version is newer than this harness");
    if (version === 6) return;
    if (version === 0)
      this.db.exec(`BEGIN IMMEDIATE;
   CREATE TABLE missions(id TEXT PRIMARY KEY,scope TEXT NOT NULL,title TEXT NOT NULL,boundaries TEXT NOT NULL,created TEXT NOT NULL,UNIQUE(id,scope));
   CREATE INDEX missions_scope ON missions(scope,created);
   CREATE TABLE nodes(mission_id TEXT NOT NULL,scope TEXT NOT NULL,id TEXT NOT NULL,state TEXT NOT NULL,result TEXT NOT NULL DEFAULT 'null',attempt INTEGER NOT NULL DEFAULT 0,lease TEXT,owner TEXT,expires INTEGER,PRIMARY KEY(mission_id,id),UNIQUE(mission_id,id,scope),FOREIGN KEY(mission_id,scope) REFERENCES missions(id,scope));
   CREATE TABLE edges(mission_id TEXT NOT NULL,scope TEXT NOT NULL,node_id TEXT NOT NULL,dependency TEXT NOT NULL,PRIMARY KEY(mission_id,node_id,dependency),FOREIGN KEY(mission_id,node_id,scope) REFERENCES nodes(mission_id,id,scope),FOREIGN KEY(mission_id,dependency,scope) REFERENCES nodes(mission_id,id,scope));
   CREATE TABLE checkpoints(seq INTEGER PRIMARY KEY AUTOINCREMENT,mission_id TEXT NOT NULL,scope TEXT NOT NULL,node_id TEXT NOT NULL,attempt INTEGER NOT NULL,state TEXT NOT NULL,payload TEXT NOT NULL,timestamp TEXT NOT NULL,FOREIGN KEY(mission_id,node_id,scope) REFERENCES nodes(mission_id,id,scope));
   CREATE INDEX checkpoints_mission ON checkpoints(scope,mission_id,seq);
   CREATE TABLE active_missions(scope TEXT PRIMARY KEY,id TEXT NOT NULL,FOREIGN KEY(id,scope) REFERENCES missions(id,scope));
   CREATE TABLE revisions(id TEXT PRIMARY KEY,scope TEXT NOT NULL,source_id TEXT NOT NULL,uri TEXT NOT NULL,title TEXT NOT NULL,hash TEXT NOT NULL,current INTEGER NOT NULL,created TEXT NOT NULL,UNIQUE(id,scope));
   CREATE UNIQUE INDEX current_revision ON revisions(scope,source_id,uri) WHERE current=1;
   CREATE TABLE chunks(id TEXT PRIMARY KEY,scope TEXT NOT NULL,revision_id TEXT NOT NULL,ordinal INTEGER NOT NULL,text TEXT NOT NULL,hash TEXT NOT NULL,UNIQUE(id,scope),FOREIGN KEY(revision_id,scope) REFERENCES revisions(id,scope));
   CREATE INDEX chunks_revision ON chunks(revision_id,ordinal);
   CREATE TABLE findings(id TEXT PRIMARY KEY,scope TEXT NOT NULL,mission_id TEXT NOT NULL,title TEXT NOT NULL,severity TEXT NOT NULL,description TEXT NOT NULL,limitations TEXT NOT NULL,status TEXT NOT NULL,confidence REAL NOT NULL,checks TEXT NOT NULL,created TEXT NOT NULL,UNIQUE(id,scope),FOREIGN KEY(mission_id,scope) REFERENCES missions(id,scope));
   CREATE INDEX findings_mission ON findings(scope,mission_id,status);
   CREATE TABLE finding_evidence(finding_id TEXT NOT NULL,scope TEXT NOT NULL,observation_id TEXT NOT NULL,hash TEXT NOT NULL,PRIMARY KEY(finding_id,observation_id),FOREIGN KEY(finding_id,scope) REFERENCES findings(id,scope));
   CREATE TABLE finding_citations(finding_id TEXT NOT NULL,scope TEXT NOT NULL,chunk_id TEXT NOT NULL,PRIMARY KEY(finding_id,chunk_id),FOREIGN KEY(finding_id,scope) REFERENCES findings(id,scope),FOREIGN KEY(chunk_id,scope) REFERENCES chunks(id,scope));
   CREATE TABLE verification_links(mission_id TEXT NOT NULL,scope TEXT NOT NULL,finding_id TEXT NOT NULL,attempt INTEGER NOT NULL,PRIMARY KEY(mission_id,finding_id,attempt),FOREIGN KEY(finding_id,scope) REFERENCES findings(id,scope),FOREIGN KEY(mission_id,scope) REFERENCES missions(id,scope));
   CREATE INDEX citation_chunk ON finding_citations(chunk_id);
   CREATE TABLE memory_uses(scope TEXT NOT NULL,session_id TEXT NOT NULL,turn_id TEXT NOT NULL,chunk_id TEXT NOT NULL,timestamp TEXT NOT NULL,PRIMARY KEY(scope,session_id,turn_id,chunk_id),FOREIGN KEY(chunk_id,scope) REFERENCES chunks(id,scope));
   CREATE TABLE mission_reviews(mission_id TEXT PRIMARY KEY,scope TEXT NOT NULL,digest TEXT NOT NULL,payload TEXT NOT NULL,timestamp TEXT NOT NULL,FOREIGN KEY(mission_id,scope) REFERENCES missions(id,scope));
   CREATE TABLE source_specs(id TEXT NOT NULL,scope TEXT NOT NULL,payload TEXT NOT NULL,etag TEXT,last_modified TEXT,last_synced TEXT,PRIMARY KEY(id,scope));
   CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
   CREATE TABLE search_records(id TEXT PRIMARY KEY,scope TEXT NOT NULL,kind TEXT NOT NULL,title TEXT NOT NULL,text TEXT NOT NULL,reference TEXT NOT NULL,hash TEXT NOT NULL,mission_id TEXT);
   CREATE INDEX search_scope ON search_records(scope,kind);
   CREATE VIRTUAL TABLE search_fts USING fts5(id UNINDEXED,title,text);
   CREATE TRIGGER search_insert AFTER INSERT ON search_records BEGIN INSERT INTO search_fts(id,title,text)VALUES(new.id,new.title,new.text);END;
   CREATE TRIGGER search_update AFTER UPDATE ON search_records BEGIN DELETE FROM search_fts WHERE id=old.id;INSERT INTO search_fts(id,title,text)VALUES(new.id,new.title,new.text);END;
   CREATE TRIGGER search_delete AFTER DELETE ON search_records BEGIN DELETE FROM search_fts WHERE id=old.id;END;
   CREATE TRIGGER checkpoints_immutable_update BEFORE UPDATE ON checkpoints BEGIN SELECT RAISE(ABORT,'Immutable checkpoint');END;
   CREATE TRIGGER checkpoints_immutable_delete BEFORE DELETE ON checkpoints BEGIN SELECT RAISE(ABORT,'Immutable checkpoint');END;
    PRAGMA user_version=1;COMMIT;`);
    if (version < 2)
      this.db.exec(`BEGIN IMMEDIATE;
      CREATE TABLE IF NOT EXISTS verification_links(mission_id TEXT NOT NULL,scope TEXT NOT NULL,finding_id TEXT NOT NULL,attempt INTEGER NOT NULL,PRIMARY KEY(mission_id,finding_id,attempt),FOREIGN KEY(finding_id,scope) REFERENCES findings(id,scope),FOREIGN KEY(mission_id,scope) REFERENCES missions(id,scope));
      CREATE TRIGGER IF NOT EXISTS search_delete AFTER DELETE ON search_records BEGIN DELETE FROM search_fts WHERE id=old.id;END;
      CREATE TABLE IF NOT EXISTS finding_verifications(finding_id TEXT PRIMARY KEY,scope TEXT NOT NULL,observation_id TEXT NOT NULL,hash TEXT NOT NULL,attempt INTEGER NOT NULL,timestamp TEXT NOT NULL,FOREIGN KEY(finding_id,scope) REFERENCES findings(id,scope));
      CREATE TABLE IF NOT EXISTS memory_refs(scope TEXT NOT NULL,session_id TEXT NOT NULL,turn_id TEXT NOT NULL,reference_id TEXT NOT NULL,kind TEXT NOT NULL,hash TEXT NOT NULL,timestamp TEXT NOT NULL,PRIMARY KEY(scope,session_id,turn_id,reference_id));
      CREATE INDEX IF NOT EXISTS memory_refs_session ON memory_refs(scope,session_id,timestamp);
      CREATE TRIGGER IF NOT EXISTS chunks_immutable_update BEFORE UPDATE ON chunks BEGIN SELECT RAISE(ABORT,'Immutable source chunk');END;
      CREATE TRIGGER IF NOT EXISTS chunks_immutable_delete BEFORE DELETE ON chunks BEGIN SELECT RAISE(ABORT,'Immutable source chunk');END;
      CREATE TRIGGER IF NOT EXISTS revisions_immutable_update BEFORE UPDATE ON revisions WHEN new.id!=old.id OR new.scope!=old.scope OR new.source_id!=old.source_id OR new.uri!=old.uri OR new.title!=old.title OR new.hash!=old.hash OR new.created!=old.created BEGIN SELECT RAISE(ABORT,'Immutable source revision');END;
      CREATE TRIGGER IF NOT EXISTS revisions_immutable_delete BEFORE DELETE ON revisions BEGIN SELECT RAISE(ABORT,'Immutable source revision');END;
      PRAGMA user_version=2;COMMIT;`);
    if (version < 3) {
      this.db.exec(`BEGIN IMMEDIATE;
      CREATE TABLE IF NOT EXISTS approvals(id TEXT NOT NULL,scope TEXT NOT NULL,mission_id TEXT NOT NULL,action TEXT NOT NULL,justification TEXT NOT NULL,requested_by TEXT NOT NULL,status TEXT NOT NULL,created TEXT NOT NULL,decided TEXT,decided_by TEXT,PRIMARY KEY(id,scope),FOREIGN KEY(mission_id,scope) REFERENCES missions(id,scope));
      CREATE INDEX approvals_scope ON approvals(scope,status,created);
      PRAGMA user_version=3;COMMIT;`);
    }
    if (version < 4)
      this.db.exec(
        `BEGIN IMMEDIATE; ALTER TABLE finding_verifications ADD COLUMN detail TEXT NOT NULL DEFAULT '{}'; PRAGMA user_version=4; COMMIT;`,
      );
    if (version < 5)
      this.db.exec(`BEGIN IMMEDIATE;
      CREATE TABLE IF NOT EXISTS mission_roots(mission_id TEXT NOT NULL,scope TEXT NOT NULL,root TEXT NOT NULL,PRIMARY KEY(mission_id,scope),FOREIGN KEY(mission_id,scope) REFERENCES missions(id,scope));
      PRAGMA user_version=5;COMMIT;`);
    if (version < 6)
      this.db.exec(`BEGIN IMMEDIATE;
      CREATE TABLE IF NOT EXISTS entities(id TEXT PRIMARY KEY,scope TEXT NOT NULL,type TEXT NOT NULL,key TEXT NOT NULL,label TEXT NOT NULL,attributes TEXT NOT NULL,observation_ids TEXT NOT NULL,created TEXT NOT NULL,updated TEXT NOT NULL,UNIQUE(scope,type,key),UNIQUE(id,scope));
      CREATE INDEX IF NOT EXISTS entities_scope ON entities(scope,type);
      CREATE TABLE IF NOT EXISTS relations(id TEXT PRIMARY KEY,scope TEXT NOT NULL,source TEXT NOT NULL,target TEXT NOT NULL,kind TEXT NOT NULL,attributes TEXT NOT NULL,observation_ids TEXT NOT NULL,created TEXT NOT NULL,UNIQUE(scope,source,target,kind),FOREIGN KEY(source,scope) REFERENCES entities(id,scope),FOREIGN KEY(target,scope) REFERENCES entities(id,scope));
      CREATE INDEX IF NOT EXISTS relations_source ON relations(scope,source);
      CREATE INDEX IF NOT EXISTS relations_target ON relations(scope,target);
      PRAGMA user_version=6;COMMIT;`);
  }
  private open(scope: string) {
    if (this.closed) throw new Error("Platform store is closed");
    identifier(scope);
  }
  private tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const out = fn();
      this.db.exec("COMMIT");
      return out;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }
  private index(
    scope: string,
    id: string,
    kind: SearchResult["kind"],
    title: string,
    body: string,
    reference: string,
    missionId?: string,
  ) {
    this.open(scope);
    const safe = redactText(body);
    this.db
      .prepare(
        "INSERT INTO search_records VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title,text=excluded.text,hash=excluded.hash",
      )
      .run(
        id,
        scope,
        kind,
        title,
        safe,
        reference,
        hash(safe),
        missionId ?? null,
      );
  }
  /**
   * The directory an engagement owns. It anchors every artifact and capture,
   * so evidence cannot be scattered across a session's working directory.
   */
  private checkRoot(value: string) {
    if (typeof value !== "string" || !value.trim())
      throw new Error("An engagement root is required");
    const file = path.resolve(value);
    assertPlainPath(file);
    if (!fs.statSync(file).isDirectory())
      throw new Error("The engagement root must be an existing directory");
    if (path.dirname(file) === file)
      throw new Error("The filesystem root is not an engagement");
    return fs.realpathSync(file);
  }
  createMission(
    scope: string,
    title: string,
    boundaries: string,
    graph?: GraphNode[],
    root?: string,
  ): Mission {
    this.open(scope);
    title = text(title, 500);
    boundaries = text(boundaries, 8000);
    const engagementRoot = root === undefined ? undefined : this.checkRoot(root);
    const nodes =
      graph ??
      STAGES.map((id, i) => ({ id, dependsOn: i ? [STAGES[i - 1]] : [] }));
    if (!Array.isArray(nodes) || nodes.length < 7 || nodes.length > 30)
      throw new Error("Invalid graph size");
    const map = new Map(nodes.map((n) => [n.id, n]));
    if (map.size !== nodes.length || STAGES.some((s) => !map.has(s)))
      throw new Error("Graph must contain unique mandatory stages");
    for (const n of nodes) {
      identifier(n.id);
      if (
        !Array.isArray(n.dependsOn) ||
        n.dependsOn.length > 30 ||
        new Set(n.dependsOn).size !== n.dependsOn.length ||
        n.dependsOn.some((d) => !map.has(d))
      )
        throw new Error("Invalid graph dependency");
    }
    const done = new Set<string>(),
      visiting = new Set<string>();
    const visit = (id: string) => {
      if (visiting.has(id)) throw new Error("Graph cycle");
      if (done.has(id)) return;
      visiting.add(id);
      map.get(id)!.dependsOn.forEach(visit);
      visiting.delete(id);
      done.add(id);
    };
    nodes.forEach((n) => visit(n.id));
    const ancestry = new Map<string, Set<string>>();
    const ancestors = (id: string): Set<string> => {
      if (!ancestry.has(id))
        ancestry.set(
          id,
          new Set(
            map.get(id)!.dependsOn.flatMap((dep) => [dep, ...ancestors(dep)]),
          ),
        );
      return ancestry.get(id)!;
    };
    if (
      map.get("scope-validation")!.dependsOn.length ||
      nodes.some(
        (n) =>
          n.id !== "scope-validation" &&
          !ancestors(n.id).has("scope-validation"),
      ) ||
      STAGES.some(
        (stage, i) => i > 0 && !ancestors(stage).has(STAGES[i - 1]),
      ) ||
      nodes.some((n) => n.id !== "report" && !ancestors("report").has(n.id))
    )
      throw new Error(
        "Graph bypasses mandatory scope/validation/evidence gates",
      );
    const id = `mission-${newId().slice(0, 18)}`;
    this.tx(() => {
      this.db
        .prepare("INSERT INTO missions VALUES(?,?,?,?,?)")
        .run(id, scope, title, boundaries, now());
      for (const n of nodes)
        this.db
          .prepare(
            "INSERT INTO nodes(mission_id,scope,id,state)VALUES(?,?,?,?)",
          )
          .run(
            id,
            scope,
            n.id,
            n.id === "scope-validation" ? "WAITING_APPROVAL" : "PENDING",
          );
      for (const n of nodes)
        for (const d of n.dependsOn)
          this.db
            .prepare("INSERT INTO edges VALUES(?,?,?,?)")
            .run(id, scope, n.id, d);
      this.db
        .prepare(
          "INSERT INTO active_missions VALUES(?,?) ON CONFLICT(scope)DO UPDATE SET id=excluded.id",
        )
        .run(scope, id);
      if (engagementRoot)
        this.db
          .prepare("INSERT INTO mission_roots VALUES(?,?,?)")
          .run(id, scope, engagementRoot);
    });
    this.index(
      scope,
      id,
      "mission",
      title,
      `${title}\n${boundaries}`,
      `cyber://mission/${id}`,
      id,
    );
    return this.mission(scope, id);
  }
  mission(scope: string, id: string): Mission {
    this.open(scope);
    identifier(id);
    const row = this.db
      .prepare("SELECT * FROM missions WHERE id=? AND scope=?")
      .get(id, scope);
    if (!row) throw new Error("Missing mission in this scope");
    const nodes = this.db
      .prepare(
        "SELECT * FROM nodes WHERE mission_id=? AND scope=? ORDER BY rowid",
      )
      .all(id, scope)
      .map((n) => ({
        id: String(n.id),
        state: n.state as Mission["state"],
        result: parse(n.result),
        attempt: Number(n.attempt),
        dependsOn: this.db
          .prepare(
            "SELECT dependency FROM edges WHERE mission_id=? AND scope=? AND node_id=?",
          )
          .all(id, scope, n.id)
          .map((e) => String(e.dependency)),
      }));
    const state: Mission["state"] = nodes.some((n) => n.state === "RUNNING")
      ? "RUNNING"
      : nodes.some((n) => n.state === "WAITING_APPROVAL")
        ? "WAITING_APPROVAL"
        : nodes.some((n) => n.state === "FAILED")
          ? "FAILED"
          : nodes.every((n) => n.state === "COMPLETED" || n.state === "SKIPPED")
            ? "COMPLETED"
            : "PENDING";
    return {
      id,
      scope,
      title: String(row.title),
      boundaries: String(row.boundaries),
      state,
      nodes,
    };
  }
  /** The report gate lives with the engagement workflow; a host registers it once. */
  setReportGuard(guard: (scope: string, missionId: string) => void) {
    this.reportGuard = guard;
  }
  active(scope: string): Mission | undefined {
    this.open(scope);
    const row = this.db
      .prepare("SELECT id FROM active_missions WHERE scope=?")
      .get(scope);
    return row ? this.mission(scope, String(row.id)) : undefined;
  }
  /** The engagement directory declared with the mission, when one was. */
  missionRoot(scope: string, id: string): string | undefined {
    this.open(scope);
    const row = this.db
      .prepare("SELECT root FROM mission_roots WHERE mission_id=? AND scope=?")
      .get(id, scope);
    return row ? String(row.root) : undefined;
  }
  /**
   * The approval queue.
   *
   * An action that the engagement forbids unattended stops here, with the
   * reason it needs a human. It is refused until the operator decides, and
   * the decision is written down.
   */
  requestApproval(
    scope: string,
    missionId: string,
    action: string,
    justification: string,
    requestedBy: string,
  ) {
    this.mission(scope, missionId);
    const id = `AP-${newId().slice(0, 18)}`;
    const reason = text(justification, 2000);
    if (!reason.trim()) throw new Error("An approval needs its reason");
    if (!action.trim())
      throw new Error("An approval needs the action it covers");
    identifier(requestedBy);
    this.tx(() => {
      this.db
        .prepare("INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?,NULL,NULL)")
        .run(
          id,
          scope,
          missionId,
          text(action, 1000),
          reason,
          requestedBy,
          "pending",
          now(),
        );
    });
    return this.approval(scope, id);
  }

  approval(scope: string, id: string) {
    this.open(scope);
    identifier(id);
    const row = this.db
      .prepare("SELECT * FROM approvals WHERE scope=? AND id=?")
      .get(scope, id);
    if (!row) throw new Error("Unknown approval");
    return {
      id: String(row.id),
      scope: String(row.scope),
      missionId: String(row.mission_id),
      action: String(row.action),
      justification: String(row.justification),
      requestedBy: String(row.requested_by),
      status: String(row.status),
      created: String(row.created),
      decided: row.decided ? String(row.decided) : null,
      decidedBy: row.decided_by ? String(row.decided_by) : null,
    };
  }

  approvals(scope: string, status?: string, limit = 50) {
    this.open(scope);
    if (
      status !== undefined &&
      !["pending", "approved", "denied"].includes(status)
    )
      throw new Error("Invalid approval status");
    if (!Number.isInteger(limit) || limit < 1 || limit > 200)
      throw new Error("Invalid limit");
    const rows = status
      ? this.db
          .prepare(
            "SELECT id FROM approvals WHERE scope=? AND status=? ORDER BY created DESC LIMIT ?",
          )
          .all(scope, status, limit)
      : this.db
          .prepare(
            "SELECT id FROM approvals WHERE scope=? ORDER BY created DESC LIMIT ?",
          )
          .all(scope, limit);
    return rows.map((row) => this.approval(scope, String(row.id)));
  }

  decideApproval(
    scope: string,
    id: string,
    approve: boolean,
    decidedBy: string,
  ) {
    const current = this.approval(scope, id);
    if (current.status !== "pending")
      throw new Error("Approval was already decided");
    identifier(decidedBy);
    this.tx(() => {
      this.db
        .prepare(
          "UPDATE approvals SET status=?,decided=?,decided_by=? WHERE scope=? AND id=? AND status='pending'",
        )
        .run(approve ? "approved" : "denied", now(), decidedBy, scope, id);
    });
    return this.approval(scope, id);
  }

  approveScope(scope: string, id: string) {
    this.mission(scope, id);
    this.tx(() => {
      const node = this.db
        .prepare(
          "SELECT state FROM nodes WHERE mission_id=? AND id='scope-validation'",
        )
        .get(id);
      if (node?.state !== "WAITING_APPROVAL")
        throw new Error("Scope is not awaiting approval");
      this.db
        .prepare(
          "UPDATE nodes SET state='COMPLETED',result=? WHERE mission_id=? AND id='scope-validation'",
        )
        .run(json({ approvedBy: "user", timestamp: now() }), id);
      this.checkpoint(scope, id, "scope-validation", "COMPLETED", {
        approvedBy: "user",
      });
    });
  }
  private checkpoint(
    scope: string,
    id: string,
    node: string,
    state: string,
    payload: unknown,
  ) {
    const attempt = this.db
      .prepare("SELECT attempt FROM nodes WHERE mission_id=? AND id=?")
      .get(id, node)!.attempt;
    this.db
      .prepare(
        "INSERT INTO checkpoints(mission_id,scope,node_id,attempt,state,payload,timestamp)VALUES(?,?,?,?,?,?,?)",
      )
      .run(id, scope, node, attempt, state, json(payload), now());
  }
  claim(
    scope: string,
    id: string,
    node: string,
    owner: string,
    findingIds: string[] = [],
  ): string {
    this.mission(scope, id);
    identifier(owner);
    return this.tx(() => {
      const m = this.mission(scope, id),
        n = m.nodes.find((n) => n.id === node);
      if (
        !n ||
        n.id === "scope-validation" ||
        n.state !== "PENDING" ||
        n.dependsOn.some(
          (dep) =>
            !m.nodes.some(
              (d) => d.id === dep && ["COMPLETED", "SKIPPED"].includes(d.state),
            ),
        )
      )
        throw new Error("Node not ready: scope, state or dependency gate");
      const lease = newId();
      this.db
        .prepare(
          "UPDATE nodes SET state='RUNNING',attempt=attempt+1,lease=?,owner=?,expires=? WHERE mission_id=? AND scope=? AND id=?",
        )
        .run(lease, owner, Date.now() + 15000, id, scope, node);
      if (node === "validation")
        for (const findingId of new Set(findingIds)) {
          if (this.finding(scope, findingId).missionId !== id)
            throw new Error("Finding is outside this mission");
          this.db
            .prepare("INSERT INTO verification_links VALUES(?,?,?,?)")
            .run(id, scope, findingId, n.attempt + 1);
        }
      this.checkpoint(scope, id, node, "RUNNING", { lease, owner });
      return lease;
    });
  }
  heartbeat(scope: string, id: string, node: string, lease: string) {
    this.open(scope);
    const changed = this.db
      .prepare(
        "UPDATE nodes SET expires=? WHERE mission_id=? AND scope=? AND id=? AND lease=? AND state='RUNNING'",
      )
      .run(Date.now() + 15000, id, scope, node, lease);
    if (!changed.changes) throw new Error("Lost node lease");
  }
  private assertReportReady(scope: string, id: string) {
    // The report gate belongs to the engagement workflow, which owns the
    // report tables and the rendered files. A host that mounts it registers
    // the guard; the store no longer reads those tables on its own.
    if (this.reportGuard) return this.reportGuard(scope, id);
    // Legacy host without the workflow: the table is the only witness.
    const table = this.db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='workflow_reports'",
      )
      .get();
    const latest = table
      ? this.db
          .prepare(
            "SELECT * FROM workflow_reports WHERE scope=? AND mission_id=? ORDER BY rowid DESC LIMIT 1",
          )
          .get(scope, id)
      : undefined;
    if (!latest || latest.reviewed !== 1)
      throw new Error(
        "Report stage requires a registered, visually reviewed report artifact",
      );
    const snapshot = parse(latest.snapshot),
      payload = parse(latest.payload);
    if (snapshot.sourceHash !== this.reportFingerprint(scope, id))
      throw new Error("Report snapshot is stale");
    const check = (file: string, expected: string) => {
      assertPlainPath(file);
      if (
        createHash("sha256").update(fs.readFileSync(file)).digest("hex") !==
        expected
      )
        throw new Error("Reviewed report content changed");
    };
    check(payload.snapshotPath, payload.snapshotHash);
    for (const artifactId of payload.artifacts) {
      const row = this.db
        .prepare(
          "SELECT payload FROM workflow_artifacts WHERE id=? AND scope=? AND mission_id=?",
        )
        .get(artifactId, scope, id);
      if (!row) throw new Error("Reviewed report artifact missing");
      const artifact = parse(row.payload);
      check(artifact.path, artifact.sha256);
      // The rendered pages are proofs too: re-hash them at the stage close,
      // not only when the report was registered and reviewed.
      if (artifact.kind === "report-qa") {
        const qa = JSON.parse(fs.readFileSync(artifact.path, "utf8"));
        if (!Array.isArray(qa?.pageImages) || qa.pageImages.length !== qa.pages)
          throw new Error("Report page manifest is incomplete");
        const folder = path.dirname(artifact.path);
        for (const page of qa.pageImages) {
          if (
            !page ||
            typeof page.path !== "string" ||
            typeof page.sha256 !== "string"
          )
            throw new Error("Invalid report page entry");
          const file = path.resolve(folder, page.path);
          if (!file.startsWith(folder + path.sep))
            throw new Error("Report page escapes the report folder");
          check(file, page.sha256);
        }
      }
    }
  }
  finish(
    scope: string,
    id: string,
    node: string,
    lease: string,
    results: Pick<
      WorkerResult,
      "status" | "evidence" | "summary" | "role" | "observationIds"
    >[],
  ) {
    this.mission(scope, id);
    if (
      !Array.isArray(results) ||
      !results.length ||
      results.length > 10 ||
      results.some(
        (r) =>
          !WORKER_ROLES.includes(r.role) ||
          !["completed", "error", "aborted", "budget-exceeded"].includes(
            r.status,
          ),
      )
    )
      throw new Error("Invalid worker checkpoint");
    if (
      node === "validation" &&
      results.some((r) => r.role !== "verification-agent")
    )
      throw new Error("Validation needs independent verification workers");
    if (node === "report" && results.some((r) => r.role !== "report-agent"))
      throw new Error("Report stage needs report workers");
    const ids = [
      ...new Set(
        results.flatMap((r) => [
          ...(r.evidence ?? []),
          ...(r.observationIds ?? []),
        ]),
      ),
    ];
    this.evidenceStore.evidence(scope, ids);
    for (const r of results)
      if (r.status === "completed") {
        const proofs = [...(r.evidence ?? []), ...(r.observationIds ?? [])];
        if (!proofs.length)
          throw new Error("A completed stage requires observed evidence");
        if (!this.evidenceStore.evidence(scope, proofs).some((o) => o.success))
          throw new Error("A completed stage requires successful evidence");
      }
    // The checkpoint keeps what actually proves the stage. A worker may report
    // its evidence as observation ids; both are evidence, and the recorded
    // result must not hide one of them, or a verification stage would look
    // empty while it is not.
    const recorded = results.map((r) => ({
      ...r,
      evidence: [
        ...new Set([...(r.evidence ?? []), ...(r.observationIds ?? [])]),
      ],
    }));
    this.tx(() => {
      this.assertLease(scope, id, node, lease);
      if (node === "report") this.assertReportReady(scope, id);
      const state = recorded.every((r) => r.status === "completed")
        ? "COMPLETED"
        : "FAILED";
      this.checkpoint(scope, id, node, state, recorded);
      this.db
        .prepare(
          "UPDATE nodes SET state=?,result=?,lease=NULL,owner=NULL,expires=NULL WHERE mission_id=? AND scope=? AND id=?",
        )
        .run(state, json(recorded), id, scope, node);
    });
    this.indexEvidence(scope, ids);
    const m = this.mission(scope, id);
    this.index(
      scope,
      id,
      "mission",
      m.title,
      json(m),
      `cyber://mission/${id}`,
      id,
    );
  }
  private assertLease(scope: string, id: string, node: string, lease: string) {
    const row = this.db
      .prepare(
        "SELECT lease,state FROM nodes WHERE mission_id=? AND scope=? AND id=?",
      )
      .get(id, scope, node);
    if (row?.state !== "RUNNING" || row.lease !== lease)
      throw new Error("Node state/lease mismatch");
  }
  interrupt(
    scope: string,
    id: string,
    node: string,
    lease: string,
    reason: string,
    results?: WorkerResult[],
  ) {
    this.tx(() => {
      this.assertLease(scope, id, node, lease);
      const payload = {
        reason: text(reason.slice(0, 24000)),
        uncertainEffects: true,
        workers: results ?? [],
      };
      this.checkpoint(scope, id, node, "WAITING_APPROVAL", payload);
      this.db
        .prepare(
          "UPDATE nodes SET state='WAITING_APPROVAL',result=?,lease=NULL,owner=NULL,expires=NULL WHERE mission_id=? AND scope=? AND id=?",
        )
        .run(json(payload), id, scope, node);
    });
  }
  resume(scope: string, id: string): Mission {
    this.mission(scope, id);
    this.tx(() => {
      const running = this.db
        .prepare(
          "SELECT * FROM nodes WHERE mission_id=? AND scope=? AND state='RUNNING'",
        )
        .all(id, scope);
      if (running.some((n) => Number(n.expires) > Date.now()))
        throw new Error("Mission has a live running lease");
      for (const n of running) {
        this.checkpoint(scope, id, String(n.id), "WAITING_APPROVAL", {
          uncertainEffects: true,
          reason: "Expired lease; inspect external effects before retry",
        });
        this.db
          .prepare(
            "UPDATE nodes SET state='WAITING_APPROVAL',lease=NULL,owner=NULL,expires=NULL WHERE mission_id=? AND id=?",
          )
          .run(id, n.id);
      }
      this.db
        .prepare(
          "INSERT INTO active_missions VALUES(?,?) ON CONFLICT(scope)DO UPDATE SET id=excluded.id",
        )
        .run(scope, id);
    });
    return this.mission(scope, id);
  }
  checkpoints(scope: string, id: string) {
    this.mission(scope, id);
    return this.db
      .prepare(
        "SELECT * FROM checkpoints WHERE scope=? AND mission_id=? ORDER BY seq DESC LIMIT 200",
      )
      .all(scope, id)
      .reverse()
      .map((r) => ({
        id: `checkpoint-${r.seq}`,
        nodeId: String(r.node_id),
        attempt: Number(r.attempt),
        state: String(r.state),
        payload: parse(r.payload),
        timestamp: String(r.timestamp),
      }));
  }
  reopenValidation(
    scope: string,
    id: string,
    reason: string,
    operator: string,
  ) {
    const explanation = text(reason, 4000),
      decidedBy = text(operator, 300);
    this.tx(() => {
      const mission = this.mission(scope, id);
      if (mission.nodes.some((n) => n.state === "RUNNING"))
        throw new Error(
          "Mission has running work; inspect effects before reopening validation",
        );
      if (
        !mission.nodes.some(
          (n) => n.id === "validation" && n.state === "COMPLETED",
        )
      )
        throw new Error("Only completed validation can be reopened");
      for (const node of ["validation", "evidence", "report"]) {
        this.checkpoint(scope, id, node, "PENDING", {
          reason: explanation,
          decidedBy,
          previousResultRetainedInHistory: true,
        });
        this.db
          .prepare(
            "UPDATE nodes SET state='PENDING',result='null',lease=NULL,owner=NULL,expires=NULL WHERE scope=? AND mission_id=? AND id=?",
          )
          .run(scope, id, node);
      }
      this.db
        .prepare(
          "DELETE FROM finding_verifications WHERE scope=? AND finding_id IN (SELECT id FROM findings WHERE scope=? AND mission_id=?)",
        )
        .run(scope, scope, id);
      this.db
        .prepare(
          "UPDATE findings SET status='unverified' WHERE scope=? AND mission_id=? AND status='verified'",
        )
        .run(scope, id);
    });
    return this.mission(scope, id);
  }
  retry(scope: string, id: string, node: string) {
    this.mission(scope, id);
    this.tx(() => {
      const row = this.db
        .prepare("SELECT state FROM nodes WHERE mission_id=? AND id=?")
        .get(id, node);
      if (
        node === "scope-validation" ||
        !row ||
        !["FAILED", "WAITING_APPROVAL"].includes(String(row.state))
      )
        throw new Error("Node cannot be retried");
      this.checkpoint(scope, id, node, "PENDING", {
        approvedBy: "user",
        possibleEffectsAcknowledged: true,
      });
      this.db
        .prepare("UPDATE nodes SET state='PENDING' WHERE mission_id=? AND id=?")
        .run(id, node);
    });
  }
  skip(scope: string, id: string, node: string, reason: string) {
    this.mission(scope, id);
    if (["scope-validation", "validation", "evidence", "report"].includes(node))
      throw new Error("Mandatory stages cannot be skipped");
    this.tx(() => {
      const row = this.db
        .prepare("SELECT state FROM nodes WHERE mission_id=? AND id=?")
        .get(id, node);
      if (
        !row ||
        !["PENDING", "FAILED", "WAITING_APPROVAL"].includes(String(row.state))
      )
        throw new Error("Node cannot be skipped");
      this.checkpoint(scope, id, node, "SKIPPED", {
        approvedBy: "user",
        reason: text(reason),
      });
      this.db
        .prepare(
          "UPDATE nodes SET state='SKIPPED',result=? WHERE mission_id=? AND id=?",
        )
        .run(json({ reason }), id, node);
    });
  }
  indexEvidence(scope: string, ids: string[]) {
    for (const o of this.evidenceStore.evidence(scope, ids))
      this.index(
        scope,
        o.id,
        "evidence",
        o.tool,
        json(o),
        `cyber://evidence/${o.id}`,
      );
  }
  ingest(
    scope: string,
    sourceId: string,
    uri: string,
    title: string,
    body: string,
  ): SourceChunk[] {
    const ids = this.tx(() =>
      this.ingestDocument(scope, sourceId, uri, title, body),
    );
    return ids.map((id) => this.chunk(scope, id));
  }
  private ingestDocument(
    scope: string,
    sourceId: string,
    uri: string,
    title: string,
    body: string,
  ): string[] {
    this.open(scope);
    identifier(sourceId);
    title = text(title, 1000);
    body = text(body, 20000000);
    uri = text(uri, 8000);
    const digest = hash(body),
      revision = `R-${hash(`${scope}:${sourceId}:${uri}:${digest}`).slice(0, 32)}`;
    this.db
      .prepare(
        "UPDATE revisions SET current=0 WHERE scope=? AND source_id=? AND uri=?",
      )
      .run(scope, sourceId, uri);
    this.db
      .prepare(
        "INSERT INTO revisions VALUES(?,?,?,?,?,?,1,?) ON CONFLICT(id)DO UPDATE SET current=1",
      )
      .run(revision, scope, sourceId, uri, title, digest, now());
    if (
      this.db
        .prepare("SELECT id FROM chunks WHERE revision_id=? LIMIT 1")
        .get(revision)
    )
      return this.db
        .prepare("SELECT id FROM chunks WHERE revision_id=? ORDER BY ordinal")
        .all(revision)
        .map((r) => String(r.id));
    let ordinal = 0;
    for (let offset = 0; offset < body.length; offset += 3500) {
      const value = body.slice(offset, offset + 4000),
        id = `C-${hash(`${revision}:${ordinal}:${value}`).slice(0, 32)}`;
      this.db
        .prepare("INSERT INTO chunks VALUES(?,?,?,?,?,?)")
        .run(id, scope, revision, ordinal++, value, hash(value));
      this.index(scope, id, "source", title, value, uri);
    }
    return this.db
      .prepare("SELECT id FROM chunks WHERE revision_id=? ORDER BY ordinal")
      .all(revision)
      .map((row) => String(row.id));
  }
  chunk(scope: string, id: string): SourceChunk {
    this.open(scope);
    const row = this.db
      .prepare(
        "SELECT c.*,r.source_id,r.uri,r.title,r.current FROM chunks c JOIN revisions r ON r.id=c.revision_id WHERE c.id=? AND c.scope=?",
      )
      .get(id, scope);
    if (!row) throw new Error("Missing source citation in this scope");
    return {
      id,
      scope,
      sourceId: String(row.source_id),
      uri: String(row.uri),
      title: String(row.title),
      text: String(row.text),
      hash: String(row.hash),
      current: row.current === 1,
      ordinal: Number(row.ordinal),
    };
  }
  retireMissing(scope: string, sourceId: string, uris: string[]) {
    this.open(scope);
    const set = new Set(uris);
    this.tx(() => this.retireDocuments(scope, sourceId, set));
  }
  private retireDocuments(scope: string, sourceId: string, set: Set<string>) {
    for (const r of this.db
      .prepare(
        "SELECT uri FROM revisions WHERE scope=? AND source_id=? AND current=1",
      )
      .all(scope, sourceId))
      if (!set.has(String(r.uri)))
        this.db
          .prepare(
            "UPDATE revisions SET current=0 WHERE scope=? AND source_id=? AND uri=?",
          )
          .run(scope, sourceId, r.uri);
  }
  syncDocuments(
    spec: SourceSpec,
    documents: { uri: string; title: string; text: string }[],
    etag?: string,
    lastModified?: string,
  ) {
    this.open(spec.scope);
    this.tx(() => {
      if (json(this.sourceState(spec.scope, spec.id).spec) !== json(spec))
        throw new Error("Source registration changed during sync");
      for (const doc of documents)
        if (doc.text.trim())
          this.ingestDocument(
            spec.scope,
            spec.id,
            doc.uri,
            doc.title,
            doc.text,
          );
      this.retireDocuments(
        spec.scope,
        spec.id,
        new Set(documents.filter((d) => d.text.trim()).map((d) => d.uri)),
      );
      this.synced(spec.scope, spec.id, etag, lastModified);
    });
  }
  evidence(scope: string, ids: string[]) {
    this.open(scope);
    return this.evidenceStore.evidence(scope, ids);
  }
  createFinding(scope: string, p: FindingProposal) {
    this.mission(scope, p.missionId);
    const title = text(p.title, 1000),
      description = text(p.description),
      limitations = text(p.limitations);
    if (
      !["informational", "low", "medium", "high", "critical"].includes(
        p.severity,
      )
    )
      throw new Error("Invalid severity");
    if (
      !Array.isArray(p.evidence) ||
      !p.evidence.length ||
      p.evidence.length > 100 ||
      !Array.isArray(p.sources) ||
      p.sources.length > 100 ||
      !Array.isArray(p.checks) ||
      p.checks.length > 100
    )
      throw new Error("Invalid evidence/citations/checks");
    const observations = this.evidenceStore.evidence(scope, p.evidence);
    p.sources.forEach((id) => this.chunk(scope, id));
    for (const c of p.checks) {
      if (
        !["reproduction", "positive-control", "negative-control"].includes(
          c.purpose,
        ) ||
        typeof c.contains !== "string" ||
        c.contains.trim().length < 4 ||
        !observations.some(
          (o) =>
            o.id === c.observationId &&
            o.output.includes(c.contains) &&
            o.success,
        )
      )
        throw new Error("Finding check lacks observed evidence");
    }
    // A negative control proves the procedure does not fire on a benign
    // input. It must therefore observe a different output than the
    // reproduction: the same output would have to be both the claim and its
    // refutation. The comparison is made on the output, so a control that
    // replays the same run under another observation id is refused too.
    const reproduction = p.checks.filter((c) => c.purpose === "reproduction");
    const controls = p.checks.filter((c) => c.purpose === "negative-control");
    for (const control of controls) {
      for (const claim of reproduction) {
        const claimed = observations.find((o) => o.id === claim.observationId);
        const observed = observations.find((o) => o.id === control.observationId);
        if (claimed && observed && claimed.output === observed.output)
          throw new Error(
            "A negative control must observe a different output than the reproduction",
          );
      }
    }
    const id = `F-${newId().slice(0, 18)}`,
      confidence = Math.min(
        0.75,
        new Set(p.checks.map((c) => c.purpose)).size / 3,
      );
    this.tx(() => {
      this.db
        .prepare("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?)")
        .run(
          id,
          scope,
          p.missionId,
          title,
          p.severity,
          description,
          limitations,
          "unverified",
          confidence,
          json(p.checks),
          now(),
        );
      for (const o of observations)
        this.db
          .prepare("INSERT INTO finding_evidence VALUES(?,?,?,?)")
          .run(id, scope, o.id, o.hash);
      for (const chunk of new Set(p.sources))
        this.db
          .prepare("INSERT INTO finding_citations VALUES(?,?,?)")
          .run(id, scope, chunk);
    });
    const finding = this.finding(scope, id);
    this.index(
      scope,
      id,
      "finding",
      title,
      json(finding),
      `cyber://finding/${id}`,
      p.missionId,
    );
    return finding;
  }
  finding(scope: string, id: string) {
    this.open(scope);
    const row = this.db
      .prepare("SELECT * FROM findings WHERE id=? AND scope=?")
      .get(id, scope);
    if (!row) throw new Error("Missing finding in scope");
    const evidence = this.db
      .prepare(
        "SELECT observation_id,hash FROM finding_evidence WHERE finding_id=? AND scope=?",
      )
      .all(id, scope);
    return {
      id,
      scope,
      missionId: String(row.mission_id),
      title: String(row.title),
      createdAt: String(row.created),
      severity: String(row.severity),
      description: String(row.description),
      limitations: String(row.limitations),
      status: String(row.status),
      confidence: Number(row.confidence),
      confidenceBasis:
        "Observed control-category coverage, not a statistical probability or proof of impact",
      checks: parse(row.checks) as FindingProposal["checks"],
      evidence: evidence.map((e) => String(e.observation_id)),
      sources: this.db
        .prepare(
          "SELECT chunk_id FROM finding_citations WHERE finding_id=? AND scope=?",
        )
        .all(id, scope)
        .map((c) => this.chunk(scope, String(c.chunk_id))),
      verification: (() => {
        const v = this.db
          .prepare(
            "SELECT * FROM finding_verifications WHERE finding_id=? AND scope=?",
          )
          .get(id, scope);
        return v
          ? {
              observationId: String(v.observation_id),
              hash: String(v.hash),
              attempt: Number(v.attempt),
              verifiedBy: parse(v.detail),
              humanApproval: null,
              timestamp: String(v.timestamp),
            }
          : null;
      })(),
    };
  }
  findings(scope: string, missionId: string) {
    this.mission(scope, missionId);
    return this.db
      .prepare(
        "SELECT id FROM findings WHERE scope=? AND mission_id=? ORDER BY created",
      )
      .all(scope, missionId)
      .map((r) => this.finding(scope, String(r.id)));
  }
  findingHash(scope: string, id: string) {
    const f = this.finding(scope, id);
    return hash(
      json({
        id: f.id,
        missionId: f.missionId,
        title: f.title,
        severity: f.severity,
        description: f.description,
        limitations: f.limitations,
        checks: f.checks,
        evidence: f.evidence,
        sources: f.sources.map((s) => ({ id: s.id, hash: s.hash })),
      }),
    );
  }
  reportFingerprint(scope: string, missionId: string) {
    const m = this.mission(scope, missionId);
    return hash(
      json({
        missionId,
        scope,
        boundaries: m.boundaries,
        findings: this.findings(scope, missionId).map((f) => ({
          id: f.id,
          hash: this.findingHash(scope, f.id),
          status: f.status,
          verification: f.verification,
        })),
      }),
    );
  }
  private checkVerification(
    scope: string,
    finding: ReturnType<PlatformStore["finding"]>,
    checks: FindingProposal["checks"],
    sessionId: string,
  ) {
    if (!Array.isArray(checks) || checks.length < 2 || checks.length > 30)
      throw new Error("Verification needs reproduction and negative controls");
    const purposes = new Set(checks.map((c) => c.purpose));
    if (!purposes.has("reproduction") || !purposes.has("negative-control"))
      throw new Error("Verification needs reproduction and negative controls");
    const initial = this.evidenceStore.evidence(scope, finding.evidence),
      proofs = this.evidenceStore.evidence(
        scope,
        checks.map((c) => c.observationId),
      );
    const reopened = this.db
      .prepare(
        "SELECT timestamp FROM checkpoints WHERE scope=? AND mission_id=? AND node_id='validation' AND state='PENDING' ORDER BY seq DESC LIMIT 1",
      )
      .get(scope, finding.missionId);
    const cutoff = Math.max(
      Date.parse(finding.createdAt),
      reopened ? Date.parse(String(reopened.timestamp)) : 0,
    );
    if (proofs.some((o) => Date.parse(o.timestamp) < cutoff))
      throw new Error(
        "Verification requires fresh observations for the current validation",
      );
    if (
      proofs.some(
        (o) =>
          !o.success ||
          o.sessionId !== sessionId ||
          finding.evidence.includes(o.id) ||
          initial.some((old) => old.sessionId === o.sessionId),
      )
    )
      throw new Error(
        "Verification requires fresh successful observations from a distinct session",
      );
    for (const c of checks) {
      if (
        typeof c.contains !== "string" ||
        c.contains.trim().length < 4 ||
        !proofs.some(
          (o) => o.id === c.observationId && o.output.includes(c.contains),
        )
      )
        throw new Error("Verification control lacks observed evidence");
      if (
        !finding.checks.some(
          (expected) =>
            expected.purpose === c.purpose && expected.contains === c.contains,
        )
      )
        throw new Error(
          "Verification does not test the finding's declared criterion",
        );
    }
    // The controls are compared by their output, not only by the
    // observation they cite: a control that replays the same run under
    // another observation id proves nothing either. The same observation
    // would carry the same output, so this covers both.
    const claims = checks.filter((c) => c.purpose === "reproduction");
    for (const control of checks.filter(
      (c) => c.purpose === "negative-control",
    )) {
      for (const claim of claims) {
        const claimed = proofs.find((o) => o.id === claim.observationId);
        const observed = proofs.find((o) => o.id === control.observationId);
        if (claimed && observed && claimed.output === observed.output)
          throw new Error(
            "A negative control must observe a different output than the reproduction",
          );
      }
    }
  }
  verificationPayload(
    scope: string,
    id: string,
    sessionId: string,
    checks: FindingProposal["checks"],
  ) {
    const finding = this.finding(scope, id);
    this.checkVerification(scope, finding, checks, sessionId);
    return {
      type: "finding-verification",
      findingId: id,
      findingHash: this.findingHash(scope, id),
      runId: newId(),
      verdict: "confirmed",
      checks,
    };
  }
  verifyFinding(scope: string, id: string, verificationId?: string) {
    const f = this.finding(scope, id),
      m = this.mission(scope, f.missionId);
    const verification = m.nodes.find((n) => n.id === "validation");
    if (
      verification?.state !== "COMPLETED" ||
      !Array.isArray(verification.result) ||
      !verification.result.some(
        (r: any) => r.role === "verification-agent" && r.evidence?.length,
      )
    )
      throw new Error("Independent verification-stage evidence is required");
    if (
      !this.db
        .prepare(
          "SELECT 1 FROM verification_links WHERE mission_id=? AND scope=? AND finding_id=? AND attempt=?",
        )
        .get(f.missionId, scope, f.id, verification.attempt)
    )
      throw new Error(
        "Finding was not included in the completed verification checkpoint",
      );
    if (
      !f.sources.length ||
      !f.checks.some((c) => c.purpose === "reproduction") ||
      !f.checks.some((c) => c.purpose === "negative-control")
    )
      throw new Error(
        "Sources, reproduction and negative controls are required",
      );
    if (
      !verificationId ||
      f.evidence.includes(verificationId) ||
      !verification.result.some(
        (r: Pick<WorkerResult, "evidence" | "role">) =>
          r.role === "verification-agent" &&
          r.evidence.includes(verificationId),
      )
    )
      throw new Error(
        "Choose an independent verification observation from the completed validation checkpoint",
      );
    const observation = this.evidenceStore.evidence(scope, [verificationId])[0];
    if (!observation.success)
      throw new Error("Independent verification observation failed");
    let attestation: any;
    try {
      attestation = JSON.parse(observation.output);
    } catch {
      throw new Error("A linked verification attestation is required");
    }
    if (
      observation.tool !== "harness:verification" ||
      attestation.findingId !== id ||
      attestation.findingHash !== this.findingHash(scope, id) ||
      attestation.verdict !== "confirmed"
    )
      throw new Error("Verification attestation is unrelated or stale");
    this.checkVerification(scope, f, attestation.checks, observation.sessionId);
    const observations = this.evidenceStore.evidence(scope, f.evidence);
    if (
      f.checks.some(
        (c) =>
          !observations.some(
            (o) =>
              o.id === c.observationId &&
              o.success &&
              o.output.includes(c.contains),
          ),
      )
    )
      throw new Error("Observed checks no longer match evidence");
    // The declared control must observe a different output than the
    // reproduction it refutes. The same observation would have the same
    // output, so this covers the control that cites the reproduction too.
    for (const control of f.checks.filter(
      (c) => c.purpose === "negative-control",
    )) {
      for (const claim of f.checks.filter(
        (c) => c.purpose === "reproduction",
      )) {
        const claimed = observations.find((o) => o.id === claim.observationId);
        const observed = observations.find(
          (o) => o.id === control.observationId,
        );
        if (claimed && observed && claimed.output === observed.output)
          throw new Error(
            "A negative control must observe a different output than the reproduction",
          );
      }
    }
    this.db
      .prepare(
        "INSERT INTO finding_verifications(finding_id,scope,observation_id,hash,attempt,timestamp,detail) VALUES(?,?,?,?,?,?,?) ON CONFLICT(finding_id)DO UPDATE SET observation_id=excluded.observation_id,hash=excluded.hash,attempt=excluded.attempt,timestamp=excluded.timestamp,detail=excluded.detail",
      )
      .run(
        id,
        scope,
        verificationId,
        observation.hash,
        verification.attempt,
        now(),
        json({
          sessionId: observation.sessionId,
          runId: attestation.runId,
          kind: "technical-reproduction",
        }),
      );
    this.db
      .prepare(
        "UPDATE findings SET status='verified',confidence=? WHERE id=? AND scope=?",
      )
      .run(new Set(f.checks.map((c) => c.purpose)).size / 3, id, scope);
    const updated = this.finding(scope, id);
    this.index(
      scope,
      id,
      "finding",
      updated.title,
      json(updated),
      `cyber://finding/${id}`,
      f.missionId,
    );
    return updated;
  }
  rejectFinding(scope: string, id: string) {
    const f = this.finding(scope, id);
    this.db
      .prepare(
        "UPDATE findings SET status='disproven',confidence=0 WHERE id=? AND scope=?",
      )
      .run(id, scope);
    this.index(
      scope,
      id,
      "finding",
      f.title,
      json(this.finding(scope, id)),
      `cyber://finding/${id}`,
      f.missionId,
    );
    return this.finding(scope, id);
  }
  search(
    scope: string,
    kind: SearchResult["kind"] | "all",
    query: string,
    limit = 10,
  ): SearchResult[] {
    this.open(scope);
    if (
      ![
        "all",
        "mission",
        "evidence",
        "finding",
        "source",
        "knowledge",
      ].includes(kind) ||
      !Number.isInteger(limit) ||
      limit < 1 ||
      limit > 50
    )
      throw new Error("Invalid search kind/limit");
    const ranking = memoryQuery(query);
    const tokens = ranking.terms;
    if (!tokens.length) return [];
    if (kind === "all" || kind === "knowledge") this.indexKnowledge(scope);
    const match = tokens.map((t) => `"${t}"`).join(" OR ");
    const candidates = this.db
      .prepare(
        `SELECT s.* FROM search_fts JOIN search_records s ON s.id=search_fts.id WHERE search_fts MATCH ? AND s.scope=? AND (?='all' OR s.kind=?) AND (s.kind!='source' OR EXISTS(SELECT 1 FROM chunks c JOIN revisions r ON r.id=c.revision_id WHERE c.id=s.id AND r.current=1)) ORDER BY rank LIMIT ?`,
      )
      .all(match, scope, kind, kind, 200);
    return rankMemory(
      candidates.map((r) => ({
        id: String(r.id),
        kind: String(r.kind),
        title: String(r.title),
        text: String(r.text),
        raw: r,
      })),
      ranking,
    )
      .slice(0, limit)
      .map(({ raw: r }) => ({
        id: String(r.id),
        kind: r.kind as SearchResult["kind"],
        title: String(r.title),
        excerpt: (() => {
          const original = String(r.text);
          if (r.kind === "knowledge" || r.kind === "evidence") {
            try {
              const data = JSON.parse(original);
              const fragment =
                r.kind === "knowledge" ? data.content : data.output;
              if (typeof fragment === "string" && original.includes(fragment))
                return fragment.slice(0, 1800);
            } catch {
              /* Keep an original contiguous excerpt. */
            }
          }
          return original.slice(0, 1800);
        })(),
        reference: String(r.reference),
        hash: String(r.hash),
        missionId: r.mission_id ? String(r.mission_id) : undefined,
      }));
  }
  recall(
    scope: string,
    sessionId: string,
    turnId: string,
    query: string,
    maxChars: number,
  ) {
    if (!Number.isFinite(maxChars) || maxChars < 0 || maxChars > 64000)
      throw new Error("Invalid recall character budget");
    const hits = this.search(scope, "all", query, 50),
      selected: SearchResult[] = [];
    const seen = new Set<string>();
    for (const hit of hits) {
      if (selected.length >= 8) break;
      const raw = this.db
        .prepare("SELECT text FROM search_records WHERE id=? AND scope=?")
        .get(hit.id, scope);
      const key = memoryFragment(hit.kind, String(raw!.text));
      if (seen.has(key)) continue;
      selected.push(hit);
      if (json(selected).length > maxChars) {
        selected.pop();
        continue;
      }
      seen.add(key);
    }
    for (const hit of selected) {
      this.db
        .prepare("INSERT OR IGNORE INTO memory_refs VALUES(?,?,?,?,?,?,?)")
        .run(scope, sessionId, turnId, hit.id, hit.kind, hit.hash, now());
      if (hit.kind !== "source") continue;
      this.db
        .prepare("INSERT OR IGNORE INTO memory_uses VALUES(?,?,?,?,?)")
        .run(scope, sessionId, turnId, hit.id, now());
    }
    return selected;
  }
  memoryUses(scope: string, sessionId: string) {
    this.open(scope);
    return this.db
      .prepare(
        "SELECT * FROM memory_refs WHERE scope=? AND session_id=? ORDER BY timestamp LIMIT 200",
      )
      .all(scope, sessionId)
      .map((r) => ({
        turnId: String(r.turn_id),
        referenceId: String(r.reference_id),
        kind: String(r.kind),
        hash: String(r.hash),
        timestamp: String(r.timestamp),
      }));
  }
  completedMissions(scope: string) {
    this.open(scope);
    return this.db
      .prepare(
        "SELECT id FROM missions m WHERE scope=? AND NOT EXISTS(SELECT 1 FROM nodes n WHERE n.mission_id=m.id AND n.state NOT IN ('COMPLETED','SKIPPED')) ORDER BY created DESC LIMIT 50",
      )
      .all(scope)
      .map((r) => String(r.id));
  }
  reviewDone(scope: string, id: string, digest: string) {
    this.mission(scope, id);
    return (
      this.db
        .prepare(
          "SELECT digest FROM mission_reviews WHERE mission_id=? AND scope=?",
        )
        .get(id, scope)?.digest === digest
    );
  }
  recordMissionReview(
    scope: string,
    id: string,
    digest: string,
    payload: unknown,
  ) {
    this.mission(scope, id);
    this.db
      .prepare(
        "INSERT INTO mission_reviews VALUES(?,?,?,?,?) ON CONFLICT(mission_id)DO UPDATE SET digest=excluded.digest,payload=excluded.payload,timestamp=excluded.timestamp",
      )
      .run(id, scope, digest, json(payload), now());
  }
  review(scope: string, id: string) {
    this.mission(scope, id);
    const r = this.db
      .prepare("SELECT * FROM mission_reviews WHERE mission_id=? AND scope=?")
      .get(id, scope);
    return r
      ? { digest: r.digest, payload: parse(r.payload), timestamp: r.timestamp }
      : null;
  }
  putSource(spec: SourceSpec) {
    this.open(spec.scope);
    identifier(spec.id);
    this.db
      .prepare(
        "INSERT INTO source_specs(id,scope,payload)VALUES(?,?,?) ON CONFLICT(id,scope)DO UPDATE SET payload=excluded.payload,etag=NULL,last_modified=NULL",
      )
      .run(spec.id, spec.scope, json(spec));
  }
  sources(scope: string): SourceSpec[] {
    this.open(scope);
    return this.db
      .prepare("SELECT payload FROM source_specs WHERE scope=? ORDER BY id")
      .all(scope)
      .map((r) => parse(r.payload));
  }
  sourceState(scope: string, id: string) {
    this.open(scope);
    const r = this.db
      .prepare("SELECT * FROM source_specs WHERE scope=? AND id=?")
      .get(scope, id);
    if (!r) throw new Error("Source not registered in this scope");
    return {
      spec: parse(r.payload) as SourceSpec,
      etag: r.etag as string | null,
      lastModified: r.last_modified as string | null,
    };
  }
  synced(scope: string, id: string, etag?: string, lastModified?: string) {
    this.open(scope);
    this.db
      .prepare(
        "UPDATE source_specs SET etag=?,last_modified=?,last_synced=? WHERE scope=? AND id=?",
      )
      .run(etag ?? null, lastModified ?? null, now(), scope, id);
  }
  metadata(key: string, value?: string): string | undefined {
    if (this.closed) throw new Error("Store closed");
    if (value !== undefined)
      this.db
        .prepare(
          "INSERT INTO meta VALUES(?,?)ON CONFLICT(key)DO UPDATE SET value=excluded.value",
        )
        .run(key, value);
    return this.db.prepare("SELECT value FROM meta WHERE key=?").get(key)
      ?.value as string | undefined;
  }
  indexKnowledge(scope: string) {
    const facts = this.evidenceStore.getKnowledge(scope, undefined, 200),
      active = new Set(facts.map((f) => `K-${f.id}`));
    this.tx(() => {
      for (const row of this.db
        .prepare(
          "SELECT id FROM search_records WHERE scope=? AND kind='knowledge'",
        )
        .all(scope))
        if (!active.has(String(row.id)))
          this.db
            .prepare("DELETE FROM search_records WHERE id=? AND scope=?")
            .run(row.id, scope);
      for (const fact of facts)
        this.index(
          scope,
          `K-${fact.id}`,
          "knowledge",
          fact.key,
          json(fact),
          `cyber://knowledge/${fact.id}`,
        );
    });
  }
  /** A fact needs the observations it was read from, in this scope. */
  private checkObservations(scope: string, ids: unknown): string[] {
    if (!Array.isArray(ids) || !ids.length || ids.length > 50)
      throw new Error("An entity or relation needs 1..50 observations");
    const unique = [...new Set(ids.map((value) => String(value)))];
    if (unique.length !== ids.length)
      throw new Error("Duplicate observation id");
    let found: unknown[] = [];
    try {
      found = this.evidenceStore.evidence(scope, unique);
    } catch {
      throw new Error("Observation missing in this scope");
    }
    if (found.length !== unique.length)
      throw new Error("Observation missing in this scope");
    return unique;
  }
  private checkAttributes(value: unknown): Record<string, unknown> {
    if (value === undefined) return {};
    if (!value || typeof value !== "object" || Array.isArray(value))
      throw new Error("Attributes must be an object");
    const serialized = JSON.stringify(value);
    if (serialized.length > 20000) throw new Error("Attributes are too large");
    if (redactText(serialized) !== serialized)
      throw new Error("Attributes carry a secret; redact it first");
    return value as Record<string, unknown>;
  }
  private entityFrom(row: Row): Entity {
    return {
      id: String(row.id),
      scope: String(row.scope),
      type: row.type as EntityType,
      key: String(row.key),
      label: String(row.label),
      attributes: parse(row.attributes) as Record<string, unknown>,
      observationIds: parse(row.observation_ids) as string[],
      created: String(row.created),
      updated: String(row.updated),
    };
  }
  private relationFrom(row: Row): Relation {
    return {
      id: String(row.id),
      scope: String(row.scope),
      source: String(row.source),
      target: String(row.target),
      kind: String(row.kind),
      attributes: parse(row.attributes) as Record<string, unknown>,
      observationIds: parse(row.observation_ids) as string[],
      created: String(row.created),
    };
  }
  /**
   * Record one thing the engagement learned. The key is the identity inside
   * its type, so a second read merges instead of duplicating.
   */
  upsertEntity(
    scope: string,
    input: {
      type: string;
      key: string;
      label?: string;
      attributes?: unknown;
      observationIds: unknown;
    },
  ): Entity {
    this.open(scope);
    if (!ENTITY_TYPES.includes(input.type as EntityType))
      throw new Error("Unsupported entity type");
    const key = String(input.key ?? "").trim();
    if (!key || key.length > 300 || /[\u0000-\u001f]/.test(key))
      throw new Error("Invalid entity key");
    const label =
      input.label === undefined ? "" : text(String(input.label), 500);
    const attributes = this.checkAttributes(input.attributes);
    const observations = this.checkObservations(scope, input.observationIds);
    return this.tx(() => {
      const existing = this.db
        .prepare("SELECT * FROM entities WHERE scope=? AND type=? AND key=?")
        .get(scope, input.type, key) as Row | undefined;
      if (!existing) {
        const id = `entity-${newId()}`;
        this.db
          .prepare("INSERT INTO entities VALUES(?,?,?,?,?,?,?,?,?)")
          .run(
            id,
            scope,
            input.type,
            key,
            label,
            json(attributes),
            json(observations),
            now(),
            now(),
          );
        return this.entity(scope, id);
      }
      const current = this.entityFrom(existing);
      this.db
        .prepare(
          "UPDATE entities SET label=?,attributes=?,observation_ids=?,updated=? WHERE id=? AND scope=?",
        )
        .run(
          label || current.label,
          json({ ...current.attributes, ...attributes }),
          json([...new Set([...current.observationIds, ...observations])]),
          now(),
          current.id,
          scope,
        );
      return this.entity(scope, current.id);
    });
  }
  entity(scope: string, id: string): Entity {
    this.open(scope);
    identifier(id);
    const row = this.db
      .prepare("SELECT * FROM entities WHERE id=? AND scope=?")
      .get(id, scope);
    if (!row) throw new Error("Missing entity in this scope");
    return this.entityFrom(row);
  }
  entities(
    scope: string,
    filter: { type?: string; query?: string; limit?: number } = {},
  ): Entity[] {
    this.open(scope);
    if (
      filter.type !== undefined &&
      !ENTITY_TYPES.includes(filter.type as EntityType)
    )
      throw new Error("Unsupported entity type");
    const limit = filter.limit === undefined ? 100 : filter.limit;
    if (!Number.isInteger(limit) || limit < 1 || limit > 500)
      throw new Error("Invalid entity limit");
    const query = filter.query ? String(filter.query) : "";
    const rows = (
      filter.type
        ? this.db
            .prepare(
              "SELECT * FROM entities WHERE scope=? AND type=? AND (?='' OR instr(lower(key),lower(?))>0 OR instr(lower(label),lower(?))>0) ORDER BY created DESC LIMIT ?",
            )
            .all(scope, filter.type, query, query, query, limit)
        : this.db
            .prepare(
              "SELECT * FROM entities WHERE scope=? AND (?='' OR instr(lower(key),lower(?))>0 OR instr(lower(label),lower(?))>0) ORDER BY created DESC LIMIT ?",
            )
            .all(scope, query, query, query, limit)
    ) as Row[];
    return rows.map((row) => this.entityFrom(row));
  }
  /** Link two known things. The same edge merges its evidence. */
  relate(
    scope: string,
    input: {
      from: string;
      to: string;
      kind: string;
      attributes?: unknown;
      observationIds: unknown;
    },
  ): Relation {
    this.open(scope);
    const source = this.entity(scope, String(input.from ?? "")),
      target = this.entity(scope, String(input.to ?? ""));
    if (source.id === target.id)
      throw new Error("An entity cannot relate to itself");
    const kind = String(input.kind ?? "").trim();
    if (!/^[a-z][a-z0-9-]{1,40}$/.test(kind))
      throw new Error("Invalid relation kind");
    const attributes = this.checkAttributes(input.attributes);
    const observations = this.checkObservations(scope, input.observationIds);
    return this.tx(() => {
      const existing = this.db
        .prepare(
          "SELECT * FROM relations WHERE scope=? AND source=? AND target=? AND kind=?",
        )
        .get(scope, source.id, target.id, kind) as Row | undefined;
      if (!existing) {
        const id = `relation-${newId()}`;
        this.db
          .prepare("INSERT INTO relations VALUES(?,?,?,?,?,?,?,?)")
          .run(
            id,
            scope,
            source.id,
            target.id,
            kind,
            json(attributes),
            json(observations),
            now(),
          );
        return this.relation(scope, id);
      }
      const current = this.relationFrom(existing);
      this.db
        .prepare(
          "UPDATE relations SET attributes=?,observation_ids=? WHERE id=? AND scope=?",
        )
        .run(
          json({ ...current.attributes, ...attributes }),
          json([...new Set([...current.observationIds, ...observations])]),
          current.id,
          scope,
        );
      return this.relation(scope, current.id);
    });
  }
  relation(scope: string, id: string): Relation {
    this.open(scope);
    identifier(id);
    const row = this.db
      .prepare("SELECT * FROM relations WHERE id=? AND scope=?")
      .get(id, scope);
    if (!row) throw new Error("Missing relation in this scope");
    return this.relationFrom(row);
  }
  relations(scope: string, id?: string): Relation[] {
    this.open(scope);
    if (id !== undefined) {
      this.entity(scope, id);
      return (
        this.db
          .prepare(
            "SELECT * FROM relations WHERE scope=? AND (source=? OR target=?) ORDER BY created",
          )
          .all(scope, id, id) as Row[]
      ).map((row) => this.relationFrom(row));
    }
    return (
      this.db
        .prepare("SELECT * FROM relations WHERE scope=? ORDER BY created")
        .all(scope) as Row[]
    ).map((row) => this.relationFrom(row));
  }
  /**
   * The shortest chain between two entities, following relations in either
   * direction. This is what turns a list of facts into a pivot.
   */
  path(
    scope: string,
    from: string,
    to: string,
    maxDepth = 4,
  ): { entities: Entity[]; relations: Relation[] } | null {
    this.open(scope);
    const start = this.entity(scope, from),
      end = this.entity(scope, to);
    if (!Number.isInteger(maxDepth) || maxDepth < 1 || maxDepth > 6)
      throw new Error("Invalid path depth");
    const adjacency = new Map<
      string,
      { next: string; relation: Relation }[]
    >();
    for (const relation of this.relations(scope)) {
      const out = adjacency.get(relation.source) ?? [];
      out.push({ next: relation.target, relation });
      adjacency.set(relation.source, out);
      const back = adjacency.get(relation.target) ?? [];
      back.push({ next: relation.source, relation });
      adjacency.set(relation.target, back);
    }
    const queue: { id: string; chain: string[]; path: Relation[] }[] = [
      { id: start.id, chain: [start.id], path: [] },
    ];
    const seen = new Set([start.id]);
    while (queue.length) {
      const current = queue.shift()!;
      if (current.path.length >= maxDepth) continue;
      for (const edge of adjacency.get(current.id) ?? []) {
        if (seen.has(edge.next)) continue;
        const chain = [...current.chain, edge.next],
          path = [...current.path, edge.relation];
        if (edge.next === end.id)
          return {
            entities: chain.map((id) => this.entity(scope, id)),
            relations: path,
          };
        seen.add(edge.next);
        queue.push({ id: edge.next, chain, path });
      }
    }
    return null;
  }

  close() {
    if (!this.closed) {
      this.closed = true;
      this.db.close();
    }
  }
}
