/** Versioned reports, bounded capitalization and cleanup strictly after restitution. */
import * as fs from "node:fs";
import * as path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import {
  assertPlainPath,
  atomicWrite,
  json,
  newId,
  now,
  redactText,
} from "./util";
import type { PlatformStore } from "./platform-store";
import type { StorePort } from "./types";
const digestFile = (file: string) =>
  createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const text = (value: unknown, max = 16000): string => {
  if (typeof value !== "string" || !value.trim() || value.length > max)
    throw new Error("A bounded nonempty text is required");
  return redactText(value);
};
const kinds = [
  "evidence",
  "poc",
  "capture",
  "script",
  "rule",
  "fixture",
  "report-docx",
  "report-pdf",
  "report-qa",
];
export class EngagementWorkflow {
  private db: DatabaseSync;
  constructor(
    private root: string,
    private platform: PlatformStore,
    private evidence: StorePort,
  ) {
    const file = path.join(root, "platform.sqlite");
    assertPlainPath(file);
    this.db = new DatabaseSync(file);
    this.db.exec(`PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
   CREATE TABLE IF NOT EXISTS workflow_artifacts(id TEXT PRIMARY KEY,scope TEXT NOT NULL,mission_id TEXT NOT NULL,payload TEXT NOT NULL,FOREIGN KEY(mission_id,scope) REFERENCES missions(id,scope));
   CREATE TABLE IF NOT EXISTS workflow_reports(id TEXT PRIMARY KEY,scope TEXT NOT NULL,mission_id TEXT NOT NULL,snapshot TEXT NOT NULL,payload TEXT NOT NULL,reviewed INTEGER NOT NULL DEFAULT 0,FOREIGN KEY(mission_id,scope) REFERENCES missions(id,scope));
   CREATE TABLE IF NOT EXISTS workflow_restitutions(report_id TEXT PRIMARY KEY,scope TEXT NOT NULL,mission_id TEXT NOT NULL,payload TEXT NOT NULL,FOREIGN KEY(report_id) REFERENCES workflow_reports(id));
   CREATE TABLE IF NOT EXISTS workflow_capitalizations(id TEXT PRIMARY KEY,scope TEXT NOT NULL,mission_id TEXT NOT NULL,snapshot_hash TEXT NOT NULL,payload TEXT NOT NULL,UNIQUE(scope,mission_id,snapshot_hash),FOREIGN KEY(mission_id,scope) REFERENCES missions(id,scope));
   CREATE TABLE IF NOT EXISTS workflow_cleanup(id TEXT PRIMARY KEY,scope TEXT NOT NULL,mission_id TEXT NOT NULL,report_id TEXT NOT NULL,payload TEXT NOT NULL,FOREIGN KEY(report_id) REFERENCES workflow_restitutions(report_id));
   CREATE TABLE IF NOT EXISTS workflow_events(id INTEGER PRIMARY KEY AUTOINCREMENT,scope TEXT NOT NULL,event TEXT NOT NULL,payload TEXT NOT NULL,created TEXT NOT NULL);
   CREATE TRIGGER IF NOT EXISTS workflow_events_no_update BEFORE UPDATE ON workflow_events BEGIN SELECT RAISE(ABORT,'Immutable workflow event'); END;
   CREATE TRIGGER IF NOT EXISTS workflow_events_no_delete BEFORE DELETE ON workflow_events BEGIN SELECT RAISE(ABORT,'Immutable workflow event'); END;
   CREATE TRIGGER IF NOT EXISTS workflow_artifacts_no_update BEFORE UPDATE ON workflow_artifacts BEGIN SELECT RAISE(ABORT,'Immutable artifact'); END;
   CREATE TRIGGER IF NOT EXISTS workflow_artifacts_no_delete BEFORE DELETE ON workflow_artifacts BEGIN SELECT RAISE(ABORT,'Immutable artifact'); END;
   CREATE TRIGGER IF NOT EXISTS workflow_reports_snapshot_immutable BEFORE UPDATE ON workflow_reports WHEN new.snapshot!=old.snapshot OR new.id!=old.id OR new.scope!=old.scope OR new.mission_id!=old.mission_id BEGIN SELECT RAISE(ABORT,'Immutable report snapshot'); END;
   CREATE TRIGGER IF NOT EXISTS workflow_reports_no_delete BEFORE DELETE ON workflow_reports BEGIN SELECT RAISE(ABORT,'Immutable report version'); END;
   CREATE TRIGGER IF NOT EXISTS workflow_restitutions_no_update BEFORE UPDATE ON workflow_restitutions BEGIN SELECT RAISE(ABORT,'Immutable restitution'); END;
   CREATE TRIGGER IF NOT EXISTS workflow_restitutions_no_delete BEFORE DELETE ON workflow_restitutions BEGIN SELECT RAISE(ABORT,'Immutable restitution'); END;
   CREATE TRIGGER IF NOT EXISTS workflow_finding_changed AFTER UPDATE ON findings BEGIN
    UPDATE workflow_reports SET reviewed=0 WHERE scope=new.scope AND mission_id=new.mission_id;
    UPDATE nodes SET state='PENDING',result='null',lease=NULL,owner=NULL,expires=NULL WHERE scope=new.scope AND mission_id=new.mission_id AND id='report' AND state='COMPLETED'; END;
   CREATE TRIGGER IF NOT EXISTS workflow_finding_created AFTER INSERT ON findings BEGIN
    UPDATE workflow_reports SET reviewed=0 WHERE scope=new.scope AND mission_id=new.mission_id;
    UPDATE nodes SET state='PENDING',result='null',lease=NULL,owner=NULL,expires=NULL WHERE scope=new.scope AND mission_id=new.mission_id AND id='report' AND state='COMPLETED'; END;
  `);
  }
  close() {
    this.db.close();
  }
  private tx<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const value = fn();
      this.db.exec("COMMIT");
      return value;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
  private event(scope: string, event: string, payload: unknown) {
    this.db
      .prepare(
        "INSERT INTO workflow_events(scope,event,payload,created) VALUES(?,?,?,?)",
      )
      .run(scope, event, json(payload), now());
  }
  registerArtifact(
    scope: string,
    missionId: string,
    input: {
      path: string;
      kind: string;
      observationIds: string[];
      caption?: string;
    },
    allowedRoot: string,
  ) {
    return this.tx(() => {
      this.platform.mission(scope, missionId);
      if (!kinds.includes(input.kind))
        throw new Error("Unsupported artifact kind");
      const file = path.resolve(input.path),
        allowed = fs.realpathSync(allowedRoot);
      assertPlainPath(file);
      if (file !== allowed && !file.startsWith(allowed + path.sep))
        throw new Error("Artifact is outside the engagement directory");
      const stat = fs.statSync(file);
      if (!stat.isFile() || stat.size < 1 || stat.size > 100000000)
        throw new Error("Invalid artifact size");
      const signature = fs.readFileSync(file).subarray(0, 8);
      if (
        input.kind === "report-docx" &&
        signature.subarray(0, 4).toString("hex") !== "504b0304"
      )
        throw new Error("Invalid Word artifact signature");
      if (
        input.kind === "report-pdf" &&
        signature.subarray(0, 5).toString() !== "%PDF-"
      )
        throw new Error("Invalid PDF artifact signature");
      if (!Array.isArray(input.observationIds) || !input.observationIds.length)
        throw new Error("Artifact provenance needs observations");
      this.evidence.evidence(scope, input.observationIds);
      const value = {
        id: `artifact-${newId()}`,
        scope,
        missionId,
        kind: input.kind,
        path: file,
        sha256: digestFile(file),
        bytes: stat.size,
        observationIds: input.observationIds,
        caption: input.caption ? text(input.caption, 2000) : "",
        createdAt: now(),
      };
      this.db
        .prepare("INSERT INTO workflow_artifacts VALUES(?,?,?,?)")
        .run(value.id, scope, missionId, json(value));
      this.event(scope, "artifact.registered", {
        id: value.id,
        kind: value.kind,
        sha256: value.sha256,
      });
      return value;
    });
  }
  artifact(scope: string, id: string) {
    const row = this.db
      .prepare("SELECT payload FROM workflow_artifacts WHERE scope=? AND id=?")
      .get(scope, id);
    if (!row) throw new Error("Artifact not found in this scope");
    const a = JSON.parse(String(row.payload));
    assertPlainPath(a.path);
    if (digestFile(a.path) !== a.sha256)
      throw new Error("Artifact content changed; register a new version");
    return a;
  }
  snapshot(scope: string, missionId: string, config: any) {
    return this.tx(() => {
      const m = this.platform.mission(scope, missionId);
      if (
        !m.nodes.some((n) => n.id === "validation" && n.state === "COMPLETED")
      )
        throw new Error(
          "A report snapshot requires the completed validation stage",
        );
      for (const k of ["title", "client", "author", "period", "method"])
        text(config?.[k], 8000);
      // The deliverables folder is created with the snapshot, inside the
      // engagement. It is versioned because the generator refuses to overwrite
      // a report that was already delivered.
      const engagementRoot = this.platform.missionRoot(scope, missionId);
      const reportDir = engagementRoot
        ? path.join(
            engagementRoot,
            `rapport-v${
              Number(
                this.db
                  .prepare(
                    "SELECT COUNT(*) AS n FROM workflow_reports WHERE scope=? AND mission_id=?",
                  )
                  .get(scope, missionId)!.n,
              ) + 1
            }`,
          )
        : undefined;
      let bytes = 0;
      const rows = this.platform
        .findings(scope, missionId)
        .filter((f) => !["disproven", "rejected"].includes(f.status));
      if (rows.length > 100) throw new Error("Report finding limit exceeded");
      const findings = rows.map((f) => {
        const d = config.findings?.[f.id];
        if (!d) throw new Error(`Missing report details for ${f.id}`);
        const classification = d.classification ?? "vulnerability";
        if (
          ![
            "vulnerability",
            "observation",
            "not-reproduced",
            "not-tested",
            "blocked",
          ].includes(classification)
        )
          throw new Error("Invalid finding classification");
        if (classification === "vulnerability" && f.status !== "verified")
          throw new Error(
            "Only verified findings can be reported as vulnerabilities",
          );
        for (const k of ["asset", "preconditions", "impact", "closure"])
          text(d[k]);
        for (const k of ["steps", "remediation"])
          if (!Array.isArray(d[k]) || !d[k].length || d[k].length > 100)
            throw new Error(`Missing ${k}`);
          else d[k].forEach((v: unknown) => text(v));
        const artifacts = (d.artifactIds ?? []).map((id: string) => {
          const a = this.artifact(scope, id);
          if (a.missionId !== missionId)
            throw new Error("Artifact belongs to another mission");
          return a;
        });
        const observations = this.evidence
          .evidence(scope, f.evidence)
          .map((o) => ({
            id: o.id,
            tool: o.tool,
            input: o.input,
            success: o.success,
            timestamp: o.timestamp,
            hash: o.hash,
            rawHash: o.rawHash ?? null,
            truncated: o.truncated ?? null,
            output: o.output,
          }));
        const entry = {
          ...f,
          asset: text(d.asset),
          preconditions: text(d.preconditions),
          impact: text(d.impact),
          closure: text(d.closure),
          steps: d.steps.map((v: unknown) => text(v)),
          remediation: d.remediation.map((v: unknown) => text(v)),
          cvss: d.cvss ?? null,
          businessRisk: d.businessRisk ? text(d.businessRisk) : null,
          classification,
          artifacts,
          observations,
        };
        bytes += Buffer.byteLength(json(entry), "utf8");
        if (bytes > 9500000)
          throw new Error("Report snapshot size limit exceeded");
        return entry;
      });
      const snapshot = {
        schemaVersion: 1,
        id: `report-${newId()}`,
        missionId,
        scope,
        createdAt: now(),
        sourceHash: this.platform.reportFingerprint(scope, missionId),
        title: text(config.title),
        client: text(config.client),
        author: text(config.author),
        period: text(config.period),
        method: text(config.method),
        boundaries: m.boundaries,
        findings,
        cleanupPolicy: "after-restitution-only",
      };
      const file = path.join(
          this.root,
          "reports",
          scope,
          missionId,
          `${snapshot.id}.json`,
        ),
        serialized = json(snapshot);
      if (Buffer.byteLength(serialized, "utf8") > 10000000)
        throw new Error("Report snapshot size limit exceeded");
      atomicWrite(file, serialized);
      this.db
        .prepare(
          "INSERT INTO workflow_reports(id,scope,mission_id,snapshot,payload) VALUES(?,?,?,?,?)",
        )
        .run(
          snapshot.id,
          scope,
          missionId,
          json(snapshot),
          json({
            snapshotPath: file,
            snapshotHash: digestFile(file),
            artifacts: [],
            review: null,
          }),
        );
      this.db
        .prepare(
          "UPDATE nodes SET state='PENDING',result='null',lease=NULL,owner=NULL,expires=NULL WHERE scope=? AND mission_id=? AND id='report' AND state='COMPLETED'",
        )
        .run(scope, missionId);
      this.event(scope, "report.snapshot", {
        id: snapshot.id,
        sourceHash: snapshot.sourceHash,
      });
      return {
        snapshot,
        path: file,
        sha256: digestFile(file),
        ...(reportDir ? { reportDir } : {}),
      };
    });
  }
  report(scope: string, id: string) {
    const row = this.db
      .prepare("SELECT * FROM workflow_reports WHERE scope=? AND id=?")
      .get(scope, id);
    if (!row) throw new Error("Report not found in this scope");
    return {
      id,
      scope,
      missionId: String(row.mission_id),
      snapshot: JSON.parse(String(row.snapshot)),
      ...JSON.parse(String(row.payload)),
      reviewed: Boolean(row.reviewed),
    };
  }
  private current(r: any) {
    const latest = this.db
      .prepare(
        "SELECT id FROM workflow_reports WHERE scope=? AND mission_id=? ORDER BY rowid DESC LIMIT 1",
      )
      .get(r.scope, r.missionId);
    if (latest?.id !== r.id)
      throw new Error("Report snapshot is stale; use the latest version");
    if (
      r.snapshot.sourceHash !==
      this.platform.reportFingerprint(r.scope, r.missionId)
    )
      throw new Error("Report snapshot is stale; generate a new version");
    if (digestFile(r.snapshotPath) !== r.snapshotHash)
      throw new Error("Report snapshot changed");
  }
  private checkPages(r: any) {
    const artifacts = r.artifacts.map((id: string) =>
      this.artifact(r.scope, id),
    );
    const qa = artifacts.find((a: any) => a.kind === "report-qa");
    if (!qa || !r.qa)
      throw new Error(
        "Register generated files and rendered pages before review",
      );
    const root = path.dirname(qa.path);
    for (const image of r.qa.pageImages) {
      const file = path.resolve(root, image.path);
      if (!file.startsWith(root + path.sep))
        throw new Error("QA page path escaped");
      assertPlainPath(file);
      if (digestFile(file) !== image.sha256)
        throw new Error("Rendered page changed after generation");
    }
  }
  registerReport(scope: string, id: string, artifactIds: string[]) {
    return this.tx(() => {
      const r = this.report(scope, id);
      this.current(r);
      if (!Array.isArray(artifactIds) || artifactIds.length !== 3)
        throw new Error("Exactly three report artifacts are required");
      const artifacts = artifactIds.map((a) => this.artifact(scope, a));
      if (artifacts.some((a) => a.missionId !== r.missionId))
        throw new Error("Report artifact belongs to another mission");
      for (const kind of ["report-docx", "report-pdf", "report-qa"])
        if (artifacts.filter((a) => a.kind === kind).length !== 1)
          throw new Error(`Exactly one ${kind} artifact is required`);
      const qa = JSON.parse(
        fs.readFileSync(
          artifacts.find((a) => a.kind === "report-qa").path,
          "utf8",
        ),
      );
      if (
        qa.snapshotId !== id ||
        qa.snapshotHash !== r.snapshotHash ||
        !Number.isInteger(qa.pages) ||
        qa.pages < 1 ||
        qa.pages > 100 ||
        qa.structuredChecks !== true
      )
        throw new Error("Invalid report QA manifest");
      for (const [kind, key] of [
        ["report-docx", "docxHash"],
        ["report-pdf", "pdfHash"],
      ])
        if (qa[key] !== artifacts.find((a) => a.kind === kind).sha256)
          throw new Error("Report QA hash mismatch");
      if (
        !Array.isArray(qa.pageImages) ||
        qa.pageImages.length !== qa.pages ||
        new Set(qa.pageImages.map((i: any) => i.path)).size !== qa.pages
      )
        throw new Error(
          "Every report page must have a distinct rendered image",
        );
      this.checkPages({ ...r, artifacts: artifactIds, qa });
      const payload = {
        snapshotPath: r.snapshotPath,
        snapshotHash: r.snapshotHash,
        artifacts: artifactIds,
        qa,
        review: null,
      };
      this.db
        .prepare(
          "UPDATE workflow_reports SET payload=?,reviewed=0 WHERE id=? AND scope=?",
        )
        .run(json(payload), id, scope);
      this.event(scope, "report.generated", {
        id,
        artifacts: artifactIds,
        pages: qa.pages,
      });
      return this.report(scope, id);
    });
  }
  assertReportReview(
    scope: string,
    id: string,
    input: {
      pagesReviewed: number[];
      decision: "approved" | "changes-required";
      reviewer: string;
      notes: string;
    },
  ) {
    const r = this.report(scope, id);
    this.current(r);
    this.checkPages(r);
    const expected = Array.from({ length: r.qa.pages }, (_, i) => i + 1);
    if (
      !Array.isArray(input.pagesReviewed) ||
      JSON.stringify(
        [...new Set(input.pagesReviewed)].sort((a, b) => a - b),
      ) !== JSON.stringify(expected)
    )
      throw new Error("Visual review must cover every rendered page");
    if (!["approved", "changes-required"].includes(input.decision))
      throw new Error("Invalid report review decision");
    return {
      r,
      review: {
        ...input,
        reviewer: text(input.reviewer, 300),
        notes: text(input.notes, 4000),
        reviewedAt: now(),
      },
    };
  }
  reviewReport(
    scope: string,
    id: string,
    input: {
      pagesReviewed: number[];
      decision: "approved" | "changes-required";
      reviewer: string;
      notes: string;
    },
  ) {
    return this.tx(() => {
      const { r, review } = this.assertReportReview(scope, id, input),
        { snapshotPath, snapshotHash, artifacts, qa } = r;
      this.db
        .prepare(
          "UPDATE workflow_reports SET payload=?,reviewed=? WHERE id=? AND scope=?",
        )
        .run(
          json({ snapshotPath, snapshotHash, artifacts, qa, review }),
          input.decision === "approved" ? 1 : 0,
          id,
          scope,
        );
      this.event(scope, "report.reviewed", { id, review });
      return this.report(scope, id);
    });
  }
  assertRestitution(
    scope: string,
    id: string,
    evidenceId: string,
    operator: string,
    statement: string,
  ) {
    const r = this.report(scope, id);
    this.current(r);
    if (!r.reviewed)
      throw new Error("Restitution requires the reviewed current report");
    this.checkPages(r);
    const proof = this.evidence.evidence(scope, [evidenceId])[0];
    if (!proof.success)
      throw new Error("Restitution needs successful supporting evidence");
    if (
      this.db
        .prepare("SELECT 1 FROM workflow_restitutions WHERE report_id=?")
        .get(id)
    )
      throw new Error("Restitution already recorded");
    return {
      r,
      value: {
        reportId: id,
        missionId: r.missionId,
        evidenceId,
        reportHash: r.snapshotHash,
        operator: text(operator, 300),
        statement: text(statement, 4000),
        restitutedAt: now(),
      },
    };
  }
  recordRestitution(
    scope: string,
    id: string,
    evidenceId: string,
    operator: string,
    statement: string,
  ) {
    return this.tx(() => {
      const { r, value } = this.assertRestitution(
        scope,
        id,
        evidenceId,
        operator,
        statement,
      );
      this.db
        .prepare("INSERT INTO workflow_restitutions VALUES(?,?,?,?)")
        .run(id, scope, r.missionId, json(value));
      this.event(scope, "report.restituted", value);
      return value;
    });
  }
  cleanupPlan(
    scope: string,
    reportId: string,
    description: string,
    argv: string[],
    verifyArgv: string[],
  ) {
    return this.tx(() => {
      const r = this.report(scope, reportId);
      this.current(r);
      if (
        !this.db
          .prepare(
            "SELECT 1 FROM workflow_restitutions WHERE report_id=? AND scope=?",
          )
          .get(reportId, scope)
      )
        throw new Error("Cleanup is forbidden before restitution");
      for (const args of [argv, verifyArgv])
        if (
          !Array.isArray(args) ||
          !args.length ||
          args.length > 256 ||
          args.some(
            (a) =>
              typeof a !== "string" || a.length > 32768 || /[\0\r\n]/.test(a),
          )
        )
          throw new Error(
            "Cleanup needs explicit command and verification argv",
          );
      const c = {
        id: `cleanup-${newId()}`,
        reportId,
        missionId: r.missionId,
        description: text(description),
        argv,
        verifyArgv,
        status: "planned",
        createdAt: now(),
        processId: null,
        verificationProcessId: null,
      };
      this.db
        .prepare("INSERT INTO workflow_cleanup VALUES(?,?,?,?,?)")
        .run(c.id, scope, r.missionId, reportId, JSON.stringify(c));
      this.event(scope, "cleanup.planned", { id: c.id, reportId });
      return c;
    });
  }
  cleanup(scope: string, id: string) {
    const row = this.db
      .prepare("SELECT payload FROM workflow_cleanup WHERE scope=? AND id=?")
      .get(scope, id);
    if (!row) throw new Error("Cleanup not found");
    return JSON.parse(String(row.payload));
  }
  assertCleanupStart(scope: string, id: string, verification = false) {
    const c = this.cleanup(scope, id);
    this.current(this.report(scope, c.reportId));
    if (
      !this.db
        .prepare(
          "SELECT 1 FROM workflow_restitutions WHERE report_id=? AND scope=?",
        )
        .get(c.reportId, scope)
    )
      throw new Error("Cleanup is forbidden before restitution");
    if (verification ? c.status !== "executed" : c.status !== "planned")
      throw new Error("Invalid cleanup transition");
  }
  cleanupStarted(
    scope: string,
    id: string,
    processId: string,
    verification = false,
  ) {
    return this.tx(() => {
      this.assertCleanupStart(scope, id, verification);
      const c = this.cleanup(scope, id),
        previous = JSON.stringify(c);
      c[verification ? "verificationProcessId" : "processId"] = processId;
      c.status = verification ? "verifying" : "running";
      if (
        !this.db
          .prepare(
            "UPDATE workflow_cleanup SET payload=? WHERE scope=? AND id=? AND payload=?",
          )
          .run(JSON.stringify(c), scope, id, previous).changes
      )
        throw new Error("Concurrent cleanup transition");
      this.event(scope, "cleanup.started", { id, processId, verification });
      return c;
    });
  }
  cleanupResult(
    scope: string,
    id: string,
    processId: string,
    success: boolean,
  ) {
    return this.tx(() => {
      const c = this.cleanup(scope, id),
        previous = JSON.stringify(c),
        verify = c.status === "verifying";
      if (
        !["running", "verifying"].includes(c.status) ||
        processId !== (verify ? c.verificationProcessId : c.processId)
      )
        throw new Error(
          "Cleanup outcome is not linked to the recorded process",
        );
      c.status = success ? (verify ? "completed" : "executed") : "failed";
      c.updatedAt = now();
      if (
        !this.db
          .prepare(
            "UPDATE workflow_cleanup SET payload=? WHERE scope=? AND id=? AND payload=?",
          )
          .run(JSON.stringify(c), scope, id, previous).changes
      )
        throw new Error("Concurrent cleanup transition");
      this.event(scope, "cleanup.result", { id, processId, status: c.status });
      return c;
    });
  }
  capitalization(
    scope: string,
    missionId: string,
    input: {
      outcome: "none" | "candidate" | "validated";
      reason: string;
      artifactIds: string[];
      tests: {
        observationId: string;
        contains: string;
        kind: "positive" | "negative";
      }[];
    },
  ) {
    return this.tx(() => {
      this.platform.mission(scope, missionId);
      if (
        !Array.isArray(input.artifactIds) ||
        input.artifactIds.length > 20 ||
        !Array.isArray(input.tests) ||
        input.tests.length > 50
      )
        throw new Error("Capitalization input limit exceeded");
      if (!["none", "candidate", "validated"].includes(input.outcome))
        throw new Error("Invalid capitalization outcome");
      text(input.reason, 4000);
      const artifacts = input.artifactIds.map((id) => this.artifact(scope, id));
      if (artifacts.some((a) => a.missionId !== missionId))
        throw new Error("Capitalization artifact belongs to another mission");
      if (input.outcome === "validated") {
        if (new Set(input.tests.map((t) => t.observationId)).size < 2)
          throw new Error(
            "Capitalization needs distinct positive and negative test observations",
          );
        if (
          !artifacts.length ||
          !input.tests.some((t) => t.kind === "positive") ||
          !input.tests.some((t) => t.kind === "negative")
        )
          throw new Error(
            "Validated capitalization needs artifacts and positive/negative tests",
          );
        for (const t of input.tests) {
          const proof = this.evidence.evidence(scope, [t.observationId])[0];
          if (
            !proof.success ||
            typeof t.contains !== "string" ||
            t.contains.length < 4 ||
            !proof.output.includes(t.contains)
          )
            throw new Error("Capitalization test lacks observed results");
        }
      }
      const snapshotHash = this.platform.reportFingerprint(scope, missionId),
        value = {
          id: `capitalization-${newId()}`,
          missionId,
          snapshotHash,
          ...input,
          reason: text(input.reason, 4000),
          recordedAt: now(),
        };
      this.db
        .prepare(
          "INSERT INTO workflow_capitalizations VALUES(?,?,?,?,?) ON CONFLICT(scope,mission_id,snapshot_hash) DO UPDATE SET id=excluded.id,payload=excluded.payload",
        )
        .run(value.id, scope, missionId, snapshotHash, json(value));
      this.event(scope, "capitalization.recorded", value);
      return value;
    });
  }
  status(scope: string, missionId: string) {
    this.platform.mission(scope, missionId);
    const rows = (table: string) =>
      this.db
        .prepare(`SELECT payload FROM ${table} WHERE scope=? AND mission_id=?`)
        .all(scope, missionId)
        .map((r) => JSON.parse(String(r.payload)));
    return {
      reports: this.db
        .prepare(
          "SELECT id,reviewed FROM workflow_reports WHERE scope=? AND mission_id=? ORDER BY rowid DESC",
        )
        .all(scope, missionId),
      restitutions: rows("workflow_restitutions"),
      capitalizations: rows("workflow_capitalizations"),
      cleanup: rows("workflow_cleanup").map(
        ({ argv, verifyArgv, ...safe }) => safe,
      ),
      cleanupPolicy: "after-restitution-only",
    };
  }
}
