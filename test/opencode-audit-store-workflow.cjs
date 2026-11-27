/**
 * Verification tests for store concurrency/transactions, workflow & cleanup
 * invariants, investigation stagnation/hypothesis/coverage guards, task tree
 * invariants, and SSRF/CLI/ingest/search/prototype fixes.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const childProcess = require("node:child_process");
const { createHash } = require("node:crypto");
const { mock } = require("node:test");
const { syncBuiltinESMExports } = require("node:module");
const { DatabaseSync } = require("node:sqlite");

const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti, modules }) => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "harness-audit-sw-"));
  const digest = (file) =>
    createHash("sha256").update(fs.readFileSync(file)).digest("hex");

  const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
  const { PlatformStore } = jiti(path.join(CORE, "src", "platform-store.ts"));
  const { EngagementWorkflow } = jiti(
    path.join(CORE, "src", "engagement-workflow.ts"),
  );
  const { capsule, closingGate } = jiti(path.join(CORE, "src", "capsule.ts"));
  const {
    HypothesisTracker,
    advanceHypothesis,
    detectStagnation,
    CoverageMap,
    InvestigationStore,
    surfacesFromTasks,
    assembleInvestigation,
  } = jiti(path.join(CORE, "src", "investigation.ts"));
  const { TaskStore } = jiti(path.join(CORE, "src", "tasks.ts"));
  const { SourceSynchronizer } = jiti(path.join(CORE, "src", "sources.ts"));
  const { createJiti } = require(path.join(modules, "jiti"));
  const cveJiti = createJiti(__filename, { moduleCache: false });
  const { queryNvd, querySearchsploit } = cveJiti(
    path.join(CORE, "src", "cve-sources.ts"),
  );
  const { planIngest } = jiti(path.join(CORE, "src", "osint-ingest.ts"));
  const { searchReference } = jiti(
    path.join(CORE, "src", "reference-search.ts"),
  );
  const { assetSteps } = jiti(path.join(CORE, "src", "coverage-roles.ts"));
  const { coverageProfile, coverageContract } = jiti(
    path.join(CORE, "src", "coverage-profiles.ts"),
  );
  const { scopeFor, hash } = jiti(path.join(CORE, "src", "util.ts"));

  try {
    // =========================================================================
    // 1. src/store.ts
    // =========================================================================
    const storeDir = path.join(work, "store");
    fs.mkdirSync(storeDir);
    const scope = scopeFor(storeDir);

    // Concurrent multi-process migration on a fresh DB + indexes check
    const kDbPath = path.join(storeDir, "knowledge.sqlite");
    const migrateWorker = path.join(storeDir, "migrate-worker.cjs");
    fs.writeFileSync(
      migrateWorker,
      `
      const { createJiti } = require(${JSON.stringify(path.join(modules, "jiti"))});
      const { KnowledgeStore } = createJiti(__filename)(${JSON.stringify(path.join(CORE, "src", "store.ts"))});
      const s = new KnowledgeStore(${JSON.stringify(kDbPath)});
      s.close();
      `,
    );
    await Promise.all(
      [0, 1, 2, 3].map(
        () =>
          new Promise((resolve, reject) => {
            const c = childProcess.spawn(process.execPath, [migrateWorker], {
              stdio: ["ignore", "ignore", "pipe"],
            });
            let err = "";
            c.stderr.on("data", (d) => (err += d));
            c.on("error", reject);
            c.on("close", (code) =>
              code === 0 ? resolve() : reject(new Error(err)),
            );
          }),
      ),
    );
    const kInspect = new DatabaseSync(kDbPath);
    assert.equal(
      kInspect.prepare("PRAGMA user_version").get().user_version,
      3,
      "concurrent KnowledgeStore migration finishes cleanly at user_version 3",
    );
    const kIndexes = new Set(
      kInspect
        .prepare("SELECT name FROM sqlite_master WHERE type='index'")
        .all()
        .map((r) => String(r.name)),
    );
    for (const idx of [
      "observations_scope",
      "audit_log_scope_event",
      "sessions_scope_updated",
      "reviews_scope_updated",
    ]) {
      assert.ok(kIndexes.has(idx), `KnowledgeStore created index ${idx}`);
    }
    kInspect.close();

    const store = new KnowledgeStore(kDbPath);
    store.upsertSession({
      id: "ses_s1",
      scope,
      cwd: storeDir,
      status: "active",
      updatedAt: new Date().toISOString(),
    });
    assert.throws(
      () =>
        store.upsertSession({
          id: "ses_s1",
          scope: scopeFor(work),
          cwd: work,
          status: "active",
          updatedAt: new Date().toISOString(),
        }),
      /Session scope collision/,
      "upsertSession rejects scope collision inside transaction",
    );
    store.recordMessage(
      "ses_s1",
      scope,
      "msg_1",
      "user",
      "hello",
      "2026-01-01T00:00:00.000Z",
    );
    store.recordMessage(
      "ses_s1",
      scope,
      "msg_1",
      "user",
      "hello",
      "2026-01-01T00:00:00.000Z",
    );
    assert.throws(
      () =>
        store.recordMessage(
          "ses_s1",
          scope,
          "msg_1",
          "user",
          "different",
          "2026-01-01T00:00:00.000Z",
        ),
      /Message entry collision/,
      "recordMessage rejects altered replay",
    );
    assert.throws(
      () => store.recordObservation(null),
      /Invalid observation/,
      "recordObservation validates non-object input cleanly",
    );
    const kObs = store.recordObservation({
      id: "obs-k-1",
      sessionId: "ses_s1",
      scope,
      tool: "shell",
      input: { cmd: "id" },
      output: "uid=1000\n",
      success: true,
      timestamp: new Date().toISOString(),
    });

    // Concurrent proposeKnowledge on same (scope, key)
    const proposeWorker = path.join(storeDir, "propose-worker.cjs");
    fs.writeFileSync(
      proposeWorker,
      `
      const { createJiti } = require(${JSON.stringify(path.join(modules, "jiti"))});
      const { KnowledgeStore } = createJiti(__filename)(${JSON.stringify(path.join(CORE, "src", "store.ts"))});
      const s = new KnowledgeStore(${JSON.stringify(kDbPath)});
      s.proposeKnowledge(${JSON.stringify(scope)}, {
        key: "race-key",
        content: "Observed output variant " + process.argv[2],
        kind: "environment",
        evidence: [${JSON.stringify(kObs.id)}],
      });
      s.close();
      `,
    );
    await Promise.all(
      ["a", "b", "c", "d"].map(
        (tag) =>
          new Promise((resolve, reject) => {
            const c = childProcess.spawn(
              process.execPath,
              [proposeWorker, tag],
              { stdio: ["ignore", "ignore", "pipe"] },
            );
            let err = "";
            c.stderr.on("data", (d) => (err += d));
            c.on("error", reject);
            c.on("close", (code) =>
              code === 0 ? resolve() : reject(new Error(err)),
            );
          }),
      ),
    );
    assert.equal(
      store.getKnowledge(scope).filter((k) => k.key === "race-key").length,
      1,
      "concurrent proposeKnowledge leaves exactly 1 active key",
    );
    assert.equal(
      store.pendingKnowledge(scope).filter((k) => k.key === "race-key").length,
      3,
      "remaining concurrent proposals queue cleanly as pending",
    );

    // Operator rule protection in resolveKnowledge
    store.setOperatorRule(scope, {
      key: "op-protected",
      content: "Operator rule stays active",
    });
    const pendingUnderOp = store.proposeKnowledge(scope, {
      key: "op-protected",
      content: "Inferred fact trying to replace rule",
      kind: "workflow",
      evidence: [kObs.id],
    });
    assert.equal(pendingUnderOp.status, "pending");
    assert.throws(
      () => store.resolveKnowledge(scope, pendingUnderOp.id, true),
      /cannot replace an operator rule/,
      "resolveKnowledge refuses to retire an active operator rule",
    );
    assert.equal(
      store.operatorModel(scope).find((r) => r.key === "op-protected")?.status,
      "active",
      "operator rule remains active",
    );

    // =========================================================================
    // 2. src/platform-store.ts
    // =========================================================================
    const pDir = path.join(work, "platform");
    fs.mkdirSync(pDir);
    const pScope = scopeFor(pDir);
    const pkStore = new KnowledgeStore(path.join(pDir, "knowledge.sqlite"));
    const pDbPath = path.join(pDir, "platform.sqlite");

    // Concurrent multi-process PlatformStore migration
    const pMigrateWorker = path.join(pDir, "p-migrate-worker.cjs");
    fs.writeFileSync(
      pMigrateWorker,
      `
      const { createJiti } = require(${JSON.stringify(path.join(modules, "jiti"))});
      const { KnowledgeStore } = createJiti(__filename)(${JSON.stringify(path.join(CORE, "src", "store.ts"))});
      const { PlatformStore } = createJiti(__filename)(${JSON.stringify(path.join(CORE, "src", "platform-store.ts"))});
      const k = new KnowledgeStore(${JSON.stringify(path.join(pDir, "knowledge.sqlite"))});
      const p = new PlatformStore(${JSON.stringify(pDbPath)}, k);
      p.close();
      k.close();
      `,
    );
    await Promise.all(
      [0, 1, 2, 3].map(
        () =>
          new Promise((resolve, reject) => {
            const c = childProcess.spawn(process.execPath, [pMigrateWorker], {
              stdio: ["ignore", "ignore", "pipe"],
            });
            let err = "";
            c.stderr.on("data", (d) => (err += d));
            c.on("error", reject);
            c.on("close", (code) =>
              code === 0 ? resolve() : reject(new Error(err)),
            );
          }),
      ),
    );
    const pInspect = new DatabaseSync(pDbPath);
    assert.equal(pInspect.prepare("PRAGMA user_version").get().user_version, 7);
    pInspect.close();

    const platform = new PlatformStore(pDbPath, pkStore);
    const workflow = new EngagementWorkflow(pDir, platform, pkStore);

    const pObs = (id, output, sessionId = "ses_p1", success = true) => {
      pkStore.upsertSession({
        id: sessionId,
        scope: pScope,
        cwd: pDir,
        status: "active",
        updatedAt: new Date().toISOString(),
      });
      return pkStore.recordObservation({
        id,
        sessionId,
        scope: pScope,
        tool: "shell",
        input: {},
        output,
        success,
        timestamp: new Date().toISOString(),
      });
    };
    const pOk = pObs("obs-p-ok", "stage ok");
    const pPos = pObs("obs-p-pos", "VULN_MARKER_ALPHA");
    const pNeg = pObs("obs-p-neg", "VULN_MARKER_ALPHA_BENIGN");

    // CLOSED mission enforcement & completedMissions exclusion
    const mClosed = platform.createMission(
      pScope,
      "Closed Mission",
      "Local lab only",
    );
    platform.approveScope(pScope, mClosed.id, "op-tester");
    const mClosedRe = platform.mission(pScope, mClosed.id);
    assert.equal(
      mClosedRe.nodes.find((n) => n.id === "scope-validation").result
        .approvedBy,
      "op-tester",
      "approveScope records explicit operator parameter",
    );
    // Complete all stages of mClosed, then close it — completedMissions must exclude it
    for (const [node, role] of [
      ["recon", "recon-agent"],
      ["enumeration", "recon-agent"],
      ["analysis", "recon-agent"],
      ["validation", "verification-agent"],
      ["evidence", "code-agent"],
    ]) {
      const l = platform.claim(pScope, mClosed.id, node, role);
      platform.finish(pScope, mClosed.id, node, l, [
        { role, status: "completed", summary: "ok", evidence: [pOk.id] },
      ]);
    }
    platform.closeMission(
      pScope,
      mClosed.id,
      "Engagement ended by operator decision.",
    );
    const mSkipClosed = platform.createMission(
      pScope,
      "Skip Closed Mission",
      "Local lab only",
    );
    platform.approveScope(pScope, mSkipClosed.id);
    platform.closeMission(
      pScope,
      mSkipClosed.id,
      "Closed before recon stage ran.",
    );
    assert.throws(
      () => platform.claim(pScope, mClosed.id, "report", "report-agent"),
      /Mission is closed/,
      "claim rejects CLOSED mission",
    );
    assert.throws(
      () =>
        platform.requestApproval(
          pScope,
          mClosed.id,
          "Run exploit",
          "Testing",
          "agent",
        ),
      /Mission is closed/,
      "requestApproval rejects CLOSED mission",
    );
    assert.throws(
      () => platform.reopenValidation(pScope, mClosed.id, "Redo", "op"),
      /Mission is closed/,
      "reopenValidation rejects CLOSED mission",
    );
    assert.throws(
      () => platform.retry(pScope, mClosed.id, "report"),
      /Mission is closed/,
      "retry rejects CLOSED mission",
    );
    assert.throws(
      () => platform.skip(pScope, mSkipClosed.id, "recon", "Not needed"),
      /Mission is closed/,
      "skip rejects CLOSED mission",
    );
    assert.throws(
      () =>
        platform.createFinding(pScope, {
          missionId: mClosed.id,
          title: "After close",
          severity: "low",
          description: "Desc",
          limitations: "Lim",
          evidence: [pPos.id, pNeg.id],
          sources: [],
          checks: [
            {
              observationId: pPos.id,
              contains: "VULN_MARKER_ALPHA",
              purpose: "reproduction",
            },
            {
              observationId: pNeg.id,
              contains: "VULN_MARKER_ALPHA",
              purpose: "negative-control",
            },
          ],
        }),
      /Mission is closed/,
      "createFinding rejects CLOSED mission",
    );

    // Closed mission with all nodes SKIPPED/COMPLETED must NOT appear in completedMissions
    const mAllDoneClosed = platform.createMission(
      pScope,
      "Done Then Closed",
      "Local",
    );
    platform.approveScope(pScope, mAllDoneClosed.id);
    const rawP = new DatabaseSync(pDbPath);
    rawP
      .prepare("UPDATE nodes SET state='COMPLETED' WHERE mission_id=? AND scope=?")
      .run(mAllDoneClosed.id, pScope);
    assert.ok(
      platform.completedMissions(pScope).includes(mAllDoneClosed.id),
      "completed mission appears before closure",
    );
    platform.closeMission(
      pScope,
      mAllDoneClosed.id,
      "Closed after stages were marked completed.",
    );
    assert.ok(
      !platform.completedMissions(pScope).includes(mAllDoneClosed.id),
      "completedMissions excludes closed missions",
    );

    // decideApproval concurrent double-decide throws on changes===0
    const mActive = platform.createMission(pScope, "Active Mission", "Lab");
    platform.approveScope(pScope, mActive.id);
    const ap = platform.requestApproval(
      pScope,
      mActive.id,
      "Test action",
      "Needs review",
      "agent",
    );
    platform.decideApproval(pScope, ap.id, true, "operator");
    assert.throws(
      () => platform.decideApproval(pScope, ap.id, false, "operator"),
      /already decided/,
      "second decideApproval throws",
    );

    // upsertEntity redacts key when type === "secret"
    const secEnt = platform.upsertEntity(pScope, {
      type: "secret",
      key: "api_key=syntheticsecret123",
      observationIds: [pOk.id],
    });
    assert.ok(
      !secEnt.key.includes("syntheticsecret123") &&
        secEnt.key.includes("<REDACTED>"),
      "upsertEntity redacts key when type === 'secret'",
    );

    // indexKnowledge avoids FTS write amplification on unchanged reads
    pkStore.upsertSession({
      id: "ses_k",
      scope: pScope,
      cwd: pDir,
      status: "active",
      updatedAt: new Date().toISOString(),
    });
    const kProof = pkStore.recordObservation({
      id: "obs-pk-1",
      sessionId: "ses_k",
      scope: pScope,
      tool: "shell",
      input: {},
      output: "searchable knowledge token xyz",
      success: true,
      timestamp: new Date().toISOString(),
    });
    pkStore.proposeKnowledge(pScope, {
      key: "searchable-fact",
      content: "Unique knowledge searchtermalpha fact.",
      kind: "environment",
      evidence: [kProof.id],
    });
    const hits1 = platform.search(pScope, "knowledge", "searchtermalpha", 5);
    assert.equal(hits1.length, 1);
    // Count search_records / DB commits via trigger + PRAGMA data_version on repeated search()
    rawP.exec(`
      CREATE TABLE IF NOT EXISTS _sr_writes(n INTEGER);
      DELETE FROM _sr_writes;
      CREATE TRIGGER _track_sr_ins AFTER INSERT ON search_records BEGIN INSERT INTO _sr_writes VALUES(1); END;
      CREATE TRIGGER _track_sr_upd AFTER UPDATE ON search_records BEGIN INSERT INTO _sr_writes VALUES(1); END;
    `);
    const verBefore = rawP.prepare("PRAGMA data_version").get().data_version;
    platform.search(pScope, "knowledge", "searchtermalpha", 5);
    platform.search(pScope, "all", "searchtermalpha", 5);
    const verAfter = rawP.prepare("PRAGMA data_version").get().data_version;
    assert.equal(
      rawP.prepare("SELECT COUNT(*) AS c FROM _sr_writes").get().c,
      0,
      "repeated search() does not rewrite unchanged knowledge in search_records",
    );
    assert.equal(
      verAfter,
      verBefore,
      "repeated search() commits zero database writes when knowledge is unchanged",
    );
    rawP.exec("DROP TRIGGER _track_sr_ins; DROP TRIGGER _track_sr_upd; DROP TABLE _sr_writes;");

    // recall() guards missing search_records row gracefully
    const chunk = platform.ingest(
      pScope,
      "src-recall",
      "fixture:recall",
      "Recall title",
      "Recallable searchtermalpha source body",
    )[0];
    const origSearch = platform.search.bind(platform);
    platform.search = (...args) => [
      {
        id: "vanished-record-id",
        kind: "knowledge",
        title: "vanished",
        excerpt: "vanished",
        reference: "cyber://knowledge/vanished",
        hash: "0000",
      },
      ...origSearch(...args),
    ];
    const recalled = platform.recall(
      pScope,
      "ses_k",
      "turn-1",
      "searchtermalpha",
      8000,
    );
    platform.search = origSearch;
    assert.ok(recalled.length >= 1, "recall skips vanished record without crashing");
    assert.ok(
      !recalled.some((r) => r.id === "vanished-record-id"),
      "vanished record is excluded",
    );
    assert.ok(
      platform.memoryUses(pScope, "ses_k").some((u) => u.referenceId === chunk.id),
      "recall records memory_refs/memory_uses atomically",
    );

    // verifyFinding null-attestation safety, rejectFinding deletes verification,
    // and reopenValidation with 0 verified findings still resets workflow_reports.reviewed=0
    for (const [node, role] of [
      ["recon", "recon-agent"],
      ["enumeration", "recon-agent"],
      ["analysis", "recon-agent"],
    ]) {
      const l = platform.claim(pScope, mActive.id, node, role);
      platform.finish(pScope, mActive.id, node, l, [
        { role, status: "completed", summary: "ok", evidence: [pOk.id] },
      ]);
    }
    const f1 = platform.createFinding(pScope, {
      missionId: mActive.id,
      title: "Finding 1",
      severity: "medium",
      description: "Desc",
      limitations: "Lim",
      evidence: [pPos.id, pNeg.id],
      sources: [chunk.id],
      checks: [
        {
          observationId: pPos.id,
          contains: "VULN_MARKER_ALPHA",
          purpose: "reproduction",
        },
        {
          observationId: pNeg.id,
          contains: "VULN_MARKER_ALPHA",
          purpose: "negative-control",
        },
      ],
    });
    const vPos = pObs("obs-v-pos", "VULN_MARKER_ALPHA", "ses_ver");
    const vNeg = pObs("obs-v-neg", "VULN_MARKER_ALPHA_BENIGN", "ses_ver");
    const vChecks = [
      {
        observationId: vPos.id,
        contains: "VULN_MARKER_ALPHA",
        purpose: "reproduction",
      },
      {
        observationId: vNeg.id,
        contains: "VULN_MARKER_ALPHA",
        purpose: "negative-control",
      },
    ];
    const attPayload = platform.verificationPayload(
      pScope,
      f1.id,
      "ses_ver",
      vChecks,
    );
    const attObs = pObs("obs-v-att", JSON.stringify(attPayload), "ses_ver");
    // Overwrite tool to harness:verification via direct recordObservation
    const attObsReal = pkStore.recordObservation({
      id: "obs-v-att-real",
      sessionId: "ses_ver",
      scope: pScope,
      tool: "harness:verification",
      input: { findingId: f1.id },
      output: JSON.stringify(attPayload),
      success: true,
      timestamp: new Date().toISOString(),
    });
    const nullAttObs = pkStore.recordObservation({
      id: "obs-v-att-null",
      sessionId: "ses_ver",
      scope: pScope,
      tool: "harness:verification",
      input: {},
      output: "null",
      success: true,
      timestamp: new Date().toISOString(),
    });
    const valLease = platform.claim(
      pScope,
      mActive.id,
      "validation",
      "verification-agent",
      [f1.id],
    );
    platform.finish(pScope, mActive.id, "validation", valLease, [
      {
        role: "verification-agent",
        status: "completed",
        summary: "Verified",
        evidence: [attObsReal.id, nullAttObs.id],
      },
    ]);
    assert.throws(
      () => platform.verifyFinding(pScope, f1.id, nullAttObs.id),
      /unrelated or stale/,
      "verifyFinding rejects JSON null attestation without TypeError",
    );
    const vf = platform.verifyFinding(pScope, f1.id, attObsReal.id);
    assert.equal(vf.status, "verified");
    assert.ok(vf.verification !== null);

    // Rejecting a verified finding removes finding_verifications row too
    const disproven = platform.rejectFinding(pScope, f1.id);
    assert.equal(disproven.status, "disproven");
    assert.equal(
      disproven.verification,
      null,
      "rejectFinding clears finding_verifications",
    );
    assert.equal(
      rawP
        .prepare("SELECT COUNT(*) AS c FROM finding_verifications WHERE finding_id=?")
        .get(f1.id).c,
      0,
    );

    // Snapshot & review while 0 findings are verified, then reopenValidation -> reviewed must reset to 0!
    const evLease = platform.claim(pScope, mActive.id, "evidence", "code-agent");
    platform.finish(pScope, mActive.id, "evidence", evLease, [
      { role: "code-agent", status: "completed", summary: "ok", evidence: [pOk.id] },
    ]);
    const snap = workflow.snapshot(pScope, mActive.id, {
      title: "Report",
      client: "Client",
      author: "Author",
      period: "2026",
      method: "Method",
      findings: {},
    });
    const docx = path.join(pDir, "r.docx");
    const pdf = path.join(pDir, "r.pdf");
    const png = path.join(pDir, "p1.png");
    const qaJson = path.join(pDir, "qa.json");
    fs.writeFileSync(docx, "PK\u0003\u0004doc");
    fs.writeFileSync(pdf, "%PDF-1.7\n");
    fs.writeFileSync(png, Buffer.from("89504e470d0a1a0a", "hex"));
    const aDoc = workflow.registerArtifact(
      pScope,
      mActive.id,
      { path: docx, kind: "report-docx", observationIds: [pOk.id] },
      pDir,
    );
    const aPdf = workflow.registerArtifact(
      pScope,
      mActive.id,
      { path: pdf, kind: "report-pdf", observationIds: [pOk.id] },
      pDir,
    );
    fs.writeFileSync(
      qaJson,
      JSON.stringify({
        snapshotId: snap.snapshot.id,
        snapshotHash: snap.sha256,
        docxHash: aDoc.sha256,
        pdfHash: aPdf.sha256,
        pages: 1,
        structuredChecks: true,
        pageImages: [{ path: "p1.png", sha256: digest(png) }],
      }),
    );
    const aQa = workflow.registerArtifact(
      pScope,
      mActive.id,
      { path: qaJson, kind: "report-qa", observationIds: [pOk.id] },
      pDir,
    );
    workflow.registerReport(pScope, snap.snapshot.id, [aDoc.id, aPdf.id, aQa.id]);
    workflow.reviewReport(pScope, snap.snapshot.id, {
      pagesReviewed: [1],
      decision: "approved",
      reviewer: "op",
      notes: "Reviewed",
    });
    assert.equal(workflow.report(pScope, snap.snapshot.id).reviewed, true);
    platform.reopenValidation(pScope, mActive.id, "Check again", "op");
    assert.equal(
      workflow.report(pScope, snap.snapshot.id).reviewed,
      false,
      "reopenValidation resets workflow_reports.reviewed=0 even with 0 verified findings",
    );
    // Also verify reopenValidation updates search_records for verified finding & mission
    const mSearchIdx = platform.createMission(pScope, "SearchIndexUniqueTitle", "Lab");
    platform.approveScope(pScope, mSearchIdx.id);
    for (const [node, role] of [
      ["recon", "recon-agent"],
      ["enumeration", "recon-agent"],
      ["analysis", "recon-agent"],
    ]) {
      const l = platform.claim(pScope, mSearchIdx.id, node, role);
      platform.finish(pScope, mSearchIdx.id, node, l, [
        { role, status: "completed", summary: "ok", evidence: [pOk.id] },
      ]);
    }
    const fIdx = platform.createFinding(pScope, {
      missionId: mSearchIdx.id,
      title: "SearchReopenFindingUnique",
      severity: "high",
      description: "Unique finding desc",
      limitations: "Lim",
      evidence: [pPos.id, pNeg.id],
      sources: [chunk.id],
      checks: [
        { observationId: pPos.id, contains: "VULN_MARKER_ALPHA", purpose: "reproduction" },
        { observationId: pNeg.id, contains: "VULN_MARKER_ALPHA", purpose: "negative-control" },
      ],
    });
    const freshTs = new Date(Date.now() + 100).toISOString();
    const vPosIdx = pkStore.recordObservation({
      id: "obs-v-pos-idx",
      sessionId: "ses_ver",
      scope: pScope,
      tool: "shell",
      input: {},
      output: "VULN_MARKER_ALPHA",
      success: true,
      timestamp: freshTs,
    });
    const vNegIdx = pkStore.recordObservation({
      id: "obs-v-neg-idx",
      sessionId: "ses_ver",
      scope: pScope,
      tool: "shell",
      input: {},
      output: "VULN_MARKER_ALPHA_BENIGN",
      success: true,
      timestamp: freshTs,
    });
    const attIdxPayload = platform.verificationPayload(pScope, fIdx.id, "ses_ver", [
      { observationId: vPosIdx.id, contains: "VULN_MARKER_ALPHA", purpose: "reproduction" },
      { observationId: vNegIdx.id, contains: "VULN_MARKER_ALPHA", purpose: "negative-control" },
    ]);
    const attIdxObs = pkStore.recordObservation({
      id: "obs-v-att-idx",
      sessionId: "ses_ver",
      scope: pScope,
      tool: "harness:verification",
      input: { findingId: fIdx.id },
      output: JSON.stringify(attIdxPayload),
      success: true,
      timestamp: freshTs,
    });
    const valIdxLease = platform.claim(pScope, mSearchIdx.id, "validation", "verification-agent", [fIdx.id]);
    platform.finish(pScope, mSearchIdx.id, "validation", valIdxLease, [
      { role: "verification-agent", status: "completed", summary: "Verified", evidence: [attIdxObs.id] },
    ]);
    platform.verifyFinding(pScope, fIdx.id, attIdxObs.id);
    assert.match(
      String(rawP.prepare("SELECT text FROM search_records WHERE id=?").get(fIdx.id).text),
      /"status":"verified"/,
    );
    platform.reopenValidation(pScope, mSearchIdx.id, "Reopen index test", "op");
    const fRecText = String(
      rawP.prepare("SELECT text FROM search_records WHERE id=?").get(fIdx.id).text,
    );
    assert.match(
      fRecText,
      /"status":"unverified"/,
      "reopenValidation updates finding search_records",
    );
    assert.match(
      fRecText,
      /"verification":null/,
      "reopenValidation clears verification in finding search_records",
    );
    const mRecText = String(
      rawP.prepare("SELECT text FROM search_records WHERE id=?").get(mSearchIdx.id).text,
    );
    assert.match(
      mRecText,
      /"id":"validation","state":"PENDING"/,
      "reopenValidation updates mission search_records",
    );
    rawP.close();

    // =========================================================================
    // 3. src/engagement-workflow.ts & src/capsule.ts
    // =========================================================================
    // New verified mission for full report -> review -> restitution -> cleanup -> capitalization tests
    const mWf = platform.createMission(pScope, "WF Mission", "Local");
    platform.approveScope(pScope, mWf.id);
    for (const [node, role] of [
      ["recon", "recon-agent"],
      ["enumeration", "recon-agent"],
      ["analysis", "recon-agent"],
    ]) {
      const l = platform.claim(pScope, mWf.id, node, role);
      platform.finish(pScope, mWf.id, node, l, [
        { role, status: "completed", summary: "ok", evidence: [pOk.id] },
      ]);
    }
    const wfVal = platform.claim(pScope, mWf.id, "validation", "verification-agent");
    platform.finish(pScope, mWf.id, "validation", wfVal, [
      { role: "verification-agent", status: "completed", summary: "ok", evidence: [pOk.id] },
    ]);
    const wfEv = platform.claim(pScope, mWf.id, "evidence", "code-agent");
    platform.finish(pScope, mWf.id, "evidence", wfEv, [
      { role: "code-agent", status: "completed", summary: "ok", evidence: [pOk.id] },
    ]);
    const snap2 = workflow.snapshot(pScope, mWf.id, {
      title: "WF Report",
      client: "C",
      author: "A",
      period: "2026",
      method: "M",
      findings: {},
    });
    const wfDir = path.join(pDir, "wf-artifacts");
    fs.mkdirSync(wfDir);
    const docx2 = path.join(wfDir, "r2.docx");
    const pdf2 = path.join(wfDir, "r2.pdf");
    const png2 = path.join(wfDir, "page-1.png");
    const fakePng = path.join(wfDir, "not-an-image.png");
    const qa2 = path.join(wfDir, "qa2.json");
    fs.writeFileSync(docx2, "PK\u0003\u0004doc2");
    fs.writeFileSync(pdf2, "%PDF-1.7\n2");
    fs.writeFileSync(png2, Buffer.from("89504e470d0a1a0a", "hex"));
    fs.writeFileSync(fakePng, "<html>not png</html>");
    const a2Doc = workflow.registerArtifact(
      pScope,
      mWf.id,
      { path: docx2, kind: "report-docx", observationIds: [pOk.id] },
      wfDir,
    );
    const a2Pdf = workflow.registerArtifact(
      pScope,
      mWf.id,
      { path: pdf2, kind: "report-pdf", observationIds: [pOk.id] },
      wfDir,
    );
    // Reject non-image page file
    fs.writeFileSync(
      qa2,
      JSON.stringify({
        snapshotId: snap2.snapshot.id,
        snapshotHash: snap2.sha256,
        docxHash: a2Doc.sha256,
        pdfHash: a2Pdf.sha256,
        pages: 1,
        structuredChecks: true,
        pageImages: [{ path: "not-an-image.png", sha256: digest(fakePng) }],
      }),
    );
    const a2QaBad = workflow.registerArtifact(
      pScope,
      mWf.id,
      { path: qa2, kind: "report-qa", observationIds: [pOk.id] },
      wfDir,
    );
    assert.throws(
      () =>
        workflow.registerReport(pScope, snap2.snapshot.id, [
          a2Doc.id,
          a2Pdf.id,
          a2QaBad.id,
        ]),
      /PNG or JPEG/,
      "registerReport rejects non-image rendered page files",
    );

    // Valid QA registration & review & restitution
    fs.writeFileSync(
      qa2,
      JSON.stringify({
        snapshotId: snap2.snapshot.id,
        snapshotHash: snap2.sha256,
        docxHash: a2Doc.sha256,
        pdfHash: a2Pdf.sha256,
        pages: 1,
        structuredChecks: true,
        pageImages: [{ path: "page-1.png", sha256: digest(png2) }],
      }),
    );
    const a2Qa = workflow.registerArtifact(
      pScope,
      mWf.id,
      { path: qa2, kind: "report-qa", observationIds: [pOk.id] },
      wfDir,
    );
    workflow.registerReport(pScope, snap2.snapshot.id, [
      a2Doc.id,
      a2Pdf.id,
      a2Qa.id,
    ]);
    workflow.reviewReport(pScope, snap2.snapshot.id, {
      pagesReviewed: [1],
      decision: "approved",
      reviewer: "op",
      notes: "Looks good",
    });
    const wfRepLease = platform.claim(pScope, mWf.id, "report", "report-agent");
    platform.finish(pScope, mWf.id, "report", wfRepLease, [
      { role: "report-agent", status: "completed", summary: "Done", evidence: [pOk.id] },
    ]);
    workflow.recordRestitution(
      pScope,
      snap2.snapshot.id,
      pOk.id,
      "op",
      "Delivered to client",
    );

    // Block cleanupPlan & assertCleanupStart when report is unreviewed
    const rawCleanupCheck = new DatabaseSync(pDbPath);
    const clPre = workflow.cleanupPlan(
      pScope,
      snap2.snapshot.id,
      "Before reviewed reset",
      ["echo", "cleanup1"],
      ["echo", "verify1"],
    );
    rawCleanupCheck
      .prepare("UPDATE workflow_reports SET reviewed=0 WHERE id=?")
      .run(snap2.snapshot.id);
    assert.throws(
      () =>
        workflow.cleanupPlan(
          pScope,
          snap2.snapshot.id,
          "Unreviewed",
          ["echo", "cleanup2"],
          ["echo", "verify2"],
        ),
      /visually reviewed/,
      "cleanupPlan blocks when r.reviewed === 0",
    );
    assert.throws(
      () => workflow.assertCleanupStart(pScope, clPre.id, false),
      /visually reviewed/,
      "assertCleanupStart blocks when r.reviewed === 0",
    );
    rawCleanupCheck
      .prepare("UPDATE workflow_reports SET reviewed=1 WHERE id=?")
      .run(snap2.snapshot.id);
    workflow.cleanupStarted(pScope, clPre.id, "proc-pre-1", false);
    workflow.cleanupResult(pScope, clPre.id, "proc-pre-1", true);
    workflow.cleanupStarted(pScope, clPre.id, "proc-pre-2", true);
    workflow.cleanupResult(pScope, clPre.id, "proc-pre-2", true);
    rawCleanupCheck.close();

    // Block post-restitution reviewReport and registerReport
    assert.throws(
      () =>
        workflow.reviewReport(pScope, snap2.snapshot.id, {
          pagesReviewed: [1],
          decision: "changes-required",
          reviewer: "op",
          notes: "Try revoke",
        }),
      /already restituted/,
      "post-restitution reviewReport is blocked",
    );
    assert.throws(
      () =>
        workflow.registerReport(pScope, snap2.snapshot.id, [
          a2Doc.id,
          a2Pdf.id,
          a2Qa.id,
        ]),
      /already restituted/,
      "post-restitution registerReport is blocked",
    );

    // cleanupPlan rejects empty args & identical argv vs verifyArgv
    assert.throws(
      () =>
        workflow.cleanupPlan(
          pScope,
          snap2.snapshot.id,
          "Empty arg",
          ["rm", ""],
          ["test", "! -e x"],
        ),
      /explicit command/,
      "cleanupPlan rejects empty string in argv",
    );
    assert.throws(
      () =>
        workflow.cleanupPlan(
          pScope,
          snap2.snapshot.id,
          "Same argv",
          ["echo", "a"],
          ["echo", "a"],
        ),
      /must be distinct/,
      "cleanupPlan rejects identical argv and verifyArgv",
    );

    // Failed cleanup recovery: (a) direct retry on failed row
    const cl1 = workflow.cleanupPlan(
      pScope,
      snap2.snapshot.id,
      "Clean 1",
      ["rm", "-f", "tmp1"],
      ["test", "!", "-e", "tmp1"],
    );
    assert.throws(
      () => workflow.cleanupStarted(pScope, cl1.id, "   ", false),
      /process id/,
      "cleanupStarted rejects blank processId",
    );
    workflow.cleanupStarted(pScope, cl1.id, "proc-run-1", false);
    workflow.cleanupResult(pScope, cl1.id, "proc-run-1", false);
    assert.equal(workflow.cleanup(pScope, cl1.id).status, "failed");
    // Cannot jump straight to verify after run failed
    assert.throws(
      () => workflow.assertCleanupStart(pScope, cl1.id, true),
      /Invalid cleanup transition/,
    );
    // Cannot reuse failed processId
    assert.throws(
      () => workflow.cleanupStarted(pScope, cl1.id, "proc-run-1", false),
      /distinct processes/,
    );
    // Retry run with new processId -> succeed -> verify fails -> retry verify with new distinct processId -> succeed
    workflow.cleanupStarted(pScope, cl1.id, "proc-run-2", false);
    workflow.cleanupResult(pScope, cl1.id, "proc-run-2", true);
    assert.throws(
      () => workflow.cleanupStarted(pScope, cl1.id, "proc-run-2", true),
      /distinct processes/,
      "cleanupStarted forbids reusing execution processId for verification",
    );
    workflow.cleanupStarted(pScope, cl1.id, "proc-ver-1", true);
    workflow.cleanupResult(pScope, cl1.id, "proc-ver-1", false);
    assert.equal(workflow.cleanup(pScope, cl1.id).status, "failed");
    // Retry verify with fresh distinct processId
    assert.throws(
      () => workflow.cleanupStarted(pScope, cl1.id, "proc-ver-1", true),
      /distinct processes/,
    );
    workflow.cleanupStarted(pScope, cl1.id, "proc-ver-2", true);
    workflow.cleanupResult(pScope, cl1.id, "proc-ver-2", true);
    assert.equal(workflow.cleanup(pScope, cl1.id).status, "completed");

    // Failed cleanup recovery: (b) re-plan supersedes prior failed cleanup
    const clFail = workflow.cleanupPlan(
      pScope,
      snap2.snapshot.id,
      "Clean fail then replan",
      ["rm", "-f", "tmp2"],
      ["test", "!", "-e", "tmp2"],
    );
    workflow.cleanupStarted(pScope, clFail.id, "proc-fail-1", false);
    workflow.cleanupResult(pScope, clFail.id, "proc-fail-1", false);
    const clReplanned = workflow.cleanupPlan(
      pScope,
      snap2.snapshot.id,
      "Replanned clean",
      ["rm", "-f", "tmp2-fixed"],
      ["test", "!", "-e", "tmp2-fixed"],
    );
    assert.equal(
      workflow.cleanup(pScope, clFail.id).status,
      "superseded",
      "re-planning supersedes prior failed cleanup row",
    );
    workflow.cleanupStarted(pScope, clReplanned.id, "proc-re-1", false);
    workflow.cleanupResult(pScope, clReplanned.id, "proc-re-1", true);
    workflow.cleanupStarted(pScope, clReplanned.id, "proc-re-2", true);
    workflow.cleanupResult(pScope, clReplanned.id, "proc-re-2", true);

    // closingGate allows completed + superseded cleanups, blocks on unreviewed report
    const capBase = {
      scope: pScope,
      sessionID: "ses_p1",
      tasks: [],
      open: 0,
      blocked: 0,
      observations: [],
      mission: {
        id: mWf.id,
        title: "WF Mission",
        boundaries: "Local",
        state: "COMPLETED",
        stages: [{ id: "report", state: "COMPLETED" }],
      },
      workflow: workflow.status(pScope, mWf.id),
    };
    // Add capitalization first to check gate clearing cleanly
    const capScript = path.join(wfDir, "reusable.js");
    fs.writeFileSync(capScript, "console.log('ok');");
    const capArt = workflow.registerArtifact(
      pScope,
      mWf.id,
      { path: capScript, kind: "script", observationIds: [pOk.id] },
      wfDir,
    );
    const pPos2 = pObs("obs-cap-p2", "DIFFERENT_POS_OUT");
    const pPosDup = pObs("obs-cap-pdup", "VULN_MARKER_ALPHA");
    // Negative reusing one of multiple positives -> throws
    assert.throws(
      () =>
        workflow.capitalization(pScope, mWf.id, {
          outcome: "validated",
          reason: "Reused positive as negative",
          artifactIds: [capArt.id],
          tests: [
            { observationId: pPos.id, contains: "VULN_MARKER_ALPHA", kind: "positive" },
            { observationId: pPos2.id, contains: "DIFFERENT_POS_OUT", kind: "positive" },
            { observationId: pPos.id, contains: "VULN_MARKER_ALPHA", kind: "negative" },
          ],
        }),
      /distinct positive and negative/,
      "capitalization rejects negative reusing a positive observationId",
    );
    // Negative with identical output under another observationId -> throws
    assert.throws(
      () =>
        workflow.capitalization(pScope, mWf.id, {
          outcome: "validated",
          reason: "Same output replay",
          artifactIds: [capArt.id],
          tests: [
            { observationId: pPos.id, contains: "VULN_MARKER_ALPHA", kind: "positive" },
            { observationId: pPosDup.id, contains: "VULN_MARKER_ALPHA", kind: "negative" },
          ],
        }),
      /different output/,
      "capitalization rejects negative with identical output to positive",
    );
    // Whitespace-padded short contains -> throws
    assert.throws(
      () =>
        workflow.capitalization(pScope, mWf.id, {
          outcome: "validated",
          reason: "Short contains",
          artifactIds: [capArt.id],
          tests: [
            { observationId: pPos.id, contains: "VULN", kind: "positive" },
            { observationId: pNeg.id, contains: "  NO  ", kind: "negative" },
          ],
        }),
      /lacks observed/,
      "capitalization requires trimmed contains >= 4",
    );
    // ...input spread cannot overwrite id / missionId / snapshotHash
    const capRecorded = workflow.capitalization(pScope, mWf.id, {
      id: "hijack-id",
      missionId: "hijack-mission",
      snapshotHash: "hijack-hash",
      outcome: "validated",
      reason: "Valid capitalization pass",
      artifactIds: [capArt.id],
      tests: [
        { observationId: pPos.id, contains: "VULN_MARKER_ALPHA", kind: "positive" },
        { observationId: pNeg.id, contains: "VULN_MARKER_ALPHA_BENIGN", kind: "negative" },
      ],
    });
    assert.ok(capRecorded.id.startsWith("capitalization-"));
    assert.equal(capRecorded.missionId, mWf.id);
    assert.notEqual(capRecorded.snapshotHash, "hijack-hash");

    capBase.workflow = workflow.status(pScope, mWf.id);
    assert.equal(
      closingGate(capBase),
      "",
      "closingGate clears when failed cleanup was superseded and replacement completed",
    );

    // registerArtifact rejects symlinked allowedRoot
    const symlinkRoot = path.join(pDir, "sym-root");
    fs.symlinkSync(wfDir, symlinkRoot);
    assert.throws(
      () =>
        workflow.registerArtifact(
          pScope,
          mWf.id,
          { path: capScript, kind: "script", observationIds: [pOk.id] },
          symlinkRoot,
        ),
      /Linked or special|outside/,
      "registerArtifact calls assertPlainPath on allowedRoot",
    );

    // capsule() deduplicates observations
    const capTasks = new TaskStore(pDir);
    const tCap = capTasks.add(pScope, { title: "Dedup task" });
    capTasks.complete(pScope, tCap.id, [pOk.id]);
    const capVal = capsule(capTasks, pkStore, pScope, "ses_p1");
    assert.equal(
      capVal.observations.filter((o) => o.id === pOk.id).length,
      1,
      "capsule() deduplicates observations present in both proofs and recent",
    );

    workflow.close();
    platform.close();
    pkStore.close();

    // =========================================================================
    // 4. src/investigation.ts
    // =========================================================================
    const ts0 = "2026-01-01T00:00:00.000Z";
    const processNonReadCalls = [
      { tool: "cyber_process", outputHash: "same", success: false, timestamp: ts0, input: { action: "run" } },
      { tool: "cyber_process", outputHash: "same", success: false, timestamp: ts0, input: { action: "list" } },
      { tool: "cyber_process", outputHash: "same", success: false, timestamp: ts0, input: { action: "stop" } },
      { tool: "cyber_process", outputHash: "same", success: false, timestamp: ts0, input: { action: "prune" } },
      { tool: "cyber_process", outputHash: "same", success: false, timestamp: ts0, input: { action: "run" } },
    ];
    assert.deepEqual(
      detectStagnation(processNonReadCalls, 1, 1, Date.parse(ts0)),
      [],
      "detectStagnation ignores intentional cyber_process non-read actions",
    );
    const assembledProc = assembleInvestigation({
      observations: processNonReadCalls.map((c) => ({
        tool: c.tool,
        hash: c.outputHash,
        success: c.success,
        timestamp: c.timestamp,
        input: c.input,
      })),
      tasks: [{ status: "completed", evidence: ["o1"], updatedAt: ts0 }],
      hypotheses: [],
      coverage: new CoverageMap().summary(),
      nowMs: Date.parse(ts0),
    });
    assert.deepEqual(
      assembledProc.stagnation,
      [],
      "assembleInvestigation forwards input so cyber_process non-reads never trigger stagnation",
    );
    const processReadFailures = [
      { tool: "cyber_process", outputHash: "e1", success: false, timestamp: ts0, input: { action: "read" } },
      { tool: "cyber_process", outputHash: "e2", success: false, timestamp: ts0, input: { action: "read" } },
      { tool: "cyber_process", outputHash: "e3", success: false, timestamp: ts0, input: { action: "read" } },
    ];
    assert.ok(
      detectStagnation(processReadFailures, 1, 1, Date.parse(ts0)).some(
        (s) => s.kind === "same-failure",
      ),
      "cyber_process read failures still trigger same-failure",
    );

    // Stale hypothesis recovery
    const ht = new HypothesisTracker();
    ht.propose("H-stale", "Auth bypass", "2026-01-01T00:00:00.000Z");
    ht.tick(Date.parse("2026-01-01T00:35:00.000Z"));
    assert.equal(ht.list()[0].state, "stale");
    const afterEv = ht.addEvidence(
      "H-stale",
      "obs-e1",
      "2026-01-01T00:40:00.000Z",
      "hash-pos",
    );
    assert.equal(afterEv.state, "testing", "fresh evidence revives stale -> testing");
    const afterCtrl = ht.addControl(
      "H-stale",
      "obs-c1",
      "2026-01-01T00:41:00.000Z",
      "hash-neg",
    );
    assert.equal(afterCtrl.state, "confirmed", "fresh evidence+control confirms stale hypothesis");
    // Direct test() on stale hypothesis also works
    ht.propose("H-stale2", "IDOR", "2026-01-01T00:00:00.000Z");
    ht.tick(Date.parse("2026-01-01T00:35:00.000Z"));
    assert.equal(
      ht.test("H-stale2", "2026-01-01T00:40:00.000Z").state,
      "testing",
    );
    assert.equal(
      advanceHypothesis(
        {
          id: "H-adv",
          text: "t",
          state: "stale",
          evidence: ["e"],
          control: ["c"],
          outputs: { e: "1", c: "2" },
          counterEvidence: [],
          createdAt: "2026-01-01T00:00:00.000Z",
          updatedAt: "2026-01-01T00:40:00.000Z",
        },
        Date.parse("2026-01-01T00:41:00.000Z"),
      ),
      "confirmed",
    );

    // Deep copies in HypothesisTracker & CoverageMap & InvestigationStore
    const listCopy = ht.list();
    listCopy[0].evidence.push("mutated");
    listCopy[0].outputs.hacked = "x";
    assert.ok(!ht.list()[0].evidence.includes("mutated"));
    assert.equal(ht.list()[0].outputs.hacked, undefined);

    // Reject blank reason in block, blockSurface, surfacesFromTasks
    const cmap = new CoverageMap([{ id: "s1", label: "Surface 1" }]);
    assert.throws(() => cmap.block("s1", "   "), /reason/);
    const invDir = path.join(work, "inv");
    fs.mkdirSync(invDir);
    const invStore = new InvestigationStore(invDir);
    invStore.addSurface(scope, "s1", "Surface 1");
    assert.throws(() => invStore.blockSurface(scope, "s1", " \t "), /reason/);
    assert.equal(
      surfacesFromTasks([
        { id: "t1", title: "Blank block", status: "blocked", reason: "   " },
      ])[0].state,
      "untested",
      "surfacesFromTasks treats blank blocked reason as untested",
    );
    // Validate InvestigationStore.load() fails closed on corrupt shape
    fs.writeFileSync(
      path.join(invDir, `investigation-${scope}.json`),
      JSON.stringify({ hypotheses: [], surfaces: [{ id: "bad", label: "x", state: "blocked" }] }),
    );
    assert.throws(
      () => invStore.coverage(scope),
      /Invalid investigation storage/,
      "InvestigationStore.load rejects invalid element shapes",
    );

    // =========================================================================
    // 5. src/tasks.ts
    // =========================================================================
    const taskDir = path.join(work, "tasks");
    fs.mkdirSync(taskDir);
    const tasks = new TaskStore(taskDir);

    // Reopen completed/blocked parent when adding pending child
    const parent = tasks.add(scope, { title: "Parent" });
    const child1 = tasks.add(scope, { title: "Child 1", parent: parent.id });
    tasks.complete(scope, child1.id, ["obs-t1"]);
    tasks.complete(scope, parent.id, ["obs-tp"]);
    assert.equal(tasks.get(scope, parent.id).status, "completed");
    tasks.add(scope, { title: "Child 2", parent: parent.id });
    const reopenedParent = tasks.get(scope, parent.id);
    assert.equal(reopenedParent.status, "pending", "completed parent reopens on new pending child");
    assert.equal(reopenedParent.evidence, undefined);

    const blockedParent = tasks.add(scope, { title: "Blocked parent" });
    tasks.block(scope, blockedParent.id, "Wait");
    tasks.add(scope, { title: "Child of blocked", parent: blockedParent.id });
    assert.equal(tasks.get(scope, blockedParent.id).status, "pending");

    // Prevent reopening completed task when dependents or parent break invariants
    const depA = tasks.add(scope, { title: "Dep A" });
    tasks.complete(scope, depA.id, ["obs-a"]);
    const depB = tasks.add(scope, { title: "Dep B", dependsOn: [depA.id] });
    tasks.start(scope, depB.id);
    assert.throws(
      () => tasks.start(scope, depA.id),
      /dependent tasks/,
      "cannot reopen completed task while dependent is in-progress",
    );
    assert.throws(
      () => tasks.block(scope, depA.id, "Blocked now"),
      /dependent tasks/,
      "cannot block completed task while dependent is in-progress",
    );
    const pDone = tasks.add(scope, { title: "Parent done" });
    const cDone = tasks.add(scope, { title: "Child done", parent: pDone.id });
    tasks.complete(scope, cDone.id, ["obs-cd"]);
    tasks.complete(scope, pDone.id, ["obs-pd"]);
    assert.throws(
      () => tasks.start(scope, cDone.id),
      /parent task is completed/,
      "cannot reopen completed child while parent is completed",
    );

    // Validate all dependsOn before/without slicing past 10
    const ten = Array.from({ length: 10 }, (_, i) =>
      tasks.add(scope, { title: `D${i}` }).id,
    );
    assert.throws(
      () =>
        tasks.add(scope, {
          title: "Too many deps",
          dependsOn: [...ten, "missing-11th"],
        }),
      /at most 10/,
      "tasks.add rejects >10 dependencies instead of slicing past 10",
    );
    assert.throws(
      () =>
        tasks.add(scope, {
          title: "Bad dep type",
          dependsOn: [ten[0], 42],
        }),
      /Invalid task dependency/,
    );

    // Stale-lock recovery in TaskStore.mutate()
    const lockFile = path.join(taskDir, `tasks-${scope}.json.lock`);
    // Fresh empty lock still throws Concurrent
    fs.writeFileSync(lockFile, "");
    assert.throws(
      () => tasks.add(scope, { title: "Fresh lock race" }),
      /Concurrent/,
    );
    // Backdated (>30s) lock is recovered
    const oldTime = new Date(Date.now() - 60_000);
    fs.utimesSync(lockFile, oldTime, oldTime);
    const recoveredTask = tasks.add(scope, { title: "After old stale lock" });
    assert.ok(recoveredTask.id, "stale age lock recovered");
    // Dead-PID lock is recovered immediately
    fs.writeFileSync(lockFile, JSON.stringify({ pid: 999999999, createdAt: Date.now() }));
    const recoveredDeadPid = tasks.add(scope, { title: "After dead pid lock" });
    assert.ok(recoveredDeadPid.id, "dead-PID lock recovered");

    // =========================================================================
    // 6. sources.ts, cve-sources.ts, osint-ingest.ts, reference-search.ts,
    //    coverage-roles.ts, coverage-profiles.ts
    // =========================================================================
    const srcDir = path.join(work, "sources");
    const engDir = path.join(srcDir, "engagement");
    const outsideDir = path.join(srcDir, "outside");
    fs.mkdirSync(engDir, { recursive: true });
    fs.mkdirSync(outsideDir, { recursive: true });
    const skStore = new KnowledgeStore(path.join(srcDir, "knowledge.sqlite"));
    const spStore = new PlatformStore(
      path.join(srcDir, "platform.sqlite"),
      skStore,
    );
    const srcScope = scopeFor(srcDir);
    spStore.createMission(srcScope, "Source Mission", "Lab", undefined, engDir);

    const syncer = new SourceSynchronizer(
      spStore,
      async () =>
        new Response("<html><script>bad()</script><body>   </body></html>", {
          status: 200,
          headers: { "content-type": "text/html" },
        }),
      {
        lookup: async (hostname) => {
          if (hostname === "rebind.example.test")
            return [{ address: "127.0.0.1", family: 4 }];
          return [{ address: "93.184.216.34", family: 4 }];
        },
      },
    );
    // SSRF blocking in add() and sync()
    for (const badUrl of [
      "http://127.0.0.1/admin",
      "http://[::1]/admin",
      "http://169.254.169.254/latest/meta-data/",
      "http://10.0.0.1/secret",
      "http://172.16.5.4/secret",
      "http://192.168.1.1/secret",
      "http://[::ffff:127.0.0.1]/secret",
      "http://localhost/secret",
      "http://metadata.google.internal/",
    ]) {
      assert.throws(
        () => syncer.add(srcScope, "bad", badUrl),
        /blocked|not allowed/,
        `blocks SSRF URL ${badUrl}`,
      );
    }
    syncer.add(srcScope, "rebind", "https://rebind.example.test/doc");
    await assert.rejects(
      () => syncer.sync(srcScope, "rebind"),
      /blocked network address/,
      "DNS lookup validation blocks private resolved IP during sync",
    );
    syncer.add(srcScope, "empty-html", "https://public.example.test/empty.html");
    const htmlRes = await syncer.sync(srcScope, "empty-html");
    assert.equal(htmlRes.documents, 0, "tag-only empty HTML reports 0 documents");

    // Root confinement, IGNORED on root dir, skip hardlinks
    const outFile = path.join(outsideDir, "note.md");
    fs.writeFileSync(outFile, "outside");
    assert.throws(
      () => syncer.add(srcScope, "out", outFile),
      /outside the allowed root/,
      "blocks local source outside missionRoot",
    );
    const gitRoot = path.join(engDir, ".git");
    fs.mkdirSync(gitRoot);
    fs.writeFileSync(path.join(gitRoot, "config.json"), "{}");
    assert.throws(
      () => syncer.add(srcScope, "git", gitRoot),
      /sensitive source/,
      "blocks IGNORED root directory (.git)",
    );
    const docsDir = path.join(engDir, "docs");
    fs.mkdirSync(docsDir);
    const goodMd = path.join(docsDir, "good.md");
    const hardTarget = path.join(outsideDir, "hl-src.md");
    const hardLink = path.join(docsDir, "linked.md");
    fs.writeFileSync(goodMd, "valid documentation");
    fs.writeFileSync(hardTarget, "linked content");
    fs.linkSync(hardTarget, hardLink);
    syncer.add(srcScope, "docs", docsDir);
    const docSync = await syncer.sync(srcScope, "docs");
    assert.equal(
      docSync.documents,
      1,
      "hardlinks inside folder are skipped without aborting valid siblings",
    );
    spStore.close();
    skStore.close();

    // cve-sources.ts
    let execCalled = false;
    const ssMock = mock.method(childProcess, "execFileSync", () => {
      execCalled = true;
      return JSON.stringify(null);
    });
    syncBuiltinESMExports();
    try {
      const inj = querySearchsploit("apache -m --nmap=/etc/passwd");
      assert.equal(execCalled, false, "CLI -flag token does not reach execFileSync");
      assert.ok(inj.error, "flag injection returns error");
      const nullJson = querySearchsploit("  apache  ");
      assert.equal(execCalled, true);
      assert.deepEqual(nullJson, { results: [] }, "null JSON handled safely");
    } finally {
      ssMock.mock.restore();
      syncBuiltinESMExports();
    }

    const fetchMock = mock.method(globalThis, "fetch", async (url, init) => {
      assert.equal(init.redirect, "error", "queryNvd sets redirect: error");
      return {
        ok: true,
        status: 200,
        headers: new Headers({ "content-length": String(5 * 1024 * 1024) }),
        json: async () => ({ vulnerabilities: [] }),
      };
    });
    try {
      const big = await queryNvd("nginx");
      assert.match(String(big.error), /too-large/);
      fetchMock.mock.mockImplementation(async () => ({
        ok: true,
        status: 200,
        headers: new Headers(),
        text: async () =>
          JSON.stringify({
            vulnerabilities: [{ cve: { id: "CVE-2026-1", descriptions: null } }],
          }),
      }));
      const nullDesc = await queryNvd("nginx");
      assert.equal(nullDesc.results[0].id, "CVE-2026-1");
      assert.equal(nullDesc.results[0].summary, "");
    } finally {
      fetchMock.mock.restore();
    }

    // osint-ingest.ts
    const credPlan = planIngest(
      "lines",
      `https://alice:s3cr3t@example.com/login\nhttps://${"a".repeat(295)}@longuser.test/p\nhttps://example.com/${"x".repeat(310)}\n999.999.999.999\na.--\n192.0.2.1\n[2001:db8::1]\n`,
    );
    assert.ok(
      !JSON.stringify(credPlan).includes("s3cr3t"),
      "urlOf never retains URL credentials",
    );
    assert.ok(
      credPlan.entities.some(
        (e) => e.type === "url" && e.key === "https://example.com/login",
      ),
    );
    assert.ok(
      credPlan.entities.some(
        (e) => e.type === "ip" && e.key === "192.0.2.1",
      ),
      "IPv4 classified as ip",
    );
    assert.ok(
      credPlan.entities.some(
        (e) => e.type === "ip" && e.key === "2001:db8::1",
      ),
      "IPv6 classified as ip",
    );
    assert.ok(
      !credPlan.entities.some((e) => e.key === "999.999.999.999" || e.key === "a.--"),
      "invalid IPv4 and invalid TLD rejected",
    );
    const httpxPlan = planIngest(
      "httpx",
      JSON.stringify({ input: "https://fallback.test/", host: "", tech: ["Nginx"] }),
    );
    assert.ok(
      httpxPlan.entities.some((e) => e.type === "host" && e.key === "fallback.test"),
      "empty row.host falls back to URL hostname",
    );
    const manyHttpx = Array.from({ length: 200 }, (_, i) =>
      JSON.stringify({
        input: `https://h${i}.example.test/`,
        tech: Array.from({ length: 20 }, (__, j) => `tech-${i}-${j}`),
      }),
    ).join("\n");
    assert.equal(
      planIngest("httpx", manyHttpx).entities.length,
      2000,
      "httpx ingest strictly enforces MAX_ENTITIES = 2000",
    );
    assert.throws(
      () => planIngest("xml", "<x/>"),
      /Invalid dump format/,
      "unknown ingest format throws",
    );
    const jsonBad = planIngest(
      "json",
      JSON.stringify([
        { type: "host", key: "bad\nkey" },
        { type: "host", key: "arr-attr.test", attributes: ["not-object"] },
        { type: "host", key: "blank-lbl.test", label: "   " },
      ]),
    );
    assert.equal(jsonBad.entities.length, 1, "control chars and array attributes skipped");
    assert.equal(jsonBad.entities[0].label, undefined, "blank label omitted");

    // reference-search.ts
    const refDir = path.join(work, "ref");
    fs.mkdirSync(refDir);
    const refDbPath = path.join(refDir, "ref.sqlite");
    const refDb = new DatabaseSync(refDbPath);
    refDb.exec(`
      CREATE TABLE docs(id INTEGER PRIMARY KEY, shelf TEXT, kind TEXT, key TEXT, owner TEXT, text TEXT);
      CREATE VIRTUAL TABLE fts_catalog USING fts5(text);
      CREATE VIRTUAL TABLE fts_cve USING fts5(text);
    `);
    for (let i = 1; i <= 15; i++) {
      refDb
        .prepare("INSERT INTO docs VALUES(?,?,?,?,?,?)")
        .run(
          i,
          "catalog",
          "doc",
          `CAT-${i}`,
          "owner",
          `needle filler words extra content ${i}`,
        );
      refDb
        .prepare("INSERT INTO fts_catalog(rowid,text) VALUES(?,?)")
        .run(i, `needle filler words extra content ${i}`);
    }
    refDb
      .prepare("INSERT INTO docs VALUES(?,?,?,?,?,?)")
      .run(
        100,
        "cve",
        "cve",
        "CVE-2026-9999",
        "owner",
        "needle needle needle api_key=refsecret123",
      );
    refDb
      .prepare("INSERT INTO fts_cve(rowid,text) VALUES(?,?)")
      .run(100, "needle needle needle api_key=refsecret123");
    refDb.close();
    const prevRefDb = process.env.HARNESS_KNOWLEDGE_DB;
    process.env.HARNESS_KNOWLEDGE_DB = refDbPath;
    try {
      const refRes = searchReference("needle", 5);
      assert.ok(
        refRes.results.some((r) => r.key === "CVE-2026-9999"),
        "ORDER BY rank prevents fts_catalog from starving fts_cve",
      );
      const cveRow = refRes.results.find((r) => r.key === "CVE-2026-9999");
      assert.ok(
        !cveRow.excerpt.includes("refsecret123") &&
          cveRow.excerpt.includes("<REDACTED>"),
        "reference-search redacts secrets in excerpts",
      );
      // Symlinked -wal file rejected
      fs.symlinkSync("/dev/null", `${refDbPath}-wal`);
      assert.throws(
        () => searchReference("needle", 5),
        /Linked or special/,
        "reference-search checks -wal plain path",
      );
      fs.unlinkSync(`${refDbPath}-wal`);
    } finally {
      if (prevRefDb === undefined) delete process.env.HARNESS_KNOWLEDGE_DB;
      else process.env.HARNESS_KNOWLEDGE_DB = prevRefDb;
    }

    // coverage-roles.ts & coverage-profiles.ts Object.hasOwn
    assert.deepEqual(
      assetSteps("constructor"),
      ["surface", "validation"],
      "assetSteps('constructor') falls back instead of returning Object",
    );
    assert.deepEqual(assetSteps("toString"), ["surface", "validation"]);
    assert.throws(
      () => coverageProfile("constructor"),
      /Unknown coverage profile/,
    );
    assert.throws(
      () => coverageContract("toString"),
      /Unknown coverage profile/,
    );
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
};
