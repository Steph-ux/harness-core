/** Synthetic mission lifecycle; report bindings use a tiny fixture, real rendering is separate. */
const fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  { createHash } = require("node:crypto");
const { makeContext } = require("./opencode-fixture.cjs");
module.exports = async ({ assert, jiti }) => {
  const root = path.resolve(__dirname, ".."),
    work = fs.mkdtempSync(path.join(os.tmpdir(), "harness-workflow-")),
    state = path.join(work, "state");
  fs.mkdirSync(state);
  process.env.HARNESS_CORE = root;
  process.env.HARNESS_STATE_ROOT = state;
  const { KnowledgeStore } = jiti(path.join(root, "src/store.ts")),
    { PlatformStore } = jiti(path.join(root, "src/platform-store.ts")),
    { EngagementWorkflow } = jiti(
      path.join(root, "src/engagement-workflow.ts"),
    ),
    { scopeFor } = jiti(path.join(root, "src/util.ts")),
    { ProcessRegistry, processStatus } = jiti(
      path.join(root, "src/process.ts"),
    );
  const fixture = makeContext(work),
    unload = await jiti(path.join(root, "opencode/plugin.ts")).default.setup(
      fixture.ctx,
    ),
    store = new KnowledgeStore(path.join(state, "knowledge.sqlite")),
    platform = new PlatformStore(path.join(state, "platform.sqlite"), store),
    workflow = new EngagementWorkflow(state, platform, store),
    scope = scopeFor(work),
    registry = new ProcessRegistry(state);
  const context = (id = "call", sessionID = "ses_original") => ({
    sessionID,
    id,
    agent: "build",
    messageID: "msg_workflow",
    signal: new AbortController().signal,
  });
  const call = (name, input, c = context()) =>
    fixture.tools.get(name).execute(input, c);
  const session = (id) =>
    store.upsertSession({
      id,
      scope,
      cwd: work,
      status: "active",
      updatedAt: new Date().toISOString(),
    });
  const obs = (id, output, sessionId = "ses_original", success = true) => {
    session(sessionId);
    return store.recordObservation({
      id,
      sessionId,
      scope,
      tool: "shell",
      input: {},
      output,
      success,
      timestamp: new Date().toISOString(),
    });
  };
  const finish = (m, node, role, evidence, findingIds = []) => {
    const lease = platform.claim(scope, m.id, node, role, findingIds);
    return platform.finish(scope, m.id, node, lease, [
      { role, status: "completed", summary: `Observed ${node}`, evidence },
    ]);
  };
  const digest = (file) =>
    createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  const until = async (fn) => {
    const end = Date.now() + 8000;
    while (!fn() && Date.now() < end)
      await new Promise((r) => setTimeout(r, 30));
    assert.ok(fn(), "process finished");
  };
  try {
    for (const name of ["capitaliser-cyber", "rapports-cyber"])
      assert.ok(fixture.skills.has(name));
    assert.ok(
      fixture.tools
        .get("cyber_mission")
        .input.properties.action.enum.includes("reopen-validation"),
    );
    const okay = obs("obs-stage", "Étape de laboratoire observée"),
      m = platform.createMission(
        scope,
        "Mission synthétique de rapport",
        "Fixtures locales uniquement. Aucun système client.",
      );
    platform.approveScope(scope, m.id);
    const reconLease = platform.claim(scope, m.id, "recon", "recon-agent");
    assert.throws(
      () =>
        platform.finish(scope, m.id, "recon", reconLease, [
          {
            role: "recon-agent",
            status: "completed",
            summary: "No proof",
            evidence: [],
          },
        ]),
      /requires observed evidence/,
    );
    const failed = obs("obs-failed", "Échec du test", "ses_original", false);
    assert.throws(
      () =>
        platform.finish(scope, m.id, "recon", reconLease, [
          {
            role: "recon-agent",
            status: "completed",
            summary: "Failure only",
            evidence: [failed.id],
          },
        ]),
      /successful evidence/,
    );
    platform.finish(scope, m.id, "recon", reconLease, [
      {
        role: "recon-agent",
        status: "completed",
        summary: "Observed",
        evidence: [okay.id],
      },
    ]);
    finish(m, "enumeration", "recon-agent", [okay.id]);
    finish(m, "analysis", "recon-agent", [okay.id]);
    const source = platform.ingest(
        scope,
        "synthetic-source",
        "fixture:controls",
        "Fixture des contrôles",
        "Comparaison de deux sorties de laboratoire.",
      )[0],
      a = obs("obs-positive", "POSITIF résultat observé"),
      b = obs("obs-negative", "NEGATIF témoin observé");
    const proposal = {
      missionId: m.id,
      title: "Écart contrôlé dans la fixture",
      severity: "low",
      description: "Une fixture locale émet deux marqueurs différents.",
      limitations: "Résultat limité au banc local.",
      evidence: [a.id, b.id],
      sources: [source.id],
      checks: [
        {
          observationId: a.id,
          contains: "POSITIF résultat observé",
          purpose: "reproduction",
        },
        {
          observationId: b.id,
          contains: "NEGATIF témoin observé",
          purpose: "negative-control",
        },
      ],
    };
    await fixture.hooks.get("prompt")({
      sessionID: "ses_original",
      prompt: { text: "Vérifie ce JWT" },
    });
    await fixture.hooks.get("context")(
      fixture.contextEvent({ sessionID: "ses_original" }),
    );
    await fixture.hooks.get("execute.after")({
      tool: "skill",
      sessionID: "ses_original",
      id: "failed-load",
      input: { id: "harness-jwt" },
      status: "error",
      error: { message: "missing" },
    });
    await assert.rejects(
      () => call("cyber_finding", { action: "create", ...proposal }),
      /none of them was loaded/,
    );
    await fixture.hooks.get("prompt")({
      sessionID: "ses_original",
      prompt: { text: "Contrôles locaux synthétiques" },
    });
    await fixture.hooks.get("context")(
      fixture.contextEvent({ sessionID: "ses_original" }),
    );
    const finding = platform.createFinding(scope, proposal),
      get = JSON.parse(
        (await call("cyber_finding", { action: "get", id: finding.id }))
          .content,
      );
    assert.equal(get.sources[0].id, source.id);
    const va = obs(
        "obs-verify-positive",
        "POSITIF résultat observé",
        "ses_verifier",
      ),
      vb = obs("obs-verify-negative", "NEGATIF témoin observé", "ses_verifier"),
      checks = proposal.checks.map((c, i) => ({
        ...c,
        observationId: i ? vb.id : va.id,
      }));
    assert.throws(
      () =>
        platform.verificationPayload(
          scope,
          finding.id,
          "ses_original",
          proposal.checks,
        ),
      /distinct session|fresh/,
    );
    assert.throws(
      () =>
        platform.verificationPayload(
          scope,
          finding.id,
          "ses_verifier",
          checks.map((c) => ({ ...c, contains: "unrelated output" })),
        ),
      /lacks observed evidence/,
    );
    const attestation = JSON.parse(
        (
          await call(
            "cyber_verification",
            { action: "attest", findingId: finding.id, checks },
            context("attest", "ses_verifier"),
          )
        ).content,
      ),
      unrelated = obs("obs-unrelated", "Résultat sans rapport", "ses_verifier");
    finish(
      m,
      "validation",
      "verification-agent",
      [attestation.id, unrelated.id],
      [finding.id],
    );
    assert.throws(
      () => platform.verifyFinding(scope, finding.id, unrelated.id),
      /linked verification/,
    );
    const verified = platform.verifyFinding(scope, finding.id, attestation.id);
    assert.equal(verified.status, "verified");
    assert.equal(verified.verification.humanApproval, null);
    finish(m, "evidence", "code-agent", [okay.id]);
    const reportLease = platform.claim(scope, m.id, "report", "report-agent");
    assert.throws(
      () =>
        platform.finish(scope, m.id, "report", reportLease, [
          {
            role: "report-agent",
            status: "completed",
            summary: "Narration only",
            evidence: [okay.id],
          },
        ]),
      /reviewed report artifact/,
    );
    const config = {
      title: "Rapport de validation locale",
      client: "Organisation de test",
      author: "Équipe de test",
      period: "4 novembre 2026",
      method: "Tests déterministes sur des fixtures locales.",
      findings: {
        [finding.id]: {
          classification: "vulnerability",
          asset: "Fixture locale",
          preconditions: "Accès au banc local",
          impact: "Différence de réponse prouvée dans la fixture.",
          steps: ["Exécuter le cas positif.", "Exécuter le contrôle négatif."],
          remediation: ["Conserver la séparation des cas."],
          closure: "Les deux contrôles passent.",
          cvss: {
            vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
            score: 4.3,
          },
          businessRisk: "Démonstration locale sans donnée client.",
          artifactIds: [],
        },
      },
    };
    const snapshot = workflow.snapshot(scope, m.id, config);
    if (process.env.HARNESS_REPORT_SMOKE_SNAPSHOT)
      fs.copyFileSync(snapshot.path, process.env.HARNESS_REPORT_SMOKE_SNAPSHOT);
    const target = path.join(work, "test-object");
    fs.writeFileSync(target, "Keep until restitution");
    assert.throws(
      () =>
        workflow.cleanupPlan(
          scope,
          snapshot.snapshot.id,
          "Too early",
          ["true"],
          ["true"],
        ),
      /before restitution/,
    );
    assert.equal(fs.existsSync(target), true);
    assert.throws(
      () =>
        workflow.recordRestitution(
          scope,
          snapshot.snapshot.id,
          okay.id,
          "operator",
          "Too early",
        ),
      /reviewed/,
    );
    assert.throws(
      () =>
        workflow.reviewReport(scope, snapshot.snapshot.id, {
          pagesReviewed: [1],
          decision: "approved",
          reviewer: "operator",
          notes: "No generated report",
        }),
      /Register generated/,
    );
    // Synthetic signatures exercise manifest binding only, not Office/PDF parsing.
    const docx = path.join(work, "fixture.docx"),
      pdf = path.join(work, "fixture.pdf"),
      png = path.join(work, "page-1.png"),
      qaFile = path.join(work, "qa.json");
    fs.writeFileSync(docx, "PK\u0003\u0004fixture");
    fs.writeFileSync(pdf, "%PDF-1.7\nfixture");
    fs.writeFileSync(png, Buffer.from("89504e470d0a1a0a", "hex"));
    const artifact = (file, kind) =>
        workflow.registerArtifact(
          scope,
          m.id,
          { path: file, kind, observationIds: [okay.id] },
          work,
        ),
      doc = artifact(docx, "report-docx"),
      paper = artifact(pdf, "report-pdf");
    fs.writeFileSync(
      qaFile,
      JSON.stringify({
        snapshotId: snapshot.snapshot.id,
        snapshotHash: snapshot.sha256,
        docxHash: doc.sha256,
        pdfHash: paper.sha256,
        pages: 1,
        structuredChecks: true,
        pageImages: [{ path: "page-1.png", sha256: digest(png) }],
      }),
    );
    const qa = artifact(qaFile, "report-qa");
    workflow.registerReport(scope, snapshot.snapshot.id, [
      doc.id,
      paper.id,
      qa.id,
    ]);
    assert.throws(
      () =>
        workflow.reviewReport(scope, snapshot.snapshot.id, {
          pagesReviewed: [],
          decision: "approved",
          reviewer: "operator",
          notes: "Incomplete",
        }),
      /every rendered page/,
    );
    const originalImage = fs.readFileSync(png);
    fs.appendFileSync(png, "changed");
    let permissionCalls = 0;
    fixture.ctx.permission.explicit = async () => {
      permissionCalls++;
      return "once";
    };
    await assert.rejects(
      () =>
        call("cyber_report", {
          action: "review",
          reportId: snapshot.snapshot.id,
          pagesReviewed: [1],
          decision: "approved",
          notes: "Changed page",
        }),
      /Rendered page changed/,
    );
    assert.equal(permissionCalls, 0, "preflight before approval");
    fs.writeFileSync(png, originalImage);
    fixture.ctx.permission.explicit = async () => "reject";
    await assert.rejects(
      () =>
        call("cyber_report", {
          action: "review",
          reportId: snapshot.snapshot.id,
          pagesReviewed: [1],
          decision: "approved",
          notes: "Synthetic review",
        }),
      /explicit operator/,
    );
    fixture.ctx.permission.explicit = async () => "once";
    await call("cyber_report", {
      action: "review",
      reportId: snapshot.snapshot.id,
      pagesReviewed: [1],
      decision: "approved",
      notes: "Synthetic manifest binding checked",
    });
    const originalDocx = fs.readFileSync(docx);
    fs.appendFileSync(docx, "changed");
    assert.throws(
      () =>
        platform.finish(scope, m.id, "report", reportLease, [
          {
            role: "report-agent",
            status: "completed",
            summary: "Changed file",
            evidence: [okay.id],
          },
        ]),
      /content changed/,
    );
    fs.writeFileSync(docx, originalDocx);
    platform.finish(scope, m.id, "report", reportLease, [
      {
        role: "report-agent",
        status: "completed",
        summary: "Bound report reviewed",
        evidence: [okay.id],
      },
    ]);
    assert.equal(platform.mission(scope, m.id).state, "COMPLETED");
    assert.throws(
      () =>
        workflow.cleanupPlan(
          scope,
          snapshot.snapshot.id,
          "Still before restitution",
          ["true"],
          ["true"],
        ),
      /before restitution/,
    );
    assert.equal(fs.existsSync(target), true);
    await call("cyber_report", {
      action: "restitution",
      reportId: snapshot.snapshot.id,
      evidenceId: okay.id,
      statement: "Restitution synthétique effectuée",
    });
    assert.equal(fs.existsSync(target), true);
    const cleanup = workflow.cleanupPlan(
      scope,
      snapshot.snapshot.id,
      "Remove the synthetic local object",
      [
        process.execPath,
        "-e",
        `require('node:fs').unlinkSync(${JSON.stringify(target)})`,
      ],
      [
        process.execPath,
        "-e",
        `process.exit(require('node:fs').existsSync(${JSON.stringify(target)})?1:0)`,
      ],
    );
    await assert.rejects(
      () => call("cyber_cleanup", { action: "verify", id: cleanup.id }),
      /Invalid cleanup transition/,
    );
    assert.equal(fs.existsSync(target), true);
    const { DatabaseSync } = require("node:sqlite"),
      fault = new DatabaseSync(path.join(state, "platform.sqlite"));
    fault.exec(
      "CREATE TRIGGER fail_cleanup_event BEFORE INSERT ON workflow_events WHEN new.event='cleanup.started' BEGIN SELECT RAISE(ABORT,'fixture event failure'); END",
    );
    await assert.rejects(
      () => call("cyber_cleanup", { action: "run", id: cleanup.id }),
      /fixture event failure/,
    );
    assert.equal(workflow.cleanup(scope, cleanup.id).status, "planned");
    assert.equal(fs.existsSync(target), true);
    fault.exec("DROP TRIGGER fail_cleanup_event");
    fault.close();
    const run = JSON.parse(
      (await call("cyber_cleanup", { action: "run", id: cleanup.id })).content,
    );
    await until(
      () => processStatus(registry.get(scope, run.process.id)) === "succeeded",
    );
    await call("cyber_cleanup", { action: "result", id: cleanup.id });
    assert.equal(workflow.cleanup(scope, cleanup.id).status, "executed");
    assert.equal(fs.existsSync(target), false);
    const verification = JSON.parse(
      (await call("cyber_cleanup", { action: "verify", id: cleanup.id }))
        .content,
    );
    await until(
      () =>
        processStatus(registry.get(scope, verification.process.id)) ===
        "succeeded",
    );
    await call("cyber_cleanup", { action: "result", id: cleanup.id });
    assert.equal(workflow.cleanup(scope, cleanup.id).status, "completed");
    assert.throws(
      () =>
        workflow.capitalization(scope, m.id, {
          outcome: "validated",
          reason: "No tests",
          artifactIds: [doc.id],
          tests: [],
        }),
      /distinct/,
    );
    const none = workflow.capitalization(scope, m.id, {
      outcome: "none",
      reason: "No reusable change justified",
      artifactIds: [],
      tests: [],
    });
    assert.equal(none.outcome, "none");
    const script = path.join(work, "parser.cjs");
    fs.writeFileSync(script, "// synthetic reusable artifact");
    const reusable = artifact(script, "script");
    const capitalized = workflow.capitalization(scope, m.id, {
      outcome: "validated",
      reason: "Synthetic parser tested",
      artifactIds: [reusable.id],
      tests: [
        {
          observationId: va.id,
          contains: "POSITIF résultat",
          kind: "positive",
        },
        { observationId: vb.id, contains: "NEGATIF témoin", kind: "negative" },
      ],
    });
    assert.equal(capitalized.outcome, "validated");
    assert.equal(workflow.status(scope, m.id).capitalizations.length, 1);
    fixture.ctx.permission.explicit = async () => "reject";
    await assert.rejects(
      () =>
        call("cyber_mission", {
          action: "reopen-validation",
          id: m.id,
          reason: "Update finding proof",
        }),
      /explicit operator/,
    );
    fixture.ctx.permission.explicit = async () => "once";
    await new Promise((r) => setTimeout(r, 5));
    await call("cyber_mission", {
      action: "reopen-validation",
      id: m.id,
      reason: "Revalidate updated findings",
    });
    assert.equal(
      platform.mission(scope, m.id).nodes.find((n) => n.id === "validation")
        .state,
      "PENDING",
    );
    assert.equal(
      platform.mission(scope, m.id).nodes.find((n) => n.id === "report").state,
      "PENDING",
    );
    assert.equal(platform.finding(scope, finding.id).status, "unverified");
    assert.equal(platform.finding(scope, finding.id).verification, null);
    assert.equal(workflow.report(scope, snapshot.snapshot.id).reviewed, false);
    assert.equal(workflow.status(scope, m.id).restitutions.length, 1);
    assert.throws(
      () =>
        platform.verificationPayload(scope, finding.id, "ses_verifier", checks),
      /fresh observations/,
    );
    assert.throws(
      () =>
        workflow.recordRestitution(
          scope,
          snapshot.snapshot.id,
          okay.id,
          "operator",
          "Stale version",
        ),
      /stale/,
    );
  } finally {
    unload();
    workflow.close();
    platform.close();
    store.close();
    fs.rmSync(work, { recursive: true, force: true });
  }
};
