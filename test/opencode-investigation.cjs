/**
 * The investigation engine is an arbiter, not a suggestion box.
 *
 * A model that loops on one tool, leaves hypotheses untested, or concludes
 * before covering the surface must be told so from the state, not from its
 * own story. These checks prove the signals fire on the bad state and stay
 * silent on the good one.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti }) => {
  const inv = jiti(path.join(CORE, "src", "investigation.ts"));
  const {
    HypothesisTracker,
    advanceHypothesis,
    detectStagnation,
    CoverageMap,
    directives,
    investigationBlock,
    INVESTIGATION_MARKER,
    InvestigationStore,
    assembleInvestigation,
    addressedPct,
    CONCLUSION_THRESHOLD,
    surfacesFromTasks,
    taskCoverageSummary,
  } = inv;
  const { closingGate } = jiti(path.join(CORE, "src", "capsule.ts"));

  // --- HypothesisTracker ---------------------------------------------------

  const tracker = new HypothesisTracker();
  const h = tracker.propose("H1", "SQLi on login form", "2024-01-01T00:00:00Z");
  assert.equal(h.id, "H1", "a proposed hypothesis carries its id");
  assert.equal(h.state, "proposed", "a new hypothesis starts proposed");
  assert.equal(h.evidence.length, 0, "a new hypothesis has no evidence");

  assert.throws(
    () => tracker.propose("H1", "other", "2024-01-01T00:00:00Z"),
    /already exists/,
    "a duplicate hypothesis id is refused",
  );

  const testing = tracker.test("H1", "2024-01-01T00:01:00Z");
  assert.equal(testing.state, "testing", "testing starts from proposed");
  const confirmed = tracker.addEvidence("H1", "obs-123", "2024-01-01T00:02:00Z");
  assert.equal(confirmed.state, "confirmed", "evidence confirms a testing hypothesis");
  assert.deepEqual(confirmed.evidence, ["obs-123"], "the proof travels with the hypothesis");

  assert.throws(
    () => tracker.addEvidence("H1", "obs-2", "2024-01-01T00:03:00Z"),
    /already confirmed/,
    "a confirmed hypothesis is closed to new evidence",
  );
  assert.throws(
    () => tracker.refute("H1", "obs-neg", "2024-01-01T00:03:00Z"),
    /confirmed/,
    "a confirmed hypothesis cannot be reopened as refuted",
  );

  tracker.propose("H2", "SSRF via redirect", "2024-01-01T00:00:00Z");
  const refuted = tracker.refute("H2", "obs-neg", "2024-01-01T00:01:00Z");
  assert.equal(refuted.state, "refuted", "counter-evidence refutes a hypothesis");
  assert.deepEqual(refuted.counterEvidence, ["obs-neg"], "the refutation proof travels");

  // Stale detection: 30 minutes without movement.
  tracker.propose("H3", "old one", "2024-01-01T00:00:00Z");
  const stale = tracker.tick(Date.parse("2024-01-01T00:00:00Z") + 31 * 60 * 1000);
  assert.equal(stale.length, 1, "an untouched hypothesis goes stale");
  assert.equal(stale[0].state, "stale", "the stale transition is recorded");

  // A terminal hypothesis never goes stale.
  const stale2 = tracker.tick(Date.parse("2024-01-01T00:00:00Z") + 60 * 60 * 1000);
  assert.equal(stale2.length, 0, "confirmed and refuted hypotheses do not go stale");
  assert.equal(
    tracker.list().find((x) => x.id === "H1").state,
    "confirmed",
    "tick does not touch a confirmed hypothesis",
  );

  // advanceHypothesis: counter-evidence beats everything, stale only moves open ones.
  const base = {
    id: "X",
    text: "t",
    state: "testing",
    evidence: [],
    counterEvidence: [],
    createdAt: "2024-01-01T00:00:00Z",
    updatedAt: "2024-01-01T00:00:00Z",
  };
  assert.equal(
    advanceHypothesis({ ...base, counterEvidence: ["neg"] }, Date.parse(base.updatedAt)),
    "refuted",
    "counter-evidence refutes even a testing hypothesis",
  );
  assert.equal(
    advanceHypothesis({ ...base, state: "confirmed" }, Date.now()),
    "confirmed",
    "a confirmed hypothesis stays confirmed",
  );

  // active() and refuted() partition the registry.
  const t2 = new HypothesisTracker();
  t2.propose("A", "active", "2024-01-01T00:00:00Z");
  t2.propose("B", "testing", "2024-01-01T00:00:00Z");
  t2.test("B", "2024-01-01T00:01:00Z");
  t2.propose("C", "done", "2024-01-01T00:00:00Z");
  t2.test("C", "2024-01-01T00:01:00Z");
  t2.addEvidence("C", "obs-1", "2024-01-01T00:02:00Z");
  assert.equal(t2.active().length, 2, "active filters proposed and testing");
  assert.equal(t2.refuted().length, 0, "refuted is empty when none was refuted");

  // --- Stagnation detector -------------------------------------------------

  const ts = "2024-01-01T00:00:00Z";
  assert.deepEqual(
    detectStagnation([], 5, 0, Date.now()),
    [],
    "a fresh session has no stagnation signal",
  );

  const loopCalls = Array.from({ length: 5 }, (_, i) => ({
    tool: "nmap",
    outputHash: `h${i}`,
    success: true,
    timestamp: ts,
  }));
  const loopSignals = detectStagnation(loopCalls, 3, 0, Date.parse(ts));
  assert.ok(
    loopSignals.some((s) => s.kind === "tool-loop"),
    "a tool called 5 times in the window is a loop",
  );
  assert.equal(
    loopSignals.find((s) => s.kind === "tool-loop").severity,
    "critical",
    "5 repeats is critical, not a hint",
  );

  const repeatCalls = Array.from({ length: 4 }, () => ({
    tool: "curl",
    outputHash: "deadbeef",
    success: true,
    timestamp: ts,
  }));
  assert.ok(
    detectStagnation(repeatCalls, 2, 0, Date.parse(ts)).some(
      (s) => s.kind === "output-repeat",
    ),
    "the same output hash 4 times is an output repeat",
  );

  const failCalls = Array.from({ length: 3 }, () => ({
    tool: "sqlmap",
    outputHash: "err1",
    success: false,
    timestamp: ts,
  }));
  assert.ok(
    detectStagnation(failCalls, 1, 0, Date.parse(ts)).some(
      (s) => s.kind === "same-failure",
    ),
    "a tool failing 3 times is a repeated failure",
  );

  const baseMs = Date.parse(ts);
  const slowCalls = Array.from({ length: 6 }, (_, i) => ({
    tool: `tool${i}`,
    outputHash: `h${i}`,
    success: true,
    timestamp: new Date(baseMs + i * 1000).toISOString(),
  }));
  assert.ok(
    detectStagnation(slowCalls, 5, 0, baseMs + 20 * 60 * 1000).some(
      (s) => s.kind === "no-progress",
    ),
    "open tasks and no completion for 15+ minutes is no progress",
  );

  const healthyCalls = [
    { tool: "nmap", outputHash: "a", success: true, timestamp: ts },
    { tool: "curl", outputHash: "b", success: true, timestamp: ts },
    { tool: "sqlmap", outputHash: "c", success: true, timestamp: ts },
  ];
  assert.deepEqual(
    detectStagnation(healthyCalls, 3, 1, Date.parse(ts)),
    [],
    "varied tools and a recent completion produce no signal",
  );

  // --- CoverageMap ---------------------------------------------------------

  const map = new CoverageMap([
    { id: "auth", label: "Authentication" },
    { id: "sqli", label: "SQL injection" },
  ]);
  const s0 = map.summary();
  assert.equal(s0.total, 2, "the map starts with its entries");
  assert.equal(s0.untested, 2, "every entry starts untested");
  assert.equal(s0.tested, 0, "nothing is tested at start");

  map.start("auth");
  assert.equal(map.summary().inProgress, 1, "start moves a surface to in-progress");
  map.complete("auth", ["obs-1"]);
  assert.equal(map.summary().tested, 1, "complete with evidence marks tested");
  assert.equal(map.summary().inProgress, 0, "a completed surface is no longer in-progress");

  map.block("sqli", "WAF blocks every probe");
  const s1 = map.summary();
  assert.equal(s1.blocked, 1, "block marks the surface blocked");
  assert.equal(
    s1.surfaces.find((x) => x.id === "sqli").reason,
    "WAF blocks every probe",
    "a blocked surface carries its reason",
  );

  assert.throws(
    () => map.complete("sqli", []),
    /at least one/,
    "a surface cannot be tested without an observation",
  );

  const map2 = new CoverageMap([
    { id: "a", label: "A" },
    { id: "b", label: "B" },
  ]);
  map2.complete("a", ["obs-1"]);
  const untested = map2.untested();
  assert.equal(untested.length, 1, "untested returns only untested surfaces");
  assert.equal(untested[0].id, "b", "the tested surface is not in untested");

  const map3 = new CoverageMap();
  map3.add("new", "New surface");
  assert.equal(map3.summary().total, 1, "add inserts a new surface");
  map3.add("new", "New surface");
  assert.equal(map3.summary().total, 1, "add does not duplicate");

  // --- Directives ----------------------------------------------------------

  const mkH = (id, state, extra = {}) => ({
    id,
    text: "t",
    state,
    evidence: [],
    counterEvidence: [],
    createdAt: "",
    updatedAt: "",
    ...extra,
  });
  const mkCov = (over = {}) => ({
    total: 0,
    tested: 0,
    inProgress: 0,
    blocked: 0,
    untested: 0,
    surfaces: [],
    ...over,
  });

  const good = directives({
    hypotheses: [mkH("H1", "testing")],
    stagnation: [],
    coverage: mkCov({ total: 10, tested: 8, inProgress: 2 }),
    completedWithEvidence: 3,
    observationCount: 20,
  });
  assert.equal(good.length, 0, "a progressing session gets no directive");

  // A blocked surface is a standing nudge: the blocker may no longer hold.
  const blockedNudge = directives({
    hypotheses: [mkH("H1", "testing")],
    stagnation: [],
    coverage: mkCov({ total: 10, tested: 7, inProgress: 2, blocked: 1 }),
    completedWithEvidence: 3,
    observationCount: 20,
  });
  assert.ok(
    blockedNudge.some((d) => d.priority === "recommended" && d.text.includes("blocked")),
    "a blocked surface provokes a review of its blocker",
  );

  const loopD = directives({
    hypotheses: [],
    stagnation: [{ kind: "tool-loop", detail: "nmap called 5 times", severity: "critical" }],
    coverage: mkCov(),
    completedWithEvidence: 0,
    observationCount: 5,
  });
  assert.ok(
    loopD.some((d) => d.priority === "mandatory" && d.text.includes("STAGNATION")),
    "a critical tool loop is a mandatory directive",
  );

  const noProgD = directives({
    hypotheses: [],
    stagnation: [{ kind: "no-progress", detail: "5 tasks open", severity: "critical" }],
    coverage: mkCov(),
    completedWithEvidence: 0,
    observationCount: 10,
  });
  assert.ok(
    noProgD.some((d) => d.priority === "mandatory" && d.text.includes("NO PROGRESS")),
    "no progress is a mandatory directive",
  );

  const failD = directives({
    hypotheses: [],
    stagnation: [{ kind: "same-failure", detail: "sqlmap failed 3 times", severity: "critical" }],
    coverage: mkCov(),
    completedWithEvidence: 0,
    observationCount: 5,
  });
  assert.ok(
    failD.some((d) => d.priority === "mandatory" && d.text.includes("REPEATED FAILURE")),
    "a repeated failure tells the model to move on",
  );

  const staleD = directives({
    hypotheses: [mkH("H1", "stale")],
    stagnation: [],
    coverage: mkCov({ total: 5, tested: 2, untested: 3 }),
    completedWithEvidence: 2,
    observationCount: 10,
  });
  assert.ok(
    staleD.some((d) => d.priority === "mandatory" && d.text.includes("STALE")),
    "a stale hypothesis is mandatory to resolve",
  );

  const noHypD = directives({
    hypotheses: [],
    stagnation: [],
    coverage: mkCov({ total: 5, tested: 2, untested: 3 }),
    completedWithEvidence: 1,
    observationCount: 10,
  });
  assert.ok(
    noHypD.some((d) => d.text.includes("No active hypothesis")),
    "observations without a hypothesis provoke one",
  );

  const refutedD = directives({
    hypotheses: [mkH("H1", "refuted", { counterEvidence: ["neg-1"] })],
    stagnation: [],
    coverage: mkCov({ total: 5, tested: 2, untested: 3 }),
    completedWithEvidence: 1,
    observationCount: 10,
  });
  assert.ok(
    refutedD.some((d) => d.text.includes("All hypotheses refuted") && d.text.includes("Do not revisit")),
    "refuted hypotheses are not revisited",
  );

  const covD = directives({
    hypotheses: [mkH("H1", "testing")],
    stagnation: [],
    coverage: mkCov({
      total: 4,
      tested: 1,
      untested: 3,
      surfaces: [
        { id: "a", label: "Auth", state: "tested", evidence: ["o1"] },
        { id: "b", label: "SQLi", state: "untested", evidence: [] },
        { id: "c", label: "XSS", state: "untested", evidence: [] },
        { id: "d", label: "SSRF", state: "untested", evidence: [] },
      ],
    }),
    completedWithEvidence: 1,
    observationCount: 15,
  });
  assert.ok(
    covD.some((d) => d.text.includes("Coverage:") && d.text.includes("SQLi")),
    "untested surfaces are named so the model picks one",
  );

  const premature = directives({
    hypotheses: [],
    stagnation: [],
    coverage: mkCov({
      total: 10,
      tested: 3,
      inProgress: 1,
      untested: 6,
      surfaces: Array.from({ length: 10 }, (_, i) => ({
        id: `s${i}`,
        label: `S${i}`,
        state: i < 3 ? "tested" : i === 3 ? "in-progress" : "untested",
        evidence: i < 3 ? ["o1"] : [],
      })),
    }),
    completedWithEvidence: 2,
    observationCount: 20,
  });
  assert.ok(
    premature.some((d) => d.priority === "mandatory" && d.text.includes("PREMATURE CONCLUSION")),
    "under 60% coverage, a conclusion is premature",
  );

  const mature = directives({
    hypotheses: [],
    stagnation: [],
    coverage: mkCov({
      total: 10,
      tested: 7,
      inProgress: 1,
      untested: 2,
      surfaces: Array.from({ length: 10 }, (_, i) => ({
        id: `s${i}`,
        label: `S${i}`,
        state: i < 7 ? "tested" : i === 7 ? "in-progress" : "untested",
        evidence: i < 7 ? ["o1"] : [],
      })),
    }),
    completedWithEvidence: 5,
    observationCount: 30,
  });
  assert.ok(
    !mature.some((d) => d.text.includes("PREMATURE CONCLUSION")),
    "above 60% coverage the conclusion guard stays silent",
  );

  // --- addressedPct: a blocked surface is addressed ------------------------

  assert.equal(addressedPct({ total: 0, tested: 0, blocked: 0 }), null, "no surface means no percentage");
  assert.equal(addressedPct({ total: 10, tested: 3, blocked: 4 }), 70, "tested plus blocked is addressed");
  assert.equal(addressedPct({ total: 10, tested: 0, blocked: 10 }), 100, "all blocked with a reason is fully addressed");
  assert.equal(CONCLUSION_THRESHOLD, 60, "the conclusion threshold is 60%");

  // Blocked-with-reason surfaces lift the guard even when few are tested.
  const blockedAddressed = directives({
    hypotheses: [],
    stagnation: [],
    coverage: mkCov({
      total: 10,
      tested: 3,
      blocked: 4,
      untested: 3,
      surfaces: Array.from({ length: 10 }, (_, i) => ({
        id: `s${i}`,
        label: `S${i}`,
        state: i < 3 ? "tested" : i < 7 ? "blocked" : "untested",
        evidence: i < 3 ? ["o1"] : [],
        ...(i >= 3 && i < 7 ? { reason: "out of scope" } : {}),
      })),
    }),
    completedWithEvidence: 2,
    observationCount: 20,
  });
  assert.ok(
    !blockedAddressed.some((d) => d.text.includes("PREMATURE CONCLUSION")),
    "70% addressed (tested+blocked) does not trigger the premature guard",
  );

  // --- closingGate: hard blockers from the investigation -------------------

  const mkCapsule = (investigation, mission) => ({
    scope: "project-test",
    sessionID: "ses_test",
    tasks: [],
    open: 0,
    blocked: 0,
    observations: [],
    ...(mission ? { mission } : {}),
    ...(investigation ? { investigation } : {}),
  });

  // Untouched declared surfaces block a conclusion.
  const untestedGate = closingGate(
    mkCapsule({ untested: 3, staleHypotheses: 0, coveragePct: 40 }),
  );
  assert.match(untestedGate, /3 declared surface\(s\) never tested nor blocked/, "untested surfaces block the gate");
  assert.match(untestedGate, /under the 60% conclusion threshold/, "low coverage blocks the gate");

  // A stale hypothesis blocks a conclusion.
  const staleGate = closingGate(
    mkCapsule({ untested: 0, staleHypotheses: 2, coveragePct: 100 }),
  );
  assert.match(staleGate, /2 hypothesis\(es\) left stale/, "stale hypotheses block the gate");

  // Fully addressed coverage with no stale hypothesis: the gate is silent.
  const resolvedGate = closingGate(
    mkCapsule({ untested: 0, staleHypotheses: 0, coveragePct: 100 }),
  );
  assert.equal(resolvedGate, "", "a fully addressed investigation does not block the gate");

  // Nothing declared: no coverage blocker (cannot force declaration here).
  const noneGate = closingGate(
    mkCapsule({ untested: 0, staleHypotheses: 0, coveragePct: null }),
  );
  assert.equal(noneGate, "", "no declared surface means no coverage blocker");

  // A closed engagement is over by decision: it owes no investigation block.
  const closedGate = closingGate(
    mkCapsule(
      { untested: 5, staleHypotheses: 3, coveragePct: 10 },
      { id: "m1", title: "t", boundaries: "b", state: "CLOSED", stages: [] },
    ),
  );
  assert.ok(
    !/declared surface|left stale|conclusion threshold/.test(closedGate),
    "a closed engagement owes no investigation blocker",
  );

  // --- investigationBlock --------------------------------------------------

  assert.equal(investigationBlock([]), "", "no directive means no block");
  const block = investigationBlock([
    { priority: "mandatory", text: "Stop looping." },
    { priority: "recommended", text: "Consider XSS." },
  ]);
  assert.ok(block.startsWith(INVESTIGATION_MARKER), "the block carries its marker");
  assert.ok(block.includes("[MANDATORY] Stop looping."), "mandatory directives are labelled");
  assert.ok(block.includes("[RECOMMENDED] Consider XSS."), "recommended directives are labelled");
  assert.ok(
    block.indexOf("[MANDATORY]") < block.indexOf("[RECOMMENDED]"),
    "mandatory directives precede recommended ones",
  );

  // --- surfacesFromTasks: coverage from the task tree -----------------------

  const tasks = [
    { id: "t1", title: "Recon", status: "completed", evidence: ["obs-1"] },
    { id: "t2", title: "Auth", status: "blocked", reason: "no creds" },
    { id: "t3", title: "SQLi", status: "in-progress" },
    { id: "t4", title: "XSS", status: "pending" },
    { id: "t5", title: "sub-step", status: "pending", parentId: "t4" },
  ];
  const surfaces = surfacesFromTasks(tasks);
  assert.equal(surfaces.length, 4, "only root tasks become surfaces");
  assert.equal(surfaces.find((s) => s.id === "t1").state, "tested", "completed with evidence is tested");
  assert.equal(surfaces.find((s) => s.id === "t2").state, "blocked", "blocked is blocked");
  assert.equal(surfaces.find((s) => s.id === "t3").state, "in-progress", "in-progress is in-progress");
  assert.equal(surfaces.find((s) => s.id === "t4").state, "untested", "pending is untested");

  const tCov = taskCoverageSummary(tasks);
  assert.equal(tCov.total, 4, "task coverage counts root branches");
  assert.equal(tCov.tested, 1, "task coverage tested from evidence");
  assert.equal(tCov.blocked, 1, "task coverage blocked from status");
  assert.equal(tCov.inProgress, 1, "task coverage in-progress");
  assert.equal(tCov.untested, 1, "task coverage untested from pending");

  // A completed task without evidence is untested — not proven.
  const unproven = surfacesFromTasks([
    { id: "t1", title: "Done", status: "completed" },
  ]);
  assert.equal(unproven[0].state, "untested", "a completion without evidence is untested");

  // --- InvestigationStore persistence --------------------------------------

  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "harness-investigation-"));
  const store = new InvestigationStore(ws);
  const scope = "project-test000000000000000000";

  const ph = store.proposeHypothesis(scope, "IDOR on /api/user", "H-IDOR");
  assert.equal(ph.state, "proposed", "the store proposes a hypothesis");
  assert.equal(store.hypotheses(scope).length, 1, "the hypothesis is persisted");

  store.testHypothesis(scope, "H-IDOR");
  store.evidenceHypothesis(scope, "H-IDOR", "obs-9");
  assert.equal(
    store.hypotheses(scope).find((x) => x.id === "H-IDOR").state,
    "confirmed",
    "evidence confirms through the store",
  );

  store.proposeHypothesis(scope, "open redirect", "H-REDIR");
  store.refuteHypothesis(scope, "H-REDIR", "obs-neg");
  assert.equal(
    store.hypotheses(scope).find((x) => x.id === "H-REDIR").state,
    "refuted",
    "refutation persists",
  );

  store.addSurface(scope, "auth", "Authentication");
  store.addSurface(scope, "idor", "IDOR");
  store.startSurface(scope, "auth");
  store.completeSurface(scope, "auth", ["obs-9"]);
  store.blockSurface(scope, "idor", "needs second account");
  const cov = store.coverageSummary(scope);
  assert.equal(cov.total, 2, "surfaces persist");
  assert.equal(cov.tested, 1, "a completed surface is tested");
  assert.equal(cov.blocked, 1, "a blocked surface keeps its reason");

  // A fresh store instance reads the same file: resume finds the state.
  const store2 = new InvestigationStore(ws);
  assert.equal(store2.hypotheses(scope).length, 2, "a resumed store reads hypotheses");
  assert.equal(store2.coverageSummary(scope).total, 2, "a resumed store reads coverage");

  assert.throws(
    () => store.completeSurface(scope, "idor", []),
    /at least one/,
    "the store refuses a tested surface without evidence",
  );

  // --- assembleInvestigation -----------------------------------------------

  const nowMs = Date.parse("2024-01-01T01:00:00Z");
  const loopObs = Array.from({ length: 5 }, (_, i) => ({
    tool: "nmap",
    hash: `h${i}`,
    success: true,
    timestamp: new Date(nowMs - (5 - i) * 1000).toISOString(),
  }));
  const assembled = assembleInvestigation({
    observations: loopObs,
    tasks: [
      { status: "in-progress", updatedAt: new Date(nowMs - 20 * 60 * 1000).toISOString() },
    ],
    hypotheses: [],
    coverage: mkCov({ total: 4, tested: 1, untested: 3 }),
    nowMs,
  });
  assert.equal(assembled.observationCount, 5, "assembly counts observations");
  assert.ok(
    assembled.stagnation.some((s) => s.kind === "tool-loop"),
    "assembly detects the loop from the observation stream",
  );
  const assembledDirectives = directives(assembled);
  assert.ok(
    assembledDirectives.some((d) => d.priority === "mandatory"),
    "the assembled state produces a mandatory directive",
  );

  // A healthy stream assembles to silence.
  const healthyObs = [
    { tool: "nmap", hash: "a", success: true, timestamp: new Date(nowMs - 3000).toISOString() },
    { tool: "curl", hash: "b", success: true, timestamp: new Date(nowMs - 2000).toISOString() },
    { tool: "sqlmap", hash: "c", success: true, timestamp: new Date(nowMs - 1000).toISOString() },
  ];
  const healthyAssembled = assembleInvestigation({
    observations: healthyObs,
    tasks: [{ status: "completed", evidence: ["o1"], updatedAt: new Date(nowMs - 1000).toISOString() }],
    hypotheses: [mkH("H1", "testing")],
    coverage: mkCov({ total: 10, tested: 8, inProgress: 2 }),
    nowMs,
  });
  assert.deepEqual(
    directives(healthyAssembled),
    [],
    "a healthy assembled state stays silent",
  );

  fs.rmSync(ws, { recursive: true, force: true });
};
