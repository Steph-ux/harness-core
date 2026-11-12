/**
 * What a session teaches, on the OpenCode surface.
 *
 * The extractor is a model without tools: it reads the observations and
 * proposes. What it proposes still goes through the ordinary mechanisms, so a
 * proposal that is not backed by a successful observation is refused.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext, loadPlugin, unloadPlugins } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");
const PLUGIN = path.join(CORE, "opencode", "plugin.ts");

module.exports = async ({ assert, jiti }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-lessons-"));
  const state = path.join(workspace, "state");
  fs.mkdirSync(state, { recursive: true });
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;

  const plugin = jiti(PLUGIN).default;
  const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
  const { scopeFor } = jiti(path.join(CORE, "src", "util.ts"));
  const { lessonPrompt, parseLessonProposal } = jiti(
    path.join(CORE, "src", "lessons.ts"),
  );

  const knowledge = new KnowledgeStore(path.join(state, "knowledge.sqlite".replace("knowledge.sqite", "knowledge.sqlite")));
  const scope = scopeFor(workspace);

  knowledge.upsertSession({
    id: "ses_lesson",
    scope,
    cwd: workspace,
    status: "completed",
    updatedAt: new Date().toISOString(),
  });
  const good = knowledge.recordObservation({
    id: "obs-bon",
    sessionId: "ses_lesson",
    scope,
    tool: "shell",
    input: { command: "curl -s http://lab/ok" },
    output: "HTTP/1.1 200 OK\nmarqueur-stable\n",
    success: true,
    timestamp: new Date().toISOString(),
  });

  // The prompt carries the observations, and says the extractor cannot act.
  const prompt = lessonPrompt(
    {
      sessionId: "ses_lesson",
      scope,
      observations: knowledge.observationsForSession("ses_lesson", scope, 10),
    },
    6000,
  );
  assert.match(prompt, /marqueur-stable/, "the prompt carries the observations");
  assert.match(prompt, /no tools/, "the extractor is told it cannot act");
  assert.match(prompt, /untrusted data/, "the observations are told to be data");

  // Only a complete answer is kept.
  assert.throws(
    () => parseLessonProposal('{"knowledge":[],"skills":['),
    /did not answer with JSON/,
    "a truncated answer is not an answer",
  );

  const fixture = makeContext(workspace);
  await loadPlugin(plugin, fixture.ctx);
  const call = (input) =>
    fixture.tools.get("cyber_lessons").execute(input, {
      sessionID: "ses_current",
      agent: "build",
      messageID: "msg_lesson",
      id: "call_lesson",
      progress: () => {},
      signal: new AbortController().signal,
    });

  // A fact that no observation backs is refused; a fact that does is kept.
  fixture.answer.value = JSON.stringify({
    knowledge: [
      {
        key: "fait-sans-preuve",
        kind: "environment",
        content: "Un fait sans observation derriere.",
        evidence: ["obs-inexistant"],
      },
      {
        key: "fait-avec-preuve",
        kind: "environment",
        content: "La cible de laboratoire repond 200 avec un marqueur stable.",
        evidence: [good.id],
      },
    ],
    skills: [],
  });
  const outcome = JSON.parse((await call({ action: "run", sessionId: "ses_lesson" })).content);
  assert.equal(outcome.facts, 1, "only the fact with evidence is kept");
  assert.equal(
    outcome.rejected.length,
    1,
    "the fact without evidence is reported as refused",
  );
  const facts = knowledge
    .getKnowledge(scope)
    .filter((row) => row.kind !== "operator");
  assert.equal(
    facts.filter((row) => row.key === "fait-avec-preuve").length,
    1,
    "the fact with evidence is in the store",
  );
  assert.equal(
    facts.filter((row) => row.key === "fait-sans-preuve").length,
    0,
    "the fact without evidence never reached the store",
  );

  // The extraction is recorded, so the session is not read twice.
  const reviews = knowledge.reviews(scope, 10);
  assert.equal(reviews.length, 1, "the extraction is recorded as a review");
  assert.equal(reviews[0].sessionId, "ses_lesson", "the review names the session");
  assert.equal(reviews[0].status, "completed", "the extraction reached its end");
  const pending = JSON.parse((await call({ action: "pending" })).content);
  assert.ok(
    !pending.pending.includes("ses_lesson"),
    "a session already read is not waiting anymore",
  );

  // A session the host never closed is read once it has been quiet: "active"
  // forever is an abandoned session, not one in flight.
  const abandoned = new Date(Date.now() - 3 * 3600_000).toISOString();
  knowledge.upsertSession({
    id: "ses_abandoned", scope, cwd: workspace, status: "active",
    updatedAt: abandoned,
  });
  knowledge.recordObservation({
    id: "obs-abandoned", sessionId: "ses_abandoned", scope, tool: "shell",
    input: {}, output: "abandoned marker", success: true, timestamp: abandoned,
  });
  knowledge.upsertSession({
    id: "ses_fresh", scope, cwd: workspace, status: "completed",
    updatedAt: new Date().toISOString(),
  });
  knowledge.recordObservation({
    id: "obs-fresh", sessionId: "ses_fresh", scope, tool: "shell",
    input: {}, output: "fresh marker", success: true,
    timestamp: new Date().toISOString(),
  });
  const waiting = JSON.parse((await call({ action: "pending" })).content);
  assert.ok(
    waiting.pending.includes("ses_abandoned"),
    "a quiet session left active is waiting to be read",
  );
  assert.ok(
    !waiting.pending.includes("ses_fresh"),
    "a session that just ran is not read under itself",
  );
  // Two hours old: idle, so its age is not what keeps it waiting.
  knowledge.upsertSession({
    id: "ses_claim", scope, cwd: workspace, status: "completed",
    updatedAt: new Date(Date.now() - 2 * 3600_000).toISOString(),
  });
  knowledge.recordObservation({
    id: "obs-claim", sessionId: "ses_claim", scope, tool: "shell", input: {},
    output: "claim marker", success: true, timestamp: new Date().toISOString(),
  });
  fixture.answer.value = JSON.stringify({
    verdict: "confirmed", reason: "marker observed", evidence: ["obs-claim"],
  });
  await fixture.tools.get("cyber_review").execute(
    { action: "run", claim: "the marker exists", observationIds: ["obs-claim"] },
    { sessionID: "ses_claim", agent: "build", messageID: "msg-claim", id: "call-claim", signal: new AbortController().signal },
  );
  // Two hours old: idle, so its age is not what keeps it waiting.
  knowledge.upsertSession({
    id: "ses_claim", scope, cwd: workspace, status: "completed",
    updatedAt: new Date(Date.now() - 2 * 3600_000).toISOString(),
  });
  const afterClaimReview = JSON.parse((await call({ action: "pending" })).content);
  assert.ok(
    afterClaimReview.pending.includes("ses_claim"),
    "checking a claim does not mark the session lessons as extracted",
  );

  // The extractor proposed nothing it could not show: it never called a tool.
  assert.equal(
    fixture.generated.filter((entry) =>
      /you have no tools/i.test(String(entry.prompt)),
    ).length >= 1,
    true,
    "the extractor was called without tools",
  );

  // A provider that refuses a direct call does not stop the loop: the next
  // candidate answers, so the work is still read.
  knowledge.upsertSession({
    id: "ses_fallback", scope, cwd: workspace, status: "completed",
    updatedAt: new Date().toISOString(),
  });
  const fallbackProof = knowledge.recordObservation({
    id: "obs-fallback", sessionId: "ses_fallback", scope, tool: "shell",
    input: {}, output: "fallback marker", success: true,
    timestamp: new Date().toISOString(),
  });
  fixture.answer.value = JSON.stringify({
    knowledge: [
      {
        key: "fait-apres-refus",
        kind: "environment",
        content: "Le modele suivant a repondu apres un refus du fournisseur.",
        evidence: [fallbackProof.id],
      },
    ],
    skills: [],
  });
  // The second provider is the one that answers once the first refuses.
  fixture.models = [
    { providerID: "opencode", id: "beam-free" },
    { providerID: "Ed", id: "glm-5.3-flash" },
    { providerID: "test", id: "second-opinion" },
  ];
  fixture.failing.add("Ed/glm-5.3-flash");
  const fallback = JSON.parse(
    (await call({ action: "run", sessionId: "ses_fallback" })).content,
  );
  assert.equal(fallback.facts, 1, "the extraction still produced its fact");
  assert.equal(
    fixture.generated.some(
      (entry) => entry.model?.providerID === "Ed" && entry.model?.id === "glm-5.3-flash",
    ),
    true,
    "the refused provider was tried",
  );
  assert.equal(
    fixture.generated.some(
      (entry) => entry.model?.providerID === "test" && entry.model?.id === "second-opinion",
    ),
    true,
    "the next candidate answered the extraction",
  );
  fixture.failing.clear();

  // The operator can pin the model that serves the harness, including one the
  // default order leaves out.
  knowledge.upsertSession({
    id: "ses_pinned", scope, cwd: workspace, status: "completed",
    updatedAt: new Date().toISOString(),
  });
  const pinnedProof = knowledge.recordObservation({
    id: "obs-pinned", sessionId: "ses_pinned", scope, tool: "shell",
    input: {}, output: "pinned marker", success: true,
    timestamp: new Date().toISOString(),
  });
  fixture.answer.value = JSON.stringify({
    knowledge: [
      {
        key: "fait-epingle",
        kind: "environment",
        content: "Le modele epingle a repondu a l extraction.",
        evidence: [pinnedProof.id],
      },
    ],
    skills: [],
  });
  process.env.HARNESS_VERIFIER = "opencode/beam-free";
  const beforePinned = fixture.generated.length;
  const pinned = JSON.parse(
    (await call({ action: "run", sessionId: "ses_pinned" })).content,
  );
  const firstPinned = fixture.generated[beforePinned]?.model;
  delete process.env.HARNESS_VERIFIER;
  assert.equal(pinned.facts, 1, "the pinned model served the extraction");
  assert.equal(
    firstPinned?.providerID,
    "opencode",
    "the pinned model is tried before the configured providers",
  );
  assert.equal(firstPinned?.id, "beam-free", "the pinned model is the one named");

  // Without the environment, the choice survives in the state directory.
  knowledge.upsertSession({
    id: "ses_pinned_file", scope, cwd: workspace, status: "completed",
    updatedAt: new Date().toISOString(),
  });
  const fileProof = knowledge.recordObservation({
    id: "obs-pinned-file", sessionId: "ses_pinned_file", scope, tool: "shell",
    input: {}, output: "pinned file marker", success: true,
    timestamp: new Date().toISOString(),
  });
  fixture.answer.value = JSON.stringify({
    knowledge: [
      {
        key: "fait-epingle-fichier",
        kind: "environment",
        content: "Le modele epingle par fichier a repondu.",
        evidence: [fileProof.id],
      },
    ],
    skills: [],
  });
  fs.writeFileSync(path.join(state, "verifier"), "test/second-opinion\n");
  const beforeFile = fixture.generated.length;
  const fromFile = JSON.parse(
    (await call({ action: "run", sessionId: "ses_pinned_file" })).content,
  );
  const firstFile = fixture.generated[beforeFile]?.model;
  fs.rmSync(path.join(state, "verifier"));
  assert.equal(fromFile.facts, 1, "the model named by the file served the extraction");
  assert.equal(
    firstFile?.id,
    "second-opinion",
    "the pin from the state directory is tried first",
  );

  knowledge.close();
  await unloadPlugins();
  fs.rmSync(workspace, { recursive: true, force: true });
};
