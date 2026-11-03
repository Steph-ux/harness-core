/**
 * The learned methods, on the OpenCode surface.
 *
 * A method is learned from the work: it needs evidence, it is activated by a
 * successful observation, a later correction replaces it, and a method nobody
 * used is archived. An active method is served as a skill.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");
const PLUGIN = path.join(CORE, "opencode", "plugin.ts");

module.exports = async ({ assert, jiti }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-methods-"));
  const state = path.join(workspace, "state");
  fs.mkdirSync(state, { recursive: true });
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;

  const plugin = jiti(PLUGIN).default;
  const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
  const { SkillUpdater } = jiti(path.join(CORE, "src", "skills.ts"));
  const { scopeFor } = jiti(path.join(CORE, "src", "util.ts"));
  const { DEFAULT_CONFIG } = jiti(path.join(CORE, "src", "types.ts"));

  const store = new KnowledgeStore(path.join(state, "knowledge.sqlite"));
  const skills = new SkillUpdater(state, store, DEFAULT_CONFIG);
  const scope = scopeFor(workspace);

  for (const session of ["ses_a", "ses_b", "ses_c"]) {
    store.upsertSession({
      id: session,
      scope,
      cwd: workspace,
      status: "completed",
      updatedAt: new Date().toISOString(),
    });
  }
  const good = store.recordObservation({
    id: "obs-good",
    sessionId: "ses_a",
    scope,
    tool: "shell",
    input: { command: "echo marker" },
    output: "marker found\n",
    success: true,
    timestamp: new Date().toISOString(),
  });
  const bad = store.recordObservation({
    id: "obs-bad",
    sessionId: "ses_b",
    scope,
    tool: "shell",
    input: { command: "echo marker" },
    output: "nothing\n",
    success: false,
    timestamp: new Date().toISOString(),
  });
  // Activation needs support from distinct sessions: one session is an anecdote.
  const good2 = store.recordObservation({
    id: "obs-good-2",
    sessionId: "ses_c",
    scope,
    tool: "shell",
    input: { command: "echo marker" },
    output: "marker found\n",
    success: true,
    timestamp: new Date().toISOString(),
  });

  const method = {
    name: "verifier-un-marqueur",
    description: "Chercher un marqueur dans la sortie avant de conclure.",
    category: "investigation-patterns",
    prerequisites: [],
    procedure: [
      "Lancer la commande qui produit le marqueur.",
      "Verifier que la sortie contient le marqueur.",
    ],
    validation: [{ observationId: good.id, contains: "marker found" }],
    evidence: [good.id, good2.id],
  };

  // A method needs evidence: an unresolved failure is not a method.
  assert.throws(
    () =>
      skills.propose(scope, {
        ...method,
        name: "methode-echouee",
        evidence: [bad.id],
        validation: [{ observationId: bad.id, contains: "nothing" }],
      }),
    /Unresolved failure is not a method/,
    "a method that only failed is not a method",
  );

  // A method must say how it is checked.
  assert.throws(
    () =>
      skills.propose(scope, {
        ...method,
        name: "methode-sans-controle",
        validation: [],
      }),
    /Observed validation is required/,
    "a method without a check is refused",
  );

  // Successful observations from two distinct sessions activate the method.
  const active = skills.propose(scope, method);
  assert.equal(active.status, "active", "two sessions of success activate a method");
  assert.equal(active.version, 1, "the first version is version 1");
  assert.deepEqual(
    active.evidence,
    [good.id, good2.id],
    "the method keeps its evidence",
  );

  // One session is not support: the same method with one session stays a
  // candidate, which is what stops an anecdote from becoming a rule.
  const anecdote = skills.propose(scope, {
    ...method,
    name: "methode-anecdotique",
    evidence: [good.id],
  });
  assert.equal(
    anecdote.status,
    "candidate",
    "a single session is not support",
  );

  // A failure keeps it a candidate.
  const candidate = skills.propose(scope, {
    ...method,
    name: "methode-douteuse",
    evidence: [good.id, bad.id],
    validation: [{ observationId: good.id, contains: "marker found" }],
  });
  assert.equal(
    candidate.status,
    "candidate",
    "a method with a failure stays a candidate",
  );

  // A later correction replaces the method.
  const corrected = skills.propose(scope, {
    ...method,
    description: "Chercher un marqueur dans la sortie, puis le confirmer deux fois.",
    procedure: [
      "Lancer la commande qui produit le marqueur.",
      "Verifier que la sortie contient le marqueur.",
      "Relancer pour confirmer.",
    ],
  });
  assert.equal(corrected.version, 2, "the correction is a new version");
  assert.equal(corrected.status, "active", "the correction is active");
  const listed = skills.list(scope);
  const versions = listed.filter((row) => row.name === method.name);
  assert.equal(versions.length, 1, "the method appears once, at its last version");
  assert.equal(versions[0].version, 2, "the last version is the one kept");

  // A method the operator states keeps the evidence, but is not held to the
  // discipline of a reusable method: it is taken as given.
  const stated = skills.propose(
    scope,
    {
      ...method,
      name: "methode-ouverte",
      procedure: ["Toujours verifier la sortie avant de conclure."],
    },
    "l operateur l a enonce",
  );
  assert.equal(stated.status, "active", "a method the operator states is active");
  assert.equal(
    store
      .audits(scope, "skill.operator-priority", 10)
      .some((row) => row.detail.includes("methode-ouverte")),
    true,
    "the operator statement is recorded",
  );

  // A diary is not a method.
  assert.throws(
    () =>
      skills.propose(scope, {
        ...method,
        name: "methode-narrative",
        description: "On a essaye plusieurs approches pendant cette session.",
        evidence: [good.id],
        validation: [],
      }),
    /not a session narrative/,
    "a session narrative is not a method",
  );

  // The plugin serves the active methods as skills.
  const fixture = makeContext(workspace);
  await plugin.setup(fixture.ctx);
  assert.ok(fixture.tools.has("cyber_method"), "the plugin exposes the methods");
  const served = [...fixture.skills.values()];
  const learned = served.filter((skill) =>
    String(skill.id).startsWith("harness.learned."),
  );
  assert.ok(learned.length >= 2, "the active methods are served as skills");
  const verifier = learned.find(
    (skill) => skill.id === "harness.learned.verifier-un-marqueur",
  );
  assert.ok(verifier, "the learned method is served");
  assert.match(
    verifier.content,
    /marqueur/,
    "the served method carries its procedure",
  );
  assert.ok(
    !learned.some((skill) => skill.id === "harness.learned.methode-douteuse"),
    "a candidate is not served",
  );
  await fixture.tools.get("cyber_method").execute({
    action: "propose",
    name: "methode-apres-demarrage",
    description: "Verify a marker after plugin startup.",
    category: "investigation-patterns",
    procedure: ["Read the marker.", "Confirm its exact value."],
    evidence: [good.id, good2.id],
    validation: [{ observationId: good.id, contains: "marker found" }],
  }, {
    sessionID: "ses_a", agent: "build", messageID: "msg-method", id: "call-method",
    signal: new AbortController().signal,
  });
  assert.ok(
    fixture.skills.has("harness.learned.methode-apres-demarrage"),
    "a method promoted after startup is served without reloading the plugin",
  );

  // A method nobody used is archived.
  const old = new Date(Date.now() - 90 * 86_400_000).toISOString();
  const oldGood = store.recordObservation({
    id: "obs-old",
    sessionId: "ses_a",
    scope,
    tool: "shell",
    input: { command: "echo marker" },
    output: "marker found\n",
    success: true,
    timestamp: old,
  });
  const oldGood2 = store.recordObservation({
    id: "obs-old-2",
    sessionId: "ses_c",
    scope,
    tool: "shell",
    input: { command: "echo marker" },
    output: "marker found\n",
    success: true,
    timestamp: old,
  });
  skills.propose(scope, {
    ...method,
    name: "methode-obsolete",
    evidence: [oldGood.id, oldGood2.id],
    validation: [{ observationId: oldGood.id, contains: "marker found" }],
  });
  const archived = skills.archiveUnused(scope, [
    {
      detail: JSON.stringify({ skills: [{ name: "methode-obsolete" }] }),
      timestamp: old,
    },
  ]);
  assert.ok(
    archived.includes("methode-obsolete"),
    "a method nobody used is archived",
  );
  assert.equal(
    skills.active(scope).some((entry) => entry.revision.name === "methode-obsolete"),
    false,
    "an archived method is no longer active",
  );
  assert.equal(
    skills.active(scope).some(
      (entry) => entry.revision.name === "verifier-un-marqueur",
    ),
    true,
    "a method that was just verified is kept",
  );

  // A method crosses to every project; its evidence stays behind.
  const otherDir = fs.mkdtempSync(path.join(os.tmpdir(), "harness-methods-other-"));
  const otherScope = scopeFor(otherDir);
  store.upsertSession({
    id: "ses_other", scope: otherScope, cwd: otherDir, status: "completed",
    updatedAt: new Date().toISOString(),
  });
  assert.equal(
    skills.list(otherScope).some((row) => row.name === "verifier-un-marqueur"),
    false,
    "a project method is not visible from another project",
  );
  assert.throws(
    () => skills.promote(scope, "methode-douteuse"),
    /Only an active method can be promoted/,
    "a candidate is not promoted",
  );
  const shared = skills.promote(scope, "verifier-un-marqueur");
  assert.equal(shared.scope, "global", "the promoted method leaves the project");
  assert.equal(shared.status, "active", "a promoted method is active");
  assert.deepEqual(shared.evidence, [], "the evidence stays in the project");
  assert.deepEqual(
    shared.promotedFrom,
    [scope],
    "the promotion names the project it came from",
  );
  assert.equal(
    skills.list(otherScope).some((row) => row.name === "verifier-un-marqueur"),
    true,
    "the shared method is visible from another project",
  );
  assert.equal(
    skills.load(otherScope, "verifier-un-marqueur").content.includes("marqueur"),
    true,
    "another project can read the shared method",
  );
  assert.equal(
    skills.active(otherScope).some(
      (entry) => entry.filePath.includes(`learned-global-verifier-un-marqueur`),
    ),
    true,
    "the shared method is served from the global tree",
  );
  assert.equal(
    skills.promote(scope, "verifier-un-marqueur").version,
    shared.version,
    "promoting the same method twice does not create a version",
  );
  // A project that sees the method through the global scope has nothing to
  // promote, and saying so must not look like a refusal.
  const seenElsewhere = skills.promote(otherScope, "verifier-un-marqueur");
  assert.equal(seenElsewhere.scope, "global", "the shared method is returned");
  assert.equal(seenElsewhere.version, shared.version, "no version is created");
  assert.equal(
    store
      .audits(scope, "skill.promoted", 10)
      .some((row) => row.detail.includes("verifier-un-marqueur")),
    true,
    "the promotion is audited in the project it came from",
  );

  // A method that names its target stays where the target is.
  skills.propose(scope, {
    ...method,
    name: "methode-locale",
    description: "Appeler l hote local api.exemple.test et lire la reponse.",
    procedure: [
      "Appeler api.exemple.test avec la charge utile.",
      "Lire le code de reponse.",
    ],
  });
  assert.equal(
    skills.list(otherScope).some((row) => row.name === "methode-locale"),
    false,
    "a method that names a host is not shared",
  );
  assert.throws(
    () => skills.promote(scope, "methode-locale"),
    /cannot name a host/,
    "the promotion of a method that names a host is refused",
  );

  // Through the tool, so the surface the model uses is the one tested.
  await fixture.tools.get("cyber_method").execute(
    { action: "promote", name: "verifier-un-marqueur" },
    {
      sessionID: "ses_a", agent: "build", messageID: "msg-promote", id: "call-promote",
      signal: new AbortController().signal,
    },
  );
  assert.equal(
    fixture.skills.has("harness.learned.verifier-un-marqueur"),
    true,
    "a promoted method is still served after the promotion",
  );
  await assert.rejects(
    () =>
      fixture.tools.get("cyber_method").execute(
        { action: "promote", name: "methode-locale" },
        {
          sessionID: "ses_a", agent: "build", messageID: "msg-promote-2",
          id: "call-promote-2", signal: new AbortController().signal,
        },
      ),
    /cannot name a host/,
    "the tool refuses to share a method that names its target",
  );
  fs.rmSync(otherDir, { recursive: true, force: true });

  store.close();
  fs.rmSync(workspace, { recursive: true, force: true });
};
