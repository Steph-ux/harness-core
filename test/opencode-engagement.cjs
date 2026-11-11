/**
 * An engagement driven by OpenCode, on the same proof as the Pi harness.
 *
 * The scope is a gate, the stages are ordered, a finding is anchored on
 * observations, and it stays unverified until an independent verification
 * stage says otherwise.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext, loadPlugin, unloadPlugins } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");
const PLUGIN = path.join(CORE, "opencode", "plugin.ts");

module.exports = async ({ assert, jiti }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-engagement-"));
  const state = path.join(workspace, "state");
  fs.mkdirSync(state, { recursive: true });
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;

  const plugin = jiti(PLUGIN).default;
  const { KnowledgeStore } = jiti(path.join(CORE, "src", "store.ts"));
  const { PlatformStore } = jiti(path.join(CORE, "src", "platform-store.ts"));
  const { scopeFor } = jiti(path.join(CORE, "src", "util.ts"));

  const knowledge = new KnowledgeStore(path.join(state, "knowledge.sqlite"));
  const platform = new PlatformStore(
    path.join(state, "platform.sqlite"),
    knowledge,
  );
  const scope = scopeFor(workspace);

  knowledge.upsertSession({
    id: "ses_eng",
    scope,
    cwd: workspace,
    status: "completed",
    updatedAt: new Date().toISOString(),
  });
  const observation = (id, output, success = true) =>
    knowledge.recordObservation({
      id,
      sessionId: "ses_eng",
      scope,
      tool: "shell",
      input: { command: id },
      output,
      success,
      timestamp: new Date().toISOString(),
    });
  const recon = observation("obs-recon", "recon done\n");
  const reproduction = observation("obs-repro", "XSS confirmed in /profile\n");
  // The control observes a benign input: a different output, or it would
  // prove nothing. It carries the same marker so the finding can cite it.
  const control = observation("obs-control", "XSS confirmed marker\n");
  let verification;

  const fixture = makeContext(workspace);
  await loadPlugin(plugin, fixture.ctx);
  assert.ok(fixture.tools.has("cyber_mission"), "the engagement is driven by a tool");
  assert.ok(fixture.tools.has("cyber_finding"), "the ledger is a tool");

  const mission = (input) =>
    fixture.tools.get("cyber_mission").execute(input, {
      sessionID: "ses_eng",
      agent: "build",
      messageID: "msg_eng",
      id: "call_eng",
      progress: () => {},
      signal: new AbortController().signal,
    });
  const finding = (input) =>
    fixture.tools.get("cyber_finding").execute(input, {
      sessionID: "ses_eng",
      agent: "build",
      messageID: "msg_eng",
      id: "call_eng",
      progress: () => {},
      signal: new AbortController().signal,
    });

  // The engagement is declared with its boundaries.
  const created = JSON.parse(
    (
      await mission({
        action: "create",
        title: "Engagement de test",
        boundaries: "Cible: 10.0.0.1. Hors perimetre: tout le reste.",
      })
    ).content,
  );
  assert.ok(created.id, "the engagement has an id");
  const id = created.id;

  // The scope gate is closed until the operator opens it.
  const scopeNode = created.nodes.find(
    (node) => node.id === "scope-validation",
  );
  assert.equal(
    scopeNode.state,
    "WAITING_APPROVAL",
    "the scope waits for the operator",
  );
  await assert.rejects(
    () => mission({ action: "claim", node: "recon", owner: "recon-agent" }),
    /Node not ready/,
    "nothing is dispatched before the scope is approved",
  );

  // The approval opens it.
  await mission({ action: "approve-scope", id });
  const afterApproval = JSON.parse(
    (await mission({ action: "status", id })).content,
  );
  assert.equal(
    afterApproval.mission.nodes.find((node) => node.id === "scope-validation")
      .state,
    "COMPLETED",
    "the scope is approved",
  );

  // The stages are ordered.
  const lease = JSON.parse(
    (await mission({ action: "claim", node: "recon", owner: "recon-agent" }))
      .content,
  );
  assert.ok(lease, "the stage is taken with a lease");
  await assert.rejects(
    () => mission({ action: "claim", node: "analysis", owner: "analysis-agent" }),
    /Node not ready/,
    "a stage whose dependency is not closed cannot be taken",
  );
  await mission({
    action: "finish",
    node: "recon",
    lease,
    results: [
      {
        role: "recon-agent",
        status: "completed",
        summary: "Reconnaissance faite",
        observationIds: [recon.id],
      },
    ],
  });
  await assert.rejects(
    () =>
      mission({
        action: "finish",
        node: "recon",
        lease,
        results: [
          {
            role: "recon-agent",
            status: "completed",
            summary: "Encore",
            observationIds: [recon.id],
          },
        ],
      }),
    /lease/i,
    "a stage cannot be closed twice with the same lease",
  );

  // A source is what a finding cites.
  const chunks = platform.ingest(
    scope,
    "src-1",
    "https://cible.test/page",
    "Page de profil",
    "Le champ name est reflecte dans la reponse.",
  );
  assert.ok(chunks.length > 0, "the source is cut into chunks");

  // A finding is anchored on observations, and stays unverified.
  const proposal = {
    action: "create",
    missionId: id,
    title: "XSS reflected",
    severity: "high",
    description: "Le parametre revient dans la reponse.",
    limitations: "Non teste sur les autres pages.",
    evidence: [reproduction.id, control.id],
    sources: [chunks[0].id],
    checks: [
      {
        observationId: reproduction.id,
        contains: "XSS confirmed",
        purpose: "reproduction",
      },
      {
        observationId: control.id,
        contains: "XSS confirmed",
        purpose: "negative-control",
      },
    ],
  };
  await assert.rejects(
    () => finding({ ...proposal, evidence: ["obs-does-not-exist"] }),
    /Missing evidence/,
    "a finding cannot cite an observation that does not exist",
  );
  await assert.rejects(
    () =>
      finding({
        ...proposal,
        checks: [
          {
            observationId: reproduction.id,
            contains: "absent de la sortie",
            purpose: "reproduction",
          },
        ],
      }),
    /lacks observed evidence/,
    "a check that the output does not carry is refused",
  );
  // A negative control proves the procedure does not fire on a benign
  // input. It must observe a different output than the reproduction: the
  // same output would be both the claim and its refutation.
  await assert.rejects(
    () =>
      finding({
        ...proposal,
        checks: [
          {
            observationId: reproduction.id,
            contains: "XSS confirmed",
            purpose: "reproduction",
          },
          {
            observationId: reproduction.id,
            contains: "XSS confirmed",
            purpose: "negative-control",
          },
        ],
      }),
    /must observe a different output/,
    "a negative control cannot reuse the reproduction's observation",
  );
  // The twin: another observation, the same output. The control proves
  // nothing either, so it is refused.
  const twin = observation("obs-twin", "XSS confirmed in /profile\n");
  await assert.rejects(
    () =>
      finding({
        ...proposal,
        evidence: [reproduction.id, twin.id],
        checks: [
          {
            observationId: reproduction.id,
            contains: "XSS confirmed",
            purpose: "reproduction",
          },
          {
            observationId: twin.id,
            contains: "XSS confirmed",
            purpose: "negative-control",
          },
        ],
      }),
    /must observe a different output/,
    "a negative control cannot replay the same output under another observation",
  );
  // A request that routes to a method must load it before a finding is
  // recorded: the harness does not take the model's memory for a procedure.
  const routed = fixture.contextEvent({
    sessionID: "ses_eng",
    messages: [
      {
        info: { role: "user" },
        parts: [
          {
            type: "text",
            text: "the JWT alg header is none, can I forge an admin token?",
          },
        ],
      },
    ],
  });
  await fixture.hooks.get("context")(routed);
  assert.ok(
    routed.system.some((block) =>
      String(block.text).startsWith("Harness routing."),
    ),
    "the turn is routed to the method that covers it",
  );
  await assert.rejects(
    () => finding(proposal),
    /covers this request and none of them was loaded/,
    "a finding for a routed request needs the method loaded in the session",
  );
  // The host hands the context hook no request text, so the ledger routes on
  // the finding's own content: a JWT claim still needs the token method.
  await assert.rejects(
    () =>
      finding({
        ...proposal,
        title: "JWT alg none accepted",
        description: "The API accepts a token whose header claims alg none.",
      }),
    /covers this request and none of them was loaded/,
    "a finding whose content routes to a method needs that method loaded",
  );

  // Loading the method is what unblocks the ledger.
  await fixture.hooks.get("execute.after")({
    tool: "skill",
    sessionID: "ses_eng",
    id: "call-skill",
    status:"completed",
    input: { id: "harness-jwt" },
    result: { output: "skill content" },
  });
  const createdFinding = JSON.parse((await finding(proposal)).content);
  assert.equal(createdFinding.status, "unverified", "a finding starts unverified");
  assert.ok(
    createdFinding.confidence <= 0.75,
    "the confidence of a finding is bounded",
  );
  await assert.rejects(
    () => finding({ action: "verify", id: createdFinding.id }),
    /Independent verification-stage evidence is required/,
    "a finding cannot be verified before the verification stage",
  );

  // The verification stage is independent, and it links the findings.
  for (const [node, role] of [
    ["enumeration", "recon-agent"],
    ["analysis", "recon-agent"],
  ]) {
    const taken = JSON.parse(
      (await mission({ action: "claim", node, owner: role })).content,
    );
    await mission({
      action: "finish",
      node,
      lease: taken,
      results: [
        {
          role,
          status: "completed",
          summary: `${node} fait`,
          observationIds: [recon.id],
        },
      ],
    });
  }
  knowledge.upsertSession({id:"ses_independent",scope,cwd:workspace,status:"active",updatedAt:new Date().toISOString()});
  // Each verification control observes its own output: the control has to
  // differ from the reproduction it refutes, as the finding's own control
  // does. The marker each one carries is the one the finding declared.
  const checks=proposal.checks.map((check,index)=>{const id=`obs-independent-${index}`;knowledge.recordObservation({id,sessionId:"ses_independent",scope,tool:"shell",input:{},output:check.purpose==="negative-control"?`${check.contains} (control)`:check.contains,success:true,timestamp:new Date().toISOString()});return {...check,observationId:id};});
  verification=JSON.parse((await fixture.tools.get("cyber_verification").execute({action:"attest",findingId:createdFinding.id,checks},{sessionID:"ses_independent",agent:"build",messageID:"msg_verify",id:"call_verify"})).content);
  const validationLease = JSON.parse(
    (
      await mission({
        action: "claim",
        node: "validation",
        owner: "verification-agent",
        findingIds: [createdFinding.id],
      })
    ).content,
  );
  // The stage reports its proof as observation ids. That is evidence: the
  // checkpoint must keep it, or a verification stage looks empty while it is
  // not, and no finding could ever be verified.
  await mission({
    action: "finish",
    node: "validation",
    lease: validationLease,
    results: [
      {
        role: "verification-agent",
        status: "completed",
        summary: "Verification independante",
        observationIds: [verification.id],
      },
    ],
  });
  const stage = platform.mission(scope, id).nodes.find(
    (node) => node.id === "validation",
  );
  assert.ok(
    Array.isArray(stage.result) && stage.result[0].evidence.includes(verification.id),
    "the stage keeps the observation ids as evidence",
  );

  // The verification needs an observation that is not the finding's own.
  await assert.rejects(
    () => finding({ action: "verify", id: createdFinding.id }),
    /Choose an independent verification observation/,
    "the finding cannot be verified with its own evidence",
  );
  const verified = JSON.parse(
    (
      await finding({
        action: "verify",
        id: createdFinding.id,
        verificationId: verification.id,
      })
    ).content,
  );
  assert.equal(verified.status, "verified", "the finding is verified");

  // The checkpoints are the history of the engagement.
  const checkpoints = JSON.parse(
    (await mission({ action: "checkpoints", id })).content,
  );
  assert.ok(
    checkpoints.length >= 4,
    "the engagement keeps a checkpoint per stage",
  );
  assert.ok(
    checkpoints.some((entry) => entry.nodeId === "scope-validation"),
    "the approval is part of the history",
  );

  // The approval queue: an action that waits for the operator waits.
  const approval = (input) =>
    fixture.tools.get("cyber_approval").execute(input, {
      sessionID: "ses_eng",
      agent: "build",
      messageID: "msg_eng",
      id: "call_eng",
      progress: () => {},
      signal: new AbortController().signal,
    });
  await assert.rejects(
    () =>
      approval({
        action: "request",
        missionId: id,
        requestedAction: "Broadcast deauth",
      }),
    /why it needs the operator/,
    "an approval without its reason is refused",
  );
  const pending = JSON.parse(
    (
      await approval({
        action: "request",
        missionId: id,
        requestedAction: "Broadcast deauth sur le reseau de test",
        justification: "Degrade le reseau pour les autres utilisateurs.",
        requestedBy: "wireless-ble",
      })
    ).content,
  );
  assert.equal(pending.status, "pending", "the action waits for the operator");
  const queue = JSON.parse((await approval({ action: "list" })).content);
  assert.equal(queue.length, 1, "the queue holds the waiting action");
  fixture.ctx.permission.explicit = async () => "reject";
  await assert.rejects(
    () => approval({ action: "decide", id: pending.id, approve: true, decidedBy: "operator" }),
    /explicit operator decision/,
    "the agent cannot manufacture an operator decision",
  );
  fixture.ctx.permission.explicit = async () => "once";
  const decided = JSON.parse(
    (
      await approval({
        action: "decide",
        id: pending.id,
        approve: true,
        decidedBy: "operator",
      })
    ).content,
  );
  assert.equal(decided.status, "approved", "the decision is written down");
  assert.equal(decided.decidedBy, "operator", "the decision names who took it");
  await assert.rejects(
    () =>
      approval({
        action: "decide",
        id: pending.id,
        approve: false,
        decidedBy: "operator",
      }),
    /already decided/,
    "an approval cannot be decided twice",
  );

  // The same state, read from the store the Pi harness uses.
  assert.equal(
    platform.mission(scope, id).nodes.find(
      (node) => node.id === "scope-validation",
    ).state,
    "COMPLETED",
    "the engagement is in the shared ledger",
  );

  knowledge.close();
  platform.close();
  await unloadPlugins();
  fs.rmSync(workspace, { recursive: true, force: true });
};
