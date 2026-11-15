const path = require("node:path");

const CORE = path.resolve(__dirname, "..");

module.exports = async ({ assert, jiti }) => {
  const {
    TECHNIQUES,
    TECHNIQUE_PHASES,
    techniqueCard,
    techniqueCards,
    techniqueGaps,
    techniqueTable,
  } = jiti(path.join(CORE, "src", "techniques.ts"));
  const { EXTERNAL_METHODS, HOST_METHODS, SHIPPED_METHODS } = jiti(
    path.join(CORE, "src", "routing.ts"),
  );

  const methods = new Set([
    ...EXTERNAL_METHODS,
    ...HOST_METHODS,
    ...SHIPPED_METHODS,
  ]);
  const ids = TECHNIQUES.map((card) => card.id);

  assert.equal(new Set(ids).size, ids.length, "technique ids are unique");
  assert.ok(TECHNIQUES.length >= 40, "the registry covers every routed method");

  for (const card of TECHNIQUES) {
    assert.match(card.id, /^T-[A-Z0-9-]+$/, `${card.id} has a stable id`);
    assert.ok(
      TECHNIQUE_PHASES.includes(card.phase),
      `${card.id} names a known phase`,
    );
    assert.ok(card.name.length > 3, `${card.id} names its technique`);
    for (const field of ["precondition", "provedBy", "control", "stop", "detection"])
      assert.ok(
        typeof card[field] === "string" && card[field].trim().length > 10,
        `${card.id} states its ${field}`,
      );
    for (const tool of card.tools)
      assert.doesNotMatch(
        tool,
        /[\s/]|:\/\/|\d+\.\d+\.\d+\.\d+/,
        `${card.id} names a tool family, not a host or a command line`,
      );
    if (card.status === "carded") {
      assert.ok(card.owner, `${card.id} is carded only with an owner`);
      assert.ok(
        methods.has(card.owner),
        `${card.id} owner ${card.owner} is a declared method`,
      );
    } else {
      assert.equal(card.owner, null, `${card.id} has no owner by definition`);
      assert.ok(
        ["gap", "not-covered"].includes(card.status),
        `${card.id} declares a known status`,
      );
    }
  }

  // The contract that makes the registry worth having: no routed method exists
  // without a card that says how it is executed and how it is proven.
  const owners = new Set(
    TECHNIQUES.filter((card) => card.status === "carded").map((card) => card.owner),
  );
  for (const method of EXTERNAL_METHODS)
    assert.ok(owners.has(method), `${method} has a technique card`);

  assert.equal(techniqueCard("T-JWT").owner, "harness-jwt");
  assert.throws(() => techniqueCard("T-NOPE"), /Unknown technique card/);
  assert.equal(techniqueCards("recon").length > 5, true);
  assert.throws(() => techniqueCards("nope"), /Unknown technique phase/);
  assert.deepEqual(
    techniqueGaps().map((card) => card.id).sort(),
    ["T-C2", "T-DOS", "T-EVASION", "T-EXFIL", "T-PERSIST", "T-SOCIAL"],
    "the registry names its gaps instead of silently omitting them",
  );
  assert.equal(techniqueTable().split("\n").length, TECHNIQUES.length);
};
