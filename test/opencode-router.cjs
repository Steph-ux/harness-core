/**
 * A catalogue of skills is inert; a route is a decision.
 *
 * The request must be mapped to the method that covers it by the harness, from
 * the request text alone, with no model call and a bounded block.
 */
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { makeContext } = require("./opencode-fixture.cjs");

const CORE = path.resolve(__dirname, "..");
const PLUGIN = path.join(CORE, "opencode", "plugin.ts");

module.exports = async ({ assert, jiti }) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "harness-routing-"));
  const state = path.join(workspace, "state");
  fs.mkdirSync(state, { recursive: true });
  process.env.HARNESS_STATE_ROOT = state;
  process.env.HARNESS_CORE = CORE;

  const { ROUTES, ROUTER_MARKER, routeFor, routingTable, requestText } = jiti(
    path.join(CORE, "src", "routing.ts"),
  );

  // The matcher selects the method, not the loudest word.
  const jwt = routeFor("the JWT alg header is none, can I forge an admin token?");
  assert.ok(jwt.ids.includes("token"), "a token request routes to the token method");
  assert.equal(jwt.ids.length, 1, "one method, not a library");
  assert.match(jwt.block, /harness-jwt/, "the matched skill is named in the block");
  assert.ok(jwt.block.length <= 900, "a matched block stays a decision");
  assert.ok(
    jwt.required.includes("harness-jwt"),
    "the token row carries the evidence format: its skill must be loaded",
  );
  assert.deepEqual(
    routeFor("map the attack surface of the domain, subdomain first").required,
    [],
    "a recon row names a skill but does not gate a finding on it",
  );

  const ssrf = routeFor("blind SSRF on the image proxy, how do I see the callback?");
  assert.ok(ssrf.ids.includes("web-deep"), "ssrf routes to the deep web method");

  const recon = routeFor("map the attack surface of the domain, subdomain first");
  assert.ok(recon.ids.includes("recon"), "recon routes to the surface method");

  // No signal means the map, never a guess.
  const none = routeFor("bonjour, comment vas-tu aujourd'hui");
  assert.deepEqual(none.ids, [], "a request with no signal matches no row");
  assert.match(none.block, /^Harness routing\./, "the table is the fallback");
  assert.ok(routingTable().length <= 2000, "the table is bounded");

  // A short keyword must not fire inside a longer word.
  const capital = routeFor("the capital of the country is unknown");
  assert.ok(!capital.ids.includes("api"), "boundary matching keeps 'api' out of 'capital'");

  // One incidental word inside a pasted document is not a request for a method.
  const pasted = routeFor(
    "| ASN | Nom | Rôle | IPs v4 |\n" + "ligne de tableau sans consigne\n".repeat(40),
  );
  assert.deepEqual(
    pasted.ids,
    [],
    "a single hit inside a long document does not force a skill",
  );
  assert.match(pasted.block, /^Harness routing\./, "the map is still there");

  // Every skill named by a route must exist: on disk, or shipped by the host.
  const BUILTIN_SKILLS = new Set(["opencode"]);
  const skillsDir = path.join(os.homedir(), ".config", "opencode", "skills");
  if (fs.existsSync(skillsDir)) {
    const entries = new Set(fs.readdirSync(skillsDir));
    for (const route of ROUTES) {
      for (const skill of route.skills) {
        assert.ok(
          BUILTIN_SKILLS.has(skill) || entries.has(skill) || entries.has(`${skill}.md`),
          `route ${route.id} names a skill that exists: ${skill}`,
        );
      }
    }
  }

  // The host shapes the request text can arrive in.
  assert.equal(
    requestText({
      messages: [{ info: { role: "user" }, parts: [{ type: "text", text: "check this graphql endpoint" }] }],
    }),
    "check this graphql endpoint",
    "the request is read from the host messages",
  );
  assert.equal(requestText({ messages: [] }), "", "no request, no guess");

  // The plugin injects the route for the turn.
  const plugin = jiti(PLUGIN).default;
  const { ctx, hooks } = makeContext(workspace);
  await plugin.setup(ctx);
  const onContext = hooks.get("context");
  assert.ok(hooks.has("context"), "the plugin still hooks the model request");

  const event = makeContext(workspace).contextEvent({
    sessionID: "ses_router",
    messages: [
      {
        info: { role: "user" },
        parts: [{ type: "text", text: "the sourcemap of the dashboard exposes the internal API" }],
      },
    ],
  });
  await onContext(event);

  const block = event.system.find((entry) => String(entry.text).startsWith(ROUTER_MARKER));
  assert.ok(block, "the route reaches the turn");
  assert.match(block.text, /harness-source-deep/, "the matching skill is named");
  assert.ok(block.text.length <= 900, "the injected route is bounded");

  // A request without text still gets the map, not silence.
  const blind = makeContext(workspace).contextEvent({ sessionID: "ses_router_blind" });
  await onContext(blind);
  const table = blind.system.find((entry) => String(entry.text).startsWith(ROUTER_MARKER));
  assert.ok(table, "the map is injected when the request is unknown");
  assert.match(table.text, /No row matched/, "the map says what to do when nothing matches");

  // Injected once, never twice.
  await onContext(blind);
  const count = blind.system.filter((entry) =>
    String(entry.text).startsWith(ROUTER_MARKER),
  ).length;
  assert.equal(count, 1, "the route is carried once per request");
};
