/**
 * Deterministic routing from a request to the method that covers it.
 *
 * A catalogue of skills is inert: a model that is handed sixty of them picks
 * the tool it already knows. This module turns the catalogue into a decision
 * the harness can inject per turn — no model call, no I/O, bounded output.
 *
 * Two shapes are produced:
 *   - routingTable(): the compact map, injected when the request is unknown.
 *   - routeFor(text): the two rows that match, injected when it is known.
 */

export const ROUTER_MARKER = "Harness routing.";

/**
 * The methods the router names that this repository does not ship.
 *
 * The two authored procedures (rapports-cyber, capitaliser-cyber) travel
 * with the core. The methods below are the host's: the harness routes to
 * them and refuses a finding whose method was not loaded, but it does not
 * carry them. They are declared here so the catalogue is a contract that
 * can be checked, not a list that depends on what one machine happens to
 * have installed.
 */
export const EXTERNAL_METHODS = [
  "harness-access-control",
  "harness-api-testing",
  "harness-attack-surface",
  "harness-breach-osint",
  "harness-business-logic",
  "harness-cloud-enum",
  "harness-ct-logs",
  "harness-dns-enum",
  "harness-email-osint",
  "harness-ghidra",
  "harness-graphql",
  "harness-idor",
  "harness-jwt",
  "harness-logic-cve",
  "harness-maigret",
  "harness-mobile-pentest",
  "harness-oauth2",
  "harness-phone-osint",
  "harness-secret-scan",
  "harness-shadow-api",
  "harness-source-deep",
  "harness-subdomain-enum",
  "harness-vuln-triage",
  "harness-web-deep",
] as const;

/**
 * The skills the router names that the host itself provides.
 *
 * They are the methods of the host, not of the harness: the routing table
 * points at them, and the host decides whether they are installed.
 */
export const HOST_METHODS = [
  "code-review",
  "diagnosing-bugs",
  "opencode",
  "tdd",
] as const;

/** The skills that travel with this repository. */
export const SHIPPED_METHODS = [
  "capitaliser-cyber",
  "rapports-cyber",
] as const;

export interface Route {
  /** Stable id, also used in the audit record. */
  id: string;
  /** Skill ids to load, in order. They must exist in the skill catalogue. */
  skills: string[];
  /** Exact tool paths worth preferring over a shell fallback. */
  tools: string[];
  /** Matched case-insensitively on word boundaries against the request. */
  triggers: string[];
  /** One imperative line, shown when the row matches. */
  hint: string;
  /** Three or four words for the table. */
  label: string;
  /**
   * The row carries the evidence format the ledger accepts: a finding for a
   * request that matched it needs the skill actually loaded in the session.
   */
  enforce?: boolean;
}

export const ROUTES: readonly Route[] = [
  {
    id: "reporting",
    skills: ["rapports-cyber"],
    tools: ["cyber_report", "cyber_verification"],
    triggers: ["rapport", "rapports", "report", "restitution"],
    hint: "Freeze verified evidence, generate Word/PDF and review every page. Cleanup only after restitution.",
    label: "rapports et restitution",
  },
  {
    id: "capitalization",
    skills: ["capitaliser-cyber"],
    tools: ["cyber_capitalise"],
    triggers: [
      "capitaliser",
      "capitalisation",
      "capitalization",
      "lessons learned",
    ],
    hint: "One bounded pass, validated with positive and negative tests.",
    label: "capitalisation de mission",
  },
  {
    id: "web-deep",
    enforce: true,
    skills: ["harness-web-deep"],
    tools: ["rea.inspect_web_page"],
    triggers: [
      "ssrf",
      "ssti",
      "xxe",
      "deserialization",
      "deserialisation",
      "prototype pollution",
      "race condition",
      "toctou",
      "injection de template",
      "pollution de prototype",
      "condition de course",
    ],
    hint: "One field per mutation, out-of-band control for blind classes.",
    label: "ssrf/ssti/xxe/race",
  },
  {
    id: "api",
    skills: ["harness-api-testing", "harness-shadow-api"],
    tools: ["rea.inspect_web_page"],
    triggers: [
      "api",
      "endpoint",
      "rest",
      "swagger",
      "openapi",
      "undocumented",
      "shadow api",
    ],
    hint: "Inventory, auth, authorization, input — each with a negative control.",
    label: "api inventory/authz",
  },
  {
    id: "authz",
    enforce: true,
    skills: ["harness-idor", "harness-access-control"],
    tools: [],
    triggers: [
      "idor",
      "tenant",
      "another user",
      "other user",
      "access control",
      "privilege",
      "role",
      "owner",
      "autre utilisateur",
      "proprietaire",
      "controle d acces",
    ],
    hint: "Compare the owner's response with a second authorized identity.",
    label: "idor/access control",
  },
  {
    id: "token",
    enforce: true,
    skills: ["harness-jwt", "harness-oauth2"],
    tools: [],
    triggers: [
      "jwt",
      "token",
      "oauth",
      "oidc",
      "claim",
      "refresh",
      "assertion",
      "saml",
      "jeton",
    ],
    hint: "Decoded claims versus what the server actually accepts.",
    label: "jwt/oauth2",
  },
  {
    id: "logic",
    enforce: true,
    skills: ["harness-business-logic", "harness-logic-cve"],
    tools: [],
    triggers: [
      "price",
      "amount",
      "quantity",
      "workflow",
      "state machine",
      "coupon",
      "refund",
      "business rule",
      "payment",
      "montant",
      "prix",
      "tarif",
      "quantite",
      "remboursement",
      "panier",
      "paiement",
    ],
    hint: "Mutate one business field and show the server persisted the illegal state.",
    label: "price/state/workflow",
  },
  {
    id: "graphql",
    enforce: true,
    skills: ["harness-graphql"],
    tools: [],
    triggers: ["graphql", "introspection", "mutation", "resolver"],
    hint: "Introspection, an allowed field, then a field the identity must not read.",
    label: "graphql",
  },
  {
    id: "source",
    enforce: true,
    skills: ["harness-source-deep", "harness-secret-scan"],
    tools: ["rea.analyze_javascript_application", "rea.export_web_scripts"],
    triggers: [
      "sourcemap",
      "bundle",
      "javascript",
      "js file",
      "sink",
      "taint",
      "minified",
      "webpack",
      "code source js",
      "fichier js",
    ],
    hint: "Taint from a request field to a dangerous sink, in the shipped bytes.",
    label: "js/sourcemap audit",
  },
  {
    id: "recon",
    skills: [
      "harness-attack-surface",
      "harness-subdomain-enum",
      "harness-dns-enum",
      "harness-ct-logs",
    ],
    tools: [],
    triggers: [
      "subdomain",
      "recon",
      "asset",
      "attack surface",
      "dns",
      "certificate",
      "ct log",
      "footprint",
      "sous-domaine",
      "surface d attaque",
      "cartographie",
    ],
    hint: "Passive first; a logged name is not an authorization to probe it.",
    label: "recon/asset map",
  },
  {
    id: "cloud",
    skills: ["harness-cloud-enum"],
    tools: ["cloudflare.cf_security"],
    triggers: [
      "aws",
      "azure",
      "gcp",
      "cloud",
      "s3",
      "bucket",
      "iam",
      "cloudflare",
      "worker",
    ],
    hint: "Read-only enumeration against the live account or collected evidence.",
    label: "cloud enum",
  },
  {
    id: "binary",
    skills: ["harness-ghidra"],
    tools: ["rea.open_binary", "ghidra.decompile_function"],
    triggers: [
      "ghidra",
      "binary",
      "firmware",
      "disassembly",
      "decompile",
      "elf",
      "pe file",
      "reverse",
    ],
    hint: "Report only functions, strings and xrefs the tool output shows.",
    label: "binary/ghidra",
  },
  {
    id: "mobile",
    skills: ["harness-mobile-pentest"],
    tools: [],
    triggers: [
      "android",
      "ios",
      "apk",
      "ipa",
      "frida",
      "mobile app",
      "emulator",
    ],
    hint: "Static first; runtime or pinning only on the authorized test device.",
    label: "mobile",
  },
  {
    id: "osint",
    skills: [
      "harness-email-osint",
      "harness-maigret",
      "harness-phone-osint",
      "harness-breach-osint",
    ],
    tools: [],
    triggers: [
      "email",
      "username",
      "handle",
      "phone",
      "breach",
      "leak",
      "identity",
      "osint",
      "person",
    ],
    hint: "Two independent sources before calling a profile confirmed.",
    label: "osint identity",
  },
  {
    id: "triage",
    enforce: true,
    skills: ["harness-vuln-triage"],
    tools: ["cyber_finding"],
    triggers: [
      "scanner",
      "nuclei",
      "http 200",
      "false positive",
      "triage",
      "confirm",
      "is it real",
      "faux positif",
      "est-ce reel",
    ],
    hint: "A reproducible observation plus a negative control, or it stays a lead.",
    label: "triage/confirm",
  },
  {
    id: "bug",
    skills: ["diagnosing-bugs"],
    tools: [],
    triggers: [
      "bug",
      "broken",
      "fails",
      "failing",
      "error",
      "regression",
      "slow",
      "crash",
      "does not work",
    ],
    hint: "Three hypotheses, then trace from the source.",
    label: "debug/diagnose",
  },
  {
    id: "build",
    skills: ["tdd", "code-review"],
    tools: [],
    triggers: [
      "feature",
      "implement",
      "add support",
      "refactor",
      "test first",
      "review the changes",
      "pull request",
    ],
    hint: "Test first, then the smallest change that passes it.",
    label: "feature/tdd/review",
  },
  {
    id: "opencode",
    skills: ["opencode"],
    tools: [],
    triggers: [
      "opencode",
      "mcp",
      "plugin",
      "agent config",
      "skill file",
      "provider",
    ],
    hint: "Check how the host actually loads it before editing a config.",
    label: "host/plugin config",
  },
];

/** Words that carry no routing signal and would match too much. */
const NOISE = new Set([
  "le",
  "la",
  "les",
  "un",
  "une",
  "des",
  "de",
  "du",
  "et",
  "en",
  "the",
  "a",
  "an",
  "of",
  "to",
  "in",
  "on",
  "for",
  "with",
  "and",
  "is",
  "it",
  "this",
  "that",
  "ce",
]);

function normalise(text: string): string {
  return text
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();
}

function hit(haystack: string, trigger: string): boolean {
  const needle = normalise(trigger);
  if (!needle || NOISE.has(needle)) return false;
  // A trigger made of several words is matched as a phrase; a single word is
  // matched on boundaries so "api" does not fire on "capital".
  if (needle.includes(" ")) return haystack.includes(needle);
  const index = haystack.indexOf(needle);
  if (index < 0) return false;
  const before = index === 0 ? " " : haystack[index - 1];
  const after = haystack[index + needle.length] ?? " ";
  return !/[a-z0-9]/.test(before) && !/[a-z0-9]/.test(after);
}

/**
 * The request text the host hands to the context hook, whatever shape it uses.
 * Returns an empty string when the turn carries no request, which is the cue
 * to inject the table instead of a guess.
 */
export function requestText(event: any): string {
  const out: string[] = [];
  const push = (value: unknown) => {
    if (typeof value === "string" && value.trim())
      out.push(value.slice(0, 4000));
  };

  for (const key of ["prompt", "text", "message"]) push(event?.[key]);

  push(event?.prompt?.text);
  for (const part of Array.isArray(event?.prompt?.parts)
    ? event.prompt.parts
    : [])
    if (part?.type === "text") push(part.text);
  const messages = Array.isArray(event?.messages) ? event.messages : [];
  for (
    let index = messages.length - 1;
    index >= 0 && out.length < 3;
    index -= 1
  ) {
    const message = messages[index];
    const role = message?.info?.role ?? message?.role;
    if (role && role !== "user") continue;
    push(message?.content);
    const parts = Array.isArray(message?.parts) ? message.parts : [];
    for (const part of parts) {
      if (part?.type === "text" || part?.type === "input_text")
        push(part.text ?? part.content);
    }
  }
  return out.join("\n");
}

export interface Routing {
  ids: string[];
  /** The skills the matched rows name, for the host to check against a load. */
  skills: string[];
  /** The skills whose row is enforced: a finding needs the method loaded. */
  required: string[];
  block: string;
}

/** One row, so the injection stays a decision and not a library. */
export function routeFor(text: string, limit = 1): Routing {
  const haystack = normalise(text.replace(/\s+/g, " ").slice(0, 4000));
  const scored = ROUTES.map((route) => {
    const matched = [
      ...new Set(route.triggers.filter((trigger) => hit(haystack, trigger))),
    ];
    return {
      route,
      hits: matched.length,
      // A longer trigger is a rarer word: "sourcemap" outweighs "api".
      weight: matched.reduce(
        (sum, trigger) => sum + normalise(trigger).length,
        0,
      ),
    };
  })
    .filter((entry) => entry.hits > 0)
    .sort(
      (left, right) => right.weight - left.weight || right.hits - left.hits,
    );

  // A pasted document carries incidental words — an ASN table with "role" in
  // a header, a phone number next to "reverse". One hit inside a long text is
  // noise: the map stays available, no skill is forced.
  const noise = haystack.length > 800 && (scored[0]?.hits ?? 0) < 2;

  const chosen = noise
    ? []
    : scored.slice(0, Math.max(1, limit)).map((entry) => entry.route);
  if (!chosen.length) {
    return { ids: [], skills: [], required: [], block: routingTable() };
  }

  const lines = chosen.map((route) => {
    const skills = route.skills.join(", ");
    const tools = route.tools.length
      ? ` Tools: ${route.tools.join(", ")}.`
      : "";
    return `- ${route.label}: load ${skills}. ${route.hint}${tools}`;
  });
  const block = [
    `${ROUTER_MARKER} One method covers this request. Call the skill tool with its id before you answer or run a command: the skill carries the procedure and the evidence format this ledger accepts.`,
    ...lines,
    "Load the skill before acting; a 200 is not a finding without an observation id.",
  ].join("\n");
  return {
    ids: chosen.map((route) => route.id),
    skills: [...new Set(chosen.flatMap((route) => route.skills))],
    required: [
      ...new Set(
        chosen
          .filter((route) => route.enforce)
          .flatMap((route) => route.skills),
      ),
    ],
    block: block.slice(0, 900),
  };
}

/**
 * The always-available map. It is what stops a request from falling through to
 * the model's habits when the host hands over no request text at all.
 */
export function routingTable(): string {
  const rows = ROUTES.map(
    (route) => `${route.label} -> ${route.skills.join(", ")}`,
  );
  const block = [
    `${ROUTER_MARKER} The method is mandatory, not advice. If a row matches the request, call the skill tool with that id before you answer or run a command: the skill carries the procedure and the evidence format this ledger accepts. A question about a security method is still a request for the method; an answer built from memory is not the harness.`,
    ...rows,
    "No row matched: for ordinary development or conversation, ignore this map; for security work with no row, say the map has no row instead of inventing a method. Browser work: chrome-devtools.list_pages, rea.inspect_web_page. Evidence: cyber_finding needs observation ids; a 200 is not a finding.",
  ].join("\n");
  return block.slice(0, 2000);
}
