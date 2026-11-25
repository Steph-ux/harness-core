/**
 * Offensive phase detection, transition directives, and counter-logic vectors.
 *
 * The phase is inferred from what the model did (tools used, surfaces state),
 * not from what it claims.  When the data says "you have enough recon, start
 * exploiting", the directive is mandatory — the model cannot choose to stay
 * in recon indefinitely.
 *
 * Counter-logic vectors (Pillars 1-4) are injected as concrete test
 * suggestions when the model enters the exploit phase.  They turn the
 * abstract "test this surface" into "test step-skip on the checkout flow"
 * or "test race condition on the balance transfer".
 *
 * The 3-failure backtrack rule forces the model back to enumerate when
 * exploitation is not working — it needs more information, not more attempts.
 */

// ---------------------------------------------------------------------------
// Phase definitions
// ---------------------------------------------------------------------------

export const OFFENSIVE_PHASES = [
  "recon",
  "enumerate",
  "exploit",
  "post-exploit",
  "report",
] as const;

export type OffensivePhase = (typeof OFFENSIVE_PHASES)[number];

// Tools the model uses in each phase — used to classify, not to restrict.
const RECON_TOOLS = new Set([
  "nmap", "masscan", "httpx", "dnsx", "subfinder", "amass",
  "whatweb", "wafw00f", "dig", "whois", "shodan", "censys",
  "theHarvester", "assetfinder", "bbot",
]);

const ENUMERATE_TOOLS = new Set([
  "gobuster", "feroxbuster", "dirsearch", "ffuf", "wfuzz",
  "nikto", "arjun", "paramspider", "katana", "hakrawler",
  "source-deep", "linkfinder", "jsluice", "secretfinder",
  "jsa", "retire", "webpack-analyzer",
  "mitmproxy", "burp", "zap", "cariddi",
  "cyber_source", "cyber_entity",
]);

export const EXPLOIT_TOOLS_SET = new Set([
  "sqlmap", "dalfox", "commix", "tplmap", "ssrfmap",
  "nuclei", "xsstrike", "nosqlmap", "ysoserial",
  "hydra", "john", "hashcat", "responder", "impacket",
  "metasploit", "msfvenom", "searchsploit",
  "cyber_finding", "cyber_capture",
]);

const EXPLOIT_TOOLS = EXPLOIT_TOOLS_SET;

const POST_EXPLOIT_TOOLS = new Set([
  "mimikatz", "rubeus", "bloodhound", "sharphound",
  "crackmapexec", "evil-winrm", "psexec", "wmiexec",
  "linpeas", "winpeas", "pspy",
]);

// ---------------------------------------------------------------------------
// Phase detection — data-driven, not model-declared
// ---------------------------------------------------------------------------

export interface PhaseInput {
  toolsUsed: readonly string[];
  observationCount: number;
  surfacesTotal: number;
  surfacesTested: number;
  surfacesUntested: number;
  surfacesInProgress: number;
  confirmedFindings: number;
  consecutiveExploitFailures: number;
}

export function detectPhase(input: PhaseInput): OffensivePhase {
  const tools = new Set(input.toolsUsed);
  const reconCount = [...tools].filter((t) => RECON_TOOLS.has(t)).length;
  const enumCount = [...tools].filter((t) => ENUMERATE_TOOLS.has(t)).length;
  const exploitCount = [...tools].filter((t) => EXPLOIT_TOOLS.has(t)).length;
  const postCount = [...tools].filter((t) => POST_EXPLOIT_TOOLS.has(t)).length;

  // 3-failure backtrack: forced return to enumerate
  if (input.consecutiveExploitFailures >= 3) return "enumerate";

  // Post-exploit: confirmed findings and post-exploit tools active
  if (input.confirmedFindings > 0 && postCount > 0) return "post-exploit";

  // Exploit: exploit tools are the dominant activity
  if (exploitCount > 0 && exploitCount >= reconCount) return "exploit";

  // Enumerate: enumeration tools in use, or surfaces declared and being mapped
  if (enumCount > 0 || (input.surfacesTotal > 0 && input.surfacesInProgress > 0))
    return "enumerate";

  // Default: recon
  return "recon";
}

// ---------------------------------------------------------------------------
// Transition readiness — when should the model move to the next phase?
// ---------------------------------------------------------------------------

interface TransitionCheck {
  ready: boolean;
  targetPhase: OffensivePhase;
  reason: string;
}

export function transitionCheck(
  currentPhase: OffensivePhase,
  input: PhaseInput,
): TransitionCheck | null {
  if (currentPhase === "recon") {
    // Recon → enumerate: surfaces declared OR enough passive observations
    if (input.surfacesTotal > 0 || input.observationCount >= 8) {
      return {
        ready: true,
        targetPhase: "enumerate",
        reason: input.surfacesTotal > 0
          ? `${input.surfacesTotal} surface(s) identified. Start active enumeration: map parameters, endpoints, and input vectors on each surface.`
          : `${input.observationCount} observations collected without declaring surfaces. Name the attack surfaces before continuing.`,
      };
    }
  }

  if (currentPhase === "enumerate") {
    // Enumerate → exploit: surfaces declared AND at least some have parameters/endpoints mapped
    if (input.surfacesTotal > 0 && input.observationCount >= 12 && input.surfacesUntested > 0) {
      return {
        ready: true,
        targetPhase: "exploit",
        reason: `Enumeration sufficient: ${input.surfacesTotal} surfaces, ${input.observationCount} observations. ${input.surfacesUntested} surface(s) await offensive testing.`,
      };
    }
  }

  if (currentPhase === "exploit") {
    // Exploit → post-exploit: at least one confirmed finding
    if (input.confirmedFindings > 0 && input.surfacesUntested === 0) {
      return {
        ready: true,
        targetPhase: "post-exploit",
        reason: `${input.confirmedFindings} confirmed finding(s), all surfaces tested. Deepen: escalate confirmed findings, look for chains, test lateral impact.`,
      };
    }
    // Exploit → enumerate (backtrack): 3 consecutive failures
    if (input.consecutiveExploitFailures >= 3) {
      return {
        ready: true,
        targetPhase: "enumerate",
        reason: `3 consecutive exploit failures. Backtrack to enumeration: gather more information before retrying. Different tool, different angle.`,
      };
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Counter-logic vectors — concrete attack suggestions per surface
// ---------------------------------------------------------------------------

/** A counter-logic vector applicable to a surface. */
export interface CounterLogicVector {
  pillar: 1 | 2 | 3 | 4;
  category: string;
  test: string;
}

/**
 * Keywords in a surface label that suggest specific counter-logic vectors.
 *
 * Each pattern maps label content to Pillar 2/3 attack vectors.  The vectors
 * are concrete enough that a model can act on them without loading a skill.
 */
const SURFACE_VECTORS: {
  pattern: RegExp;
  vectors: CounterLogicVector[];
}[] = [
  {
    pattern: /auth|login|session|token|jwt|oauth|sso|saml/i,
    vectors: [
      { pillar: 2, category: "State-Machine Skip", test: "Access protected endpoints without completing the auth flow (forced browsing)" },
      { pillar: 2, category: "IDOR", test: "Replace your user/session ID with another user's in the same request" },
      { pillar: 2, category: "Race Condition", test: "Send parallel login/token-refresh requests — does it issue duplicate sessions?" },
      { pillar: 1, category: "Inversion", test: "What happens with an expired token? A malformed token? An empty Authorization header?" },
    ],
  },
  {
    pattern: /pay|checkout|cart|order|price|amount|balance|transfer|wallet|credit|debit|invoice/i,
    vectors: [
      { pillar: 2, category: "Parameter Tampering", test: "Set quantity to -1 or 0, price to 0.001, amount to negative — does the server validate?" },
      { pillar: 2, category: "Race Condition (TOCTOU)", test: "Send 10 concurrent transfer/payment requests — does it debit once or ten times?" },
      { pillar: 2, category: "State-Machine Skip", test: "Call confirm/complete without passing through validate/payment step" },
      { pillar: 2, category: "Callback Forgery", test: "Forge the payment webhook — does the server verify the signature or trust the client?" },
      { pillar: 4, category: "Precision Truncation", test: "Transfer 0.001 units repeatedly — do rounding errors accumulate?" },
    ],
  },
  {
    pattern: /api|endpoint|rest|graphql|grpc/i,
    vectors: [
      { pillar: 2, category: "IDOR Nested", test: "GET /tenant/A/resource/999 — does it verify resource 999 belongs to tenant A?" },
      { pillar: 2, category: "Method Tampering", test: "Replace GET with PUT/DELETE/PATCH — does the server enforce method restrictions?" },
      { pillar: 1, category: "Inversion", test: "What is assumed never null in the response? Send requests that break that assumption." },
      { pillar: 2, category: "Mass Assignment", test: "Add extra fields (role, isAdmin, status) to POST/PATCH — does the server accept them?" },
    ],
  },
  {
    pattern: /upload|file|image|document|attachment|media/i,
    vectors: [
      { pillar: 2, category: "File Upload Bypass", test: "Upload .php/.jsp/.aspx with double extension, null byte, or MIME mismatch" },
      { pillar: 1, category: "Inversion", test: "Upload a 0-byte file, a 100MB file, a file with path traversal in the name (../../etc/passwd)" },
      { pillar: 2, category: "Race Condition", test: "Upload + access the file before server-side validation/virus scan completes" },
    ],
  },
  {
    pattern: /search|query|filter|sort|param/i,
    vectors: [
      { pillar: 2, category: "Injection", test: "SQL injection in search/filter params: ' OR 1=1--, UNION SELECT, blind time-based" },
      { pillar: 2, category: "SSTI", test: "Template injection in search output: {{7*7}}, ${7*7}, #{7*7}" },
      { pillar: 1, category: "Inversion", test: "Empty search, search with 10000 chars, search with null bytes — observe error handling" },
    ],
  },
  {
    pattern: /admin|dashboard|panel|manage|config|setting/i,
    vectors: [
      { pillar: 2, category: "Privilege Escalation", test: "Access admin endpoints with a regular user token — is authorization enforced per-endpoint?" },
      { pillar: 2, category: "State-Machine Skip", test: "Call admin actions (delete user, change config) without the approval/confirmation step" },
      { pillar: 1, category: "Inversion", test: "What happens if the admin role is removed mid-session? Does the session retain privileges?" },
    ],
  },
  {
    pattern: /register|signup|account|profile|user/i,
    vectors: [
      { pillar: 2, category: "Race Condition", test: "Create the same account concurrently — does uniqueness hold under parallel requests?" },
      { pillar: 2, category: "Mass Assignment", test: "Add role=admin or verified=true to the registration payload" },
      { pillar: 2, category: "IDOR", test: "View/edit another user's profile by changing the user ID in the URL/body" },
    ],
  },
  {
    pattern: /coupon|discount|promo|voucher|referral|reward/i,
    vectors: [
      { pillar: 2, category: "Race Condition", test: "Apply the same one-time coupon concurrently — does it apply twice?" },
      { pillar: 2, category: "Parameter Tampering", test: "Negative discount amount, coupon on zero-value cart, stacking incompatible coupons" },
      { pillar: 4, category: "Cobra Effect", test: "Create referral loop (A refers B, B refers A) — does it grant infinite rewards?" },
    ],
  },
  {
    pattern: /mobile|app|flutter|android|ios|apk/i,
    vectors: [
      { pillar: 3, category: "Clock Manipulation", test: "Does trial/token expiry rely on device time? Change device clock forward/backward." },
      { pillar: 3, category: "Multi-Tap", test: "Tap submit 5x in 100ms — does it spawn 5 backend transactions?" },
      { pillar: 3, category: "Network Flap", test: "Drop network mid-transaction — is the state consistent when reconnected?" },
    ],
  },
  {
    pattern: /websocket|ws|socket|realtime|chat|notification/i,
    vectors: [
      { pillar: 2, category: "CSWSH", test: "Connect from a cross-origin page — is the Origin header validated?" },
      { pillar: 2, category: "Injection", test: "Send malformed JSON/frames — does the server crash or leak errors?" },
      { pillar: 2, category: "Race Condition", test: "Send messages faster than the server processes — does ordering break state?" },
    ],
  },
  {
    pattern: /js|javascript|bundle|chunk|source|spa|react|angular|vue|next|nuxt|webpack|vite|frontend|client.?side/i,
    vectors: [
      { pillar: 2, category: "JS Endpoint Extraction", test: "Download JS bundles/chunks, grep for /api/, /v1/, /graphql, fetch(, axios — map the hidden API surface the UI never exposes" },
      { pillar: 2, category: "Hardcoded Secrets", test: "Search bundles for API keys, tokens, AWS/GCP/Azure credentials, Firebase config, Stripe keys, internal hostnames" },
      { pillar: 2, category: "Source Map Leak", test: "Check for .map files (bundle.js.map) — if present, reconstruct full original source and audit business logic" },
      { pillar: 1, category: "Client-Side Auth", test: "Is authorization enforced only in JS (route guards, role checks in React/Vue)? Bypass by calling the API directly." },
      { pillar: 2, category: "Dead/Debug Code", test: "Search for console.log, debugger, TODO, HACK, staging/dev URLs, feature flags with hardcoded toggles" },
      { pillar: 4, category: "Client Trust", test: "Does the client compute prices, discounts, or permissions locally? Replay the request with tampered values — the server must re-validate." },
    ],
  },
  {
    pattern: /traffic|intercept|proxy|burp|request|response|header|cookie|cors|csp|hsts|network|http|redirect/i,
    vectors: [
      { pillar: 2, category: "Hidden Endpoints", test: "Capture all traffic during normal usage — find endpoints not in docs: internal APIs, debug routes, health checks, metrics" },
      { pillar: 2, category: "Header Injection", test: "Inject X-Forwarded-For, X-Original-URL, X-Rewrite-URL to bypass IP/path restrictions" },
      { pillar: 2, category: "Cookie Manipulation", test: "Decode session cookies (JWT, base64, serialized objects) — tamper with role/user fields, test without HttpOnly/Secure flags" },
      { pillar: 1, category: "CORS Misconfiguration", test: "Send Origin: https://evil.com — does the server reflect it in Access-Control-Allow-Origin? Test with null origin." },
      { pillar: 2, category: "Redirect Chain Abuse", test: "Follow all 3xx redirects manually — can open redirects chain to steal tokens via Referer or fragment?" },
      { pillar: 4, category: "CSP Bypass", test: "If CSP allows unsafe-inline, script-src with a CDN, or missing frame-ancestors — test XSS/clickjacking through the gap" },
    ],
  },
];

/**
 * Match counter-logic vectors to a surface based on its label.
 *
 * Returns the top N most relevant vectors, deduplicated by category.
 */
export function counterLogicFor(
  surfaceLabel: string,
  limit = 4,
): CounterLogicVector[] {
  const matched: CounterLogicVector[] = [];
  for (const entry of SURFACE_VECTORS) {
    if (entry.pattern.test(surfaceLabel)) {
      matched.push(...entry.vectors);
    }
  }
  // Deduplicate by category, keep first match
  const seen = new Set<string>();
  const unique: CounterLogicVector[] = [];
  for (const v of matched) {
    if (!seen.has(v.category)) {
      seen.add(v.category);
      unique.push(v);
    }
  }
  return unique.slice(0, limit);
}

// ---------------------------------------------------------------------------
// Phase directive — the main export consumed by directives()
// ---------------------------------------------------------------------------

export interface PhaseDirective {
  phase: OffensivePhase;
  priority: "mandatory" | "recommended";
  text: string;
}

/**
 * Produce a phase-aware directive.
 *
 * Returns null when the model is making progress in the right phase.
 * Returns a mandatory directive when it should transition.
 * Returns recommended counter-logic vectors when in exploit phase.
 */
export function phaseDirective(input: PhaseInput, surfaceLabels: readonly string[]): PhaseDirective | null {
  const phase = detectPhase(input);

  // Backtrack fires before anything else: detectPhase already forced
  // "enumerate" when consecutiveExploitFailures >= 3, but the directive
  // must still tell the model why.
  if (input.consecutiveExploitFailures >= 3) {
    return {
      phase: "enumerate",
      priority: "mandatory",
      text: `BACKTRACK: 3 consecutive exploit failures. Return to enumeration: gather more information before retrying. Different tool, different angle.`,
    };
  }

  const transition = transitionCheck(phase, input);

  // Recon → enumerate transition: mandatory after enough observations
  if (phase === "recon" && transition && input.observationCount >= 10) {
    return {
      phase: "enumerate",
      priority: "mandatory",
      text: `PHASE TRANSITION: ${transition.reason}`,
    };
  }

  // Recon → enumerate: recommended when surfaces exist but model stays in recon
  if (phase === "recon" && transition) {
    return {
      phase: "enumerate",
      priority: "recommended",
      text: `Phase transition available: ${transition.reason}`,
    };
  }

  // Enumerate → exploit transition
  if (phase === "enumerate" && transition) {
    const vectors = surfaceLabels
      .flatMap((label) => counterLogicFor(label, 2))
      .slice(0, 6);
    const vectorText = vectors.length
      ? "\nCounter-logic vectors to test:\n" +
        vectors.map((v) => `  - [P${v.pillar} ${v.category}] ${v.test}`).join("\n")
      : "";
    return {
      phase: "exploit",
      priority: input.observationCount >= 15 ? "mandatory" : "recommended",
      text: `PHASE TRANSITION: ${transition.reason}${vectorText}`,
    };
  }

  // In exploit phase: inject counter-logic vectors for untested surfaces
  if (phase === "exploit" && input.surfacesUntested > 0) {
    const vectors = surfaceLabels
      .flatMap((label) => counterLogicFor(label, 2))
      .slice(0, 4);
    if (vectors.length) {
      return {
        phase: "exploit",
        priority: "recommended",
        text: `Counter-logic vectors for untested surfaces:\n` +
          vectors.map((v) => `  - [P${v.pillar} ${v.category}] ${v.test}`).join("\n"),
      };
    }
  }

  return null;
}
