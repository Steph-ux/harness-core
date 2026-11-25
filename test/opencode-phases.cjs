/**
 * Tests for the offensive phase detection, transition directives, and
 * counter-logic vector matching.
 */
"use strict";
const path = require("node:path");

module.exports = async function phases({ assert, jiti }) {
  const CORE = path.resolve(__dirname, "..");
  const {
    OFFENSIVE_PHASES,
    detectPhase,
    transitionCheck,
    counterLogicFor,
    counterLogicGauntlet,
    phaseDirective,
  } = jiti(path.join(CORE, "src/phases.ts"));

  // -------------------------------------------------------------------------
  // Phase detection
  // -------------------------------------------------------------------------

  const baseInput = {
    toolsUsed: [],
    observationCount: 0,
    surfacesTotal: 0,
    surfacesTested: 0,
    surfacesUntested: 0,
    surfacesInProgress: 0,
    confirmedFindings: 0,
    consecutiveExploitFailures: 0,
  };

  assert.equal(
    detectPhase({ ...baseInput }),
    "recon",
    "empty state defaults to recon",
  );

  assert.equal(
    detectPhase({ ...baseInput, toolsUsed: ["nmap", "httpx", "whatweb"] }),
    "recon",
    "recon tools keep the phase in recon",
  );

  assert.equal(
    detectPhase({ ...baseInput, toolsUsed: ["gobuster", "ffuf", "nmap"], surfacesTotal: 3, surfacesInProgress: 1 }),
    "enumerate",
    "enumeration tools move phase to enumerate",
  );

  assert.equal(
    detectPhase({ ...baseInput, toolsUsed: ["sqlmap", "nmap"] }),
    "exploit",
    "exploit tool with equal recon count → exploit phase",
  );

  assert.equal(
    detectPhase({ ...baseInput, toolsUsed: ["sqlmap", "nmap", "httpx", "whatweb"] }),
    "recon",
    "recon tools dominate → recon phase even with one exploit tool",
  );

  assert.equal(
    detectPhase({ ...baseInput, toolsUsed: ["sqlmap", "dalfox"], consecutiveExploitFailures: 3 }),
    "enumerate",
    "3-failure backtrack forces return to enumerate",
  );

  assert.equal(
    detectPhase({ ...baseInput, toolsUsed: ["mimikatz", "bloodhound"], confirmedFindings: 2 }),
    "post-exploit",
    "post-exploit tools + confirmed findings → post-exploit phase",
  );

  // -------------------------------------------------------------------------
  // Transition checks
  // -------------------------------------------------------------------------

  assert.equal(
    transitionCheck("recon", { ...baseInput, observationCount: 8 })?.targetPhase,
    "enumerate",
    "recon→enumerate after 8+ observations",
  );

  assert.equal(
    transitionCheck("recon", { ...baseInput, surfacesTotal: 3 })?.targetPhase,
    "enumerate",
    "recon→enumerate when surfaces are declared",
  );

  assert.equal(
    transitionCheck("recon", { ...baseInput, observationCount: 2 }),
    null,
    "no transition when recon is still early",
  );

  assert.equal(
    transitionCheck("enumerate", {
      ...baseInput,
      surfacesTotal: 5,
      surfacesUntested: 3,
      observationCount: 15,
    })?.targetPhase,
    "exploit",
    "enumerate→exploit when surfaces and observations are sufficient",
  );

  assert.equal(
    transitionCheck("exploit", {
      ...baseInput,
      consecutiveExploitFailures: 3,
    })?.targetPhase,
    "enumerate",
    "exploit→enumerate on 3-failure backtrack",
  );

  assert.equal(
    transitionCheck("exploit", {
      ...baseInput,
      confirmedFindings: 2,
      surfacesUntested: 0,
      surfacesTotal: 3,
      surfacesTested: 3,
    })?.targetPhase,
    "post-exploit",
    "exploit→post-exploit when all surfaces tested and findings confirmed",
  );

  // -------------------------------------------------------------------------
  // Counter-logic vectors
  // -------------------------------------------------------------------------

  const authVectors = counterLogicFor("user authentication and login flow");
  assert.ok(authVectors.length > 0, "auth surface matches counter-logic vectors");
  assert.ok(
    authVectors.some((v) => v.category === "State-Machine Skip"),
    "auth surface gets state-machine skip vector",
  );
  assert.ok(
    authVectors.some((v) => v.pillar === 2),
    "auth surface gets Pillar 2 vectors",
  );

  const paymentVectors = counterLogicFor("payment checkout and balance transfer");
  assert.ok(paymentVectors.length > 0, "payment surface matches vectors");
  assert.ok(
    paymentVectors.some((v) => v.category === "Race Condition (TOCTOU)"),
    "payment surface gets TOCTOU vector",
  );
  assert.ok(
    paymentVectors.some((v) => v.category === "Parameter Tampering"),
    "payment surface gets parameter tampering vector",
  );

  const apiVectors = counterLogicFor("REST API endpoints");
  assert.ok(
    apiVectors.some((v) => v.category === "IDOR Nested"),
    "API surface gets nested IDOR vector",
  );

  const uploadVectors = counterLogicFor("file upload service");
  assert.ok(
    uploadVectors.some((v) => v.category === "File Upload Bypass"),
    "upload surface gets file upload bypass vector",
  );

  const mobileVectors = counterLogicFor("mobile app Flutter client");
  assert.ok(
    mobileVectors.some((v) => v.pillar === 3),
    "mobile surface gets Pillar 3 vectors",
  );

  const jsVectors = counterLogicFor("JavaScript bundle analysis SPA React");
  assert.ok(jsVectors.length > 0, "JS/source surface matches counter-logic vectors");
  assert.ok(
    jsVectors.some((v) => v.category === "JS Endpoint Extraction"),
    "JS surface gets endpoint extraction vector",
  );
  assert.ok(
    jsVectors.some((v) => v.category === "Source Map Leak"),
    "JS surface gets source map leak vector",
  );
  assert.ok(
    jsVectors.some((v) => v.category === "Hardcoded Secrets"),
    "JS surface gets hardcoded secrets vector",
  );

  const trafficVectors = counterLogicFor("HTTP traffic interception proxy analysis");
  assert.ok(trafficVectors.length > 0, "traffic/network surface matches vectors");
  assert.ok(
    trafficVectors.some((v) => v.category === "Hidden Endpoints"),
    "traffic surface gets hidden endpoints vector",
  );
  assert.ok(
    trafficVectors.some((v) => v.category === "CORS Misconfiguration"),
    "traffic surface gets CORS vector",
  );
  assert.ok(
    trafficVectors.some((v) => v.category === "Cookie Manipulation"),
    "traffic surface gets cookie manipulation vector",
  );

  const genericVectors = counterLogicFor("some unknown surface");
  assert.equal(genericVectors.length, 0, "unknown surface gets no vectors");

  // Dedup: a surface matching multiple patterns does not repeat categories
  const multiVectors = counterLogicFor("payment API endpoint with file upload");
  const categories = multiVectors.map((v) => v.category);
  assert.equal(
    categories.length,
    new Set(categories).size,
    "counter-logic vectors are deduplicated by category",
  );

  // Limit: counter-logic returns at most the requested number
  const limited = counterLogicFor("payment checkout cart order", 2);
  assert.ok(limited.length <= 2, "counter-logic respects the limit parameter");

  // --- New surface vector patterns ---
  const xssV = counterLogicFor("XSS cross-site scripting reflected");
  assert.ok(xssV.length > 0, "XSS surface matches");
  assert.ok(xssV.some((v) => v.category === "WAF Bypass"), "XSS gets WAF bypass");
  assert.ok(xssV.some((v) => v.category === "DOM XSS"), "XSS gets DOM XSS");
  assert.ok(xssV.some((v) => v.category === "Blind XSS"), "XSS gets blind XSS");

  const sqliV = counterLogicFor("SQL injection database MySQL", 6);
  assert.ok(sqliV.length > 0, "SQLi surface matches");
  assert.ok(sqliV.some((v) => v.category === "Second-Order SQLi"), "SQLi gets second-order");
  assert.ok(sqliV.some((v) => v.category === "OOB Exfiltration"), "SQLi gets OOB");
  assert.ok(sqliV.some((v) => v.category === "NoSQL Injection"), "SQLi gets NoSQL");

  const ssrfV = counterLogicFor("SSRF server-side request forgery", 6);
  assert.ok(ssrfV.length > 0, "SSRF surface matches");
  assert.ok(ssrfV.some((v) => v.category === "Cloud Metadata"), "SSRF gets cloud metadata");
  assert.ok(ssrfV.some((v) => v.category === "DNS Rebinding"), "SSRF gets DNS rebinding");

  const sstiV = counterLogicFor("SSTI template injection Jinja2");
  assert.ok(sstiV.length > 0, "SSTI surface matches");
  assert.ok(sstiV.some((v) => v.category === "Detection Polyglot"), "SSTI gets polyglot");

  const xxeV = counterLogicFor("XXE XML external entity upload");
  assert.ok(xxeV.length > 0, "XXE surface matches");
  assert.ok(xxeV.some((v) => v.category === "Blind OOB XXE"), "XXE gets blind OOB");

  const deserV = counterLogicFor("deserialization pickle ysoserial");
  assert.ok(deserV.length > 0, "deser surface matches");
  assert.ok(deserV.some((v) => v.category === "Java Deser"), "deser gets Java");
  assert.ok(deserV.some((v) => v.category === "Python Pickle"), "deser gets Python pickle");

  const ppV = counterLogicFor("prototype pollution __proto__ merge");
  assert.ok(ppV.length > 0, "prototype pollution matches");
  assert.ok(ppV.some((v) => v.category === "PP2RCE Gadget"), "PP gets RCE gadget");

  const cacheV = counterLogicFor("cache poisoning request smuggling desync");
  assert.ok(cacheV.length > 0, "cache poison surface matches");
  assert.ok(cacheV.some((v) => v.category === "CL.TE Desync"), "cache gets CL.TE");

  const credV = counterLogicFor("credential brute force password spray MFA");
  assert.ok(credV.length > 0, "credential surface matches");
  assert.ok(credV.some((v) => v.category === "MFA Bypass"), "credential gets MFA bypass");

  const cloudV = counterLogicFor("AWS S3 bucket IAM cloud Lambda");
  assert.ok(cloudV.length > 0, "cloud surface matches");
  assert.ok(cloudV.some((v) => v.category === "IMDS v1 SSRF"), "cloud gets IMDS");
  assert.ok(cloudV.some((v) => v.category === "IAM Privilege Escalation"), "cloud gets IAM privesc");

  const containerV = counterLogicFor("Docker Kubernetes container pod");
  assert.ok(containerV.length > 0, "container surface matches");
  assert.ok(containerV.some((v) => v.category === "Docker Socket Escape"), "container gets socket escape");

  const adV = counterLogicFor("Active Directory Kerberos LDAP domain controller");
  assert.ok(adV.length > 0, "AD surface matches");
  assert.ok(adV.some((v) => v.category === "Kerberoasting"), "AD gets Kerberoasting");
  assert.ok(adV.some((v) => v.category === "ADCS ESC1-ESC8"), "AD gets ADCS");

  const pivotV = counterLogicFor("lateral movement pivot tunnel chisel");
  assert.ok(pivotV.length > 0, "pivot surface matches");
  assert.ok(pivotV.some((v) => v.category === "Pass-the-Hash"), "pivot gets PtH");

  const dnsV = counterLogicFor("DNS subdomain zone transfer takeover");
  assert.ok(dnsV.length > 0, "DNS surface matches");
  assert.ok(dnsV.some((v) => v.category === "Subdomain Takeover"), "DNS gets takeover");

  const secretV = counterLogicFor("secret leak gitleaks .env credential scan");
  assert.ok(secretV.length > 0, "secret surface matches");
  assert.ok(secretV.some((v) => v.category === "Git History Secrets"), "secret gets git history");

  const supplyV = counterLogicFor("supply chain dependency npm audit lockfile");
  assert.ok(supplyV.length > 0, "supply chain surface matches");
  assert.ok(supplyV.some((v) => v.category === "Dependency Confusion"), "supply gets confusion");

  const llmV = counterLogicFor("LLM AI security prompt injection agent");
  assert.ok(llmV.length > 0, "LLM surface matches");
  assert.ok(llmV.some((v) => v.category === "Prompt Injection"), "LLM gets prompt injection");

  const iotV = counterLogicFor("IoT firmware MQTT embedded device");
  assert.ok(iotV.length > 0, "IoT surface matches");
  assert.ok(iotV.some((v) => v.category === "Firmware Extraction"), "IoT gets firmware");

  const redTeamV = counterLogicFor("red team kill chain C2 beacon persistence");
  assert.ok(redTeamV.length > 0, "red team surface matches");
  assert.ok(redTeamV.some((v) => v.category === "C2 Channel"), "red team gets C2");
  assert.ok(redTeamV.some((v) => v.category === "Detection Twin"), "red team gets detection twin");

  const contractV = counterLogicFor("smart contract Solidity reentrancy DeFi");
  assert.ok(contractV.length > 0, "smart contract surface matches");
  assert.ok(contractV.some((v) => v.category === "Flash Loan Attack"), "contract gets flash loan");

  const wirelessV = counterLogicFor("wireless WiFi WPA2 deauth evil twin");
  assert.ok(wirelessV.length > 0, "wireless surface matches");
  assert.ok(wirelessV.some((v) => v.category === "Evil Twin"), "wireless gets evil twin");

  const binaryV = counterLogicFor("binary reverse engineering Ghidra buffer overflow");
  assert.ok(binaryV.length > 0, "binary surface matches");
  assert.ok(binaryV.some((v) => v.category === "Buffer Overflow"), "binary gets BOF");

  const thickV = counterLogicFor("thick client Electron desktop app");
  assert.ok(thickV.length > 0, "thick client surface matches");
  assert.ok(thickV.some((v) => v.category === "DLL Hijacking"), "thick client gets DLL hijack");

  const cryptoV = counterLogicFor("TLS SSL cipher certificate crypto");
  assert.ok(cryptoV.length > 0, "crypto/TLS surface matches");
  assert.ok(cryptoV.some((v) => v.category === "Weak Cipher Suites"), "crypto gets weak ciphers");

  const gqlV = counterLogicFor("GraphQL introspection mutation");
  assert.ok(gqlV.length > 0, "GraphQL surface matches");
  assert.ok(gqlV.some((v) => v.category === "Introspection Leak"), "GraphQL gets introspection");

  const scadaV = counterLogicFor("SCADA ICS PLC Modbus industrial");
  assert.ok(scadaV.length > 0, "SCADA surface matches");
  assert.ok(scadaV.some((v) => v.category === "Unauthenticated Protocol"), "SCADA gets unauth protocol");

  const voipV = counterLogicFor("VoIP SIP RTP PBX Asterisk");
  assert.ok(voipV.length > 0, "VoIP surface matches");
  assert.ok(voipV.some((v) => v.category === "RTP Interception"), "VoIP gets RTP intercept");

  const forensicV = counterLogicFor("forensic memory dump Volatility disk image");
  assert.ok(forensicV.length > 0, "forensic surface matches");
  assert.ok(forensicV.some((v) => v.category === "Memory Analysis"), "forensic gets memory analysis");

  const socialV = counterLogicFor("social engineering phishing pretext");
  assert.ok(socialV.length > 0, "social engineering surface matches");
  assert.ok(socialV.some((v) => v.category === "Phishing Simulation"), "social gets phishing sim");

  // -------------------------------------------------------------------------
  // Phase directive — full integration
  // -------------------------------------------------------------------------

  // Recon with enough observations → mandatory transition
  const reconDirective = phaseDirective(
    { ...baseInput, toolsUsed: ["nmap", "httpx"], observationCount: 12, surfacesTotal: 3, surfacesUntested: 3 },
    ["auth login", "payment API"],
  );
  assert.ok(reconDirective, "recon with 12 obs emits a directive");
  assert.equal(reconDirective.priority, "mandatory", "recon→enumerate after 10 obs is mandatory");
  assert.match(reconDirective.text, /PHASE TRANSITION/, "directive mentions phase transition");

  // Enumerate with surfaces → transition with counter-logic vectors
  const enumDirective = phaseDirective(
    { ...baseInput, toolsUsed: ["gobuster", "ffuf"], observationCount: 15, surfacesTotal: 3, surfacesUntested: 2, surfacesInProgress: 1 },
    ["auth login", "payment checkout"],
  );
  assert.ok(enumDirective, "enumerate with surfaces emits a directive");
  assert.match(enumDirective.text, /Counter-logic/, "enumerate directive includes counter-logic vectors");

  // Exploit with backtrack
  const backtrackDirective = phaseDirective(
    { ...baseInput, toolsUsed: ["sqlmap", "dalfox"], consecutiveExploitFailures: 3 },
    [],
  );
  assert.ok(backtrackDirective, "3-failure backtrack emits a directive");
  assert.equal(backtrackDirective.priority, "mandatory", "backtrack is mandatory");
  assert.match(backtrackDirective.text, /BACKTRACK/, "directive mentions backtrack");

  // No directive when making progress
  const noDirective = phaseDirective(
    { ...baseInput, toolsUsed: ["sqlmap"], observationCount: 5 },
    [],
  );
  assert.equal(noDirective, null, "no directive when model is making normal progress in exploit");

  // Phase list is exhaustive
  assert.equal(OFFENSIVE_PHASES.length, 5, "5 offensive phases defined");
  assert.deepEqual(
    [...OFFENSIVE_PHASES],
    ["recon", "enumerate", "exploit", "post-exploit", "report"],
    "phases follow the kill chain order",
  );

  // -------------------------------------------------------------------------
  // Counter-Logic Gauntlet — permanent adversarial reasoning protocol
  // -------------------------------------------------------------------------

  // The gauntlet always returns content (never empty)
  const gauntletRecon = counterLogicGauntlet({
    currentPhase: "recon",
    hasConfirmedFindings: false,
    hasActiveHypothesis: false,
    surfacesTested: 0,
    surfacesTotal: 0,
  });
  assert.ok(gauntletRecon.length > 0, "gauntlet always produces output");
  assert.ok(gauntletRecon.startsWith("COUNTER-LOGIC PROTOCOL"), "gauntlet starts with protocol marker");

  // All 4 pillars present
  assert.match(gauntletRecon, /PILLAR 1/, "gauntlet includes Pillar 1 (Inversion)");
  assert.match(gauntletRecon, /PILLAR 2/, "gauntlet includes Pillar 2 (Offensive Logic)");
  assert.match(gauntletRecon, /PILLAR 3/, "gauntlet includes Pillar 3 (Client & Mobile Entropy)");
  assert.match(gauntletRecon, /PILLAR 4/, "gauntlet includes Pillar 4 (2nd-Order & Cobra)");

  // The 4-step ritual is present
  assert.match(gauntletRecon, /ASSUMPTION AUDIT/, "gauntlet includes Step 1");
  assert.match(gauntletRecon, /MALICIOUS PERSONA/, "gauntlet includes Step 2");
  assert.match(gauntletRecon, /BLAST-RADIUS TRACE/, "gauntlet includes Step 3");
  assert.match(gauntletRecon, /HARDENING VERDICT/, "gauntlet includes Step 4");

  // Quick reference checklist present
  assert.match(gauntletRecon, /CHECKLIST/, "gauntlet includes quick reference checklist");
  assert.match(gauntletRecon, /Can any step be skipped/, "checklist includes step-skip check");
  assert.match(gauntletRecon, /two identical actions/, "checklist includes concurrency check");

  // Key inversion concepts from the original skill
  assert.match(gauntletRecon, /Unstated Trust/, "gauntlet includes Unstated Trust Fallacy");
  assert.match(gauntletRecon, /Happy-Path Deception/, "gauntlet includes Happy-Path Deception");
  assert.match(gauntletRecon, /Out-of-Order/, "gauntlet includes Out-of-Order Execution");
  assert.match(gauntletRecon, /Infinite Resource/, "gauntlet includes Infinite Resource Illusion");

  // Pillar 2 adapts to phase
  assert.match(gauntletRecon, /recon\/enumerate/, "recon phase gets recon-specific P2");
  const gauntletExploit = counterLogicGauntlet({
    currentPhase: "exploit",
    hasConfirmedFindings: false,
    hasActiveHypothesis: true,
    surfacesTested: 3,
    surfacesTotal: 10,
  });
  assert.match(gauntletExploit, /State-Machine Skips/, "exploit phase gets state-machine P2");
  assert.match(gauntletExploit, /TOCTOU/, "exploit phase gets TOCTOU");
  assert.match(gauntletExploit, /Parameter Tampering/, "exploit phase gets parameter tampering");
  assert.match(gauntletExploit, /Callback Forgery/, "exploit phase gets callback forgery");
  assert.match(gauntletExploit, /IDOR/, "exploit phase gets IDOR nested check");

  const gauntletPostExploit = counterLogicGauntlet({
    currentPhase: "post-exploit",
    hasConfirmedFindings: true,
    hasActiveHypothesis: true,
    surfacesTested: 8,
    surfacesTotal: 10,
  });
  assert.match(gauntletPostExploit, /pivot/, "post-exploit phase gets pivot guidance");
  assert.match(gauntletPostExploit, /container.*host|user.*admin/i, "post-exploit gets escalation guidance");

  // Pillar 3 concepts from the original skill
  assert.match(gauntletRecon, /Multi-Tap/, "P3 includes Rapid Multi-Tap");
  assert.match(gauntletRecon, /Clock Manipulation/, "P3 includes Clock Manipulation");
  assert.match(gauntletRecon, /Network Flap/, "P3 includes Network Flap");
  assert.match(gauntletRecon, /Client-Side Auth/, "P3 includes Client-Side Auth bypass");

  // Pillar 4 adapts based on confirmed findings
  assert.match(gauntletRecon, /tester who proved you wrong/, "P4 without findings challenges complacency");
  assert.match(gauntletPostExploit, /attack chains/, "P4 with findings pushes chaining");
  assert.match(gauntletPostExploit, /XSS chains with CSRF/, "P4 with findings gives concrete chains");

  // Personas from the original skill
  assert.match(gauntletRecon, /Greedy Attacker/, "gauntlet includes Greedy Attacker persona");
  assert.match(gauntletRecon, /Chaotic Environment/, "gauntlet includes Chaotic Environment persona");
  assert.match(gauntletRecon, /Frantic User/, "gauntlet includes Frantic User persona");

  // The gauntlet also works in report phase
  const gauntletReport = counterLogicGauntlet({
    currentPhase: "report",
    hasConfirmedFindings: true,
    hasActiveHypothesis: false,
    surfacesTested: 10,
    surfacesTotal: 10,
  });
  assert.ok(gauntletReport.length > 0, "gauntlet fires even in report phase");
  assert.match(gauntletReport, /PILLAR 1/, "report phase still gets P1");
};
