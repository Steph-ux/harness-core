/**
 * Bounded coverage profiles for surfaces that need more than one generic task.
 * These are checklists, not claims that a pass was performed: every leaf still
 * needs its own successful observation before it can close.
 */
export const COVERAGE_PROFILES = {
  mobile: {
    title: "Mobile application deep coverage",
    steps: [
      "scope and package identity",
      "version, hash and signing certificate",
      "manifest and exported components",
      "permissions, intents and deep links",
      "backup, debuggable and cleartext settings",
      "network security, TLS and pinning",
      "API endpoints, auth and session handling",
      "WebView, JavaScript bridges and file access",
      "local storage, logs, screenshots and secrets",
      "dependencies, updates and supply chain",
      "native libraries and binary review",
      "runtime device checks and instrumentation approval",
      "authorization, business logic and abuse cases",
      "negative controls and evidence review",
    ],
  },
  cloud: {
    title: "Cloud and platform deep coverage",
    steps: [
      "scope, account and approved read-only identity",
      "evidence inventory and provider detection",
      "IAM principals, roles and trust policies",
      "storage buckets, containers and snapshots",
      "compute, images, containers and Kubernetes",
      "serverless functions and managed services",
      "network, security groups, firewalls and ingress",
      "DNS, certificates, load balancers and public exposure",
      "secrets, KMS keys and secret references",
      "logging, monitoring, audit trails and alerting",
      "CI/CD, registries and infrastructure as code",
      "metadata endpoints and workload identity",
      "read-only negative controls and dry-run validation",
      "evidence review and cleanup boundary",
    ],
  },
  harness: {
    title: "Harness and method deep audit",
    steps: [
      "method catalogue and route completeness",
      "tool discovery, availability and provenance",
      "scope, permissions and approval gates",
      "command supervision and failure diagnosis",
      "redaction, immutable observations and retention",
      "task dependencies, branches and closure rules",
      "finding reproduction and negative controls",
      "mobile, cloud and binary coverage wiring",
      "portability and missing-tool behavior",
      "report, restitution and cleanup gates",
    ],
  },
} as const;

export type CoverageProfile = keyof typeof COVERAGE_PROFILES;

/**
 * The checklist is intentionally small, while this contract carries the
 * decision support around it: what closes a surface, which method owns the
 * proof, and what to do when a provider/tool is unavailable.
 */
export const COVERAGE_CONTRACTS = {
  mobile: {
    proof: "observation-per-surface-plus-negative-control",
    methods: [
      "harness-mobile-pentest",
      "harness-source-deep",
      "harness-secret-scan",
      "harness-api-testing",
      "harness-access-control",
      "harness-idor",
      "harness-jwt",
      "harness-ghidra",
    ],
    toolFamilies: ["apktool/jadx", "adb/frida", "REA/Ghidra", "cyber_process"],
    missingTool: "not-tested-with-reason",
  },
  cloud: {
    proof: "evidence-plus-live-read-plus-negative-control",
    methods: [
      "harness-cloud-enum",
      "harness-secret-scan",
      "harness-api-testing",
      "harness-access-control",
      "harness-vuln-triage",
    ],
    toolFamilies: [
      "AWS CLI",
      "gcloud",
      "Azure CLI",
      "kubectl",
      "trivy",
      "cyber_process",
    ],
    missingTool: "evidence-only-and-not-tested",
  },
  harness: {
    proof: "successful-observation-and-negative-control",
    methods: ["harness-cyber-playbooks", "harness-vuln-triage", "rapports-cyber"],
    toolFamilies: ["cyber_process", "cyber_source", "cyber_finding", "cyber_report"],
    missingTool: "record-gap-never-guess",
  },
} as const;

export function coverageProfile(name: string): (typeof COVERAGE_PROFILES)[CoverageProfile] {
  const profile = COVERAGE_PROFILES[String(name).toLowerCase() as CoverageProfile];
  if (!profile) throw new Error("Unknown coverage profile");
  return profile;
}

export function coverageContract(name: string): (typeof COVERAGE_CONTRACTS)[CoverageProfile] {
  const key = String(name).toLowerCase() as CoverageProfile;
  const contract = COVERAGE_CONTRACTS[key];
  if (!contract) throw new Error("Unknown coverage profile");
  return contract;
}
