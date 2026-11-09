/**
 * What a complete pass over one asset means, by kind.
 *
 * The steps are a checklist, not a promise: each one still has to be observed.
 * A role is data, so a host wants ports and TLS, an account wants OSINT and
 * secrets, and a technology wants its version and its CVEs.
 */
export const ASSET_STEPS: Record<string, string[]> = {
  host: ["surface", "dns", "tls", "http", "ports", "validation"],
  domain: ["surface", "dns", "tls", "http", "validation"],
  ip: ["ports", "services", "tls", "validation"],
  url: ["surface", "web", "auth", "inputs", "validation"],
  service: ["banner", "auth", "config", "validation"],
  technology: ["version", "cve", "config", "validation"],
  certificate: ["inventory", "expiry", "san", "validation"],
  account: ["osint", "repos", "secrets", "validation"],
  repo: ["history", "secrets", "dependencies", "validation"],
  org: ["assets", "partners", "accounts", "validation"],
  person: ["accounts", "emails", "validation"],
};
export function assetSteps(type: string): string[] {
  return ASSET_STEPS[String(type).toLowerCase()] ?? ["surface", "validation"];
}
