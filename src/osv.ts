/**
 * Known vulnerabilities, as OSV answers them.
 *
 * The lookup itself is a tool call, so it leaves an observation. This module
 * only turns the answer into a bounded, stable shape: the plugin never returns
 * an unbounded third-party payload to the model.
 */
export interface OsvVulnerability {
  id: string;
  summary: string;
  aliases: string[];
  severity: string | null;
  fixed: string[];
}
const MAX_VULNS = 100;
export const OSV_ECOSYSTEMS = [
  "PyPI",
  "npm",
  "Go",
  "Debian",
  "Ubuntu",
  "Alpine",
  "Packagist",
  "Maven",
  "NuGet",
  "RubyGems",
  "crates.io",
  "Hex",
  "GitHub Actions",
] as const;
export function summarizeOsv(payload: unknown): OsvVulnerability[] {
  const value = payload as any,
    rows = Array.isArray(value?.vulns) ? value.vulns : [];
  const out: OsvVulnerability[] = [];
  for (const row of rows.slice(0, MAX_VULNS)) {
    if (!row || typeof row.id !== "string") continue;
    const score = Array.isArray(row.severity)
      ? row.severity.find((entry: any) => typeof entry?.score === "string")
          ?.score
      : undefined;
    const severity =
      typeof score === "string"
        ? score.slice(0, 200)
        : typeof row.database_specific?.severity === "string"
          ? row.database_specific.severity.slice(0, 40)
          : null;
    const fixed = new Set<string>();
    for (const affected of Array.isArray(row.affected) ? row.affected : [])
      for (const range of Array.isArray(affected?.ranges) ? affected.ranges : [])
        for (const event of Array.isArray(range?.events) ? range.events : [])
          if (typeof event?.fixed === "string") fixed.add(event.fixed);
    out.push({
      id: row.id,
      summary:
        typeof row.summary === "string" ? row.summary.slice(0, 500) : "",
      aliases: Array.isArray(row.aliases)
        ? row.aliases
            .filter((alias: unknown) => typeof alias === "string")
            .slice(0, 10)
        : [],
      severity,
      fixed: [...fixed].slice(0, 10),
    });
  }
  return out;
}
