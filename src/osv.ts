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
const MAX_ID_LEN = 64;
const MAX_ALIAS_LEN = 64;
const MAX_FIXED_LEN = 100;
const MAX_ALIASES = 10;
const MAX_FIXED = 10;
const MAX_AFFECTED = 50;
const MAX_RANGES = 50;
const MAX_EVENTS = 200;
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
    const id = row.id.trim().slice(0, MAX_ID_LEN);
    if (!id) continue;
    const score = Array.isArray(row.severity)
      ? row.severity
          .slice(0, 20)
          .find((entry: any) => typeof entry?.score === "string")?.score
      : undefined;
    const severity =
      typeof score === "string"
        ? score.slice(0, 200)
        : typeof row.database_specific?.severity === "string"
          ? row.database_specific.severity.slice(0, 40)
          : null;
    const aliases: string[] = [];
    if (Array.isArray(row.aliases)) {
      for (const alias of row.aliases.slice(0, 200)) {
        if (typeof alias === "string") {
          aliases.push(alias.slice(0, MAX_ALIAS_LEN));
          if (aliases.length >= MAX_ALIASES) break;
        }
      }
    }
    const fixed = new Set<string>();
    const affectedList = Array.isArray(row.affected)
      ? row.affected.slice(0, MAX_AFFECTED)
      : [];
    affectedLoop: for (const affected of affectedList) {
      const ranges = Array.isArray(affected?.ranges)
        ? affected.ranges.slice(0, MAX_RANGES)
        : [];
      for (const range of ranges) {
        const events = Array.isArray(range?.events)
          ? range.events.slice(0, MAX_EVENTS)
          : [];
        for (const event of events) {
          if (typeof event?.fixed === "string") {
            fixed.add(event.fixed.slice(0, MAX_FIXED_LEN));
            if (fixed.size >= MAX_FIXED) break affectedLoop;
          }
        }
      }
    }
    out.push({
      id,
      summary:
        typeof row.summary === "string" ? row.summary.slice(0, 500) : "",
      aliases,
      severity,
      fixed: [...fixed].slice(0, MAX_FIXED),
    });
  }
  return out;
}
