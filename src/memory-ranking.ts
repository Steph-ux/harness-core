import { hash } from "./util";

const normalize = (text: string) =>
  text.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();
const STOP = new Set(
  "a an the and or to of in for is it this that have we already seen technique avons nous deja vu cette les des une un le la et dans pour que est de du avec sur".split(
    " ",
  ),
);
const SYNONYMS = [
  ["authentication", "authentification"],
  ["authorization", "autorisation"],
  ["network", "reseau"],
  ["security", "securite"],
  ["evidence", "preuve"],
  ["encryption", "chiffrement"],
  ["log", "journal"],
  ["patch", "correctif"],
  ["vulnerability", "vulnerabilite"],
  ["browser", "navigateur"],
  ["timeout", "expiration"],
  ["permission", "permissions"],
  ["memory", "memoire"],
  ["process", "processus"],
  ["failure", "echec"],
];
function tokenize(text: string): string[] {
  const out: string[] = [];
  for (const token of normalize(text).match(/[\p{L}\p{N}_-]+/gu) ?? []) {
    out.push(token);
    if (/[-_]/.test(token)) {
      for (const part of token.split(/[-_]+/)) {
        if (part) out.push(part);
      }
    }
  }
  return out;
}

export function memoryQuery(query: string) {
  if (typeof query !== "string" || query.length > 4000)
    throw new Error("Invalid memory query");
  const direct = [
    ...new Set(
      tokenize(query).filter((t) => t.length > 1 && !STOP.has(t)),
    ),
  ].slice(0, 20);
  const seenGroups = new Set<readonly string[] | string>();
  const groups: string[][] = [];
  const termSet = new Set<string>();
  for (const term of direct) {
    const found = SYNONYMS.find((group) => group.includes(term));
    const key = found ?? term;
    if (seenGroups.has(key)) continue;
    const group = found ? [...found] : [term];
    const added = group.filter((t) => !termSet.has(t));
    if (termSet.size + added.length > 60) break;
    seenGroups.add(key);
    groups.push(group);
    for (const t of added) termSet.add(t);
  }
  return { direct, groups, terms: [...termSet] };
}
function body(kind: string, text: string): string {
  if (kind === "knowledge" || kind === "evidence") {
    try {
      const data = JSON.parse(text);
      if (data && typeof data === "object") {
        const field = kind === "knowledge" ? data.content : data.output;
        if (typeof field === "string") return field;
      }
    } catch {
      /* Raw text stays original. */
    }
  }
  return text;
}
function extractInputStrings(value: unknown, depth = 0): string[] {
  if (depth > 4 || value == null) return [];
  if (typeof value === "string") return [value];
  if (typeof value === "number" || typeof value === "boolean")
    return [String(value)];
  if (Array.isArray(value))
    return value.slice(0, 50).flatMap((v) => extractInputStrings(v, depth + 1));
  if (typeof value === "object")
    return Object.values(value as Record<string, unknown>)
      .slice(0, 50)
      .flatMap((v) => extractInputStrings(v, depth + 1));
  return [];
}
function searchableText(kind: string, text: string): string {
  try {
    const data = JSON.parse(text);
    if (!data || typeof data !== "object" || Array.isArray(data)) return text;
    if (kind === "knowledge") {
      return [data.key, data.kind, data.content]
        .filter((v): v is string => typeof v === "string")
        .join(" ");
    }
    if (kind === "evidence") {
      return [data.tool, data.output, ...extractInputStrings(data.input)]
        .filter((v): v is string => typeof v === "string")
        .join(" ");
    }
    if (kind === "finding") {
      return [
        data.title,
        data.severity,
        data.status,
        data.description,
        data.limitations,
      ]
        .filter((v): v is string => typeof v === "string")
        .join(" ");
    }
    if (kind === "mission") {
      return [data.title, data.boundaries, data.state]
        .filter((v): v is string => typeof v === "string")
        .join(" ");
    }
    return extractInputStrings(data).join(" ");
  } catch {
    return text;
  }
}
/** Deduplicate only the contextual projection; originals and citations remain separate. */
export function memoryFragment(kind: string, text: string): string {
  return hash(body(kind, text).toLowerCase().replace(/\s+/g, " ").trim());
}
export function rankMemory<
  T extends { id: string; kind: string; title: string; text: string },
>(candidates: T[], query: ReturnType<typeof memoryQuery>): T[] {
  if (!query.terms.length) return [];
  const mapped = candidates.slice(0, 200).map((row, index) => {
    const tokens = new Set(
      tokenize(`${row.title} ${searchableText(row.kind, row.text)}`),
    );
    const matched = query.groups.map((group) =>
      group.some((term) => tokens.has(term)),
    );
    const covered = matched.filter(Boolean).length;
    const exact = query.direct.filter((term) => tokens.has(term)).length;
    return { row, index, covered, exact, matched };
  });
  const frequencies = query.groups.map(
    (_group, i) => mapped.filter((row) => row.matched[i]).length || 1,
  );
  return mapped
    .map((row) => ({
      ...row,
      relevance: row.matched.reduce(
        (sum, matched, i) => sum + (matched ? 1 / frequencies[i] : 0),
        0,
      ),
    }))
    .filter((v) => v.covered)
    .sort(
      (a, b) =>
        b.relevance - a.relevance ||
        b.covered - a.covered ||
        b.exact - a.exact ||
        Number(b.row.kind === "knowledge") -
          Number(a.row.kind === "knowledge") ||
        a.row.title.localeCompare(b.row.title, "en") ||
        a.index - b.index,
    )
    .map((v) => v.row);
}
