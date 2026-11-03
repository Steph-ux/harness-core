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
export function memoryQuery(query: string) {
  if (typeof query !== "string" || query.length > 4000)
    throw new Error("Invalid memory query");
  const direct = [
    ...new Set(
      (normalize(query).match(/[\p{L}\p{N}_-]+/gu) ?? []).filter(
        (t) => t.length > 1 && !STOP.has(t),
      ),
    ),
  ].slice(0, 20);
  const groups = direct.map(
    (term) => SYNONYMS.find((group) => group.includes(term)) ?? [term],
  );
  return { direct, groups, terms: [...new Set(groups.flat())].slice(0, 60) };
}
function body(kind: string, text: string): string {
  if (kind === "knowledge" || kind === "evidence") {
    try {
      const data = JSON.parse(text);
      return kind === "knowledge"
        ? (data.content ?? text)
        : (data.output ?? text);
    } catch {
      /* Raw text stays original. */
    }
  }
  return text;
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
      normalize(`${row.title} ${body(row.kind, row.text)}`).match(
        /[\p{L}\p{N}_-]+/gu,
      ) ?? [],
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
        a.row.title.localeCompare(b.row.title) ||
        a.index - b.index,
    )
    .map((v) => v.row);
}
