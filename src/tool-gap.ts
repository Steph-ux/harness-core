/**
 * Explain uncovered objectives without pretending that tool discovery means
 * execution or that a keyword match proves actual operational coverage.
 */
import type { ToolCapability } from "./tool-registry";
export interface CapabilityGap {
  objective: string;
  candidates: { name: string; origin: ToolCapability["origin"] }[];
  status: "candidate-tools" | "unmatched";
  note: string;
}
const WORDS = new Set(["the", "and", "with", "for", "from", "une", "des", "les", "dans", "pour", "avec", "sur", "audit", "tool", "tools", "outil", "outils", "test", "not", "never", "need", "needs"]);
function words(text: string): Set<string> {
  return new Set(text.normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .toLowerCase().split(/[^a-z0-9]+/).filter((part) => part.length > 2 && !WORDS.has(part)));
}
export function identifyToolGaps(objectives: string[], available: ToolCapability[]): CapabilityGap[] {
  if (!Array.isArray(objectives) || !objectives.length || objectives.length > 25 ||
      objectives.some((item) => typeof item !== "string" || !item.trim() || item.length > 300))
    throw new Error("Provide 1-25 short, concrete objectives");
  return objectives.map((objective) => {
    const wanted = words(objective);
    const candidates = available
      .map((item) => {
        const name = words(item.name);
        const description = words(item.description);
        let score = 0;
        for (const word of wanted)
          score += name.has(word) ? 5 : description.has(word) ? 1 : 0;
        return { item, score };
      }).filter((entry) => entry.score > 0)
      .sort((a, b) => b.score - a.score).slice(0, 5)
      .map(({ item }) => ({ name: item.name, origin: item.origin }));
    return {
      objective, candidates,
      status: candidates.length ? "candidate-tools" as const : "unmatched" as const,
      note: candidates.length
        ? "Names/descriptions match only. Test suitability, permissions and execution before claiming coverage."
        : "No matching tool in the current inventory. Inspect alternative names before proposing an improvement.",
    };
  });
}
