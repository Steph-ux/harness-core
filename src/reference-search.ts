/** Bounded read-only search of an operator-provided SQLite reference index. */
import * as fs from "node:fs";
import * as path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { assertPlainPath } from "./util";

export function searchReference(query: unknown, limit: unknown = 10) {
  if (typeof query !== "string" || !query.trim() || query.length > 200)
    throw new Error("A nonempty query of at most 200 characters is required");
  if (!Number.isInteger(limit) || (limit as number) < 1 || (limit as number) > 40)
    throw new Error("Invalid search limit");
  const configured = process.env.HARNESS_KNOWLEDGE_DB?.trim();
  const home = process.env.HARNESS_TOOL_HOME?.trim();
  if (!configured && !home) throw new Error("Reference database is not configured");
  const file = path.resolve(configured || path.join(home!, "memory_primary.sqlite"));
  assertPlainPath(file);
  if (!fs.existsSync(file) || !fs.statSync(file).isFile())
    throw new Error("Reference database is unavailable");
  const db = new DatabaseSync(file, { readOnly: true });
  try {
    const exact = /^(?:CVE-\d{4}-\d{4,}|CWE-\d+|CAPEC-\d+|T\d{4}(?:\.\d{3})?)$/i.test(query.trim());
    let rows;
    if (exact) {
      rows = db.prepare("SELECT shelf,kind,key,owner,substr(text,1,1200) AS excerpt FROM docs WHERE key=? COLLATE NOCASE LIMIT ?")
        .all(query.trim(), limit as number);
    } else {
      const tokens = query.match(/[\p{L}\p{N}_]+/gu) ?? [];
      if (!tokens.length || tokens.length > 12) throw new Error("Invalid search query");
      const match = tokens.map((token) => `"${token}"`).join(" AND ");
      rows = db.prepare(`
        SELECT d.shelf,d.kind,d.key,d.owner,substr(d.text,1,1200) AS excerpt
        FROM fts_catalog f JOIN docs d ON d.id=f.rowid
        WHERE fts_catalog MATCH ?
        UNION ALL
        SELECT d.shelf,d.kind,d.key,d.owner,substr(d.text,1,1200) AS excerpt
        FROM fts_cve f JOIN docs d ON d.id=f.rowid
        WHERE fts_cve MATCH ?
        LIMIT ?
      `).all(match, match, limit as number);
    }
    return {
      source: file,
      query: query.trim(),
      results: rows,
      limitations: "Reference data only; not a finding. Source freshness and upstream provenance are not verified.",
    };
  } finally {
    db.close();
  }
}
