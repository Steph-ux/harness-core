/**
 * Turn a collected dump into graph facts.
 *
 * The parser is pure: it reads text, never the network, and returns the
 * entities and relations to record. The caller binds them to the observation
 * that produced the dump, so an ingested host is as checkable as a typed one.
 */
import { ENTITY_TYPES, type EntityType } from "./platform-types";

export interface IngestEntity {
  type: EntityType;
  key: string;
  label?: string;
  attributes?: Record<string, unknown>;
}
export interface IngestRelation {
  source: { type: EntityType; key: string };
  target: { type: EntityType; key: string };
  kind: string;
}
export interface IngestPlan {
  entities: IngestEntity[];
  relations: IngestRelation[];
  skipped: number;
}
export type IngestFormat = "lines" | "httpx" | "json";
const MAX_ENTITIES = 2000;
const MAX_LINE = 300;

function hostOf(value: string): string | undefined {
  let host = value.trim().toLowerCase();
  if (!host) return;
  host = host.replace(/\.$/, "");
  if (!host || host.length > MAX_LINE) return;
  if (!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,}$/.test(host) &&
      !/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host))
    return;
  return host;
}

function urlOf(value: string): string | undefined {
  try {
    const url = new URL(value.trim());
    if (!["http:", "https:"].includes(url.protocol)) return;
    return url.toString().slice(0, MAX_LINE);
  } catch {
    return;
  }
}

function add(
  plan: IngestPlan,
  seen: Set<string>,
  entity: IngestEntity,
): void {
  const id = `${entity.type}:${entity.key}`;
  if (seen.has(id)) return;
  if (!ENTITY_TYPES.includes(entity.type)) return;
  seen.add(id);
  plan.entities.push(entity);
}

export function planIngest(format: IngestFormat, text: string): IngestPlan {
  const plan: IngestPlan = { entities: [], relations: [], skipped: 0 },
    seen = new Set<string>();
  if (format === "lines") {
    for (const raw of text.split(/\r?\n/)) {
      if (plan.entities.length >= MAX_ENTITIES) break;
      const line = raw.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) continue;
      const url = /^https?:\/\//i.test(line) ? urlOf(line) : undefined;
      if (url) {
        add(plan, seen, { type: "url", key: url });
        const host = hostOf(new URL(url).hostname);
        if (host) {
          add(plan, seen, { type: "host", key: host });
          plan.relations.push({
            source: { type: "url", key: url },
            target: { type: "host", key: host },
            kind: "resolves-to",
          });
        }
        continue;
      }
      const host = hostOf(line);
      if (host) add(plan, seen, { type: "host", key: host });
      else plan.skipped += 1;
    }
    return plan;
  }
  if (format === "httpx") {
    for (const raw of text.split(/\r?\n/)) {
      if (plan.entities.length >= MAX_ENTITIES) break;
      const line = raw.trim();
      if (!line) continue;
      let row: any;
      try {
        row = JSON.parse(line);
      } catch {
        plan.skipped += 1;
        continue;
      }
      const source = typeof row?.input === "string" ? row.input : row?.url;
      const url = typeof source === "string" ? urlOf(source) : undefined;
      if (!url) {
        plan.skipped += 1;
        continue;
      }
      add(plan, seen, { type: "url", key: url });
      const host = hostOf(
        typeof row?.host === "string" ? row.host : new URL(url).hostname,
      );
      if (host) {
        add(plan, seen, { type: "host", key: host });
        plan.relations.push({
          source: { type: "url", key: url },
          target: { type: "host", key: host },
          kind: "resolves-to",
        });
      }
      const techs = Array.isArray(row?.tech)
        ? row.tech
        : typeof row?.tech === "string"
          ? row.tech.split(",")
          : [];
      for (const tech of techs.slice(0, 20)) {
        if (typeof tech !== "string" || !tech.trim()) continue;
        const key = tech.trim().toLowerCase().slice(0, 100);
        add(plan, seen, { type: "technology", key });
        if (host)
          plan.relations.push({
            source: { type: "host", key: host },
            target: { type: "technology", key },
            kind: "uses",
          });
      }
    }
    return plan;
  }
  let rows: unknown;
  try {
    rows = JSON.parse(text);
  } catch {
    throw new Error("The JSON dump is not valid JSON");
  }
  if (!Array.isArray(rows)) throw new Error("The JSON dump must be an array");
  for (const row of rows) {
    if (plan.entities.length >= MAX_ENTITIES) break;
    const value = row as any;
    if (typeof value?.type !== "string" || typeof value?.key !== "string") {
      plan.skipped += 1;
      continue;
    }
    if (!ENTITY_TYPES.includes(value.type as EntityType)) {
      plan.skipped += 1;
      continue;
    }
    const key = value.key.trim().slice(0, MAX_LINE);
    if (!key) {
      plan.skipped += 1;
      continue;
    }
    add(plan, seen, {
      type: value.type as EntityType,
      key,
      ...(typeof value.label === "string" ? { label: value.label.slice(0, 300) } : {}),
      ...(value.attributes && typeof value.attributes === "object"
        ? { attributes: value.attributes }
        : {}),
    });
  }
  return plan;
}
