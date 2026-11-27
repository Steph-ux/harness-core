/**
 * Turn a collected dump into graph facts.
 *
 * The parser is pure: it reads text, never the network, and returns the
 * entities and relations to record. The caller binds them to the observation
 * that produced the dump, so an ingested host is as checkable as a typed one.
 */
import * as net from "node:net";
import { ENTITY_TYPES, type EntityType } from "./platform-types";
import { redactText } from "./util";

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

function targetOf(
  value: string,
): { type: "ip" | "host"; key: string } | undefined {
  let host = value.trim().toLowerCase();
  if (!host) return;
  if (host.startsWith("[") && host.endsWith("]")) {
    const inner = host.slice(1, -1);
    if (!inner || inner.includes("%") || !net.isIPv6(inner)) return;
    return { type: "ip", key: inner };
  }
  if (net.isIPv6(host)) {
    if (host.includes("%")) return;
    return { type: "ip", key: host };
  }
  if (net.isIPv4(host)) return { type: "ip", key: host };
  host = host.replace(/\.$/, "");
  if (!host || host.length > 253) return;
  const labels = host.split(".");
  if (labels.length < 2) return;
  const labelRe = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  if (!labels.every((label) => labelRe.test(label))) return;
  const tld = labels[labels.length - 1];
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9]{2,59})$/.test(tld)) return;
  return { type: "host", key: host };
}

function urlOf(value: string): string | undefined {
  try {
    const url = new URL(value.trim());
    if (!["http:", "https:"].includes(url.protocol)) return;
    // Never retain URL credentials or silently corrupt oversized URLs.
    url.username = "";
    url.password = "";
    if (!targetOf(url.hostname)) return;
    const cleaned = url.toString();
    if (cleaned.length > MAX_LINE || /[\u0000-\u001f]/.test(cleaned)) return;
    return cleaned;
  } catch {
    return;
  }
}

function add(
  plan: IngestPlan,
  seen: Set<string>,
  entity: IngestEntity,
): boolean {
  if (!ENTITY_TYPES.includes(entity.type)) return true;
  const id = `${entity.type}:${entity.key}`;
  if (seen.has(id)) return true;
  if (plan.entities.length >= MAX_ENTITIES) return false;
  seen.add(id);
  plan.entities.push(entity);
  return true;
}

export function planIngest(format: IngestFormat, text: string): IngestPlan {
  if (format !== "lines" && format !== "httpx" && format !== "json")
    throw new Error("Invalid dump format");
  if (typeof text !== "string") throw new Error("Invalid dump text");
  const plan: IngestPlan = { entities: [], relations: [], skipped: 0 },
    seen = new Set<string>();
  if (format === "lines") {
    for (const raw of text.split(/\r?\n/)) {
      if (plan.entities.length >= MAX_ENTITIES) break;
      const line = raw.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) continue;
      const url = /^https?:\/\//i.test(line) ? urlOf(line) : undefined;
      if (url) {
        if (!add(plan, seen, { type: "url", key: url })) break;
        const target = targetOf(new URL(url).hostname);
        if (target) {
          if (!add(plan, seen, target)) break;
          plan.relations.push({
            source: { type: "url", key: url },
            target,
            kind: "resolves-to",
          });
        }
        continue;
      }
      const target = targetOf(line);
      if (target) {
        if (!add(plan, seen, target)) break;
      } else plan.skipped += 1;
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
      if (!add(plan, seen, { type: "url", key: url })) break;
      const rawHost =
        typeof row?.host === "string" && row.host.trim()
          ? row.host
          : new URL(url).hostname;
      const target = targetOf(rawHost) ?? targetOf(new URL(url).hostname);
      if (target) {
        if (!add(plan, seen, target)) break;
        plan.relations.push({
          source: { type: "url", key: url },
          target,
          kind: "resolves-to",
        });
      }
      const techs = Array.isArray(row?.tech)
        ? row.tech
        : typeof row?.tech === "string"
          ? row.tech.split(",")
          : [];
      for (const tech of techs.slice(0, 20)) {
        if (plan.entities.length >= MAX_ENTITIES) break;
        if (typeof tech !== "string" || !tech.trim() || /[\u0000-\u001f]/.test(tech))
          continue;
        const key = tech.trim().toLowerCase().slice(0, 100);
        if (!add(plan, seen, { type: "technology", key })) break;
        if (target)
          plan.relations.push({
            source: target,
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
    if (!row || typeof row !== "object" || Array.isArray(row)) {
      plan.skipped += 1;
      continue;
    }
    const value = row as Record<string, unknown>;
    if (typeof value.type !== "string" || typeof value.key !== "string") {
      plan.skipped += 1;
      continue;
    }
    if (!ENTITY_TYPES.includes(value.type as EntityType)) {
      plan.skipped += 1;
      continue;
    }
    const rawKey = value.key.trim().slice(0, MAX_LINE);
    const key = value.type === "secret" ? redactText(rawKey) : rawKey;
    if (!key || /[\u0000-\u001f]/.test(key)) {
      plan.skipped += 1;
      continue;
    }
    let label: string | undefined;
    if (value.label !== undefined) {
      if (typeof value.label !== "string") {
        plan.skipped += 1;
        continue;
      }
      const trimmed = redactText(value.label.trim()).slice(0, 300);
      if (trimmed) label = trimmed;
    }
    let attributes: Record<string, unknown> | undefined;
    if (value.attributes !== undefined) {
      if (
        !value.attributes ||
        typeof value.attributes !== "object" ||
        Array.isArray(value.attributes)
      ) {
        plan.skipped += 1;
        continue;
      }
      let serialized: string;
      try {
        serialized = JSON.stringify(value.attributes);
      } catch {
        plan.skipped += 1;
        continue;
      }
      if (
        !serialized ||
        serialized.length > 20000 ||
        redactText(serialized) !== serialized
      ) {
        plan.skipped += 1;
        continue;
      }
      attributes = value.attributes as Record<string, unknown>;
    }
    if (
      !add(plan, seen, {
        type: value.type as EntityType,
        key,
        ...(label !== undefined ? { label } : {}),
        ...(attributes !== undefined ? { attributes } : {}),
      })
    )
      break;
  }
  return plan;
}
