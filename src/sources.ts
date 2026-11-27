import * as dns from "node:dns";
import * as fs from "node:fs";
import * as net from "node:net";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { PlatformStore } from "./platform-store";
import { assertPlainPath, redactText } from "./util";
import type { SourceSpec } from "./platform-types";

const ALLOWED = /\.(?:md|txt|json|jsonl|yaml|yml|html?|xml|csv|log)$/i;
const IGNORED =
  /^(?:\.git|\.env(?:\..*)?|node_modules|vendor|dist|build|\.ssh|auth\.json|telegram\.json|credentials.*|.*\.(?:pem|key|p12))$/i;
const MAX_TOTAL_BYTES = 20000000;
function plainText(body: string): string {
  if (body.includes("\0"))
    throw new Error("Binary source content is not supported");
  return body;
}
function isBlockedIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255))
    return true;
  const [a, b, c] = parts;
  return (
    a === 0 ||
    a === 10 ||
    (a === 100 && b >= 64 && b <= 127) ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}
function parseIpv6Groups(raw: string): number[] | null {
  const ip = raw.toLowerCase();
  const v4Match = /:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(ip);
  let headStr = ip;
  const tailGroups: number[] = [];
  if (v4Match) {
    const octets = v4Match[1].split(".").map(Number);
    if (octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    tailGroups.push((octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]);
    headStr = ip.slice(0, ip.length - v4Match[1].length) + "0:0";
    // Replace trailing 0:0 placeholder after parsing groups.
    const parsed = parseIpv6Groups(headStr);
    if (!parsed) return null;
    return [...parsed.slice(0, 6), ...tailGroups];
  }
  const halves = headStr.split("::");
  if (halves.length > 2) return null;
  const parseSide = (side: string) =>
    side === "" ? [] : side.split(":").map((g) => parseInt(g, 16));
  const left = parseSide(halves[0]);
  const right = halves.length === 2 ? parseSide(halves[1]) : [];
  if (
    [...left, ...right].some((n) => !Number.isInteger(n) || n < 0 || n > 0xffff)
  )
    return null;
  const missing = 8 - left.length - right.length;
  if (halves.length === 1 && missing !== 0) return null;
  if (halves.length === 2 && missing < 1) return null;
  return [...left, ...new Array(missing).fill(0), ...right];
}
function isBlockedIp(raw: string): boolean {
  const clean = raw.replace(/^\[|\]$/g, "").split("%")[0].toLowerCase();
  if (net.isIPv4(clean)) return isBlockedIpv4(clean);
  if (!net.isIPv6(clean)) return true;
  const g = parseIpv6Groups(clean);
  if (!g) return true;
  // Unspecified (::) or loopback (::1)
  if (g.slice(0, 7).every((x) => x === 0) && (g[7] === 0 || g[7] === 1))
    return true;
  // IPv4-mapped (::ffff:a.b.c.d) or IPv4-compatible (::a.b.c.d)
  if (
    g.slice(0, 5).every((x) => x === 0) &&
    (g[5] === 0xffff || g[5] === 0)
  ) {
    const v4 = `${g[6] >> 8}.${g[6] & 0xff}.${g[7] >> 8}.${g[7] & 0xff}`;
    return isBlockedIpv4(v4);
  }
  // NAT64 (64:ff9b::/96 or 64:ff9b:1::/48)
  if (g[0] === 0x0064 && g[1] === 0xff9b && (g[2] === 0 || g[2] === 1)) {
    const v4 = `${g[6] >> 8}.${g[6] & 0xff}.${g[7] >> 8}.${g[7] & 0xff}`;
    return isBlockedIpv4(v4);
  }
  // Discard-only (100::/64)
  if (g[0] === 0x0100 && g.slice(1, 4).every((x) => x === 0)) return true;
  // Unique local fc00::/7, link-local fe80::/10, site-local fec0::/10, multicast ff00::/8
  if ((g[0] & 0xfe00) === 0xfc00) return true;
  if ((g[0] & 0xffc0) === 0xfe80) return true;
  if ((g[0] & 0xffc0) === 0xfec0) return true;
  if ((g[0] & 0xff00) === 0xff00) return true;
  return false;
}
function assertSafeHostname(hostname: string): boolean {
  const clean = hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (!clean) throw new Error("Source URL has an empty host");
  if (net.isIP(clean) !== 0) {
    if (isBlockedIp(clean))
      throw new Error("Source URL resolves to a blocked network address");
    return true;
  }
  if (
    clean === "localhost" ||
    clean.endsWith(".localhost") ||
    clean.endsWith(".local") ||
    clean.endsWith(".internal") ||
    clean.endsWith(".arpa") ||
    clean === "metadata" ||
    clean === "instance-data" ||
    clean === "metadata.google.internal" ||
    !clean.includes(".")
  )
    throw new Error("Source URL host is not allowed");
  return false;
}
const normPath = (p: string) =>
  process.platform === "win32" ? p.toLowerCase() : p;
export interface SourceSyncOptions {
  roots?: string[];
  allowedRoot?: string;
  lookup?: (hostname: string) => Promise<{ address: string; family: number }[]>;
}
/** Explicit, project-scoped sources only. No crawling, cloning or model-driven source registration. */
export class SourceSynchronizer {
  private closed = false;
  private controllers = new Set<AbortController>();
  private jobs = new Set<Promise<unknown>>();
  private busy = new Set<string>();
  constructor(
    private store: PlatformStore,
    private fetcher: typeof fetch = fetch,
    private opts: SourceSyncOptions = {},
  ) {}
  private effectiveRoots(scope: string, explicitRoot?: string): string[] {
    const raw: string[] = [];
    if (explicitRoot) raw.push(explicitRoot);
    else if (this.opts.allowedRoot || this.opts.roots?.length) {
      if (this.opts.allowedRoot) raw.push(this.opts.allowedRoot);
      if (this.opts.roots) raw.push(...this.opts.roots);
    } else {
      const active = this.store.active(scope);
      const mRoot = active
        ? this.store.missionRoot(scope, active.id)
        : undefined;
      if (mRoot) raw.push(mRoot);
    }
    if (!raw.length)
      throw new Error("Local source requires an engagement root or allowed root");
    return raw.map((r) => {
      const resolved = path.resolve(r);
      assertPlainPath(resolved);
      const canonical = fs.realpathSync.native(resolved);
      if (path.dirname(canonical) === canonical)
        throw new Error("Filesystem root is not an allowed source root");
      return canonical;
    });
  }
  private assertConfined(
    scope: string,
    resolved: string,
    explicitRoot?: string,
  ): string {
    const roots = this.effectiveRoots(scope, explicitRoot);
    const canonical = fs.realpathSync.native(resolved);
    for (const root of roots) {
      if (
        normPath(canonical) === normPath(root) ||
        normPath(canonical).startsWith(normPath(root) + path.sep)
      ) {
        const rel = path.relative(root, canonical);
        if (
          rel &&
          rel.split(path.sep).some((seg) => seg && IGNORED.test(seg))
        )
          throw new Error("Unsupported or sensitive source file");
        return canonical;
      }
    }
    throw new Error("Source location is outside the allowed root");
  }
  private async assertSafeRemoteUrl(location: string): Promise<void> {
    const u = new URL(location);
    if (!["http:", "https:"].includes(u.protocol))
      throw new Error("Unsupported source URL protocol");
    if (u.username || u.password || u.hash || redactText(location) !== location)
      throw new Error("Source URL cannot contain credentials or secrets");
    const isIp = assertSafeHostname(u.hostname);
    if (isIp) return;
    const lookup =
      this.opts.lookup ??
      ((host: string) => dns.promises.lookup(host, { all: true }));
    let records: { address: string; family: number }[];
    try {
      records = await lookup(u.hostname);
    } catch {
      throw new Error("Source host resolution failed");
    }
    if (!Array.isArray(records) || !records.length)
      throw new Error("Source host resolved to no addresses");
    for (const rec of records) {
      if (!rec?.address || isBlockedIp(rec.address))
        throw new Error("Source URL resolves to a blocked network address");
    }
  }
  add(
    scope: string,
    id: string,
    location: string,
    allowedRoot?: string,
  ): SourceSpec {
    if (this.closed) throw new Error("Source synchronizer closed");
    if (this.busy.has(`${scope}:${id}`))
      throw new Error("Source sync already running");
    let kind: SourceSpec["kind"];
    if (/^https?:\/\//i.test(location)) {
      const u = new URL(location);
      if (
        u.username ||
        u.password ||
        u.hash ||
        redactText(location) !== location
      )
        throw new Error("Source URL cannot contain credentials or secrets");
      assertSafeHostname(u.hostname);
      kind = "url";
      location = u.href;
    } else {
      location = path.resolve(location);
      assertPlainPath(location);
      const stat = fs.lstatSync(location, { throwIfNoEntry: false });
      if (!stat) throw new Error("Source location does not exist");
      if (stat.isSymbolicLink())
        throw new Error("Linked or special harness paths are not allowed");
      kind = stat.isDirectory() ? "folder" : "file";
      if (IGNORED.test(path.basename(location)))
        throw new Error("Unsupported or sensitive source file");
      if (kind === "file" && !ALLOWED.test(location))
        throw new Error("Unsupported or sensitive source file");
      location = this.assertConfined(scope, location, allowedRoot);
    }
    const spec = {
      id,
      scope,
      location,
      kind,
      enabled: true,
      maxFiles: 500,
      maxBytes: 2000000,
    };
    this.store.putSource(spec);
    return spec;
  }
  async sync(
    scope: string,
    id: string,
    parent?: AbortSignal,
  ): Promise<{ documents: number; unchanged?: boolean }> {
    if (this.closed) throw new Error("Source synchronizer closed");
    if (this.busy.size >= 3)
      throw new Error("Source synchronization concurrency limit reached");
    const key = `${scope}:${id}`;
    if (this.busy.has(key)) throw new Error("Source sync already running");
    this.busy.add(key);
    const controller = new AbortController();
    this.controllers.add(controller);
    const abort = () => controller.abort(parent?.reason);
    parent?.addEventListener("abort", abort, { once: true });
    if (parent?.aborted) abort();
    const timer = setTimeout(
      () => controller.abort(new Error("Source sync timeout")),
      60000,
    );
    const job = this.run(scope, id, controller.signal);
    this.jobs.add(job);
    try {
      return await job;
    } finally {
      clearTimeout(timer);
      parent?.removeEventListener("abort", abort);
      this.controllers.delete(controller);
      this.jobs.delete(job);
      this.busy.delete(key);
    }
  }
  private async run(scope: string, id: string, signal: AbortSignal) {
    signal.throwIfAborted();
    const state = this.store.sourceState(scope, id),
      spec = state.spec;
    if (!spec.enabled) throw new Error("Source disabled");
    if (
      !Number.isInteger(spec.maxBytes) ||
      spec.maxBytes < 1 ||
      spec.maxBytes > 2000000 ||
      !Number.isInteger(spec.maxFiles) ||
      spec.maxFiles < 1 ||
      spec.maxFiles > 500
    )
      throw new Error("Invalid source bounds");
    if (spec.kind === "url") {
      await this.assertSafeRemoteUrl(spec.location);
      signal.throwIfAborted();
      const headers: Record<string, string> = {};
      if (state.etag) headers["If-None-Match"] = state.etag;
      if (state.lastModified) headers["If-Modified-Since"] = state.lastModified;
      const response = await this.fetcher(spec.location, {
        signal,
        headers,
        redirect: "error",
      });
      signal.throwIfAborted();
      if (response.status === 304) return { documents: 0, unchanged: true };
      if (!response.ok) throw new Error(`Source HTTP ${response.status}`);
      const reader = response.body?.getReader();
      if (!reader) throw new Error("Source has no readable body");
      const parts: Uint8Array[] = [];
      let size = 0;
      try {
        for (;;) {
          signal.throwIfAborted();
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > spec.maxBytes) throw new Error("Source exceeds maxBytes");
          parts.push(value);
        }
      } finally {
        await reader.cancel().catch(() => {});
      }
      signal.throwIfAborted();
      let body = Buffer.concat(parts).toString("utf8");
      if (/text\/html/i.test(response.headers.get("content-type") ?? ""))
        body = body
          .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, " ")
          .replace(/<[^>]*>/g, " ");
      const text = plainText(body);
      const docs = text.trim()
        ? [{ uri: spec.location, title: id, text }]
        : [];
      this.store.syncDocuments(
        spec,
        docs,
        response.headers.get("etag") ?? undefined,
        response.headers.get("last-modified") ?? undefined,
      );
      return { documents: docs.length };
    }
    assertPlainPath(spec.location);
    if (IGNORED.test(path.basename(spec.location)))
      throw new Error("Unsupported or sensitive source file");
    this.assertConfined(scope, path.resolve(spec.location));
    const files: string[] = [];
    let visited = 0;
    const walk = async (dir: string, depth = 0): Promise<void> => {
      signal.throwIfAborted();
      if (depth > 20) throw new Error("Source exceeds directory depth limit");
      assertPlainPath(dir);
      for (const entry of await fs.promises.readdir(dir, {
        withFileTypes: true,
      })) {
        signal.throwIfAborted();
        if (++visited > 10000)
          throw new Error("Source exceeds directory entry limit");
        if (entry.isSymbolicLink() || IGNORED.test(entry.name)) continue;
        const file = path.join(dir, entry.name);
        const lstat = fs.lstatSync(file, { throwIfNoEntry: false });
        if (!lstat || lstat.isSymbolicLink()) continue;
        if (lstat.isDirectory()) await walk(file, depth + 1);
        else if (lstat.isFile() && ALLOWED.test(entry.name)) {
          if (lstat.nlink > 1) continue;
          files.push(file);
          if (files.length > spec.maxFiles)
            throw new Error(
              "Source exceeds maxFiles; previous index remains current",
            );
        }
      }
    };
    if (spec.kind === "folder") await walk(spec.location);
    else files.push(spec.location);
    const documents: { uri: string; title: string; text: string }[] = [];
    let totalBytes = 0;
    const openFlags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
    for (const file of files) {
      signal.throwIfAborted();
      assertPlainPath(file);
      const preStat = fs.lstatSync(file);
      const handle = await fs.promises.open(file, openFlags);
      const pieces: Buffer[] = [];
      let bytes = 0;
      try {
        const fdStat = await handle.stat();
        if (
          !fdStat.isFile() ||
          fdStat.nlink > 1 ||
          fdStat.dev !== preStat.dev ||
          fdStat.ino !== preStat.ino
        )
          throw new Error("Linked or special harness paths are not allowed");
        if (fdStat.size > spec.maxBytes)
          throw new Error("Source file exceeds maxBytes");
        const chunk = Buffer.allocUnsafe(65536);
        for (;;) {
          signal.throwIfAborted();
          const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
          if (bytesRead === 0) break;
          bytes += bytesRead;
          totalBytes += bytesRead;
          if (bytes > spec.maxBytes || totalBytes > MAX_TOTAL_BYTES)
            throw new Error("Source exceeds byte budget");
          pieces.push(Buffer.from(chunk.subarray(0, bytesRead)));
        }
      } finally {
        await handle.close();
      }
      assertPlainPath(file);
      const text = plainText(Buffer.concat(pieces).toString("utf8"));
      if (!text.trim()) continue;
      documents.push({
        uri: pathToFileURL(file).href,
        title: path.relative(spec.location, file) || path.basename(file),
        text,
      });
    }
    signal.throwIfAborted();
    this.store.syncDocuments(spec, documents);
    return { documents: documents.length };
  }
  async close() {
    this.closed = true;
    for (const c of this.controllers)
      c.abort(new Error("Source sync shutdown"));
    await Promise.allSettled([...this.jobs]);
  }
}
