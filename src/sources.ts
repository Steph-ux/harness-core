import * as fs from "node:fs";
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
/** Explicit, project-scoped sources only. No crawling, cloning or model-driven source registration. */
export class SourceSynchronizer {
  private closed = false;
  private controllers = new Set<AbortController>();
  private jobs = new Set<Promise<unknown>>();
  private busy = new Set<string>();
  constructor(
    private store: PlatformStore,
    private fetcher: typeof fetch = fetch,
  ) {}
  add(scope: string, id: string, location: string): SourceSpec {
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
      kind = "url";
      location = u.href;
    } else {
      location = path.resolve(location);
      assertPlainPath(location);
      const stat = fs.statSync(location, { throwIfNoEntry: false });
      if (!stat) throw new Error("Source location does not exist");
      kind = stat.isDirectory() ? "folder" : "file";
      if (
        kind === "file" &&
        (!ALLOWED.test(location) || IGNORED.test(path.basename(location)))
      )
        throw new Error("Unsupported or sensitive source file");
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
      this.store.syncDocuments(
        spec,
        [{ uri: spec.location, title: id, text: plainText(body) }],
        response.headers.get("etag") ?? undefined,
        response.headers.get("last-modified") ?? undefined,
      );
      return { documents: 1 };
    }
    assertPlainPath(spec.location);
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
        if (entry.isDirectory()) await walk(file, depth + 1);
        else if (entry.isFile() && ALLOWED.test(entry.name)) {
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
    for (const file of files) {
      signal.throwIfAborted();
      assertPlainPath(file);
      if (fs.statSync(file).size > spec.maxBytes)
        throw new Error("Source file exceeds maxBytes");
      const pieces: Buffer[] = [];
      let bytes = 0;
      const stream = fs.createReadStream(file, {
        signal,
        highWaterMark: 65536,
      });
      try {
        for await (const piece of stream) {
          signal.throwIfAborted();
          const value = Buffer.isBuffer(piece) ? piece : Buffer.from(piece);
          bytes += value.length;
          totalBytes += value.length;
          if (bytes > spec.maxBytes || totalBytes > MAX_TOTAL_BYTES)
            throw new Error("Source exceeds byte budget");
          pieces.push(value);
        }
      } finally {
        stream.destroy();
      }
      assertPlainPath(file);
      documents.push({
        uri: pathToFileURL(file).href,
        title: path.relative(spec.location, file) || path.basename(file),
        text: plainText(Buffer.concat(pieces).toString("utf8")),
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
