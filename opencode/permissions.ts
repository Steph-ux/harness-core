/**
 * Native permission asks for the OpenCode host.
 *
 * Shell commands go through the host's permission API. Operator transitions
 * require a fresh `once` answer; a remembered allow is not a human decision.
 */
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";

/** Use the official client's discovery and authentication, never a guessed URL. */
async function localApi(args: string[], signal?: AbortSignal): Promise<any> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["api", ...args], {
      stdio: ["ignore", "pipe", "pipe"],
      signal,
    });
    let output = "";
    const timer = setTimeout(() => child.kill("SIGTERM"), 15000);
    child.stdout.on("data", (chunk) => {
      output += chunk;
    });
    // API errors may contain a command or credentials; do not echo stderr.
    child.stderr.resume();
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0)
        return reject(new Error("OpenCode permission API request failed"));
      try {
        resolve(JSON.parse(output));
      } catch {
        reject(new Error("Invalid OpenCode permission API response"));
      }
    });
  });
}

/** 2.0.26 exposes permission.create over HTTP, but not assert in the plugin. */
export async function assertProcessPermission(
  ctx: any,
  context: any,
  command: string,
  request = localApi,
): Promise<void> {
  const input = {
    sessionID: context.sessionID,
    agent: context.agent,
    source: { type: "tool", messageID: context.messageID, id: context.id },
    action: "shell",
    resources: [command],
  };
  if (typeof ctx.permission?.assert === "function") {
    await ctx.permission.assert(input);
    return;
  }
  context.signal?.throwIfAborted();
  const info = await request(["get", "/api/info"], context.signal);
  if (info.pid !== process.pid)
    throw new Error(
      "Permission API belongs to another server; command refused",
    );
  if (typeof ctx.event?.subscribe !== "function")
    throw new Error("Permission event stream unavailable; command refused");

  const id = `per_${randomUUID()}`;
  const controller = new AbortController();
  const signal = context.signal
    ? AbortSignal.any([controller.signal, context.signal])
    : controller.signal;
  // Listen before creating the request so a fast human response is not lost.
  const decision = (async () => {
    try {
      for await (const event of ctx.event.subscribe({ signal })) {
        if (
          event.type === "permission.replied" &&
          event.data?.sessionID === context.sessionID &&
          event.data.requestID === id
        )
          return { reply: event.data.reply };
      }
      return {
        error: new Error("Permission event stream closed; command refused"),
      };
    } catch (error) {
      return { error };
    }
  })();
  try {
    const { sessionID, ...payload } = input;
    const response = await request(
      [
        "post",
        `/api/session/${encodeURIComponent(sessionID)}/permission`,
        "--data",
        JSON.stringify({ ...payload, id }),
      ],
      signal,
    );
    const result = response.data ?? response;
    if (result.id !== id)
      throw new Error("Permission request identity mismatch");
    if (result.effect === "allow") return;
    if (result.effect !== "ask") throw new Error("Shell permission denied");
    const outcome = await decision;
    signal.throwIfAborted();
    if (outcome.error) throw outcome.error;
    if (outcome.reply !== "once" && outcome.reply !== "always")
      throw new Error("Shell permission rejected");
  } finally {
    controller.abort();
    await decision;
  }
}

/** Operator-only transitions require a fresh interactive answer, never a saved allow. */
export async function assertOperatorDecision(
  ctx: any,
  context: any,
  resource: string,
  request = localApi,
): Promise<void> {
  if (typeof ctx.permission?.explicit === "function") {
    const reply = await ctx.permission.explicit({ context, resource });
    if (reply !== "once")
      throw new Error("An explicit operator decision is required");
    return;
  }
  context.signal?.throwIfAborted();
  const info = await request(["get", "/api/info"], context.signal);
  if (info.pid !== process.pid)
    throw new Error(
      "Permission API belongs to another server; decision refused",
    );
  if (typeof ctx.event?.subscribe !== "function")
    throw new Error("Permission event stream unavailable; decision refused");
  const id = `per_${randomUUID()}`;
  const controller = new AbortController();
  const signal = context.signal
    ? AbortSignal.any([controller.signal, context.signal])
    : controller.signal;
  const decision = (async () => {
    try {
      for await (const event of ctx.event.subscribe({ signal })) {
        if (
          event.type === "permission.replied" &&
          event.data?.sessionID === context.sessionID &&
          event.data.requestID === id
        )
          return { reply: event.data.reply };
      }
      return {
        error: new Error("Permission event stream closed; decision refused"),
      };
    } catch (error) {
      return { error };
    }
  })();
  try {
    const response = await request(
      [
        "post",
        `/api/session/${encodeURIComponent(context.sessionID)}/permission`,
        "--data",
        JSON.stringify({
          id,
          agent: context.agent,
          source: {
            type: "tool",
            messageID: context.messageID,
            id: context.id,
          },
          action: "harness_operator",
          resources: [resource],
        }),
      ],
      signal,
    );
    const result = response.data ?? response;
    if (result.id !== id)
      throw new Error("Permission request identity mismatch");
    // The base policy allows unknown actions. That is not a human decision.
    if (result.effect !== "ask")
      throw new Error(
        "harness_operator must be configured as ask; decision refused",
      );
    const outcome = await decision;
    signal.throwIfAborted();
    if (outcome.error) throw outcome.error;
    if (outcome.reply !== "once")
      throw new Error("The operator must approve this transition once");
  } finally {
    controller.abort();
    await decision;
  }
}
