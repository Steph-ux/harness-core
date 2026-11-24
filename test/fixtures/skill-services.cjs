/**
 * Trusted, synthetic services. Deliberately insecure branches bind only loopback.
 * Uploaded bytes stay in memory and are never interpreted or used as paths.
 */
const crypto = require("node:crypto");
const http = require("node:http");
const net = require("node:net");

const NOW = 1800000000;
const KEY = "synthetic-jwt-key-for-local-fixtures-only";
const ZONE = "fixture.test";
const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aRZsAAAAASUVORK5CYII=",
  "base64",
);
const PRIVATE = "JWT-PRIVATE-FIXTURE";

function mint(payload = {}, unsigned = false) {
  const header = Buffer.from(
    JSON.stringify({ alg: unsigned ? "none" : "HS256", typ: "JWT" }),
  ).toString("base64url");
  const claims = Buffer.from(
    JSON.stringify({ sub: "actor-a", aud: "fixture-api", exp: NOW + 60, ...payload }),
  ).toString("base64url");
  const input = `${header}.${claims}`;
  const signature = unsigned
    ? ""
    : crypto.createHmac("sha256", KEY).update(input).digest("base64url");
  return `${input}.${signature}`;
}

function authorized(token, allowUnsigned) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString());
    if (claims.aud !== "fixture-api" || !Number.isInteger(claims.exp) || claims.exp <= NOW)
      return false;
    if (header.alg === "none") return allowUnsigned && parts[2] === "";
    if (header.alg !== "HS256") return false;
    const expected = crypto.createHmac("sha256", KEY)
      .update(`${parts[0]}.${parts[1]}`).digest();
    const received = Buffer.from(parts[2], "base64url");
    return received.length === expected.length &&
      crypto.timingSafeEqual(expected, received);
  } catch {
    return false;
  }
}

async function bodyOf(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 32768) throw new Error("fixture body limit");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function multipart(body, contentType) {
  const boundary = /boundary="?([^";\s]+)/i.exec(contentType)?.[1];
  if (!boundary || boundary.length > 100) throw new Error("fixture boundary");
  const split = body.indexOf("\r\n\r\n");
  const end = body.lastIndexOf(`\r\n--${boundary}--`);
  if (split < 0 || end <= split) throw new Error("fixture multipart shape");
  const headers = body.subarray(0, split).toString("latin1");
  const filename = /filename="([^"]{1,100})"/i.exec(headers)?.[1];
  if (!filename) throw new Error("fixture filename");
  return { filename, bytes: body.subarray(split + 4, end) };
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  return server.address().port;
}

async function openHttp() {
  const uploads = new Map();
  let sequence = 0;
  const server = http.createServer(async (request, response) => {
    const send = (status, value, type = "application/json") => {
      response.writeHead(status, { "Content-Type": type, Connection: "close" });
      response.end(Buffer.isBuffer(value) ? value : JSON.stringify(value));
    };
    try {
      const route = request.url;
      if (["/jwt/strict", "/jwt/unsigned", "/jwt/soft-login"].includes(route)) {
        const token = (request.headers.authorization || "").replace(/^Bearer /, "");
        if (authorized(token, route === "/jwt/unsigned"))
          return send(200, { marker: PRIVATE, actor: "actor-a" });
        if (route === "/jwt/soft-login")
          return send(200, Buffer.from("<html>Public login form</html>"), "text/html");
        return send(401, { error: "denied" });
      }
      const actor = { "Bearer fixture-a": "actor-a", "Bearer fixture-b": "actor-b" }[
        request.headers.authorization
      ];
      if (!actor) return send(401, { error: "authentication required" });
      if (request.method === "POST" &&
          ["/upload/strict", "/upload/leaky", "/upload/static"].includes(route)) {
        if (sequence >= 16) return send(429, { error: "fixture object limit" });
        const file = multipart(await bodyOf(request), request.headers["content-type"] || "");
        if (route !== "/upload/static" &&
            !file.bytes.subarray(0, 8).equals(PNG.subarray(0, 8)))
          return send(415, { error: "PNG signature required" });
        const id = String(++sequence);
        uploads.set(id, { ...file, actor, mode: route });
        return send(201, { url: `/files/${id}` });
      }
      const id = /^\/files\/(\d+)$/.exec(route)?.[1];
      const file = uploads.get(id);
      if (!file) return send(404, { error: "missing" });
      if (file.mode !== "/upload/leaky" && file.actor !== actor)
        return send(403, { error: "owner required" });
      return send(200, file.bytes,
        file.mode === "/upload/static" ? "application/x-httpd-php" : "image/png");
    } catch {
      if (!response.headersSent) send(400, { error: "invalid fixture request" });
      else response.destroy();
    }
  });
  server.requestTimeout = 3000;
  server.headersTimeout = 3000;
  const port = await listen(server);
  return {
    base: `http://127.0.0.1:${port}`,
    close: async () => {
      const closed = new Promise((resolve) => server.close(resolve));
      server.closeAllConnections();
      await closed;
      uploads.clear();
    },
  };
}

function name(value) {
  return Buffer.concat([
    ...value.split(".").map((label) => Buffer.concat([
      Buffer.from([label.length]), Buffer.from(label, "ascii"),
    ])),
    Buffer.from([0]),
  ]);
}

function numbers(...values) {
  const buffer = Buffer.alloc(values.length * 2);
  values.forEach((value, index) => buffer.writeUInt16BE(value, index * 2));
  return buffer;
}

const QUESTION = Buffer.concat([name(ZONE), numbers(252, 1)]);
const QUERY = Buffer.concat([numbers(0x4a50, 0, 1, 0, 0, 0), QUESTION]);

function soa(serial) {
  const timing = Buffer.alloc(20);
  [serial, 60, 60, 3600, 60].forEach((value, index) =>
    timing.writeUInt32BE(value, index * 4));
  return Buffer.concat([name(`ns.${ZONE}`), name(`hostmaster.${ZONE}`), timing]);
}

function rr(type, data) {
  const ttl = Buffer.alloc(4);
  ttl.writeUInt32BE(60);
  return Buffer.concat([name(ZONE), numbers(type, 1), ttl, numbers(data.length), data]);
}

function message(records, rcode = 0, question = false) {
  const payload = Buffer.concat([
    numbers(0x4a50, 0x8400 | rcode, question ? 1 : 0, records.length, 0, 0),
    ...(question ? [QUESTION] : []),
    ...records,
  ]);
  return Buffer.concat([numbers(payload.length), payload]);
}

async function openDns(mode) {
  const sockets = new Set();
  const first = message([rr(6, soa(7)), rr(1, Buffer.from([192, 0, 2, 10]))], 0, true);
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
    socket.setTimeout(3000, () => socket.destroy());
    let received = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      received = Buffer.concat([received, chunk]);
      if (received.length > 512) return socket.destroy();
      if (received.length < QUERY.length + 2) return;
      if (!received.subarray(2).equals(QUERY)) return socket.destroy();
      socket.removeAllListeners("data");
      if (mode === "silent") return;
      if (mode === "refused") return socket.end(message([], 5, true));
      if (mode === "incomplete") return socket.end(first);
      socket.end(Buffer.concat([
        first, message([rr(6, soa(mode === "mismatched-soa" ? 8 : 7))]),
      ]));
    });
  });
  const port = await listen(server);
  return {
    port,
    close: async () => {
      const closed = new Promise((resolve) => server.close(resolve));
      for (const socket of sockets) socket.destroy();
      await closed;
    },
  };
}

module.exports = { openHttp, openDns, mint, PNG, PRIVATE, QUERY, ZONE };
