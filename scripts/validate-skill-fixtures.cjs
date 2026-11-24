#!/usr/bin/env node
/**
 * Behavioral smoke checks for three playbooks, using trusted authored fixtures.
 * No target program is executed. No external endpoint or credential is accepted.
 * Passing these checks does not validate every branch or an agent's skill usage.
 */
const assertDefault = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");
const services = require("../test/fixtures/skill-services.cjs");

const exec = promisify(execFile);
const ROOT = path.resolve(__dirname, "..");
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");

function recipe(skill, select) {
  const body = fs.readFileSync(path.join(ROOT, ".opencode/skills", skill, "SKILL.md"), "utf8");
  const commands = [...body.matchAll(/^cyber_process argv=(\[.+\])$/gm)]
    .map((match) => JSON.parse(match[1]));
  const argv = commands.find(select);
  if (!argv) throw new Error(`Missing executable recipe: ${skill}`);
  return { skill, sha256: hash(body), argv };
}

function parseAxfr(wire) {
  const records = [];
  let frame = 0;
  while (frame < wire.length) {
    if (frame + 2 > wire.length) return "incomplete";
    const length = wire.readUInt16BE(frame);
    const end = frame + 2 + length;
    if (end > wire.length || length < 12) return "incomplete";
    const packet = wire.subarray(frame + 2, end);
    frame = end;
    if (packet.readUInt16BE(0) !== 0x4a50 || !(packet.readUInt16BE(2) & 0x8000))
      return "invalid-response";
    const rcode = packet.readUInt16BE(2) & 15;
    if (rcode === 5) return "denied";
    if (rcode !== 0) return "invalid-response";
    let offset = 12;
    function readName() {
      const labels = [];
      for (let count = 0; count < 128; count++) {
        if (offset >= packet.length) throw new Error("truncated DNS name");
        const size = packet[offset++];
        if (size === 0) return labels.join(".");
        // This fixture client intentionally handles uncompressed names only.
        if (size > 63 || offset + size > packet.length)
          throw new Error("unsupported or truncated fixture DNS label");
        labels.push(packet.subarray(offset, offset + size).toString("ascii"));
        offset += size;
      }
      throw new Error("fixture DNS label limit");
    }
    const questions = packet.readUInt16BE(4);
    const answers = packet.readUInt16BE(6);
    if (questions > 1 || answers > 64) return "invalid-response";
    for (let index = 0; index < questions; index++) {
      if (readName() !== services.ZONE ||
          packet.readUInt16BE(offset) !== 252 ||
          packet.readUInt16BE(offset + 2) !== 1) return "invalid-response";
      offset += 4;
    }
    for (let index = 0; index < answers; index++) {
      const owner = readName();
      if (offset + 10 > packet.length) return "incomplete";
      const type = packet.readUInt16BE(offset);
      const klass = packet.readUInt16BE(offset + 2);
      const size = packet.readUInt16BE(offset + 8);
      offset += 10;
      if (offset + size > packet.length) return "incomplete";
      records.push({ owner, type, klass, data: packet.subarray(offset, offset + size) });
      offset += size;
    }
    if (offset !== packet.length || records.length > 128) return "invalid-response";
  }
  const first = records[0];
  const last = records.at(-1);
  return records.length >= 2 &&
    first.type === 6 && last.type === 6 &&
    first.owner === services.ZONE && last.owner === services.ZONE &&
    first.klass === 1 && last.klass === 1 && first.data.equals(last.data)
    ? "complete"
    : "incomplete";
}

async function dnsExchange(port) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    const socket = net.createConnection({ host: "127.0.0.1", port });
    socket.setTimeout(500);
    socket.on("connect", () => {
      const length = Buffer.alloc(2);
      length.writeUInt16BE(services.QUERY.length);
      socket.write(Buffer.concat([length, services.QUERY]));
    });
    socket.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > 8192) return socket.destroy(new Error("DNS fixture byte limit"));
      chunks.push(chunk);
    });
    socket.on("end", () => resolve({ wire: Buffer.concat(chunks), timedOut: false }));
    socket.on("timeout", () => {
      socket.destroy();
      resolve({ wire: Buffer.concat(chunks), timedOut: true });
    });
    socket.on("error", reject);
  });
}

async function validate({ assert = assertDefault } = {}) {
  // Recipe failures occur before resources are allocated.
  const jwt = recipe("harness-jwt", (argv) => argv[0] === "node" && argv[1] === "-e");
  const dns = recipe("harness-dns-enum", (argv) => argv[0] === "dig");
  const upload = recipe("harness-file-upload", (argv) => argv.includes("-F"));
  const parent = process.platform === "win32"
    ? path.join(os.tmpdir(), "opencode") : os.tmpdir();
  fs.mkdirSync(parent, { recursive: true });
  const scratch = fs.mkdtempSync(path.join(parent, "skill-fixtures-"));
  const env = {
    PATH: process.env.PATH || "",
    ...(process.platform === "win32"
      ? { SystemRoot: process.env.SystemRoot || "C:\\Windows" } : {}),
    HOME: scratch, USERPROFILE: scratch, TEMP: scratch, TMP: scratch,
    XDG_CONFIG_HOME: scratch,
  };
  const curl = process.platform === "win32"
    ? path.join(env.SystemRoot, "System32", "curl.exe") : "curl";
  const options = { cwd: scratch, env, timeout: 5000, maxBuffer: 65536, windowsHide: true };
  const report = {
    scope: "trusted-local-fixtures",
    address: "127.0.0.1",
    recipes: [jwt, dns, upload].map(({ skill, sha256 }) => ({ skill, sha256 })),
    limits: [
      "dig CLI not exercised",
      "DNS client covers uncompressed synthetic AXFR over TCP, not production DNS parsing",
      "No PHP/browser execution, JWKS, key confusion or real target application tested",
      "These deterministic checks do not evaluate model/agent adherence to a skill",
    ],
    cases: [],
  };
  let http;
  let request = 0;
  function record(domain, kind, id, bytes, actual, expected) {
    assert.deepEqual(actual, expected, id);
    report.cases.push({
      domain, kind, id, verdict: "pass", actual, expected, outputHash: hash(bytes),
    });
  }
  async function curlRequest(argv, bearer) {
    const number = ++request;
    const headers = path.join(scratch, `response-${number}.headers`);
    const body = path.join(scratch, `response-${number}.body`);
    const authorization = path.join(scratch, `request-${number}.headers`);
    fs.writeFileSync(authorization, `Authorization: Bearer ${bearer}\n`, { mode: 0o600 });
    const url = new URL(argv.at(-1));
    assert.equal(url.hostname, "127.0.0.1", "requests remain on loopback");
    assert.equal(url.origin, http.base, "requests stay on the owned fixture");
    await exec(curl, [
      "--disable", "--noproxy", "*", "--proto", "=http",
      "--connect-timeout", "1", "--max-time", "3",
      "-H", `@${authorization}`, "--dump-header", headers, "--output", body,
      ...argv,
    ], options);
    const headerText = fs.readFileSync(headers, "utf8");
    const status = Number(/^HTTP\/[\d.]+ (\d+)/m.exec(headerText)?.[1]);
    assert.ok(status, "actual HTTP response status was recorded");
    return { status, headers: headerText, body: fs.readFileSync(body) };
  }
  async function uploadFile(file, route) {
    const argv = upload.argv.slice(1).map((item) => item
      .replace("<fixture-file>", file)
      .replace("<approved-upload-url>", `${http.base}${route}`));
    // Store headers in the per-request artifact instead of curl's stdout.
    const dump = argv.indexOf("-D");
    if (dump >= 0) argv.splice(dump, 2);
    return curlRequest(argv, "fixture-a");
  }
  try {
    http = await services.openHttp();
    const token = services.mint();
    const parts = token.split(".");
    const signature = Buffer.from(parts[2], "base64url");
    signature[0] ^= 1;
    const flipped = `${parts[0]}.${parts[1]}.${signature.toString("base64url")}`;
    const tokenFile = path.join(scratch, "synthetic.jwt");
    fs.writeFileSync(tokenFile, token, { mode: 0o600 });
    const decoded = await exec(process.execPath, jwt.argv.slice(1).map(
      (item) => item.replace("<restricted-token-file>", tokenFile),
    ), options);
    const decodedBody = JSON.parse(decoded.stdout);
    record("jwt", "positive", "jwt.offline-recipe", decoded.stdout,
      { sha256: decodedBody.sha256, headerNames: decodedBody.headerNames },
      { sha256: hash(token), headerNames: ["alg", "typ"] });
    assert.ok(!decoded.stdout.includes(token), "offline recipe does not print its input token");

    for (const [id, kind, route, value, status, marker] of [
      ["jwt.valid-owner", "positive", "/jwt/strict", token, 200, true],
      ["jwt.flipped-signature", "negative", "/jwt/strict", flipped, 401, false],
      ["jwt.public-login-200", "false-positive", "/jwt/soft-login", flipped, 200, false],
      ["jwt.unsigned-lab-access", "positive", "/jwt/unsigned", services.mint({}, true), 200, true],
      ["jwt.unsigned-strict-denial", "negative", "/jwt/strict", services.mint({}, true), 401, false],
      ["jwt.wrong-audience", "negative", "/jwt/strict", services.mint({ aud: "other-api" }), 401, false],
    ]) {
      const response = await curlRequest(["-sS", `${http.base}${route}`], value);
      record("jwt", kind, id, response.body,
        { status: response.status, privateMarker: response.body.includes(services.PRIVATE) },
        { status, privateMarker: marker });
    }
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const alias = parts[2].slice(0, -1) +
      alphabet[alphabet.indexOf(parts[2].at(-1)) | 1];
    assert.notEqual(alias, parts[2], "padding-bit mutation changes serialization");
    assert.deepEqual(Buffer.from(alias, "base64url"), Buffer.from(parts[2], "base64url"),
      "padding-bit mutation does not change signature bytes");
    const aliasResponse = await curlRequest(
      ["-sS", `${http.base}/jwt/strict`], `${parts[0]}.${parts[1]}.${alias}`,
    );
    record("jwt", "false-positive", "jwt.padding-alias", aliasResponse.body,
      {
        status: aliasResponse.status,
        privateMarker: aliasResponse.body.includes(services.PRIVATE),
        signatureBytesChanged: false,
      },
      { status: 200, privateMarker: true, signatureBytesChanged: false });

    assert.ok(dns.argv.includes("+tries=1"), "DNS recipe does not schedule retries");
    assert.ok(dns.argv.includes("+time=5"), "DNS recipe has a bounded deadline");
    for (const [mode, kind, expected] of [
      ["complete", "positive", "complete"],
      ["refused", "negative", "denied"],
      ["incomplete", "false-positive", "incomplete"],
      ["mismatched-soa", "false-positive", "incomplete"],
      ["silent", "false-positive", "not-tested"],
    ]) {
      const server = await services.openDns(mode);
      try {
        const result = await dnsExchange(server.port);
        const actual = result.timedOut ? "not-tested" : parseAxfr(result.wire);
        record("dns", kind, `dns.${mode}`, result.wire, actual, expected);
      } finally {
        await server.close();
      }
    }

    const imageFile = path.join(scratch, "fixture.png");
    const invalidFile = path.join(scratch, "invalid.png");
    const sourceFile = path.join(scratch, "literal.php");
    const source = Buffer.from('<?php echo "CANARY"; /* inert bytes, never interpreted */ ?>');
    fs.writeFileSync(imageFile, services.PNG);
    fs.writeFileSync(invalidFile, "not an image");
    fs.writeFileSync(sourceFile, source);
    const strict = await uploadFile(imageFile, "/upload/strict");
    assert.equal(strict.status, 201, "the playbook multipart recipe uploads a real fixture");
    const strictUrl = JSON.parse(strict.body).url;
    const own = await curlRequest(["-sS", `${http.base}${strictUrl}`], "fixture-a");
    record("upload", "positive", "upload.owner-read", own.body,
      { status: own.status, sha256: hash(own.body) }, { status: 200, sha256: hash(services.PNG) });
    const denied = await curlRequest(["-sS", `${http.base}${strictUrl}`], "fixture-b");
    record("upload", "negative", "upload.owner-boundary", denied.body, denied.status, 403);
    const leaky = await uploadFile(imageFile, "/upload/leaky");
    assert.equal(leaky.status, 201);
    const cross = await curlRequest(
      ["-sS", `${http.base}${JSON.parse(leaky.body).url}`], "fixture-b",
    );
    record("upload", "positive", "upload.cross-owner-leak", cross.body,
      { status: cross.status, sha256: hash(cross.body) }, { status: 200, sha256: hash(services.PNG) });
    const rejected = await uploadFile(invalidFile, "/upload/strict");
    record("upload", "negative", "upload.invalid-magic", rejected.body, rejected.status, 415);
    const stored = await uploadFile(sourceFile, "/upload/static");
    assert.equal(stored.status, 201);
    const retrieved = await curlRequest(
      ["-sS", `${http.base}${JSON.parse(stored.body).url}`], "fixture-a",
    );
    record("upload", "false-positive", "upload.literal-source-not-execution", retrieved.body,
      {
        status: retrieved.status,
        phpContentType: /content-type: application\/x-httpd-php/i.test(retrieved.headers),
        unchangedSource: retrieved.body.equals(source),
      },
      { status: 200, phpContentType: true, unchangedSource: true });
    return report;
  } finally {
    try {
      if (http) await http.close();
    } finally {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  }
}

module.exports = { validate };

if (require.main === module) {
  validate().then((report) => {
    if (process.argv.includes("--json")) console.log(JSON.stringify(report, null, 2));
    else {
      for (const item of report.cases)
        console.log(`PASS ${item.id} [${item.kind}]`);
      console.log(`PASS ${report.cases.length} cases; 3 domains; loopback fixtures only`);
      for (const limit of report.limits) console.log(`LIMIT ${limit}`);
    }
  }).catch((error) => {
    console.error(error.stack);
    process.exitCode = 1;
  });
}
