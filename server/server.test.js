"use strict";

// Tests for the bSecured Express server. Run with: node --test
// Uses only the Node built-ins (node:test, node:assert, node:crypto, node:http)
// and the global fetch; no external test dependencies.

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const crypto = require("node:crypto");

const { app } = require("./server.js");

let server;
let base;

test.before(async () => {
  server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => new Promise((resolve) => server.close(resolve)));

// --- helpers ---------------------------------------------------------------

function newDashboardKey() {
  return crypto.randomBytes(32).toString("base64url"); // 43 chars, no padding
}

function newKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const rawPublic = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return { privateKey, publicKeyB64: Buffer.from(rawPublic).toString("base64") };
}

function uniqueDeviceId(prefix = "dev") {
  return `${prefix}-${crypto.randomBytes(4).toString("hex")}`;
}

function reportBody(deviceId, overrides = {}) {
  return JSON.stringify({
    v: 1,
    device_id: deviceId,
    build_id: "bsec-test",
    detected_at: "2026-10-13T18:22:04.031Z",
    threat_type: "MITM_PIN_FAILURE",
    evidence: { observed_spki: "abc=", system_trust_ok: true, issuer: "mitmproxy", proxy_env: null },
    ...overrides,
  });
}

function registerDevice(dashboardKey, deviceId, publicKeyB64) {
  return fetch(`${base}/v1/devices`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${dashboardKey}` },
    body: JSON.stringify({ device_id: deviceId, public_key: publicKeyB64 }),
  });
}

// Sign the exact body bytes and POST the report. `signWith` lets a test forge.
function sendReport(deviceId, privateKey, { overrides = {}, signWith } = {}) {
  const body = reportBody(deviceId, overrides);
  const signature = crypto.sign(null, Buffer.from(body), signWith || privateKey).toString("base64");
  return fetch(`${base}/v1/reports`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-BSec-Signature": signature },
    body,
  });
}

function listReports(dashboardKey) {
  return fetch(`${base}/v1/reports`, { headers: { Authorization: `Bearer ${dashboardKey}` } });
}

// A dashboard key plus one registered device, as the bsecured tool would set up.
async function makeProject(prefix) {
  const key = newDashboardKey();
  const deviceId = uniqueDeviceId(prefix);
  const { privateKey, publicKeyB64 } = newKeypair();
  const r = await registerDevice(key, deviceId, publicKeyB64);
  assert.equal(r.status, 200, await r.text());
  return { key, deviceId, privateKey };
}

// --- tests -----------------------------------------------------------------

test("a signed report from a registered device is accepted and listed", async () => {
  const alice = await makeProject("alice");
  assert.equal((await sendReport(alice.deviceId, alice.privateKey)).status, 200);

  const listed = await (await listReports(alice.key)).json();
  assert.equal(listed.length, 1);
  assert.equal(listed[0].device_id, alice.deviceId);
  assert.equal(listed[0].threat_type, "MITM_PIN_FAILURE");
});

test("a forged signature is rejected and nothing is stored", async () => {
  const alice = await makeProject("alice");
  const attacker = newKeypair();

  const r = await sendReport(alice.deviceId, alice.privateKey, { signWith: attacker.privateKey });
  assert.equal(r.status, 401);
  assert.deepEqual(await r.json(), { error: "rejected" });

  assert.deepEqual(await (await listReports(alice.key)).json(), []);
});

test("a report from an unregistered device is rejected", async () => {
  const ghost = newKeypair();
  const r = await sendReport(uniqueDeviceId("ghost"), ghost.privateKey);
  assert.equal(r.status, 401);
  assert.deepEqual(await r.json(), { error: "rejected" });
});

test("reading requires a valid dashboard key", async () => {
  assert.equal((await fetch(`${base}/v1/reports`)).status, 401);
  assert.equal((await fetch(`${base}/v1/stream`)).status, 401);
  assert.equal((await fetch(`${base}/v1/reports`, { headers: { Authorization: "Bearer too-short" } })).status, 401);
});

test("each project sees only its own reports", async () => {
  const alice = await makeProject("alice");
  const bob = await makeProject("bob");

  await sendReport(alice.deviceId, alice.privateKey);
  await sendReport(alice.deviceId, alice.privateKey);
  await sendReport(bob.deviceId, bob.privateKey);

  const aliceReports = await (await listReports(alice.key)).json();
  const bobReports = await (await listReports(bob.key)).json();
  assert.equal(aliceReports.length, 2);
  assert.ok(aliceReports.every((r) => r.device_id === alice.deviceId));
  assert.equal(bobReports.length, 1);
  assert.equal(bobReports[0].device_id, bob.deviceId);
});

test("a device id cannot be taken over by another project", async () => {
  const alice = await makeProject("shared");
  const strangerKey = newDashboardKey();
  const stranger = newKeypair();

  const r = await registerDevice(strangerKey, alice.deviceId, stranger.publicKeyB64);
  assert.equal(r.status, 409);
  // Alice's original device still works.
  assert.equal((await sendReport(alice.deviceId, alice.privateKey)).status, 200);
});

test("an oversized body is rejected with 413", async () => {
  const r = await fetch(`${base}/v1/reports`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "x".repeat(9000),
  });
  assert.equal(r.status, 413);
  assert.deepEqual(await r.json(), { error: "too_large" });
});

test("invalid JSON is rejected with 400", async () => {
  const r = await fetch(`${base}/v1/reports`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{not json",
  });
  assert.equal(r.status, 400);
  assert.deepEqual(await r.json(), { error: "malformed" });
});

test("an unknown threat type is rejected with 400", async () => {
  const alice = await makeProject("alice");
  const r = await sendReport(alice.deviceId, alice.privateKey, { overrides: { threat_type: "SOMETHING_ELSE" } });
  assert.equal(r.status, 400);
});

test("a report cannot name its own project", async () => {
  const alice = await makeProject("alice");
  const bob = await makeProject("bob");

  // Alice's device signs a report whose body tries to claim bob's project id.
  const r = await sendReport(alice.deviceId, alice.privateKey, { overrides: { project_id: "someone-elses" } });
  assert.equal(r.status, 200); // the stray field is ignored, not trusted

  // It is filed under Alice (the signer), never under the project the body named.
  assert.equal((await (await listReports(alice.key)).json()).length, 1);
  assert.deepEqual(await (await listReports(bob.key)).json(), []);
});
