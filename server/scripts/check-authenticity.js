"use strict";

/**
 * Report-authenticity check: proves that the server rejects a report that is not
 * signed by the registered device's key, and stores nothing from it.
 *
 * It registers a throwaway device under a throwaway dashboard key, then sends:
 *   1. a genuine report, signed with the device's key       -> expect 200 (control)
 *   2. a forged report, signed with an attacker's key       -> expect 401
 *   3. the genuine report's body altered, original signature -> expect 401
 *   4. a report from a device that was never registered     -> expect 401
 * and finally reads the project's reports, the same read the dashboard makes:
 * only the control may be stored.
 *
 * The server answers 401 {"error":"rejected"} for both an unknown device and a
 * bad signature, so case 1 is what shows the device is registered and case 2 is
 * therefore rejected for its signature alone.
 *
 * Each run leaves the throwaway device and the one genuine report in the store,
 * under a dashboard key that is discarded, so no dashboard ever shows them.
 *
 * Uses only Node built-ins, so it needs no `npm install`. Prints no keys.
 *
 * Run with:  node server/scripts/check-authenticity.js [server-url]
 *            (default: https://bsecured-server.onrender.com)
 */

const crypto = require("crypto");

const base = (process.argv[2] || "https://bsecured-server.onrender.com").replace(/\/+$/, "");

/**
 * Generates an Ed25519 keypair
 * @returns the private key, and the raw 32-byte public key as base64
 */
function newKeypair()
{
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return { privateKey, publicKeyB64: Buffer.from(raw).toString("base64") };
}

/**
 * Signs the exact body bytes, as the guard does
 * @param body the report body string
 * @param privateKey the Ed25519 private key to sign with
 * @returns the base64 signature for the X-BSec-Signature header
 */
function sign(body, privateKey)
{
  return crypto.sign(null, Buffer.from(body), privateKey).toString("base64");
}

/**
 * Builds a report body in the guard's wire format
 * @param deviceId the device the report claims to come from
 * @param issuer a marker stored in the evidence, to tell the cases apart
 * @returns the report as a JSON string
 */
function reportBody(deviceId, issuer)
{
  return JSON.stringify({
    v: 1,
    device_id: deviceId,
    build_id: "authenticity-check",
    detected_at: new Date().toISOString(),
    threat_type: "MITM_PIN_FAILURE",
    evidence: { observed_spki: "authenticity-check", system_trust_ok: true, issuer, proxy_env: null },
  });
}

/**
 * POSTs a body to the server
 * @param path the endpoint path
 * @param body the exact body string
 * @param headers extra request headers
 * @returns the HTTP status and the response text
 */
async function post(path, body, headers)
{
  const res = await fetch(base + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body,
  });
  return { status: res.status, text: await res.text() };
}

(async () => {
  const dashboardKey = crypto.randomBytes(32).toString("base64url");
  const deviceId = `dev-authcheck-${crypto.randomBytes(4).toString("hex")}`;
  const device = newKeypair();
  const attacker = newKeypair();

  const health = await (await fetch(`${base}/healthz`)).text();
  const registered = await post("/v1/devices",
    JSON.stringify({ device_id: deviceId, public_key: device.publicKeyB64 }),
    { Authorization: `Bearer ${dashboardKey}` });
  if (registered.status !== 200)
  {
    throw new Error(`device registration failed: ${registered.status} ${registered.text}`);
  }

  const genuine = reportBody(deviceId, "genuine");
  const forged = reportBody(deviceId, "forged");
  const altered = genuine.replace('"issuer":"genuine"', '"issuer":"altered"');
  const unregistered = reportBody(`dev-authcheck-unregistered-${crypto.randomBytes(4).toString("hex")}`, "unregistered");

  const cases = [
    ["genuine report, device's key (control)", 200, genuine, sign(genuine, device.privateKey)],
    ["forged report, attacker's key", 401, forged, sign(forged, attacker.privateKey)],
    ["altered body, original signature", 401, altered, sign(genuine, device.privateKey)],
    ["unregistered device", 401, unregistered, sign(unregistered, attacker.privateKey)],
  ];

  console.log(`server:  ${base}`);
  console.log(`health:  ${health}`);
  console.log(`device:  ${deviceId} (registered)\n`);

  let passed = true;
  for (const [name, expected, body, signature] of cases)
  {
    const res = await post("/v1/reports", body, { "X-BSec-Signature": signature });
    const ok = res.status === expected;
    passed = passed && ok;
    console.log(`${ok ? "PASS" : "FAIL"}  ${name.padEnd(40)} expected ${expected}, got ${res.status} ${res.text}`);
  }

  // Read back what the server kept, through the dashboard's own read interface
  const stored = await (await fetch(`${base}/v1/reports`, {
    headers: { Authorization: `Bearer ${dashboardKey}` },
  })).json();
  const kept = stored.map((r) => r.evidence.issuer);
  const onlyGenuine = kept.length === 1 && kept[0] === "genuine";
  passed = passed && onlyGenuine;
  console.log(`${onlyGenuine ? "PASS" : "FAIL"}  ${"stored for this project".padEnd(40)} ${kept.length} report(s): ${JSON.stringify(kept)}`);

  console.log(passed ? "\nall checks passed" : "\nFAILED");
  process.exit(passed ? 0 : 1);
})().catch((err) => {
  console.error("check-authenticity failed:", err.message);
  process.exit(1);
});
