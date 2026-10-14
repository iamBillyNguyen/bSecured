/**
 * bSecured Server
 * 
 * Author: Billy Nguyen - A01181323
 */

"use strict";

const http = require("http");
const https = require("https");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");

const PORT = Number(process.env.BSEC_PORT || 8000);
const HOST = process.env.BSEC_HOST || "127.0.0.1";
const MAX_BODY_BYTES = Number(process.env.BSEC_MAX_BODY_BYTES || 8192);
const KEEPALIVE_MS = 15000; // milliseconds
const MAX_REPORTS = Number(process.env.BSEC_MAX_REPORTS || 10000); // bounded in-memory queue

const LOOPBACK_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?$/;
const DEVICE_ID = /^[A-Za-z0-9._-]+$/;
const DASHBOARD_KEY = /^[A-Za-z0-9_-]{43}$/; // 32 random bytes, base64url, no padding
const TIMESTAMP = /T.*(Z|[+-]\d\d:\d\d)$/; // must carry a time zone

/** 
 * ErrorMessage class stores error status and reason of error
 * If error status is 401, return static public reason "rejected" to avoid probing for device ids or keys.
 */
class ErrorMessage extends Error 
{
  constructor(status, reason) 
  {
    super(reason);
    this.status = status;
    this.reason = reason;
    this.publicReason = status === 401 ? "rejected" : reason;
  }
}

/**
 * Gets project id from the dashboard key
 * @param key a base64 key
 * @returns the project id, the first 32 hex of the SHA-256 key
 */
function getProjectIdFromKey(key) 
{
  // Returns null if no dashboard key exists
  if (!DASHBOARD_KEY.test(key)) 
  {
    return null;
  }

  const raw = Buffer.from(key, "base64url");
  return crypto.createHash("sha256").update(raw).digest("hex").slice(0, 32);
}

/**
 * Gets project id from the request header's Auth
 * @param req a request containing the dashboard key in its header
 * @returns the project id retrieved from the request header's Auth
 */
function getProjectIdFromRequestAuth(req) 
{
  const [scheme, key] = (req.headers.authorization || "").split(" ");
  const projectId = scheme && scheme.toLowerCase() === "bearer" ? getProjectIdFromKey((key || "").trim()) : null;

  // Throws error if invalid (null) project id
  if (!projectId) 
  {
    throw new ErrorMessage(401, "bad_dashboard_key");
  }
  return projectId;
}

// Ed25519 verification from a raw 32-byte public key (no external dependency).
// A raw key is wrapped in the fixed 12-byte SPKI prefix before crypto reads it.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Verifies an Ed25519 detached signature over the exact message bytes
 * @param publicKey the device's raw 32-byte public key
 * @param message the exact bytes that were signed
 * @param signatureB64 the base64 signature from the X-BSec-Signature header
 * @returns true if the signature is valid, false for any failure
 */
function verifySignature(publicKey, message, signatureB64)
{
  if (!signatureB64)
  {
    return false;
  }

  try
  {
    const signature = Buffer.from(signatureB64, "base64");
    if (signature.length !== 64)
    {
      return false;
    }

    const key = crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
      format: "der",
      type: "spki",
    });
    return crypto.verify(null, message, key, signature);
  }
  catch
  {
    return false;
  }
}

/** In-memory store */
// TODO: To be replaced by a hosted DB
const devices = new Map(); // device_id -> { projectId, publicKey (Buffer) }
const reports = []; // bounded FIFO queue, newest last; capped at MAX_REPORTS
let nextReportId = 1; // monotonic, so ids stay unique after the queue drops old reports

/**
 * Registers a device, or re-keys one already in the same project
 * @param deviceId the device id to register
 * @param projectId the project the dashboard key opens
 * @param publicKey the device's raw 32-byte public key
 * @returns true if registered, false if the id belongs to another project
 */
function registerDevice(deviceId, projectId, publicKey)
{
  const existing = devices.get(deviceId);

  // Refuses a cross-project takeover of an existing device id
  if (existing && existing.projectId !== projectId)
  {
    return false;
  }

  devices.set(deviceId, { projectId, publicKey });
  return true;
}

/**
 * Stores one accepted report under its project
 * @param report the validated report
 * @param projectId the signing device's project
 * @param receivedAt the server clock timestamp
 * @returns the stored report, with its id
 */
function saveReport(report, projectId, receivedAt)
{
  const stored = {
    id: nextReportId++,
    projectId,
    device_id: report.device_id,
    build_id: report.build_id,
    threat_type: report.threat_type,
    detected_at: report.detected_at, // client clock, evidence only
    received_at: receivedAt, // server clock, orders everything
    evidence: report.evidence,
  };
  reports.push(stored);

  // Bounded queue: drop the oldest once the cap is reached, so attacker-controlled
  // report volume cannot grow memory without limit.
  if (reports.length > MAX_REPORTS)
  {
    reports.shift();
  }
  return stored;
}

/**
 * Gets a project's most recent reports, newest first
 * @param projectId the project to read
 * @param limit the most reports to return
 * @returns an array of stored reports
 */
function recentReports(projectId, limit)
{
  const out = [];
  for (let i = reports.length - 1; i >= 0 && out.length < limit; i--)
  {
    if (reports[i].projectId === projectId)
    {
      out.push(reports[i]);
    }
  }
  return out;
}

/**
 * Converts the report as JSON for the dashboard
 * @param r a stored report
 * @returns the report as plain JSON
 */
function reportJson(r)
{
  return {
    report_id: r.id,
    device_id: r.device_id,
    build_id: r.build_id,
    threat_type: r.threat_type,
    detected_at: r.detected_at,
    received_at: r.received_at,
    evidence: r.evidence,
  };
}

// Live fan-out: viewers grouped by project, so a report only reaches its own.
const viewers = new Map(); // projectId -> Set<res>

/**
 * Adds an open stream response to its project's set of viewers
 * @param projectId the project the viewer's key opens
 * @param res the open Server-Sent Events response
 */
function subscribe(projectId, res)
{
  if (!viewers.has(projectId))
  {
    viewers.set(projectId, new Set());
  }
  viewers.get(projectId).add(res);
}

/**
 * Removes a closed stream response, and the project's set once empty
 * @param projectId the project the viewer was watching
 * @param res the response that closed
 */
function unsubscribe(projectId, res)
{
  const set = viewers.get(projectId);
  if (set)
  {
    set.delete(res);
    if (set.size === 0)
    {
      viewers.delete(projectId);
    }
  }
}

/**
 * Writes one report as an SSE frame to every open stream of a project
 * @param projectId the project the report belongs to
 * @param event the report plus its ingest_ms
 */
function publish(projectId, event)
{
  const set = viewers.get(projectId);
  if (!set)
  {
    return;
  }

  const frame = `event: report\ndata: ${JSON.stringify(event)}\n\n`;
  for (const res of set)
  {
    res.write(frame);
  }
}

// Report validation: minimal, but a report can never name its own project.
const THREAT_TYPES = new Set(["MITM_PIN_FAILURE"]);

/**
 * Parses and validates the raw request body into a report
 * Only the known fields are copied, so a project named in the body is ignored.
 * @param raw the exact request body bytes
 * @returns a validated report, or null if the body is malformed
 */
function parseReport(raw)
{
  let body;
  try
  {
    body = JSON.parse(raw);
  }
  catch
  {
    return null;
  }

  if (typeof body !== "object" || body === null)
  {
    return null;
  }
  if (body.v !== 1)
  {
    return null;
  }
  if (typeof body.device_id !== "string" || !DEVICE_ID.test(body.device_id))
  {
    return null;
  }
  if (typeof body.build_id !== "string" || !body.build_id)
  {
    return null;
  }
  if (typeof body.detected_at !== "string" || !TIMESTAMP.test(body.detected_at))
  {
    return null;
  }
  if (!THREAT_TYPES.has(body.threat_type))
  {
    return null;
  }

  const evidence = body.evidence ?? {};
  if (typeof evidence !== "object" || Array.isArray(evidence))
  {
    return null;
  }

  const keys = Object.keys(evidence);
  if (keys.length > 32)
  {
    return null;
  }

  // Evidence must be a flat object of string, number, boolean or null values
  for (const k of keys)
  {
    const t = typeof evidence[k];
    if (evidence[k] !== null && t !== "string" && t !== "number" && t !== "boolean")
    {
      return null;
    }
  }

  return {
    device_id: body.device_id,
    build_id: body.build_id,
    detected_at: body.detected_at,
    threat_type: body.threat_type,
    evidence,
  };
}

/**
 * Gets the current server time as an ISO string
 * @returns the UTC time, e.g. 2026-10-13T18:22:04.113Z
 */
function isoNow()
{
  return new Date().toISOString();
}

/** bSecured Server */
const app = express();
app.disable("x-powered-by");

// CORS for the local dashboard only, GET only: a browser can never register a
// device or send a report cross-origin.
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowed = origin && LOOPBACK_ORIGIN.test(origin);

  if (allowed)
  {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET");
    res.setHeader("Access-Control-Allow-Headers", "Authorization");
  }

  if (req.method === "OPTIONS")
  {
    const method = req.headers["access-control-request-method"] || "GET";
    if (allowed && method === "GET")
    {
      return res.status(204).end();
    }
    return res.status(400).type("text/plain").end("CORS not allowed");
  }

  next();
});

// GET /healthz - check the server's health and liveness
app.get("/healthz", (req, res) => res.json({ ok: true, store: "memory" }));

// POST /v1/devices — register a build's device under the key's project.
app.post("/v1/devices", express.json({ limit: MAX_BODY_BYTES }), (req, res) => {
  const projectId = getProjectIdFromRequestAuth(req);
  const { device_id, public_key } = req.body || {};

  if (typeof device_id !== "string" || !DEVICE_ID.test(device_id))
  {
    throw new ErrorMessage(400, "malformed");
  }

  let publicKey;
  try
  {
    publicKey = Buffer.from(public_key, "base64");
  }
  catch
  {
    throw new ErrorMessage(400, "malformed");
  }

  if (publicKey.length !== 32)
  {
    throw new ErrorMessage(400, "malformed");
  }
  if (!registerDevice(device_id, projectId, publicKey))
  {
    throw new ErrorMessage(409, "device_id_taken");
  }

  res.json({ device_id });
});

// POST /v1/reports — verify a signed report and store it, over the exact bytes.
app.post("/v1/reports", express.raw({ type: "*/*", limit: MAX_BODY_BYTES }), (req, res) => {
  const started = process.hrtime.bigint();
  const raw = req.body; // exact bytes, as signed

  const report = parseReport(raw);
  if (!report)
  {
    throw new ErrorMessage(400, "malformed");
  }

  const device = devices.get(report.device_id);
  if (!device)
  {
    throw new ErrorMessage(401, "unknown_device");
  }

  if (!verifySignature(device.publicKey, raw, req.headers["x-bsec-signature"]))
  {
    throw new ErrorMessage(401, "bad_signature");
  }

  const stored = saveReport(report, device.projectId, isoNow());
  const ingestMs = Number(process.hrtime.bigint() - started) / 1e6;
  publish(device.projectId, { ...reportJson(stored), ingest_ms: Math.round(ingestMs * 1000) / 1000 });
  res.json({ report_id: stored.id, received_at: stored.received_at });
});

// GET /v1/reports — this project's recent reports, newest first.
app.get("/v1/reports", (req, res) => {
  const projectId = getProjectIdFromRequestAuth(req);
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
  res.json(recentReports(projectId, limit).map(reportJson));
});

// GET /v1/stream — a live Server-Sent Events feed of this project's reports.
app.get("/v1/stream", (req, res) => {
  const projectId = getProjectIdFromRequestAuth(req);
  res.status(200).set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no", // tell nginx-style proxies not to buffer the stream
  });
  res.write(": connected\n\n"); // flush headers through any proxy at once
  subscribe(projectId, res);

  const keepalive = setInterval(() => res.write(": keepalive\n\n"), KEEPALIVE_MS);
  req.on("close", () => {
    clearInterval(keepalive);
    unsubscribe(projectId, res);
  });
});

// Body-parser and ErrorMessage errors, turned into clean JSON.
app.use((err, req, res, next) => {
  if (err.type === "entity.too.large")
  {
    return res.status(413).json({ error: "too_large" });
  }
  if (err.type === "entity.parse.failed")
  {
    return res.status(400).json({ error: "malformed" });
  }
  if (err instanceof ErrorMessage)
  {
    console.log(`rejected path=${req.path} reason=${err.reason} status=${err.status}`);
    return res.status(err.status).json({ error: err.publicReason });
  }

  console.error(err);
  res.status(500).json({ error: "internal" });
});

/**
 * Creates the HTTP server, or an HTTPS server when a TLS cert and key are set
 * @returns the server to listen on
 */
function createServer()
{
  const keyPath = process.env.BSEC_TLS_KEY;
  const certPath = process.env.BSEC_TLS_CERT;

  if (keyPath && certPath)
  {
    return https.createServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }, app);
  }
  return http.createServer(app);
}

module.exports = { app, createServer };

// Start the server only when run directly, not when imported by the tests.
if (require.main === module)
{
  const server = createServer();
  server.listen(PORT, HOST, () => {
    const scheme = process.env.BSEC_TLS_KEY && process.env.BSEC_TLS_CERT ? "https" : "http";
    console.log(`bSecured server on ${scheme}://${HOST}:${PORT} (in-memory store)`);
  });
}
