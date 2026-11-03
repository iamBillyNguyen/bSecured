"use strict";

/**
 * In-memory report store — the prototype back end. Data is lost on restart.
 * Used for the test suite and for local runs without a DATABASE_URL, so the
 * server has no external dependency unless Postgres is actually configured.
 *
 * Implements the same async interface as store/postgres.js.
 */
function createMemoryStore({ maxReports = 10000 } = {})
{
  const devices = new Map(); // device_id -> { projectId, publicKey (Buffer) }
  const reports = []; // bounded FIFO queue, newest last; capped at maxReports
  let nextReportId = 1; // monotonic, so ids stay unique after the queue drops old reports

  // Nothing to set up for the in-memory store.
  async function init() {}

  /**
   * Registers a device, or re-keys one already in the same project
   * @returns true if registered, false if the id belongs to another project
   */
  async function registerDevice(deviceId, projectId, publicKey)
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
   * Looks up a registered device
   * @returns { projectId, publicKey (Buffer) } or null
   */
  async function getDevice(deviceId)
  {
    return devices.get(deviceId) || null;
  }

  /**
   * Stores one accepted report under its project
   * @returns the stored report, with its id
   */
  async function saveReport(report, projectId, receivedAt)
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
    if (reports.length > maxReports)
    {
      reports.shift();
    }
    return stored;
  }

  /**
   * Gets a project's most recent reports, newest first
   * @returns an array of stored reports
   */
  async function recentReports(projectId, limit)
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

  // Nothing to tear down.
  async function close() {}

  return { name: "memory", init, registerDevice, getDevice, saveReport, recentReports, close };
}

module.exports = { createMemoryStore };
