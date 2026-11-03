"use strict";

const { createPool } = require("./pg");

/**
 * PostgreSQL report store — the production back end (e.g. Neon). Reports and
 * devices persist across restarts. Uses the pooled connection for application
 * traffic; schema creation lives in scripts/init-db.js and uses the direct one.
 *
 * Implements the same async interface as store/memory.js.
 */
function createPostgresStore()
{
  const pool = createPool(); // pooled connection for query traffic

  // Verify connectivity at startup so a bad DATABASE_URL fails the deploy loudly
  // rather than on the first report. The schema itself is applied out of band by
  // `npm run db:init` (scripts/init-db.js).
  async function init()
  {
    await pool.query("SELECT 1");
  }

  /**
   * Registers a device, or re-keys one already in the same project.
   * The ON CONFLICT ... WHERE clause makes a cross-project takeover a no-op,
   * so it affects zero rows and we report failure.
   * @returns true if registered or re-keyed, false if the id belongs to another project
   */
  async function registerDevice(deviceId, projectId, publicKey)
  {
    const res = await pool.query(
      `INSERT INTO devices (device_id, project_id, public_key)
            VALUES ($1, $2, $3)
       ON CONFLICT (device_id) DO UPDATE
            SET public_key = EXCLUDED.public_key
          WHERE devices.project_id = EXCLUDED.project_id
      RETURNING device_id`,
      [deviceId, projectId, publicKey]
    );
    return res.rowCount === 1;
  }

  /**
   * Looks up a registered device
   * @returns { projectId, publicKey (Buffer) } or null
   */
  async function getDevice(deviceId)
  {
    const res = await pool.query(
      "SELECT project_id, public_key FROM devices WHERE device_id = $1",
      [deviceId]
    );
    if (res.rowCount === 0)
    {
      return null;
    }
    const row = res.rows[0];
    return { projectId: row.project_id, publicKey: row.public_key }; // bytea -> Buffer
  }

  /**
   * Stores one accepted report under its project
   * @returns the stored report, with its id
   */
  async function saveReport(report, projectId, receivedAt)
  {
    const res = await pool.query(
      `INSERT INTO reports
         (project_id, device_id, build_id, threat_type, detected_at, received_at, evidence)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
       RETURNING id`,
      [
        projectId,
        report.device_id,
        report.build_id,
        report.threat_type,
        report.detected_at,
        receivedAt,
        JSON.stringify(report.evidence),
      ]
    );
    return {
      id: Number(res.rows[0].id),
      projectId,
      device_id: report.device_id,
      build_id: report.build_id,
      threat_type: report.threat_type,
      detected_at: report.detected_at,
      received_at: receivedAt,
      evidence: report.evidence,
    };
  }

  /**
   * Gets a project's most recent reports, newest first
   * @returns an array of stored reports
   */
  async function recentReports(projectId, limit)
  {
    const res = await pool.query(
      `SELECT id, project_id, device_id, build_id, threat_type, detected_at, received_at, evidence
         FROM reports
        WHERE project_id = $1
        ORDER BY id DESC
        LIMIT $2`,
      [projectId, limit]
    );
    return res.rows.map((row) => ({
      id: Number(row.id),
      projectId: row.project_id,
      device_id: row.device_id,
      build_id: row.build_id,
      threat_type: row.threat_type,
      detected_at: row.detected_at,
      // received_at comes back as a Date from a timestamptz column; the in-memory
      // store returns the original ISO string, so normalise to match.
      received_at: row.received_at instanceof Date ? row.received_at.toISOString() : row.received_at,
      evidence: row.evidence,
    }));
  }

  async function close()
  {
    await pool.end();
  }

  return { name: "postgres", init, registerDevice, getDevice, saveReport, recentReports, close };
}

module.exports = { createPostgresStore };
