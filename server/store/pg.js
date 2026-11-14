"use strict";

const { Pool } = require("pg");

/**
 * Decides the TLS setting for a Postgres connection.
 *   DATABASE_SSL=disable  -> no TLS (local Postgres over localhost only)
 *   (unset)               -> verify the certificate for a remote host (Neon's
 *                            certificate is publicly trusted, so this works out
 *                            of the box); no TLS for a local host.
 *
 * There is deliberately no "skip verification" option. bSecured exists to detect
 * man-in-the-middle interception; it will not ship a switch that turns off the
 * very check it is about. If a private CA is ever required, trust it through the
 * standard NODE_EXTRA_CA_CERTS environment variable instead of disabling the check.
 */
function sslConfig(url)
{
  const mode = (process.env.DATABASE_SSL || "").toLowerCase();
  if (mode === "disable") return false;

  const local = /@(localhost|127\.0\.0\.1|\[::1\])[:/]/.test(url);
  return local ? false : { rejectUnauthorized: true };
}

/**
 * Picks the connection string. The application uses the pooled DATABASE_URL;
 * schema migrations pass direct=true to prefer the unpooled connection, because
 * Neon's pooled (PgBouncer, transaction-mode) endpoint cannot run multi-statement
 * or session-state migrations reliably. `neon env pull` writes both variables.
 */
function pickUrl(direct)
{
  if (direct)
  {
    return process.env.DATABASE_URL_UNPOOLED || process.env.DATABASE_URL;
  }
  return process.env.DATABASE_URL;
}

/**
 * Creates a Postgres connection pool from the environment
 * @param direct true to prefer the direct (unpooled) URL, for migrations
 * @returns a pg Pool
 */
function createPool({ direct = false } = {})
{
  const connectionString = pickUrl(direct);
  if (!connectionString)
  {
    throw new Error("DATABASE_URL is not set");
  }
  return new Pool({
    connectionString,
    ssl: sslConfig(connectionString),
    max: Number(process.env.PGPOOL_MAX || 5),
  });
}

module.exports = { createPool, sslConfig };
