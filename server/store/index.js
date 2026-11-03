"use strict";

const { createMemoryStore } = require("./memory");

/**
 * Selects the report store:
 *   - BSEC_STORE=memory | postgres forces a back end, regardless of DATABASE_URL.
 *   - otherwise, PostgreSQL when DATABASE_URL is set (production), else in-memory
 *     (the prototype, and the test suite).
 *
 * The Postgres module (and its `pg` dependency) is required lazily, so a
 * memory-only run — including `node --test` — never needs `pg` loaded.
 */
function createStore({ maxReports } = {})
{
  const override = (process.env.BSEC_STORE || "").toLowerCase();
  const usePostgres = override === "postgres" || (override !== "memory" && !!process.env.DATABASE_URL);

  if (usePostgres)
  {
    const { createPostgresStore } = require("./postgres");
    return createPostgresStore();
  }
  return createMemoryStore({ maxReports });
}

module.exports = { createStore };
