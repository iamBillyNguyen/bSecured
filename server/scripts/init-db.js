"use strict";

/**
 * Applies schema.sql to the database. Uses the DIRECT (unpooled) connection,
 * because Neon's pooled PgBouncer endpoint cannot run this multi-statement
 * migration reliably.
 *
 * Run with:  npm run db:init    (loads server/.env via node --env-file)
 */

const fs = require("fs");
const path = require("path");
const { createPool } = require("../store/pg");

(async () => {
  const pool = createPool({ direct: true });
  const sql = fs.readFileSync(path.join(__dirname, "..", "schema.sql"), "utf8");
  await pool.query(sql);
  console.log("schema applied");
  await pool.end();
})().catch((err) => {
  console.error("init-db failed:", err.message);
  process.exit(1);
});
