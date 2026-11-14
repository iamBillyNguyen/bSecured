-- bSecured report store schema (PostgreSQL / Neon).
-- Apply with: npm run db:init  (uses the direct, unpooled connection)
-- Safe to run repeatedly; every statement is IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS devices (
  device_id   TEXT PRIMARY KEY,
  project_id  TEXT        NOT NULL,
  public_key  BYTEA       NOT NULL,            -- raw 32-byte Ed25519 public key
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS reports (
  id           BIGSERIAL   PRIMARY KEY,
  project_id   TEXT        NOT NULL,
  device_id    TEXT        NOT NULL,
  build_id     TEXT        NOT NULL,
  threat_type  TEXT        NOT NULL,
  detected_at  TEXT        NOT NULL,           -- client clock, evidence only (stored as sent)
  received_at  TIMESTAMPTZ NOT NULL,           -- server clock, orders everything
  evidence     JSONB       NOT NULL DEFAULT '{}'::jsonb
);

-- Serves "this project's recent reports, newest first" (GET /v1/reports).
CREATE INDEX IF NOT EXISTS reports_project_recent
  ON reports (project_id, id DESC);
