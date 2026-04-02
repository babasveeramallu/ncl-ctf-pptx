PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS competitions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  start_ts    INTEGER,
  end_ts      INTEGER,
  notes       TEXT,
  created_at  INTEGER DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS challenges (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  comp_id        INTEGER REFERENCES competitions(id) ON DELETE CASCADE,
  title          TEXT NOT NULL,
  category       TEXT NOT NULL,
  difficulty     TEXT,
  points         INTEGER DEFAULT 0,
  status         TEXT DEFAULT 'unsolved',
  notes          TEXT,
  solved_at      INTEGER,
  time_spent_s   INTEGER DEFAULT 0,
  created_at     INTEGER DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_challenges_comp    ON challenges(comp_id);
CREATE INDEX IF NOT EXISTS idx_challenges_status  ON challenges(status);
CREATE INDEX IF NOT EXISTS idx_challenges_cat     ON challenges(category);

CREATE TABLE IF NOT EXISTS recipes (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  name           TEXT NOT NULL UNIQUE,
  description    TEXT,
  steps_json     TEXT NOT NULL,
  use_count      INTEGER DEFAULT 0,
  last_used_at   INTEGER,
  created_at     INTEGER DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS flags (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  challenge_id   INTEGER NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
  flag_value     TEXT NOT NULL,
  tool_used      TEXT,
  recipe_id      INTEGER REFERENCES recipes(id),
  submitted_at   INTEGER DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS tool_outputs (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  challenge_id   INTEGER REFERENCES challenges(id) ON DELETE SET NULL,
  module         TEXT NOT NULL,
  operation      TEXT NOT NULL,
  input_summary  TEXT,
  output_json    TEXT,
  elapsed_ms     INTEGER,
  success        INTEGER DEFAULT 1,
  created_at     INTEGER DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_tool_outputs_challenge ON tool_outputs(challenge_id);
CREATE INDEX IF NOT EXISTS idx_tool_outputs_created   ON tool_outputs(created_at DESC);
