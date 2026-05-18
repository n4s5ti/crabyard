CREATE TABLE IF NOT EXISTS interactive_sessions (
  id TEXT PRIMARY KEY,
  repo TEXT NOT NULL,
  branch TEXT NOT NULL,
  runtime TEXT NOT NULL,
  command TEXT NOT NULL,
  prompt TEXT NOT NULL,
  owner TEXT NOT NULL,
  status TEXT NOT NULL,
  lease_id TEXT,
  attach_url TEXT,
  vnc_url TEXT,
  last_event TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  stopped_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_interactive_sessions_status ON interactive_sessions(status);
CREATE INDEX IF NOT EXISTS idx_interactive_sessions_owner ON interactive_sessions(owner);
CREATE INDEX IF NOT EXISTS idx_interactive_sessions_updated ON interactive_sessions(updated_at);

CREATE TABLE IF NOT EXISTS interactive_session_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (session_id) REFERENCES interactive_sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_interactive_session_events_session_id
  ON interactive_session_events(session_id, created_at);
