PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS pairings (
    pairing_id TEXT PRIMARY KEY,
    origin TEXT NOT NULL,
    request_id TEXT NOT NULL,
    network TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    state TEXT NOT NULL,
    web_connected_at_ms INTEGER,
    phone_connected_at_ms INTEGER,
    closed_at_ms INTEGER,
    last_error TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pairing_id TEXT NOT NULL,
    direction TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    nonce_b64 TEXT NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    acked_at_ms INTEGER,
    UNIQUE(pairing_id, msg_id),
    FOREIGN KEY(pairing_id) REFERENCES pairings(pairing_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pairing_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    FOREIGN KEY(pairing_id) REFERENCES pairings(pairing_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_pairings_expires_at_ms ON pairings(expires_at_ms);
CREATE INDEX IF NOT EXISTS idx_pairings_state ON pairings(state);
CREATE INDEX IF NOT EXISTS idx_messages_pairing_id ON messages(pairing_id);
CREATE INDEX IF NOT EXISTS idx_messages_pairing_direction ON messages(pairing_id, direction);
CREATE INDEX IF NOT EXISTS idx_events_pairing_id ON events(pairing_id);
CREATE INDEX IF NOT EXISTS idx_events_created_at_ms ON events(created_at_ms);
