CREATE TABLE IF NOT EXISTS servers (
    address TEXT PRIMARY KEY,
    world_id BIGINT,
    name TEXT NOT NULL,
    description TEXT,
    status TEXT,
    topic_status JSONB,
    players INTEGER DEFAULT 0,
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS player_history (
    id SERIAL PRIMARY KEY,
    address TEXT NOT NULL,
    players INTEGER NOT NULL,
    recorded_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_player_history_address ON player_history(address);
CREATE INDEX IF NOT EXISTS idx_player_history_recorded_at ON player_history(recorded_at);
