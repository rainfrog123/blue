CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS ws_frames (
    id BIGSERIAL,
    connection_name TEXT NOT NULL,
    direction TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type TEXT,
    table_id TEXT,
    seq BIGINT,
    payload_json JSONB,
    payload_text TEXT
);

SELECT create_hypertable('ws_frames', 'received_at', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_ws_frames_id ON ws_frames (id);
CREATE INDEX IF NOT EXISTS idx_ws_frames_table_time ON ws_frames (table_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_ws_frames_event_time ON ws_frames (event_type, received_at DESC);

CREATE OR REPLACE VIEW latest_table_state AS
SELECT DISTINCT ON (table_id)
    table_id,
    connection_name,
    event_type AS last_event_type,
    seq AS last_seq,
    received_at AS last_received_at,
    payload_json AS last_payload_json,
    payload_text AS last_payload_text
FROM ws_frames
WHERE table_id IS NOT NULL
ORDER BY table_id, received_at DESC;

CREATE OR REPLACE VIEW latest_event_by_type AS
SELECT DISTINCT ON (event_type, COALESCE(table_id, 'GLOBAL'))
    event_type,
    COALESCE(table_id, 'GLOBAL') AS table_scope,
    connection_name,
    seq,
    received_at,
    payload_json,
    payload_text
FROM ws_frames
ORDER BY event_type, COALESCE(table_id, 'GLOBAL'), received_at DESC;
