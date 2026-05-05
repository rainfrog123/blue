# Baccarat Docker Usage Guide

This guide shows how to run and inspect the websocket collector stack under:

- `baccarat/docker/docker-compose.yml`

Stack components:

- `collector` (Node.js + `ws`)
- `redis` (short-term in-memory state)
- `timescaledb` (long-term frame logging)

---

## 1) Start / stop

From anywhere:

```bash
docker-compose -f "/allah/blue/web/apps/tampermonkey/stake/baccarat/docker/docker-compose.yml" up -d --build
```

Stop:

```bash
docker-compose -f "/allah/blue/web/apps/tampermonkey/stake/baccarat/docker/docker-compose.yml" down
```

Stop and delete volumes (DANGEROUS: wipes Redis + DB data):

```bash
docker-compose -f "/allah/blue/web/apps/tampermonkey/stake/baccarat/docker/docker-compose.yml" down -v
```

---

## 2) Update websocket session/config

Edit:

- `baccarat/docker/streaming/config/ws-config.json`

Important fields:

- `connections[0].url` (fresh `JSESSIONID` etc.)
- `connections[0].headers.Origin`
- `connections[0].headers.User-Agent`
- optional cookies if needed

After editing config:

```bash
docker restart baccarat-ws-collector
```

---

## 3) Check service health

```bash
docker-compose -f "/allah/blue/web/apps/tampermonkey/stake/baccarat/docker/docker-compose.yml" ps
```

Expected:

- `baccarat-redis` -> healthy
- `baccarat-timescaledb` -> healthy
- `baccarat-ws-collector` -> Up

Dashboard health quick-check:

```bash
curl http://127.0.0.1:8080/health
```

---

## 4) Check collector logs

Live logs:

```bash
docker logs -f baccarat-ws-collector
```

Last lines:

```bash
docker logs baccarat-ws-collector --tail 80
```

Healthy signs:

- `[infra] redis + postgres ready`
- `[pragmatic-game] connected`

Failure signs:

- `Unexpected server response: 401` -> session URL expired/invalid

---

## 5) Verify data is being retrieved

## A) PostgreSQL / TimescaleDB (long-term logs)

How many frames logged:

```bash
docker exec baccarat-timescaledb psql -U collector -d baccarat -c "SELECT count(*) AS frames, max(received_at) AS last_frame_at FROM ws_frames;"
```

Latest 20 frames:

```bash
docker exec baccarat-timescaledb psql -U collector -d baccarat -c "SELECT received_at, connection_name, event_type, table_id, seq FROM ws_frames ORDER BY received_at DESC LIMIT 20;"
```

Latest frames for one table:

```bash
docker exec baccarat-timescaledb psql -U collector -d baccarat -c "SELECT received_at, event_type, seq, payload_text FROM ws_frames WHERE table_id='cbcf6qas8fscb222' ORDER BY received_at DESC LIMIT 20;"
```

Counts by event type:

```bash
docker exec baccarat-timescaledb psql -U collector -d baccarat -c "SELECT event_type, count(*) FROM ws_frames GROUP BY event_type ORDER BY count(*) DESC LIMIT 20;"
```

## Easy views (latest snapshot)

The stack also provides two convenience views:

- `latest_table_state` -> latest row per `table_id`
- `latest_event_by_type` -> latest row per `(event_type, table scope)`

Latest table snapshot:

```bash
docker exec baccarat-timescaledb psql -U collector -d baccarat -c "SELECT table_id, last_event_type, last_seq, last_received_at FROM latest_table_state ORDER BY last_received_at DESC LIMIT 20;"
```

Inspect one table:

```bash
docker exec baccarat-timescaledb psql -U collector -d baccarat -c "SELECT * FROM latest_table_state WHERE table_id='cbcf6qas8fscb222';"
```

Latest event per type/scope:

```bash
docker exec baccarat-timescaledb psql -U collector -d baccarat -c "SELECT event_type, table_scope, seq, received_at FROM latest_event_by_type ORDER BY received_at DESC LIMIT 50;"
```

## B) Redis (short-term state)

Global state:

```bash
docker exec baccarat-redis redis-cli HGETALL baccarat:state:global
```

How many tables currently tracked:

```bash
docker exec baccarat-redis redis-cli SCARD baccarat:tables
```

List first few tables:

```bash
docker exec baccarat-redis redis-cli SMEMBERS baccarat:tables | head
```

Inspect one table state:

```bash
docker exec baccarat-redis redis-cli HGETALL baccarat:state:table:cbcf6qas8fscb222
```

---

## 6) Practical workflow

1. Start stack with `up -d --build`
2. Open dashboard: `http://127.0.0.1:8080`
3. Tail collector logs and ensure websocket is connected
4. Run frame count query in TimescaleDB every 10-20s and ensure count is increasing
5. Inspect Redis global state (`last_seq` should keep moving)
6. When session expires (`401`), update `ws-config.json` URL and restart collector

---

## 7) Web dashboard + API

The collector now exposes a web UI and JSON API on port `8080`.

- UI: `http://127.0.0.1:8080`
- Casino-style lobby UI: `http://127.0.0.1:8080/casino`
- Health: `GET /health`
- Global Redis snapshot: `GET /api/global`
- Latest per-table state (from SQL view): `GET /api/tables`
- Recent events: `GET /api/events?limit=120`
- Recent events for one table: `GET /api/events?table_id=<TABLE_ID>&limit=120`
- Table change timeline (friendly summaries): `GET /api/table/<TABLE_ID>/changes?limit=200`
- Live lobby snapshot feed: `GET /api/lobby`

Example:

```bash
curl "http://127.0.0.1:8080/api/events?table_id=cbcf6qas8fscb222&limit=20"
```

---

## 8) Troubleshooting

## Collector starts but no frames

- Check logs for `401`
- Replace session URL (`JSESSIONID`) with fresh one from browser capture
- Restart collector

### Verify game + lobby both ingesting

```bash
docker exec baccarat-timescaledb psql -U collector -d baccarat -c "SELECT connection_name, count(*) FROM ws_frames WHERE received_at > now() - interval '3 minutes' GROUP BY connection_name ORDER BY connection_name;"
```

Expected: rows for both `pragmatic-game` and `pragmatic-lobby`.

## TimescaleDB init issue

If schema is broken or you want a clean reset:

```bash
docker-compose -f "/allah/blue/web/apps/tampermonkey/stake/baccarat/docker/docker-compose.yml" down -v
docker-compose -f "/allah/blue/web/apps/tampermonkey/stake/baccarat/docker/docker-compose.yml" up -d --build
```

If schema changed and you need to re-apply SQL without full reset:

```bash
docker exec baccarat-timescaledb psql -U collector -d baccarat -f /docker-entrypoint-initdb.d/01-init.sql
```

## Redis/Postgres not healthy

Check container logs:

```bash
docker logs baccarat-redis --tail 120
docker logs baccarat-timescaledb --tail 120
```

