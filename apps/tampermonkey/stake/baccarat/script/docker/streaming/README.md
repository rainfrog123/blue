# Baccarat Streaming Stack

Dockerized websocket collection stack:

- **Collector**: Node.js + `ws`
- **Short-term state**: Redis
- **Long-term logs**: TimescaleDB/PostgreSQL

## Run

From `baccarat/`:

```bash
docker compose up -d --build
```

## Config (editable from outside)

Edit:

- `streaming/config/ws-config.json`

This file is bind-mounted into the collector container.

## Notes

- Update `connections[].url` with your current session URL.
- If needed add cookies/headers under `connections[].headers`.
- Collector reconnects automatically when socket closes.

## Data locations

- Redis:
  - `baccarat:state:global`
  - `baccarat:tables` (set)
  - `baccarat:state:table:{tableId}`

- TimescaleDB table:
  - `ws_frames`
