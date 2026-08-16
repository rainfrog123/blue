# Beszel Hub stack

Central monitoring Hub (PocketBase) + optional **local** agent. Remote VPS agents use [`../beszel-agent/`](../beszel-agent/).

| Script | Role |
| --- | --- |
| **`setup-hub.sh <host>`** | First-time bootstrap (admin, universal token, fleet `site.env`, local agent) |
| **`up.sh <host>`** | Start / restart Hub (requires `hosts/<host>/beszel/HUB`) |
| `docker-compose.yml` | `beszel` + profile `agent` |
| `.env.example` | Template for `hosts/<host>/beszel/site.env` |

## First-time (new Hub host)

```bash
# Optional: APP_URL=https://beszel.example.com ADMIN_EMAIL=you@x.com
bash cloud/common/stacks/beszel/setup-hub.sh azure

# Point Cloudflare Tunnel at the Hub (same tunnel-net as cloudflared):
#   hostname → http://beszel:8090
# Then set APP_URL to that https:// URL and recreate:
#   edit hosts/azure/beszel/site.env → APP_URL=…
#   bash cloud/common/stacks/beszel/up.sh azure --with-agent
```

Creates:

- `hosts/<host>/beszel/HUB`
- `hosts/<host>/beszel/site.env` + `admin.password` (gitignored)
- `stacks/beszel-agent/site.env` fleet defaults for other hosts

## Day-2

```bash
bash cloud/common/stacks/beszel/up.sh azure
bash cloud/common/stacks/up-all.sh azure   # also starts Hub when HUB marker present
```

## Notes

- Bind defaults to `127.0.0.1:8090` — expose via CF Tunnel, not public `:8090`.
- Hub host skips the **remote** agent stack (`beszel-agent/up.sh`) because of `HUB`; local agent runs in this compose (`--profile agent`).
- Live azure Hub today may still live under `/opt/beszel` until migrated into `hosts/azure/beszel/data`.
