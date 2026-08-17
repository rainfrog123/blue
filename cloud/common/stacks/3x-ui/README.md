# 3x-ui stack (SQLite) — **default** proxy stack

Panel + embedded Xray. Keeps `cloudflared` as a sibling for CF Trojan.

```bash
bash cloud/common/stacks/3x-ui/up.sh azure    # or ali-jp|digi|oracle-tokyo|…
bash cloud/common/stacks/up-all.sh azure      # MIGRATE → 3x-ui + cloudflared
bash cloud/common/stacks/3x-ui/seed-inbounds.sh oracle-tokyo
```

`setup/init.sh` seeds `hosts/<host>/3x-ui/` with **`MIGRATE`** by default (`LEGACY_PROXIES=1` keeps old stacks), then:

1. Applies panel login from `site.env`
2. Runs **`seed-inbounds.sh`** so SS / Hy2 / Trojan exist immediately (no UI click-ops)

| Item | Value |
| --- | --- |
| Image | `ghcr.io/mhsanaei/3x-ui:latest` |
| DB | SQLite in `hosts/<host>/3x-ui/db/` → `/etc/x-ui/` |
| Panel | `127.0.0.1:2053` (SSH tunnel) |
| Defaults | SS `:12033` · Hy2 `:443/udp` (self-signed) · Trojan WS `:8080` · optional VLESS REALITY `:8443/tcp` (touch `REALITY`) |
| Network | `init_tunnel-net` |
| mem_limit | `350m` |

| Marker in `hosts/<host>/3x-ui/` | `up-all.sh` |
| --- | --- |
| **`MIGRATE`** (default) | Only 3x-ui + cloudflared |
| `ENABLED` | Legacy stacks, then also 3x-ui |
| *(none)* | Legacy only |

| File | Tracked? | Purpose |
| --- | --- | --- |
| **`inbound.env`** | **yes** | SS / Hy2 / Trojan / REALITY / HY2_SNI (Clash secrets; survives `git clone`) |
| `REALITY` | yes | Marker: seed VLESS REALITY `:8443/tcp` (Hy2 stays UDP 443) |
| `site.env` | no | Panel login only (+ copy of proxy keys) |
| `clash.snippet.yml` | no | Auto paste helper for `blue.yml` |
| `db/` `cert/` | no | Runtime |

`seed-inbounds.sh` also fills `clients` + `client_inbounds` (required by newer 3x-ui — inbound JSON alone leaves Xray with empty clients).

`SKIP_XUI_SEED=1` skips inbound seeding from `init.sh` / `up.sh`.
