# Host: azure (Azure Singapore)

SSH: `ssh azure`

```bash
bash cloud/common/stacks/up-all.sh azure          # MIGRATE → 3x-ui + cloudflared
bash cloud/common/stacks/3x-ui/up.sh azure
ssh -L 2053:127.0.0.1:2053 azure
```

**Default:** `3x-ui` (SQLite) + `cloudflared` (`a.hyas.site` → `http://3x-ui:8080`).
Panel: `hosts/azure/3x-ui/site.env` · marker `MIGRATE`.
Legacy site files under `hysteria/` / `ss-rust/` / `xray-trojan/` kept for reference.

Provider CLI: `cloud/providers/azure/`.
