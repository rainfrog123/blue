# ali-jp cloudflared

Tunnel: `ali-jp` · hostname **`ajp.hyas.space`** → `http://xray-trojan:8080`

```bash
bash cloud/common/stacks/cloudflared/up.sh ali-jp
```

Per-host secret: `site.env` with `CF_TUNNEL_TOKEN=...` (gitignored).
