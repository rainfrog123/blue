# oracle-a1 cloudflared

Tunnel: `oracle-a1` (`1ba8001a-41e8-497e-9c0e-7d42621faa8e`) · hostnames **`oa1.hyas.space`** + **`oa1.hyas.site`** → `http://3x-ui:8080`

```bash
bash cloud/common/stacks/cloudflared/up.sh oracle-a1
```

Per-host secret: `site.env` with `CF_TUNNEL_TOKEN=...` (gitignored).
