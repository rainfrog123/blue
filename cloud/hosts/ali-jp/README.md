# Host: ali-jp (Aliyun Tokyo SWAS)

SSH: `ali-jp` -> `47.79.91.138` · Obsidian: `Aliyun Host ali-jp`

```bash
bash cloud/common/stacks/up-all.sh ali-jp          # MIGRATE → 3x-ui + cloudflared
bash cloud/common/stacks/3x-ui/up.sh ali-jp
ssh -L 2053:127.0.0.1:2053 ali-jp                        # panel
```

**Live (2026-08-06):** `3x-ui` (SQLite) + `cloudflared`. Legacy ss/hy2/xray-trojan removed.
Trojan via CF: **`ajp.hyas.space`** (+ `ajp.hyas.site`) → `http://3x-ui:8080`.
Panel secrets: `3x-ui/site.env` (gitignored). Marker: `3x-ui/MIGRATE`.
Provider CLI: `cloud/providers/alibaba/swas/cli.py`.
