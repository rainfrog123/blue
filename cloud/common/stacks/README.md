# Shared proxy stacks

**Default:** `3x-ui` (SQLite) + `cloudflared` when `hosts/<host>/3x-ui/MIGRATE` exists, plus **Beszel agent** when `beszel-agent/site.env` is present.
Legacy protocol stacks stay for hosts without that marker.

| Stack | Defaults | Host site file | Bring up |
| --- | --- | --- | --- |
| **3x-ui** | compose (SQLite) | `hosts/<host>/3x-ui/` (`db/`, `MIGRATE`, `site.env`) | `bash …/3x-ui/up.sh <host>` |
| cloudflared | compose | `hosts/<host>/cloudflared/site.env` | `bash …/cloudflared/up.sh <host>` |
| **beszel** (Hub) | compose | `hosts/<host>/beszel/` (`HUB`, `site.env`) | `bash …/beszel/setup-hub.sh <host>` then `up.sh` |
| **beszel-agent** | compose | `hosts/<host>/beszel-agent/site.env` (fleet Hub) | `bash …/beszel-agent/up.sh <host>` |
| hysteria | `defaults.yaml` | `hosts/<host>/hysteria/site.yaml` | `bash …/hysteria/up.sh <host>` |
| ss-rust | `defaults.json` | `hosts/<host>/ss-rust/site.json` | `bash …/ss-rust/up.sh <host>` |
| xray-trojan | `defaults.json` | `hosts/<host>/xray-trojan/site.json` | `bash …/xray-trojan/up.sh <host>` |
| xray-reality | `defaults.json` | `hosts/<host>/xray-reality/site.json` | `bash …/xray-reality/up.sh <host>` |

Beszel Hub: `setup-hub.sh` / `hosts/<host>/beszel/HUB`. Agent stack skipped on Hub hosts. Fleet agent defaults: `stacks/beszel-agent/site.env` (gitignored).

```bash
bash cloud/common/stacks/up-all.sh azure
bash cloud/common/stacks/3x-ui/up.sh azure
```

`<host>` is `digi`, `ali`, `azure`, or `ali-jp`.

`init.sh` creates **`MIGRATE`** by default. Use `LEGACY_PROXIES=1` for the old five-stack path.
