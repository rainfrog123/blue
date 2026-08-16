# Cloud

Shared proxy stacks in `common/stacks`, per-box secrets in `hosts`, provider CLIs in `providers`.

**Default proxy path:** **3x-ui** (SQLite panel + Xray) + **cloudflared** + **Beszel agent**. Legacy per-protocol stacks remain for hosts without `3x-ui/MIGRATE`.

```text
cloud/
  README.md
  common/
    lib/                 # ipv6.sh, jsonutil.py
    stacks/              # 3x-ui, cloudflared, beszel-agent, hysteria, ss-rust, xray-* + up-all.sh
    setup/               # **init.sh** (seeds 3x-ui MIGRATE + Beszel agent by default)
    vnc/
  hosts/
    digi|ali|azure|ali-jp|oracle-tokyo/   # site files + 3x-ui/ + beszel-agent/
  providers/
    digitalocean|alibaba|azure|aws|gcp|linode|vultr|oracle/
```

## Quick start

```bash
# Bootstrap a box (default: 3x-ui + cloudflared + Beszel agent)
bash cloud/common/setup/init.sh azure          # or digi|ali|ali-jp|oracle-tokyo
bash cloud/providers/azure/init.sh             # thin wrapper → azure
bash cloud/providers/oracle/init.sh            # thin wrapper → oracle-tokyo

# Bring-up only
bash cloud/common/stacks/up-all.sh azure       # MIGRATE → 3x-ui + cloudflared + beszel-agent
bash cloud/common/stacks/3x-ui/up.sh azure
bash cloud/common/stacks/beszel-agent/up.sh ali-jp

# Legacy stacks instead (old path)
LEGACY_PROXIES=1 bash cloud/common/setup/init.sh digi
SKIP_BESZEL=1 bash cloud/common/setup/init.sh digi
```

| Stack | Role | Per-host |
| --- | --- | --- |
| **3x-ui** | **Default** — panel + SS/Hy2/Trojan/REALITY | `hosts/<host>/3x-ui/` (`MIGRATE`, `site.env`, `db/`) |
| cloudflared | CF tunnel (sibling) | `hosts/<host>/cloudflared/site.env` |
| **beszel** | Fleet monitoring **Hub** | `hosts/<host>/beszel/` (`setup-hub.sh`) |
| **beszel-agent** | Fleet monitoring agent → Hub | `hosts/<host>/beszel-agent/site.env` |
| hysteria / ss-rust / xray-* | Legacy (no `MIGRATE`) | `site.yaml` / `site.json` |

Hub: `bash cloud/common/stacks/beszel/setup-hub.sh <host>` (marker `beszel/HUB`). Agent stack skipped on Hub hosts. Live azure Hub may still be `/opt/beszel` until migrated.

Panel access: `ssh -L 2053:127.0.0.1:2053 <host>` → `http://127.0.0.1:2053<PANEL_BASE_PATH>`

Host short names: `digi` / `ali` / `azure` / `ali-jp` / `oracle-a1` / `oracle-tokyo` in `up.sh` arguments.

## Host bootstrap (`init.sh`)

```bash
bash cloud/common/setup/init.sh digi          # or ali / azure / ali-jp
bash cloud/providers/digitalocean/init.sh     # digi
bash cloud/providers/alibaba/init.sh          # ali
bash cloud/providers/azure/init.sh            # azure
```

Seeds `hosts/<host>/3x-ui/{MIGRATE,site.env,db,cert}` unless `LEGACY_PROXIES=1`, then applies panel login and runs `stacks/3x-ui/seed-inbounds.sh` so SS / Hy2 / Trojan + Xray clients are ready immediately (`SKIP_XUI_SEED=1` to skip). Proxy secrets live in **tracked** `hosts/<host>/3x-ui/inbound.env` (Clash); panel login stays in gitignored `site.env`.

## Provider CLIs

```bash
python cloud/providers/alibaba/ecs/cli.py status
python cloud/providers/azure/cli.py status
python cloud/providers/oracle/cli.py status
python cloud/providers/oracle/Retry-A1.py          # A1 capacity catcher
```
