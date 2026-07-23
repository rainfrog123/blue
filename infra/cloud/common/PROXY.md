# Proxy stack — common defaults + per-VPS site

Same pattern as Hysteria2: **shared knobs live under `infra/cloud/common/`**. Each VPS only keeps secrets / identity in `site.json` or `site.env`.

## Services

| Service | Common defaults | Per-VPS site | Bring up |
|---------|-----------------|--------------|----------|
| **hysteria** | `common/hysteria/defaults.yaml` | `<vps>/hysteria/site.yaml` | `bash common/hysteria/up.sh <vps>` |
| **ss-rust** | `common/ss-rust/defaults.json` | `<vps>/ss-rust/site.json` | `bash common/ss-rust/up.sh <vps>` |
| **xray-trojan** | `common/xray-trojan/defaults.json` | `<vps>/xray-trojan/site.json` | `bash common/xray-trojan/up.sh <vps>` |
| **xray-reality** | `common/xray-reality/defaults.json` | `<vps>/xray-reality/site.json` | `bash common/xray-reality/up.sh <vps>` |
| **cloudflared** | `common/cloudflared/docker-compose.yml` | `<vps>/cloudflared/site.env` | `bash common/cloudflared/up.sh <vps>` |

`<vps>` is `digi`, `ali`, or `azure`.

## What goes where

**Edit once in common** (method, timeouts, Reality dest/SNI, routing, listen hints, Brutal bandwidth, images/wiring).

**Reconfigure per VPS** only when that box differs:

- passwords / UUID / Reality keys / WARP key
- ACME domain (Hy2)
- ports / WS path if that box is special
- Cloudflare tunnel token

Generated `config.json` / `config.yaml` files are gitignored under each VPS dir — `up.sh` / `render.py` rebuild them.

## Digi full stack

```bash
cd /allah/blue && git pull
docker network inspect init_tunnel-net >/dev/null 2>&1 || docker network create init_tunnel-net
for s in ss-rust xray-reality xray-trojan hysteria cloudflared; do
  bash infra/cloud/common/$s/up.sh digi
done
docker ps -a
```

## Ali (SS + Hy2 + Trojan tunnel)

```bash
docker network inspect init_tunnel-net >/dev/null 2>&1 || docker network create init_tunnel-net
bash infra/cloud/common/ss-rust/up.sh ali
bash infra/cloud/common/hysteria/up.sh ali
bash infra/cloud/common/xray-trojan/up.sh ali
bash infra/cloud/common/cloudflared/up.sh ali
```

`infra/cloud/ali/init/docker-compose.yml` is legacy (token was embedded there); prefer `ali/cloudflared` + `ali/xray-trojan`.

## Preview without Docker

```bash
python3 infra/cloud/common/ss-rust/render.py digi --stdout
python3 infra/cloud/common/xray-trojan/render.py digi --stdout
python3 infra/cloud/common/xray-reality/render.py digi --stdout
python3 infra/cloud/common/hysteria/render.py digi
```
