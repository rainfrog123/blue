# Shared cloud helpers

| Path | Role |
| --- | --- |
| `lib/` | `ipv6.sh`, `jsonutil.py` |
| `stacks/` | **3x-ui** / cloudflared / **beszel** (Hub) / **beszel-agent** / hysteria / ss-rust / xray-* (+ `up-all.sh`) |
| `setup/` | **`init.sh`** — seeds 3x-ui MIGRATE + Beszel agent by default; `LEGACY_PROXIES=1` / `SKIP_BESZEL=1` |
| `vnc/` | VNC notes |

```bash
bash cloud/common/setup/init.sh azure   # or digi / ali / ali-jp
bash cloud/providers/azure/init.sh
```

See [stacks/README.md](./stacks/README.md) and [../README.md](../README.md).
