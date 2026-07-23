# Shared cloud helpers

| Path | Role |
| --- | --- |
| `lib/` | `ipv6.sh`, `jsonutil.py`; `os.sh` redirects to `setup/init.sh` |
| `stacks/` | hysteria / ss-rust / xray-* / cloudflared (+ `up-all.sh`) |
| `setup/` | **`init.sh`** (shared VPS bootstrap), ssr-deploy, volume transfer |
| `vnc/` | VNC notes |

Bootstrap any host:

```bash
bash infra/cloud/common/setup/init.sh digi   # or ali / azure
# thin wrappers (same name everywhere):
bash infra/cloud/providers/digitalocean/init.sh
bash infra/cloud/providers/alibaba/init/init.sh
bash infra/cloud/providers/azure/init.sh
```

See [stacks/README.md](./stacks/README.md) and [../README.md](../README.md).
