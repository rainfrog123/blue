# DigitalOcean provider

CLIs and helpers for Digi droplets. Host proxy secrets: `cloud/hosts/digi/`.

## Bootstrap

```bash
bash cloud/providers/digitalocean/init.sh
# same as:
bash cloud/common/setup/init.sh digi
```


Default proxies: **3x-ui** + cloudflared (`MIGRATE`). `LEGACY_PROXIES=1` for legacy stacks.

## Proxies

```bash
bash cloud/common/stacks/up-all.sh digi
```
