# DigitalOcean provider

CLIs and helpers for Digi droplets. Host proxy secrets: `infra/cloud/hosts/digi/`.

## Bootstrap

```bash
bash infra/cloud/providers/digitalocean/init.sh
# same as:
bash infra/cloud/common/setup/init.sh digi
```

`os.sh` is a deprecated alias → `init.sh`.

## Proxies

```bash
bash infra/cloud/common/stacks/up-all.sh digi
```
