# infra/cloud

Shared proxy stacks in `common/stacks`, per-box secrets in `hosts`, provider CLIs in `providers`.

```text
infra/cloud/
  README.md
  common/
    lib/                 # os.sh, ipv6.sh, jsonutil.py
    stacks/              # hysteria, ss-rust, xray-*, cloudflared + up-all.sh
    setup/               # server-init, ssr-deploy, …
    vnc/
  hosts/
    digi|ali|azure/      # site.yaml / site.json / site.env + acme/ only
  providers/
    digitalocean|alibaba|azure|aws|gcp|linode|vultr/
```

## Quick start

```bash
bash infra/cloud/common/stacks/up-all.sh digi
bash infra/cloud/common/stacks/hysteria/up.sh ali
bash infra/cloud/common/stacks/ss-rust/up.sh ali
```

| Stack | Common defaults | Per-host site file |
| --- | --- | --- |
| hysteria | `common/stacks/hysteria/defaults.yaml` | `hosts/<host>/hysteria/site.yaml` |
| ss-rust | `common/stacks/ss-rust/defaults.json` | `hosts/<host>/ss-rust/site.json` |
| xray-trojan | `common/stacks/xray-trojan/defaults.json` | `hosts/<host>/xray-trojan/site.json` |
| xray-reality | `common/stacks/xray-reality/defaults.json` | `hosts/<host>/xray-reality/site.json` |
| cloudflared | `common/stacks/cloudflared/docker-compose.yml` | `hosts/<host>/cloudflared/site.env` |

Generated `config.json` under hosts is gitignored — `up.sh` rebuilds it.

## Naming

| Old | New |
| --- | --- |
| `infra/cloud/common/<stack>/` | `infra/cloud/common/stacks/<stack>/` |
| `infra/cloud/{digi,ali,azure}/<stack>/` | `infra/cloud/hosts/{digi,ali,azure}/<stack>/` |
| `infra/cloud/digi/{cli,helpers,…}` | `infra/cloud/providers/digitalocean/` |
| `infra/cloud/ali/{ecs,swas,init,…}` | `infra/cloud/providers/alibaba/` |
| `infra/cloud/azure/{cli,core,…}` | `infra/cloud/providers/azure/` |
| `infra/cloud/{aws,gcp,linode,vultr}/` | `infra/cloud/providers/{aws,gcp,linode,vultr}/` |

Host short names stay `digi` / `ali` / `azure` in `up.sh` arguments.

## Provider CLIs

```bash
python infra/cloud/providers/alibaba/ecs/cli.py status
python infra/cloud/providers/azure/cli.py status
```
