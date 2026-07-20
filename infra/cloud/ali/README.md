# Alibaba Cloud (`infra/cloud/ali`)

Tooling for Aliyun ECS (Hong Kong) and SWAS (Singapore), plus host bootstrap configs.

## Layout

```
ali/
├── README.md          # this file
├── common.py          # shared cred_loader path + CLI banner
├── ecs/               # Elastic Compute Service (default: ap-southeast-1)
│   ├── cli.py         # main entry: status, provision, spot-prices, …
│   ├── aliyun_client.py
│   ├── ecs_operations.py
│   └── README.md
├── swas/              # Simple Application Server (ap-southeast-1)
│   ├── cli.py
│   ├── API.md
│   └── *.sh           # reboot / tmux / auto-restart helpers
├── init/              # on-host bootstrap (apt, vnc, proxy stacks)
└── config/            # cloud-init + service config templates
```

## Quick commands

```bash
# ECS (Singapore by default)
python infra/cloud/ali/ecs/cli.py status
python infra/cloud/ali/ecs/cli.py traffic
python infra/cloud/ali/ecs/cli.py coupon
python infra/cloud/ali/ecs/cli.py spot-prices

# SWAS (Singapore)
python infra/cloud/ali/swas/cli.py info
```

## Credentials

Both CLIs load keys via `infra/scripts/cred_loader.py` (`get_alibaba()`), through `ali/common.py`.

## Packages

```bash
pip install alibabacloud_ecs20140526 alibabacloud_vpc20160428 alibabacloud_bssopenapi20171214 alibabacloud_swas_open20200601 alibabacloud_tea_openapi
```
