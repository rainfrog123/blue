# Alibaba Cloud (`cloud/providers/alibaba`)

Tooling for Aliyun ECS and SWAS. Host proxy secrets live under `cloud/hosts/ali/`.

## Layout

```
providers/alibaba/
├── README.md
├── common.py          # shared cred_loader path + CLI banner
├── ecs/               # Elastic Compute Service
├── swas/              # Simple Application Server
├── init.sh            # thin → common/setup/init.sh ali
├── init/              # on-host extras (vnc, apt sources, …)
└── config/            # cloud-init + service config templates
```

## Quick commands

```bash
python cloud/providers/alibaba/ecs/cli.py status
python cloud/providers/alibaba/swas/cli.py info

# on the Ali host
bash cloud/providers/alibaba/init.sh
# or shared:
bash cloud/common/setup/init.sh ali
bash cloud/common/stacks/up-all.sh ali
```

## Credentials

CLIs load keys via `workstation/scripts/cred_loader.py` (`get_alibaba()`), through `providers/alibaba/common.py`.

## Packages

```bash
pip install alibabacloud_ecs20140526 alibabacloud_vpc20160428 alibabacloud_bssopenapi20171214 alibabacloud_swas_open20200601 alibabacloud_tea_openapi
```

Default proxies: **3x-ui** + cloudflared (`MIGRATE`). `LEGACY_PROXIES=1` for legacy stacks.
