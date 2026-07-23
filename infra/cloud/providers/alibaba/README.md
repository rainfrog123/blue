# Alibaba Cloud (`infra/cloud/providers/alibaba`)

Tooling for Aliyun ECS and SWAS. Host proxy secrets live under `infra/cloud/hosts/ali/`.

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
python infra/cloud/providers/alibaba/ecs/cli.py status
python infra/cloud/providers/alibaba/swas/cli.py info

# on the Ali host
bash infra/cloud/providers/alibaba/init.sh
# or shared:
bash infra/cloud/common/setup/init.sh ali
bash infra/cloud/common/stacks/up-all.sh ali
```

## Credentials

CLIs load keys via `infra/scripts/cred_loader.py` (`get_alibaba()`), through `providers/alibaba/common.py`.

## Packages

```bash
pip install alibabacloud_ecs20140526 alibabacloud_vpc20160428 alibabacloud_bssopenapi20171214 alibabacloud_swas_open20200601 alibabacloud_tea_openapi
```
