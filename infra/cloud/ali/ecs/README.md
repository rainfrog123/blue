# Alibaba Cloud ECS CLI

Python toolkit for ECS instances, images, snapshots, and spot pricing.

Default region: **ap-southeast-1** (Singapore).

## Usage

```bash
python cli.py status                  # resource summary
python cli.py traffic                 # public egress this month (CDT + IPv6)
python cli.py traffic --month 2026-07
python cli.py list instances
python cli.py list images
python cli.py provision --spot        # create from latest custom image
python cli.py spot-prices             # cheapest spot in Singapore (default)
python cli.py spot-prices --region ap-southeast-1 --max-mem 2
python cli.py terminate
python cli.py create image
python cli.py cleanup --images
python cli.py diagnose --port 22
python cli.py rotate                  # backup image then terminate
```

## Files

| File | Role |
|------|------|
| `cli.py` | Unified CLI entry |
| `aliyun_client.py` | Credentials, ECS/VPC clients, default `REGION_ID` |
| `ecs_operations.py` | List/create/delete helpers for instances, images, snapshots, disks |
| `../common.py` | Shared `cred_loader` bootstrap |

## Prerequisites

```bash
pip install alibabacloud_ecs20140526 alibabacloud_vpc20160428 alibabacloud_bssopenapi20171214 alibabacloud_tea_openapi
```

Credentials: `infra/scripts/cred_loader.py` → `get_alibaba()`.

## Notes

- Provision/list/status/spot-prices/traffic all default to `REGION_ID` (`ap-southeast-1`).
- Override spot queries with `--region` if needed.
- Spot prices include a 20 GB system disk + 1 Mbps pay-by-traffic in the quote.
- `traffic` reads BSS bills: **CDT** (IPv4 fixed public IP) + **IPv6 gateway**. ECS compute lines do not include egress.
- CDT free quota (in code): **220 GB/month** = 20 GB China + **200 GB overseas** (Singapore). `traffic` prints used vs remaining.
- List prices (in code): CDT APAC **¥0.70/GB** (0~10 TB after free), CDT China **¥0.80/GB**, IPv6 gateway SG **¥0.80/GB**.
