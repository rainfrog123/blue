# Azure provider

CLIs for Azure VMs. Host proxy secrets: `cloud/hosts/azure/`.

## Bootstrap

```bash
bash cloud/providers/azure/init.sh
# same as:
bash cloud/common/setup/init.sh azure
```

Default proxies: **3x-ui** (SQLite) + **cloudflared** (`MIGRATE`).  
`LEGACY_PROXIES=1` for old hysteria/ss-rust/xray stacks.

## Proxies

```bash
bash cloud/common/stacks/up-all.sh azure
bash cloud/common/stacks/3x-ui/up.sh azure
ssh -L 2053:127.0.0.1:2053 azure   # panel
```
