# Azure provider

CLIs for Azure VMs. Host proxy secrets: `infra/cloud/hosts/azure/`.

## Bootstrap

```bash
bash infra/cloud/providers/azure/init.sh
# same as:
bash infra/cloud/common/setup/init.sh azure
```

## Proxies

```bash
bash infra/cloud/common/stacks/up-all.sh azure
```
