# Host: azure (Azure Singapore)

Site secrets only. Shared stacks: `infra/cloud/common/stacks/`.

```bash
bash infra/cloud/common/stacks/hysteria/up.sh azure
# optional image pin in site.env: HY2_IMAGE=tobyxdd/hysteria:v2.9.3
```

Provider CLI: `infra/cloud/providers/azure/`.
