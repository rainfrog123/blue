# azure xray-trojan

Needs `hosts/azure/cloudflared/site.env` (tunnel `a` → `a.hyas.site`).

```bash
bash infra/cloud/common/stacks/xray-trojan/up.sh azure
bash infra/cloud/common/stacks/cloudflared/up.sh azure
```
