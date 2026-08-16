# azure xray-trojan

Needs `hosts/azure/cloudflared/site.env` (tunnel `a` → `a.hyas.site`).

```bash
bash cloud/common/stacks/xray-trojan/up.sh azure
bash cloud/common/stacks/cloudflared/up.sh azure
```
