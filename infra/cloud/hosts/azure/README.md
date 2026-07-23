# Host: azure (Azure Singapore)

```bash
bash infra/cloud/common/stacks/up-all.sh azure
```

Stacks: hysteria (`hyaz.hyas.site`), ss-rust (`:12033`), xray-trojan + cloudflared (`a.hyas.site`).

Needs `hosts/azure/cloudflared/site.env` (gitignored) with tunnel `a` token.

Provider CLI: `infra/cloud/providers/azure/`.
