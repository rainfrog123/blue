# Host: vultr-osk (Vultr Osaka High Frequency)

SSH: `ssh vultr-osk` → `64.176.40.20` via **ProxyJump `ali-jp`** (IPv4; ali-jp has no IPv6)  
Obsidian: `Vultr Host vultr-osk` · plan `vhf-8c-32gb` (8c / 32G / Osaka `itm`)

```bash
bash cloud/providers/vultr/init.sh
# same as:
bash cloud/common/setup/init.sh vultr-osk

bash cloud/common/stacks/up-all.sh vultr-osk
ssh -L 2053:127.0.0.1:2053 vultr-osk   # panel (if 3x-ui up)
```

**Notes:** 32 GiB RAM — no forced swap. cloudflared needs `cloudflared/site.env` token before tunnel starts. Hy2 SNI: `hyvu.hyas.site` (self-signed until ACME).
