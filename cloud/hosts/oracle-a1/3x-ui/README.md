# Host: oracle-a1 — 3x-ui (SQLite)

```bash
bash cloud/common/stacks/3x-ui/up.sh oracle-a1
ssh -L 2053:127.0.0.1:2053 oracle-a1
```

Panel URL path + passwords: `site.env` (gitignored). Clash secrets: `inbound.env` (tracked after seed).
Hy2 SNI: `hyocia1.hyas.site` (self-signed).
