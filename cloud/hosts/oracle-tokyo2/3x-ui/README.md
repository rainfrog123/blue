# Host: oracle-tokyo2 — 3x-ui (SQLite)

```bash
bash cloud/common/stacks/3x-ui/up.sh oracle-tokyo2
ssh -L 2053:127.0.0.1:2053 oracle-tokyo2
```

Panel URL path + passwords: `site.env` (gitignored). Clash secrets: `inbound.env` (tracked after seed).
