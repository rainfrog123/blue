# Host: azure — 3x-ui (SQLite)

```bash
bash cloud/common/stacks/3x-ui/up.sh azure
ssh -L 2053:127.0.0.1:2053 azure
# http://127.0.0.1:2053/ocxvvlvjb21a/
```

Volumes (gitignored): `db/`, `cert/`, `acme/`, `site.env`.
Marker: **`MIGRATE`** (default path from `init.sh` / `up-all.sh`).

Hy2 certs: copy from `../hysteria/acme/manual/` into `cert/` (hyaz.hyas.site).
