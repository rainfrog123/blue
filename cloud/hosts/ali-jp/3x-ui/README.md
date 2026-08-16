# Host: ali-jp — 3x-ui (SQLite)

```bash
bash cloud/common/stacks/3x-ui/up.sh ali-jp
ssh -L 2053:127.0.0.1:2053 ali-jp
# browser → http://127.0.0.1:2053
```

Volumes (gitignored): `db/`, `cert/`, `acme/`.

Markers:

- Touch `ENABLED` to also start from `up-all.sh`
- Touch `MIGRATE` when ready to drop ss-rust / hysteria2 / xray-trojan from `up-all.sh`
