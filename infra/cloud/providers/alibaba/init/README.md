# Alibaba host bootstrap

```bash
bash infra/cloud/providers/alibaba/init/init.sh
# same as:
bash infra/cloud/common/setup/init.sh ali
```

`system.sh` is a deprecated alias → `init.sh`.

Proxy bring-up uses `common/stacks/up-all.sh ali` (site files under `hosts/ali/`).
