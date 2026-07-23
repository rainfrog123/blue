# Shared proxy stacks

Defaults live in `infra/cloud/common/stacks/<stack>/`.
Each host only keeps site secrets under `infra/cloud/hosts/<host>/`.

| Stack | Defaults | Host site file | Bring up |
| --- | --- | --- | --- |
| hysteria | `defaults.yaml` | `hosts/<host>/hysteria/site.yaml` | `bash …/hysteria/up.sh <host>` |
| ss-rust | `defaults.json` | `hosts/<host>/ss-rust/site.json` | `bash …/ss-rust/up.sh <host>` |
| xray-trojan | `defaults.json` | `hosts/<host>/xray-trojan/site.json` | `bash …/xray-trojan/up.sh <host>` |
| xray-reality | `defaults.json` | `hosts/<host>/xray-reality/site.json` | `bash …/xray-reality/up.sh <host>` |
| cloudflared | compose | `hosts/<host>/cloudflared/site.env` | `bash …/cloudflared/up.sh <host>` |

```bash
bash infra/cloud/common/stacks/up-all.sh digi
python3 infra/cloud/common/stacks/ss-rust/render.py digi --stdout
python3 infra/cloud/common/stacks/hysteria/render.py digi
```

`<host>` is `digi`, `ali`, or `azure`.

Edit once in common (method, Brutal bandwidth, Reality dest, images).
Reconfigure per host only for passwords, ACME domain, tunnel token, keys.
