# Host: oracle-tokyo (Oracle Always Free micro)

SSH: `oracle-tokyo` → `161.33.156.243` via **ProxyJump `ali-jp`**  
Obsidian: `Oracle Host oracle-tokyo` · shape `VM.Standard.E2.1.Micro` (1 GB · x86)

```bash
# on box / from laptop after keys
bash cloud/providers/oracle/init.sh
# same as:
bash cloud/common/setup/init.sh oracle-tokyo

bash cloud/common/stacks/up-all.sh oracle-tokyo
ssh -L 2053:127.0.0.1:2053 oracle-tokyo   # panel (if 3x-ui up)
```

**Notes:** 1 GiB RAM — init forces 2G swap. Full 3x-ui may be tight; cloudflared needs `cloudflared/site.env` token before tunnel starts.
