# Host: oracle-a1 (Oracle PAYG Always Free A1)

SSH: `oracle-a1` → `161.33.146.74` via **ProxyJump `ali-jp`**  
Obsidian: [[Oracle Host a1-free-tokyo]] · shape `VM.Standard.A1.Flex` **4 OCPU / 24 GB** · Ubuntu **24.04 aarch64**

```bash
bash cloud/common/setup/init.sh oracle-a1
# or: bash cloud/providers/oracle/init.sh oracle-a1

bash cloud/common/stacks/up-all.sh oracle-a1
ssh -L 2053:127.0.0.1:2053 oracle-a1   # panel (if 3x-ui up)
```

**Notes:** ARM64 — use aarch64 images/binaries. IPv6 guest iface `enp0s6`. Init log: `/var/log/oracle-init.log`.
