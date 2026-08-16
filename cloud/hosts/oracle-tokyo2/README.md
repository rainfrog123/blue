# Host: oracle-tokyo2 (Oracle Always Free micro #2)

SSH: `oracle-tokyo2` → `141.147.186.46` via **ProxyJump `ali-jp`**  
Obsidian: [[Oracle Host oracle-tokyo2]] · shape `VM.Standard.E2.1.Micro` · Ubuntu **24.04** (1 GB · x86)

```bash
bash cloud/common/setup/init.sh oracle-tokyo2
bash cloud/common/stacks/up-all.sh oracle-tokyo2
ssh -L 2053:127.0.0.1:2053 oracle-tokyo2   # panel
```

**Notes:** 1 GiB RAM — init forces 2G swap. Hy2 SNI default `hyoci2.hyas.site` (self-signed until DNS). IPv6 not assigned yet.

**IPv6:** `2603:c021:8018:8c00:0:f39:aa06:3815` (netplan `99-ipv6.yaml` dhcp6).
