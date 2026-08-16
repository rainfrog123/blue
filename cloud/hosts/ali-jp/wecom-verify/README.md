# ali-jp wecom-verify

Public URL: **`https://wecom.hyas.space/wecom/callback`**

Unlocks WeCom **Company's Trusted IP** via Receive-Messages URL verification. Does not replace `ajp.hyas.space` Trojan.

```bash
# on laptop (repo synced to VPS as /allah/blue)
cp site.env.example site.env   # fill TOKEN / AES_KEY / CORP_ID
bash cloud/common/stacks/wecom-verify/up.sh ali-jp
```

Tunnel ingress must include `wecom.hyas.space` → `http://wecom-verify:8080` (see stack README).
