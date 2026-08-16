# wecom-verify

Tiny Flask app: WeCom `VerifyURL` for **Receive Messages via API** so you can set **Company's Trusted IP**, then `message/send`.

| Item | Value |
| --- | --- |
| Hostname | `wecom.hyas.space` |
| Origin | `http://wecom-verify:8080` |
| Paths | `/wecom/callback` or `/` |
| Host example | `hosts/ali-jp/wecom-verify/site.env` |

```bash
bash cloud/common/stacks/wecom-verify/up.sh ali-jp
```

Wire DNS + tunnel (from `network/cloudflare`, merge — do not `tunnel config set` alone or you wipe `ajp.*`):

```bash
python cli.py dns list --zone-id 14a1737c5a43cdff29c09a606c162316 --type CNAME
# then merge ingress via scripts/merge_ali-jp_wecom_tunnel.py
```
