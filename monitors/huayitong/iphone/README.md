# Huayitong — iPhone poller

Stdlib loop for the lab **6s Plus** (Procursus `python3.9`). POST goes through **CFNetwork** (`cf_post.py`) so TLS matches the app; OpenSSL `urllib` is fallback (WAF unless Shadowrocket is on).

On-device path: `/var/mobile/huayitong/iphone/`

```bash
ssh iphone
export LANG=UTF-8 LC_ALL=UTF-8 LC_CTYPE=UTF-8
# jbroot python / tmux
JB=/var/containers/Bundle/Application/.jbroot-DE917FCDBCEDF35F/usr/bin
$JB/python3 /var/mobile/huayitong/iphone/phone_poll.py --once
./start.sh          # tmux session: huayitong
tmux attach -t huayitong
```

| File | Role |
| --- | --- |
| `phone_poll.py` | urllib poll + WeCom (no `requests`) |
| `phone_config.json` | JWT / 赵宇 · `wecom_live` + Telegram (`cred.json`) |
| `state.json` | runtime baseline (not in git) |
| `start.sh` | kill/restart tmux |

Reboot / userspace reboot kills tmux. Parent package (`../main.py`) is the PC/VPS copy — needs mitm proxy on this LAN.
