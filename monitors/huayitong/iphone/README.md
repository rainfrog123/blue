# Huayitong — iPhone device files

The poller is **`../main.py`** (same as PC). This folder is only:

| File | Role |
| --- | --- |
| `cf_post.py` | CFNetwork / SecureTransport POST (WAF bypass) |
| `phone_config.json` | JWT / 赵宇 / WeCom (gitignored) |
| `state.json` | persisted baseline (gitignored) |
| `start.sh` | tmux → `python3 /var/mobile/huayitong/main.py` |
| `phone_poll.py` | shim that runs `main.py` |

On-device tree: `/var/mobile/huayitong/` (whole package) + secrets in `iphone/`.

```bash
ssh iphone
export LANG=UTF-8 LC_ALL=UTF-8 LC_CTYPE=UTF-8
JB=/var/containers/Bundle/Application/.jbroot-DE917FCDBCEDF35F/usr/bin
cd /var/mobile/huayitong/iphone && ./start.sh
$JB/python3 /var/mobile/huayitong/main.py --once
$JB/tmux attach -t huayitong
```

Reboot / userspace reboot kills tmux. Timing is in `config/settings.py` (overlaid by `phone_config.json`).
