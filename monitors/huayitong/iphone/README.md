# Huayitong — iPhone device files

The poller is **`../main.py`** (same as PC). This folder is only:

| File | Role |
| --- | --- |
| `cf_post.py` | CFNetwork / SecureTransport POST (WAF bypass) |
| `phone_config.json` | JWT + GQ / CJC webhook URLs (gitignored) |
| `state-<slug>.json` | persisted baseline per doctor (gitignored) |
| `hits-<slug>.log` | append-only slot hits per doctor (gitignored) |
| `start.sh` | tmux one session per `active: true` in `config/doctors.json` |
| `check.sh` | panes + hits; no args / `combine` = all, or `zhaoyu` / `lizhengyong` |
| `upload.sh` | PC → phone `/var/mobile/huayitong/` (not secrets / hits / state) |
| `phone_poll.py` | shim that runs `main.py` |

On-device tree: `/var/mobile/huayitong/` (whole package) + secrets in `iphone/`. **Edit on the PC**, then:

```bash
cd /c/Users/jar71/Music/blue/monitors/huayitong
./iphone/upload.sh              # needs iproxy 2222 22
./iphone/upload.sh --restart    # upload + start.sh
HOST=iphone ./iphone/upload.sh  # Wi-Fi instead of USB
```

```bash
ssh -o ClearAllForwardings=yes iphone-usb
export LANG=UTF-8 LC_ALL=UTF-8 LC_CTYPE=UTF-8
JB=/var/containers/Bundle/Application/.jbroot-DE917FCDBCEDF35F/usr/bin
cd /var/mobile/huayitong/iphone && ./start.sh
$JB/python3 /var/mobile/huayitong/main.py --doctor zhaoyu --once
$JB/tmux attach -t huayitong-zhaoyu
$JB/tmux attach -t huayitong-lizhengyong
```

Reboot / userspace reboot kills tmux. Timing is in `config/settings.py` (overlaid by `phone_config.json`).
