# Alibaba Cloud SWAS CLI

Simple Application Server (轻量应用服务器) helpers for **Singapore** (`ap-southeast-1`).

## Usage

```bash
python cli.py info                 # default instance details
python cli.py list
python cli.py start|stop|reboot
python cli.py snapshots
python cli.py snapshot create --name backup
python cli.py images               # marketplace/OS images
python cli.py image                # custom images
python cli.py disks
python cli.py firewall
```

See `API.md` for API notes. Shell helpers (`reboot.sh`, `tmux_start.sh`, auto-restart scripts) are for on-box use.

Credentials come from `../common.py` → `infra/scripts/cred_loader.py`.
