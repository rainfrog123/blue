# Alibaba Cloud SWAS CLI

Simple Application Server (轻量应用服务器) helpers for **Tokyo** (`ap-northeast-1`) by default (override with `--instance` / change `REGION_ID` in `cli.py`).

## Usage

```bash
python cli.py info                 # default instance details
python cli.py list
python cli.py start|stop|reboot
python cli.py traffic              # monthly egress package used/remaining
python cli.py snapshots
python cli.py snapshot create --name backup
python cli.py images               # marketplace/OS images
python cli.py image                # custom images
python cli.py disks
python cli.py firewall
python cli.py firewall add --port 443
python cli.py run --cmd "uname -a"
```

Optional `--instance` / `-i` overrides the hardcoded Singapore default instance.

`traffic` calls `ListInstancesTrafficPackages` (bytes → GiB). Plans with no GB package return empty usage.

See `API.md` for API notes. Shell helpers (`reboot.sh`, `tmux_start.sh`, auto-restart scripts) are for on-box use.

Credentials come from `../common.py` → `workstation/scripts/cred_loader.py`.
