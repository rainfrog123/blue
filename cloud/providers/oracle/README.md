# Oracle Cloud (`cloud/providers/oracle`)

OCI CLI for the Tokyo free-trial / Always Free tenancy — same idea as `providers/digitalocean/cli.py` and `providers/azure/cli.py`.

Vault notes: Obsidian `Tech/Cloud/Oracle/`  
(`Oracle Account`, `Oracle API Launch VM`, `Oracle Trial Machines $300`, …).

## Layout

```text
providers/oracle/
  README.md
  requirements.txt
  helpers.py         # config, list/launch/terminate
  cli.py             # argparse entrypoint
  Retry-A1.py        # Always Free A1 capacity catcher (loop)
  check_proxy.py     # system proxy smoke test
```

## Auth

Uses `~/.oci/config` + PEM (not `cred.json`).

```ini
# C:\Users\jar71\.oci\config
[DEFAULT]
user=ocid1.user.oc1..…
fingerprint=…
tenancy=ocid1.tenancy.oc1..…
region=ap-tokyo-1
key_file=C:\Users\jar71\.oci\oci_api_key.pem
```

## Install

Windows Store Python often hits path-length errors installing `oci`. Prefer a short venv:

```bash
python -m venv /c/v/oci
/c/v/oci/Scripts/pip install -r cloud/providers/oracle/requirements.txt
```

Or: `pip install oci` if your environment allows long paths.

## Quick commands

```bash
cd C:\Users\jar71\blue

python cloud/providers/oracle/cli.py status
python cloud/providers/oracle/cli.py cost          # MTD + BASIC forecast → month end
python cloud/providers/oracle/cli.py list
python cloud/providers/oracle/cli.py presets
python cloud/providers/oracle/cli.py ads
python cloud/providers/oracle/cli.py subnets

# Always Free A1 — dedicated capacity catcher (preferred)
# forever / 60s: leave running overnight
python cloud/providers/oracle/Retry-A1.py
# foothold 1 OCPU / 6 GB (often easier), then resize to 2/12
python cloud/providers/oracle/Retry-A1.py --foothold --interval 45
# cap attempts
python cloud/providers/oracle/Retry-A1.py --max 100 --interval 60

# tmux wrapper (e.g. on ali-jp) — default interval 130s
bash cloud/providers/oracle/Tmux-Retry-A1.sh
INTERVAL=130 bash cloud/providers/oracle/Tmux-Retry-A1.sh --foothold
# @reboot example:  @reboot root bash /allah/blue/cloud/providers/oracle/Tmux-Retry-A1.sh

# same via cli.py
python cloud/providers/oracle/cli.py create --preset a1-free --wait --retry 100

# Trial fat AMD (~$283/mo)
python cloud/providers/oracle/cli.py create --preset e4-8x64 --wait

python cloud/providers/oracle/cli.py info a1-free-tokyo
python cloud/providers/oracle/cli.py power off a1-free-tokyo
python cloud/providers/oracle/cli.py delete a1-free-tokyo -y

python cloud/providers/oracle/cli.py proxy
```

## Presets

| Preset | Shape | Size | Role |
| --- | --- | --- | --- |
| `a1-free` | A1.Flex | 2 / 12 | Always Free |
| `e4-8x64` | E4.Flex | 8 / 64 | Trial default |
| `e4-4x128` | E4.Flex | 4 / 128 | Trial RAM |
| `a1-32x64` | A1.Flex | 32 / 64 | Trial ARM fat (paid) |

## Host bootstrap

```bash
# on box (or after overlay)
bash cloud/providers/oracle/init.sh          # SKIP_REBOOT=1 optional
bash cloud/common/stacks/beszel-agent/seed-host.sh oracle-tokyo
bash cloud/common/stacks/beszel-agent/up.sh oracle-tokyo
```

**Beszel note:** `stacks/beszel-agent/site.env` is **gitignored**. After a bare `git clone`, overlay that file (or any filled `hosts/*/beszel-agent/site.env`) before init — otherwise seed falls back to empty `.env.example`. Prefer `seed-host.sh` (see stack README).

## Live host

- `hosts/oracle-tokyo/` — Always Free micro · SSH `oracle-tokyo` (ProxyJump `ali-jp`)
