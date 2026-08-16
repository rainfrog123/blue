# Vultr provider

API CLI + host init for Vultr. Token in `blue/secrets/cred.json` (`vultr.token`) or `VULTR_API_KEY`.

Vault: Obsidian `Tech/Cloud/Vultr/` · live box: `vultr-osk`

## CLI

```bash
cd C:\Users/jar71\blue
pip install -r cloud/providers/vultr/requirements.txt

python cloud/providers/vultr/cli.py status
python cloud/providers/vultr/cli.py account
python cloud/providers/vultr/cli.py list
```

## Host bootstrap

```bash
# on box (or after rsync of blue):
bash cloud/providers/vultr/init.sh
# → common/setup/init.sh vultr-osk
bash cloud/common/stacks/up-all.sh vultr-osk
```
