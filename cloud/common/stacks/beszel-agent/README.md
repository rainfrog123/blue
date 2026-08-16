# Beszel agent stack

Reports each VPS to the fleet Hub at **https://beszel.hyas.site** (Azure SG + CF Tunnel).

| File | Role |
| --- | --- |
| `docker-compose.yml` | `henrygd/beszel-agent` (host network) |
| `site.env` | Fleet / per-host `HUB_URL` / `TOKEN` / `KEY` — **tracked** (like `3x-ui/inbound.env`) |
| `seed-host.sh` | Copy fleet secrets → `hosts/<host>/beszel-agent/site.env` if missing |
| `.env.example` | Empty template (do **not** use as-is) |
| `up.sh <host>` | Seed if needed, then compose up |

```bash
# seed only (future hosts / after fresh git clone)
bash cloud/common/stacks/beszel-agent/seed-host.sh oracle-tokyo
FORCE_SEED=1 bash cloud/common/stacks/beszel-agent/seed-host.sh oracle-tokyo

# bring up
bash cloud/common/stacks/beszel-agent/up.sh oracle-tokyo
bash cloud/common/stacks/up-all.sh oracle-tokyo
```

**Fresh clone:** `site.env` is in git, so init/`seed-host.sh` can seed TOKEN/KEY without a local overlay. Runtime compose still uses `.env` / `data/` (gitignored).

**Hub host** (azure): `hosts/azure/beszel/HUB` → agent stack skipped.

**Skip anywhere:** `hosts/<host>/beszel-agent/SKIP` or `SKIP_BESZEL=1`.
