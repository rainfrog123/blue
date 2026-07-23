# Shared proxy stacks (digi / ali / azure)

> [!tip] Do not reconfigure each VPS from scratch
> Defaults live in `infra/cloud/common/<stack>/`. Each VPS only keeps **site secrets**.

## Pattern

| Stack | Common | Per-VPS |
| --- | --- | --- |
| `hysteria` | `defaults.yaml` + compose | `site.yaml` (domain + password) + `acme/` |
| `ss-rust` | `defaults.json` + render | `site.json` (password + port) |
| `xray-trojan` | `defaults.json` + render | `site.json` (password / email / path) |
| `xray-reality` | `defaults.json` + render | `site.json` (uuid / keys / WARP) |
| `cloudflared` | compose template | `.env` (`CF_TUNNEL_TOKEN`) |

Generated `config.json` files are gitignored — `up.sh` renders them.

## Commands

```bash
bash infra/cloud/common/up-all.sh digi
bash infra/cloud/common/ss-rust/up.sh ali
bash infra/cloud/common/hysteria/up.sh azure
```

New box: copy a `site.json` / `site.yaml` / `.env` from an existing VPS, run `up-all.sh <vps>`.
