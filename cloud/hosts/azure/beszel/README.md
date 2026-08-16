# Beszel Hub (azure)

**Live today:** Hub compose under **`/opt/beszel`** on the VPS (pre-stack). Marker **`HUB`** skips the remote `beszel-agent` stack.

**Future / rebuild:** use the blue stack:

```bash
APP_URL=https://beszel.hyas.site bash cloud/common/stacks/beszel/setup-hub.sh azure
bash cloud/common/stacks/beszel/up.sh azure
```

Public UI: https://beszel.hyas.site · Obsidian: `Tech/Network/Host/Beszel.md`

Do not add `site.env` here until migrating off `/opt/beszel` (same container names).
