# Archived MCP (blue workspace)

Moved out of active Cursor paths on **2026-08-11** so workspace MCP messenger is inactive.

| Archive file | Was |
| --- | --- |
| `mcp.json.bak` | `.cursor/mcp.json` (jefr MCP server) |
| `mcp-messenger.mdc.bak` | `.cursor/rules/mcp-messenger.mdc` |
| `infra-cursor-README.md.bak` | `workstation/cursor/README.md` |

Also archived **user-level** configs + disabled extension:

→ `C:\Users\jar71\.cursor\archive\mcp\`

Restore workspace only (example):

```bash
cp .cursor/archive/mcp/mcp.json.bak .cursor/mcp.json
cp .cursor/archive/mcp/mcp-messenger.mdc.bak .cursor/rules/mcp-messenger.mdc
cp .cursor/archive/mcp/infra-cursor-README.md.bak workstation/cursor/README.md
```

## Restore (from this archive)

```bash
# workspace messenger (if these baks exist)
cp .cursor/archive/mcp/.cursor__mcp.json.bak .cursor/mcp.json   # or mcp.json.bak → .cursor/mcp.json
cp .cursor/archive/mcp/.cursor__rules__mcp-messenger.mdc.bak .cursor/rules/mcp-messenger.mdc
cp .cursor/archive/mcp/extension__rules__mcp-messenger.mdc.bak extension/rules/mcp-messenger.mdc
# blue naming:
# cp .cursor/archive/mcp/mcp.json.bak .cursor/mcp.json
# cp .cursor/archive/mcp/mcp-messenger.mdc.bak .cursor/rules/mcp-messenger.mdc
```

User-level Cursor files (also mirrored under `blue/.cursor/archive/mcp/user-level/` on remote `blue`):

```bash
cp user-level/mcp.json.bak ~/.cursor/mcp.json
cp user-level/mcp-messenger.mdc.bak ~/.cursor/rules/mcp-messenger.mdc
# then reload Cursor / re-enable jefr extension if needed
```

Archived: 2026-08-11
