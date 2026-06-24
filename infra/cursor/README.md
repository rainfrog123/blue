# Cursor infrastructure

Tools for automating and extending **Cursor IDE** on this machine.

## Layout

```
cursor/
├── jefr-cursor/    MCP side-panel extension + Obsidian plugin (VSIX pack source)
└── accounts/       Account / hook Utilities (legacy)
```

> **CDP automation** (`workflow.py`, `cdp.py`, tile helpers) lives in the canonical repo:
> `C:/Users/jar71/Downloads/jefr-cursor/automation/` — not under this tree.

## jefr-cursor (MCP messenger)

Side-panel chat via **Model Context Protocol**. See [jefr-cursor/README.md](jefr-cursor/README.md) and [jefr-cursor/QUICKSTART.txt](jefr-cursor/QUICKSTART.txt).

**Install extension:**

```bash
cd jefr-cursor
python pack_vsix.py   # or: cd extension && npm run package
```

Drag `jefr-cursor/jefr-cursor.vsix` into Cursor Extensions, restart, enable **jefr** under Tools & MCP.

**MCP server path (workspace):**

`C:/Users/jar71/Downloads/jefr-cursor/extension/dist/mcp-server.mjs`

## automation (CDP workflow)

Canonical location:

```bash
cd C:/Users/jar71/Downloads/jefr-cursor/automation
python workflow.py
```

The jefr extension **General** tab launches this script from the open `jefr-cursor` workspace only.

See `C:/Users/jar71/Downloads/jefr-cursor/automation/README.md`.
