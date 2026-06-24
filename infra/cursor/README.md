# Cursor infrastructure

Tools for automating and extending **Cursor IDE** on this machine.

## Layout

```
cursor/
└── accounts/       Account / hook utilities (legacy)
```

All **jefr-cursor** source (extension, MCP server, automation) lives in the canonical repo:

`C:/Users/jar71/Downloads/jefr-cursor/`

## jefr-cursor (MCP messenger)

Side-panel chat via **Model Context Protocol**. See [QUICKSTART.txt](C:/Users/jar71/Downloads/jefr-cursor/QUICKSTART.txt) and [README.md](C:/Users/jar71/Downloads/jefr-cursor/README.md).

**Install extension:**

```bash
cd ~/Downloads/jefr-cursor
python pack_vsix.py   # or: cd extension && npm run package
```

Drag `jefr-cursor/jefr-cursor.vsix` into Cursor Extensions, restart, enable **jefr** under Tools & MCP.

**MCP server path (workspace):**

`C:/Users/jar71/Downloads/jefr-cursor/extension/dist/mcp-server.mjs`

## automation (CDP workflow)

```bash
cd ~/Downloads/jefr-cursor/automation
python workflow.py
```

The jefr extension **General** tab launches this script when the Downloads workspace is open.

See `C:/Users/jar71/Downloads/jefr-cursor/automation/README.md`.
