# Stake Baccarat

Two packages. Do not run both — they both hook the Pragmatic Play WebSocket.

```
stake/baccarat/
├── extension/     # LIVE Chrome MV3 — trusted CDP clicks
└── script/        # Tampermonkey fallback — untrusted dispatchEvent
```

| Package | Path | Use |
| --- | --- | --- |
| **Extension** | [`extension/`](extension/) | Load unpacked. v8.2.3. HUD in the Multiplay iframe. Toolbar chip icon + popup. |
| **Script** | [`script/`](script/) | Tampermonkey `stake-baccarat.js` v7.2.1. Disable when the extension is loaded. |

Load unpacked (unchanged):

`C:\Users\jar71\Music\blue\apps\tampermonkey\stake\baccarat\extension`
