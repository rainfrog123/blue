# Running OctoBrowser (VNC, Root, Sandbox)

How to run OctoBrowser in VNC and as root so the local API and profile browser work correctly.

## Prerequisites

- OctoBrowser AppImage (e.g. `/home/vncuser/Downloads/OctoBrowser.AppImage`)
- VNC server with display `:1` (or set `DISPLAY` accordingly)
- For running as root: environment variables below to avoid sandbox crashes

## Quick start (VNC, non-root)

```bash
DISPLAY=:1 /path/to/OctoBrowser.AppImage --no-sandbox
```

If you are **not** root, this is often enough. The local API will be on the port shown in `~/.Octo Browser/local_port` (e.g. 58888).

## Running as root (e.g. in containers / VNC as root)

When OctoBrowser runs as root, two things need `--no-sandbox`:

1. **OctoBrowser GUI** — the main Qt/Chromium process.
2. **Profile browser (Octium)** — the Chromium instance launched when you start a profile.

Without the right flags, the profile browser exits immediately and logs show: *"Profile is crashed, collecting dumps"*.

### Required environment variables

Start OctoBrowser with:

```bash
DISPLAY=:1 \
  OCTO_EXTRA_ARGS="--no-sandbox" \
  QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox --disable-gpu-sandbox" \
  /path/to/OctoBrowser.AppImage --no-sandbox
```

| Variable | Purpose |
|----------|---------|
| `DISPLAY=:1` | Use VNC display (or your X11 display). |
| `OCTO_EXTRA_ARGS="--no-sandbox"` | **Critical.** Passed to the Octium (profile) browser so it doesn’t crash when run as root. |
| `QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox --disable-gpu-sandbox"` | Used by the OctoBrowser GUI (Qt WebEngine). Needed if the main window would otherwise fail under root. |
| AppImage arg `--no-sandbox` | Required for the main OctoBrowser process when running as root. |

### One-liner (typical path)

```bash
DISPLAY=:1 OCTO_EXTRA_ARGS="--no-sandbox" QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox --disable-gpu-sandbox" /home/vncuser/Downloads/OctoBrowser.AppImage --no-sandbox
```

### Verifying

1. **GUI:** OctoBrowser window appears on the VNC display.
2. **API:**  
   ```bash
   curl -s http://localhost:$(cat ~/.Octo\ Browser/local_port)/api/v2/client/themes
   ```  
   Should return JSON with `"success": true`.
3. **Profile:** Create and start a profile via API (see `LOCAL_API.md`). The profile browser window should stay open; if it closes right away, `OCTO_EXTRA_ARGS` is likely not set when starting OctoBrowser.

### Log check

If profiles still crash, check that Octium is launched with `--no-sandbox`:

```bash
tail -50 ~/.Octo\ Browser/logs/debug.log | grep "launch args"
```

You should see `--no-sandbox` in the list, e.g.:

```
started, additional flags: [], launch args: ['--user-data-dir=...', '--octo-client-port=58888', '--no-sandbox', '--no-first-run', ...]
```

If `--no-sandbox` is missing, ensure `OCTO_EXTRA_ARGS="--no-sandbox"` is set in the environment of the process that starts the AppImage (same shell, systemd unit, or script).

## Background run

```bash
DISPLAY=:1 OCTO_EXTRA_ARGS="--no-sandbox" QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox --disable-gpu-sandbox" /home/vncuser/Downloads/OctoBrowser.AppImage --no-sandbox &
```

Wait a few seconds, then use the API (see `LOCAL_API.md`).

## Storage and port

- **Config/data:** `~/.Octo Browser/`
- **Local API port:** `~/.Octo Browser/local_port` (e.g. `58888`)
- **Logs:** `~/.Octo Browser/logs/debug.log`
- **Profile browser binary:** `~/.Octo Browser/bin/Octium/{version}/Octium`

## Troubleshooting

| Symptom | Cause | Fix |
|--------|--------|-----|
| "Running as root without --no-sandbox is not supported" | Main process needs `--no-sandbox` | Add `--no-sandbox` to the AppImage command. |
| GUI doesn’t appear | Wrong or no display | Set `DISPLAY=:1` (or your VNC/X display). |
| Profile starts then closes immediately | Octium (profile browser) running as root without sandbox disabled | Set `OCTO_EXTRA_ARGS="--no-sandbox"` when starting OctoBrowser. |
| API returns connection refused | OctoBrowser not running or wrong port | Start OctoBrowser; confirm port with `cat ~/.Octo\ Browser/local_port`. |
| GPU / compositing errors in logs | Common in headless/VNC | Often harmless; profile can still run. Optionally try `--disable-gpu` in `OCTO_EXTRA_ARGS` if needed (not required in most cases). |

## Summary

- **VNC:** Set `DISPLAY=:1` (or your display).
- **Root:** Use `--no-sandbox` on the AppImage and set `OCTO_EXTRA_ARGS="--no-sandbox"` and `QTWEBENGINE_CHROMIUM_FLAGS="--no-sandbox --disable-gpu-sandbox"` so both the GUI and the profile browser run correctly.
