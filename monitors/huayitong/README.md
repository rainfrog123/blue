# Huayitong appointment monitor

One program: `main.py`. Same loop on PC and the jailbroken iPhone — only the HTTP transport differs (CFNetwork on device, urllib + optional proxy on PC).

**Project note (Obsidian):** `Tech/RE/iOS/Apps/Huayitong/Huayitong Poller.md` — wiki [[Huayitong Poller]]. Repo pointer: [PROJECT.md](./PROJECT.md).

## Quick start

```bash
# PC / VPS (this LAN PC needs HUAYITONG_PROXY for Aliyun WAF)
cp .env.example .env
python main.py --once
python main.py --doctor zhaoyu
./start.sh                    # tmux: one session per active doctor in doctors.json

# iPhone (live 24h) — edit this folder, then upload (leaves secrets/hits/state on the phone)
./iphone/upload.sh              # USB: iproxy 2222 22 first
./iphone/upload.sh --restart    # then start.sh on the phone
HOST=iphone ./iphone/upload.sh  # Wi-Fi
ssh -o ClearAllForwardings=yes iphone-usb /var/mobile/huayitong/iphone/check.sh
```

Windows: `.\start.ps1`

## Layout

```
main.py              CLI (PC and iPhone)
config/              settings.py · doctors.json
src/                 http · api · state · monitor · notifiers
iphone/cf_post.py    CFNetwork POST (iOS only)
iphone/phone_config.json  device secrets (gitignored)
iphone/start.sh      tmux one session per active doctor
iphone/check.sh      panes + hits
iphone/upload.sh     PC → phone (skip secrets / hits / state)
```

## CLI

| Flag | Action |
| --- | --- |
| *(none)* | Run forever (all `active` doctors, one process) |
| `--once` | Single poll |
| `--doctor SLUG` | One doctor from `doctors.json` |
| `--list-doctors` | Print slug / active / hook / doctorId / docCode |
| `--test` | Test enabled notifiers |
| `--test-telegram` | Telegram only |
| `--test-serverchan` | ServerChan only |
| `--test-wecom` | WeCom CJC hook only |

## Config

- **Secrets:** `.env` on PC, or `iphone/phone_config.json` on the phone (loaded automatically).
- **Doctors:** `config/doctors.json` — `slug`, `doctorId`, `docCode`, `hook` (`gq` / `cjc`), `active`. Flip `active` and re-run `start.sh` to start/stop that tmux. `python main.py --list-doctors`.
- **Proxy:** this PC needs `HUAYITONG_PROXY=http://192.168.23.128:8080`. iPhone does not.
- **Timing (both):** normal **9–13 s**, peak **3 s** (07:59–08:04 · 19:59–20:04), error **30–60 s**.
- **Notifiers:** WeCom. GQ = 放号 only. CJC = heartbeat (+ doctors with `hook: cjc`). Telegram off.

## Alert rule

Notify when `remainingNum`, `availableCount`, or `status` changes on a known id, or a **new** `sysScheduleId` appears after warmup with `status==1` **or** `avail>0` **or** `remain>0`. First poll (empty `state-<slug>.json`) is baseline. State is saved per doctor. Every hit is also appended to **`hits-<slug>.log`** (phone: `iphone/hits-<slug>.log`) before WeCom — survives a missed push.

Related: `../hxkq/` — 华西口腔 monitor (different hospital app).
