# Huayitong appointment monitor

One program: `main.py`. Same loop on PC and the jailbroken iPhone — only the HTTP transport differs (CFNetwork on device, urllib + optional proxy on PC).

**Project note (Obsidian):** `Tech/Web/Monitors/Huayitong Appointment Monitor.md` — wiki [[Huayitong Appointment Monitor]]. Repo pointer: [PROJECT.md](./PROJECT.md).

## Quick start

```bash
# PC / VPS (this LAN PC needs HUAYITONG_PROXY for Aliyun WAF)
cp .env.example .env
python main.py --once
python main.py
./start.sh                    # tmux session: huayitong

# iPhone (live 24h) — deploy this folder to /var/mobile/huayitong/
# secrets stay in iphone/phone_config.json (not git)
ssh iphone 'cd /var/mobile/huayitong/iphone && ./start.sh'
```

Windows: `.\start.ps1`

## Layout

```
main.py              CLI (PC and iPhone)
config/              settings + doctors
src/                 http · api · state · monitor · notifiers
iphone/cf_post.py    CFNetwork POST (iOS only)
iphone/phone_config.json  device secrets (gitignored)
iphone/start.sh      tmux → python3 ../main.py
```

## CLI

| Flag | Action |
| --- | --- |
| *(none)* | Run forever |
| `--once` | Single poll |
| `--test` | Test enabled notifiers |
| `--test-telegram` | Telegram only |
| `--test-serverchan` | ServerChan only |
| `--test-wecom` | WeCom group webhook only |

## Config

- **Secrets:** `.env` on PC, or `iphone/phone_config.json` on the phone (loaded automatically).
- **Doctors:** `config/doctors.py`; phone_config `doctor` overrides when present.
- **Proxy:** this PC needs `HUAYITONG_PROXY=http://192.168.23.128:8080`. iPhone does not.
- **Timing (both):** normal **9–13 s**, peak **3 s** (07:59–08:04 · 19:59–20:04), error **30–60 s**.
- **Notifiers:** PC default `wecom,telegram`. Phone default `wecom` unless `notifiers` is set in phone_config.

## Alert rule

Notify when `remainingNum`, `availableCount`, or `status` changes on a known id, or a **new** open `sysScheduleId` appears after warmup. First poll is baseline. State is saved to `state.json`.

Related: `../hxkq/` — 华西口腔 monitor (different hospital app).
