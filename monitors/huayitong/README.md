# Huayitong appointment monitor

Poll **华医通** (West China Hospital) doctor schedules and alert when a slot becomes bookable.

**Project note (Obsidian):** `Tech/Web/Monitors/Huayitong Appointment Monitor.md` — wiki [[Huayitong Appointment Monitor]]. Repo pointer: [PROJECT.md](./PROJECT.md).

## Quick start

```bash
python -m pip install -r requirements.txt
cp .env.example .env          # fill HUAYITONG_TOKEN / ACCESS_TOKEN / COOKIE
# edit config/doctors.py
python main.py --test         # notifier smoke test
python main.py --once         # one poll
python main.py                # continuous
./start.sh                    # tmux session: huayitong
```

Windows: `.\start.ps1`

## Layout

```
config/          settings + doctors
src/             api client, state, monitor, notifiers
iphone/          6s stdlib poller (tmux on-device — WAF bypass)
main.py          CLI (PC / VPS)
PROJECT.md       what / why / how
.env.example     secrets template
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

- **Secrets:** hardcoded fallbacks in `config/settings.py`; override with `.env` (see `.env.example`).
- **Doctors:** `config/doctors.py`
- **Proxy:** this PC needs `HUAYITONG_PROXY=http://192.168.23.128:8080` (Aliyun WAF). VPS: leave unset.
- **iPhone (live 24h):** `iphone/` — see `iphone/README.md`. On-device `/var/mobile/huayitong/iphone/`.
- **Notifiers:** default `wecom,telegram` (optional `serverchan`)
- **WeCom:** **group webhook only** (`WECOM_WEBHOOK_URL`, `msgtype: text`) — no Path A `message/send`
- **Telegram:** `TELEGRAM_*` or `blue/secrets/cred.json` via `cred_loader`

## Alert rule

Notify when `remainingNum`, `availableCount`, or `status` changes on a known id, or a **new** open `sysScheduleId` appears after warmup. First poll is baseline.

Related: `../hxkq/` — 华西口腔 monitor (different hospital app).
