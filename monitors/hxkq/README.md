# Huaxi Stomatology (hxkq) appointment monitor

Poll **华西口腔** WeChat mini-program rosters (`uf-wechat.scgh114.com`) and alert when a slot **newly** becomes bookable.

**Project note (Obsidian):** `Reference/Life/Local/Huaxi Stomatology Appointment Monitor.md` — wiki [[Huaxi Stomatology Appointment Monitor]]. Repo pointer: [PROJECT.md](./PROJECT.md).

Sibling: `../huayitong/` (华医通 / 华西医院综合).

## Quick start

```bash
python -m pip install -r requirements.txt
# optional: cp .env.example .env
python main.py --test
python main.py --once
python main.py
./start.sh          # tmux session: hxkq
./stop.sh
./restart.sh
```

Windows: `.\start.ps1`

## Layout

```
config/          settings (dept id, intervals, secrets)
src/             api client, state, monitor, notifiers, logs
logs/            success.log · regular.log (gitignored)
main.py          CLI
```

## CLI

| Flag | Action |
| --- | --- |
| *(none)* | Loop |
| `--once` | Single poll |
| `--test` | Test enabled notifiers |
| `--test-telegram` / `--test-serverchan` / `--test-wecom` | One backend |

## Config

- Default dept: **牙周病科（华西院区）** `7301` — change via `HXKQ_DEPARTMENT_ID` / `settings.py`
- Also known: `7299` 中医科（华西院区）
- Notifiers: default `wecom` (optional `telegram`, `serverchan`)
- WeCom: **group webhook only** (`WECOM_WEBHOOK_URL`, text) — no Path A dual-ping

## Alert rule

Notify only when `remainingNumber` goes **0 → >0** (or newly bookable after baseline). First sighting of a slot is baseline — no spam on startup.
