# Decodo proxy toolkit

Python client for Decodo (ex-Smartproxy) — sticky/rotating proxies over **HTTPS** or **SOCKS5(h)**, plus IPQS scanning.

## Install

```bash
cd web/proxy/decodo
pip install -r requirements.txt
```

## Credentials

Via shared `infra/scripts/cred_loader.py` → `get_proxy_decodo()` / `get_ipqs()`
(`blue/cred.json`). Env overrides: `DECODO_USERNAME`, `DECODO_PASSWORD`,
`DECODO_PROTOCOL`, `DECODO_API_KEY`, `IPQS_API_KEY`.

```json
{
  "proxy": {
    "decodo": {
      "username": "spe3v7zeu6",
      "password": "…",
      "api_key": "…"
    }
  },
  "ipqs": { "default_key": "…", "api_keys": ["…"] }
}
```

Protocol is chosen per call / CLI (`-p socks5h|https|…`), not stored in creds.
Optional env: `DECODO_PROTOCOL` for a process-wide default.

## CLI

```bash
# Probe exit IP (default protocol: socks5h)
python cli.py test -c gb -s apple

# Print URL only
python cli.py url -c gb -s banana -p socks5h

# Sticky sessions + IPQS (many exits)
python cli.py ips-check -c gb -n 10 -p socks5h

# IPQS for known IP(s)
python cli.py ip-check 8.8.8.8
```

## Library

```python
from decodo import DecodoClient, build_proxy_url, SessionScanner

url = build_proxy_url(country="gb", session="apple", protocol="socks5h")
# socks5h://user-…-session-apple-sessionduration-60-country-gb:…@gate.decodo.com:10000

client = DecodoClient(country="gb", protocol="socks5h")
info = client.get_current_ip(session="apple")

with client.session("banana") as s:   # or omit name → fruit+suffix
    r = s.get("https://example.com")
    print(s.get_ip().ip)
```

### Session ids

Opaque sticky labels — digits, fruit names (`apple`), uuid hex, etc. Same id within `sessionduration` keeps the same exit IP. Must be `[A-Za-z0-9_]+` (no `: @ / -`).

### URL shapes

| Protocol | Host / port |
| --- | --- |
| `socks5` / `socks5h` | `gate.decodo.com:10000` |
| `http` / `https` | `{cc}.decodo.com` + random port `30001–50000` |

Username: `user-{user}-session-{id}-sessionduration-{mins}-country-{cc}`

## Layout

```
decodo/
├── decodo/           # package
│   ├── config.py     # creds + build_proxy_url
│   ├── client.py     # DecodoClient / StickySession
│   ├── ipqs.py
│   └── scanner.py
├── cli.py
├── proxy_forwarder.py   # local :5566 → Decodo HTTPS sticky
├── api/                 # Public API scratch (separate)
├── data/
├── _history/            # old shell scripts
└── requirements.txt
```

## Forwarder

```bash
python proxy_forwarder.py -c gb -s apple          # builds HTTPS upstream from creds
python proxy_forwarder.py --upstream 'https://…'  # or pass full URL
```
