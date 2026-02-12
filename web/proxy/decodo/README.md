# Decodo SmartProxy Client

Python client for Decodo residential proxy service with IPQS fraud scoring.

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

Credentials are loaded from `/allah/blue/cred.json`:

```json
{
  "proxy": {
    "decodo": {
      "username": "sp19qgy7m9",
      "password": "+26iSboeQ0wUyx4qEw"
    }
  },
  "ipqs": {
    "default_key": "your-ipqs-api-key"
  }
}
```

## CLI Usage

### Scan for Clean IPs

```bash
# Scan 10 sessions in GB
python cli.py scan -c gb -n 10

# Scan 20 sessions in US with 60 min duration
python cli.py scan -c us -n 20 -d 60
```

### Check IP Reputation

```bash
python cli.py check 8.8.8.8
python cli.py check 1.1.1.1 8.8.8.8
```

### Test Proxy Connection

```bash
# Random rotating IP
python cli.py test -c gb

# Sticky session
python cli.py test -c us -s mysession
```

## Library Usage

### Basic Proxy Client

```python
from decodo import DecodoClient

# Create client for GB proxies
client = DecodoClient(country="gb")

# Make request through rotating proxy
response = client.get("https://example.com")

# Get current proxy IP info
info = client.get_current_ip()
print(f"IP: {info.ip}, City: {info.city}")
```

### Sticky Sessions

```python
from decodo import DecodoClient

client = DecodoClient(country="us")

# All requests use same IP within session
with client.session("my_session") as session:
    r1 = session.get("https://example.com/login")
    r2 = session.get("https://example.com/dashboard")
    
    ip_info = session.get_ip()
    print(f"Session IP: {ip_info.ip}")
```

### IP Fraud Checking

```python
from decodo import IPQSChecker

checker = IPQSChecker()
result = checker.check("8.8.8.8")

print(f"Score: {result.fraud_score}")
print(f"Clean: {result.is_clean}")
print(f"Risk: {result.risk_level}")
```

### Session Scanner

```python
from decodo import SessionScanner

scanner = SessionScanner(
    country="gb",
    num_sessions=20,
    session_duration=60,
)

summary = scanner.scan()

print(f"Clean IPs: {summary.clean_ips}")

if summary.best_result:
    print(f"Best IP: {summary.best_result.session.ip}")
    print(f"Score: {summary.best_result.ipqs.fraud_score}")
    print(f"Proxy URL: {summary.best_result.session.proxy_url}")
```

## Proxy URL Format

```
https://user-{username}-session-{session}-sessionduration-{duration}:{password}@{country}.decodo.com:{port}
```

- **Port Range**: 10001-49999 (39,999 rotating sessions)
- **Countries**: Use 2-letter codes (`gb`, `us`, `de`, etc.)

## Project Structure

```
decodo/
├── decodo/           # Python package
│   ├── __init__.py
│   ├── client.py     # Proxy client
│   ├── config.py     # Configuration
│   ├── ipqs.py       # IPQS checker
│   └── scanner.py    # Session scanner
├── cli.py            # CLI interface
├── data/
│   └── countries.txt
├── _history/         # Old shell scripts
├── requirements.txt
└── README.md
```

## Fraud Score Interpretation

| Score | Emoji | Risk Level |
|-------|-------|------------|
| 0 | ✅✅✅ | Excellent |
| 1-19 | ✅✅ | Low |
| 20-39 | ✅ | Moderate |
| 40-69 | ⚠️ | High |
| 70+ | 🚨 | Critical |
