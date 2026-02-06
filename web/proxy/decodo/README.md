# Decodo SmartProxy Toolkit

A comprehensive toolkit for testing and validating Decodo SmartProxy connections, with integrated IP reputation checking via IPQualityScore (IPQS).

## Features

- **SOCKS5 Proxy Checker** - Test multiple SOCKS5 proxy sessions in parallel
- **HTTPS Proxy Checker** - Test HTTPS proxy connections with random port selection
- **IP Reputation Checker** - Check any IP address against IPQS fraud detection
- **Cross-Platform** - Scripts available in Bash, PowerShell, and Python
- **Async/Parallel** - High-performance parallel session testing
- **Fraud Scoring** - Automatic ranking of proxies by fraud score

## Project Structure

```
decodo/
├── checkers/           # Main proxy checking scripts
│   ├── socks5/         # SOCKS5 proxy checkers
│   │   ├── checker.sh
│   │   └── checker.ps1
│   ├── https/          # HTTPS proxy checkers
│   │   ├── checker.sh
│   │   └── checker.ps1
│   └── ip/             # IP reputation checker
│       ├── checker.sh
│       └── checker.py
├── utils/              # Utility scripts
│   ├── port_test.sh    # Test port ranges
│   └── test_proxy.py   # Simple proxy tester
├── lib/                # Shared configuration
│   ├── config.sh       # Bash config module
│   ├── config.ps1      # PowerShell config module
│   └── config.py       # Python config module
├── data/               # Reference data
│   └── countries.txt   # Country codes and names
├── examples/           # Example files
│   ├── curl_tests.txt  # Example curl commands
│   └── result.yaml     # Sample results
└── README.md
```

## Prerequisites

### For Bash Scripts
- `curl` with SOCKS5 support
- `jq` for JSON parsing
- Bash 4.0+ (for associative arrays)

### For PowerShell Scripts
- PowerShell 7.0+ (for `ForEach-Object -Parallel`)
- `curl` command available in PATH

### For Python Scripts
- Python 3.8+
- `requests` library with SOCKS support (`pip install requests[socks]`)

## Configuration

### Credentials

The toolkit loads credentials from two sources (in priority order):

1. **Environment Variables**
   ```bash
   export DECODO_USERNAME="user-xxxxx"
   export DECODO_PASSWORD="your-password"
   export IPQS_API_KEY="your-ipqs-key"
   ```

2. **Credentials File** (`~/Documents/cred.json`)
   ```json
   {
     "proxy": {
       "decodo": {
         "username": "user-xxxxx",
         "password": "your-password"
       }
     },
     "ipqs": {
       "default_key": "your-ipqs-api-key"
     }
   }
   ```

### Script Configuration

Edit the configuration section at the top of each checker script:

```bash
session_duration="60"   # Session duration in minutes (1-1440)
country="dk"            # Two-letter country code
num_sessions=10         # Number of sessions to test
max_concurrent=10       # Max parallel connections
```

## Usage

### SOCKS5 Proxy Checker

```bash
# Bash
./checkers/socks5/checker.sh

# PowerShell
./checkers/socks5/checker.ps1
```

### HTTPS Proxy Checker

```bash
# Bash
./checkers/https/checker.sh

# PowerShell
./checkers/https/checker.ps1
```

### IP Reputation Checker

```bash
# Bash - check specific IP
./checkers/ip/checker.sh 8.8.8.8

# Python
python checkers/ip/checker.py 8.8.8.8
```

### Utility Scripts

```bash
# Test a port range
./utils/port_test.sh 45000 45100

# Simple proxy test
python utils/test_proxy.py --type socks5 --country gb
python utils/test_proxy.py --type https --country us
```

## Output

The checkers output proxies ranked by fraud score:

```
====================================== 
Ranked Clean IPs by Fraud Score
======================================
✅✅✅ Score: 0 - IP: 86.170.23.77 (London, Session: session6)
socks5h://user-xxxxx-session-session6-sessionduration-60-country-gb:password@gate.decodo.com:7000
✅✅ Score: 15 - IP: 31.111.29.69 (Manchester, Session: session12)
socks5h://user-xxxxx-session-session12-sessionduration-60-country-gb:password@gate.decodo.com:7000
...

====================================== 
Best Proxy Connection:
======================================
socks5h://user-xxxxx-session-session6-sessionduration-60-country-gb:password@gate.decodo.com:7000
```

### Score Interpretation

| Score | Emoji | Risk Level |
|-------|-------|------------|
| 0 | ✅✅✅ | Excellent |
| 1-19 | ✅✅ | Low |
| 20-39 | ✅ | Moderate |
| 40-69 | ⚠️ | High |
| 70+ | 🚨 | Very High |

## Proxy Configuration Options

### Location Targeting

| Parameter | Description | Example |
|-----------|-------------|---------|
| `country` | Two-letter country code | `gb`, `us`, `de` |
| `city` | City name (underscores for spaces) | `New_York` |
| `state` | US state code | `california` |
| `continent` | Continent code | `eu`, `na`, `as` |
| `asn` | ASN number | `12345` |

### Session Types

- **SOCKS5**: Uses port 7000 with session names for sticky IPs
- **HTTPS**: Uses random ports from 30001-50000 for each request

## API Endpoints

- **Decodo IP Check**: `https://ip.decodo.com/json`
- **IPQS Fraud Check**: `https://ipqualityscore.com/api/json/ip/{api_key}/{ip}`

## License

Internal use only.
