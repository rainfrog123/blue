# West China Hospital Appointment Monitor

Monitor doctor appointment availability at West China Hospital (Sichuan University) and receive WeChat notifications when slots become available.

## Features

- **Real-time Monitoring**: Continuously checks for appointment availability
- **Smart Scheduling**: Faster checks during peak hours (7:59-8:04 AM/PM China time)
- **WeChat Notifications**: Instant alerts via ServerChan when slots open
- **Anti-Detection**: Randomized user agents, UUIDs, and request timing
- **Multi-Doctor Support**: Monitor multiple doctors simultaneously

## Project Structure

```
huaxitong/
├── config/
│   ├── __init__.py      # Config module exports
│   ├── settings.py      # Application settings
│   └── doctors.py       # Doctor configurations
├── src/
│   ├── __init__.py
│   ├── api_client.py    # Hospital API client
│   ├── models.py        # Data models
│   ├── monitor.py       # Main monitoring logic
│   └── notifiers/
│       ├── __init__.py
│       └── serverchan.py # WeChat notification service
├── main.py              # Entry point
├── start.sh             # Tmux launch script
├── requirements.txt     # Python dependencies
├── .env.example         # Environment variables template
└── README.md
```

## Installation

1. **Clone and navigate to the project:**
   ```bash
   cd /path/to/huaxitong
   ```

2. **Install dependencies:**
   ```bash
   /allah/freqtrade/.venv/bin/python3 -m pip install -r requirements.txt
   ```

3. **Configure authentication:**
   - Copy `.env.example` to `.env`
   - Fill in your API tokens (from app network inspection)
   - Add your ServerChan URL (from https://sct.ftqq.com/)

4. **Configure doctors to monitor:**
   - Edit `config/doctors.py` to add/modify doctors

## Usage

### Run the monitor directly:
```bash
/allah/freqtrade/.venv/bin/python3 main.py
```

### Run in tmux (recommended for servers):
```bash
./start.sh
```

### Test ServerChan notification:
```bash
/allah/freqtrade/.venv/bin/python3 main.py --test
```

### View running monitor:
```bash
tmux attach -t appointment_monitor
```

### Stop the monitor:
```bash
tmux kill-session -t appointment_monitor
```

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `HUAXITONG_TOKEN` | API authentication token |
| `HUAXITONG_ACCESS_TOKEN` | API access token |
| `HUAXITONG_COOKIE` | Session cookie |
| `SERVERCHAN_URL` | ServerChan notification URL |

### Settings (`config/settings.py`)

- `PEAK_HOUR_INTERVAL`: Check interval during peak hours (default: 5s)
- `NORMAL_INTERVAL_MIN/MAX`: Check interval range normally (default: 15-25s)
- `NOTIFICATION_COOLDOWN`: Minimum time between notifications (default: 300s)

### Doctors (`config/doctors.py`)

Add doctors to monitor by editing the `DOCTORS` list with their API payloads.

## How It Works

1. **Monitoring**: Periodically queries the hospital API for appointment data
2. **Change Detection**: Tracks `availableCount` and `status` for each time slot
3. **Alerting**: When slots become available (availableCount: 0->positive or status->1), sends notifications
4. **Rate Limiting**: Uses randomized intervals and rotating headers to avoid detection

## Appointment Status Codes

| Status | Meaning |
|--------|---------|
| 1 | Available |
| 2 | Fully Booked |
| 3 | Suspended |

## License

Private use only.
