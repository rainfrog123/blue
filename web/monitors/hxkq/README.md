# 🦷 Stomatology Appointment Monitor

An integrated monitoring system for West China Hospital of Stomatology (华西口腔医院) that automatically checks for available appointment slots and sends WeChat notifications via Server Chan.

## ✨ Features

- **🔍 Roster-based Monitoring**: Uses the official roster API to check for available slots
- **📱 WeChat Notifications**: Sends notifications via Server Chan with 5-minute cooldown
- **⏰ Real-time Monitoring**: Checks every 10 seconds for new appointments
- **🚀 Async Concurrent Requests**: Fast parallel processing of doctor data and slots
- **🔄 Hourly Auto-refresh**: Updates doctor list every hour to detect new/removed doctors
- **🛡️ Safety Protection**: Built-in resource limits and automatic cleanup
- **📊 Comprehensive Logging**: Detailed success and regular check logging
- **🎯 Multi-doctor Support**: Monitors all doctors in the department simultaneously

## 🏥 Default Configuration

- **Department**: 牙周病科（华西院区）(Periodontal Disease Department - Huaxi Campus)
- **Department ID**: 7301
- **Hospital**: 四川大学华西口腔医院 (West China Hospital of Stomatology)

## 📋 Requirements

- Python 3.7+
- tmux (for session management)
- bc (for floating point calculations in bash)
- aiohttp library (for async HTTP requests)
- requests library (for Server Chan notifications)

## 🚀 Installation

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Server Chan**:
   - Get your Server Chan token from [sct.ftqq.com](https://sct.ftqq.com)
   - Update the `serverchan_url` in `stomatology_monitor.py`

3. **Make scripts executable**:
   ```bash
   chmod +x start.sh stop.sh restart.sh
   ```

## 🎮 Usage

### Start the Monitor
```bash
./start.sh
```

### Stop the Monitor
```bash
./stop.sh
```

### Restart the Monitor
```bash
./restart.sh
```

### View the Monitor Session
```bash
tmux attach-session -t stomatology_monitor
```

### Check Logs
```bash
# View success notifications
tail -f stomatology_success.log

# View regular check logs
tail -f stomatology_reg.log

# View both logs simultaneously
tail -f stomatology_success.log stomatology_reg.log
```

## 🛡️ Safety Features

The system includes comprehensive safety protections:

- **CPU Limit**: 30% maximum usage
- **Memory Limit**: 200MB maximum
- **Log Size Limit**: 50MB per log file
- **Safety Check Interval**: 60 seconds
- **Automatic Cleanup**: Process cleanup on exit

## 📱 Notification System

### WeChat Notifications
- **Platform**: Server Chan (https://sct.ftqq.com)
- **Cooldown**: 5 minutes between notifications
- **Content**: Detailed appointment information including:
  - Doctor name and title
  - Available time slots
  - Appointment fees
  - Slot IDs for booking

### Notification Format
```
🦷 口腔科预约 - 发现X个空位!

## 🦷 牙周病科（华西院区） 预约信息
**医生**: Dr. Name
**时间**: 2025-07-XX XX:XX:XX CST
**发现**: X 个可预约时段

### 📋 可预约时段详情:
### 👨‍⚕️ Dr. Name (Title)
**时段 1:**
- 📅 日期: 2025-07-XX 上午 (星期X)
- 🏥 科室: 牙周病科（华西院区）
- 🔄 可预约: X/X 个名额
- 💰 费用: ¥X.00
- 🆔 时段ID: XXXXXX
```

## 📊 System Architecture

### Core Components

1. **StomatologyMonitor Class**
   - Main monitoring logic
   - API communication
   - Notification handling

2. **Tmux Session Management**
   - Background process execution
   - Session persistence
   - Easy monitoring access

3. **Safety Monitor**
   - Resource usage monitoring
   - Automatic shutdown on limits
   - Process cleanup

### API Endpoints

- **Doctor List**: `/doctor/findDoctorList.web`
- **Doctor Roster**: `/dutyRoster/findByRoster.web`
- **Base URL**: `https://uf-wechat.scgh114.com`

## 🔧 Configuration

### Change Department
Edit the `department_id` in `stomatology_monitor.py`:
```python
self.department_id = 7301  # 牙周病科
self.department_name = "牙周病科（华西院区）"
```

### Common Department IDs
- 7299: 中医科（华西院区）
- 7301: 牙周病科（华西院区）

### Adjust Check Interval
```python
self.check_interval = 10  # seconds
```

### Modify Safety Limits
Edit safety parameters in `start.sh`:
```bash
MAX_CPU_PERCENT=30
MAX_MEMORY_MB=200
MAX_LOG_SIZE_MB=50
```

## 🗂️ File Structure

```
hx_stomatology/
├── stomatology_monitor.py    # Main monitor script
├── start.sh                  # Start script with safety
├── stop.sh                   # Stop script with cleanup
├── restart.sh               # Restart script
├── requirements.txt         # Python dependencies
├── README.md               # This documentation
├── stomatology_success.log # Success notifications log
└── stomatology_reg.log     # Regular check log
```

## 🚨 Troubleshooting

### Common Issues

1. **Session Already Exists**
   ```bash
   ./stop.sh
   ./start.sh
   ```

2. **Python Path Issues**
   - Verify Python path in `start.sh`
   - Default: `/allah/freqtrade/.venv/bin/python3`

3. **No Tmux Session**
   ```bash
   sudo apt-get install tmux
   ```

4. **Permission Denied**
   ```bash
   chmod +x start.sh stop.sh restart.sh
   ```

### Debug Mode
Run the monitor directly to see detailed output:
```bash
/allah/freqtrade/.venv/bin/python3 stomatology_monitor.py
```

## 📈 Monitoring Status

### Check if Running
```bash
tmux list-sessions | grep stomatology_monitor
```

### View Resource Usage
```bash
ps aux | grep stomatology_monitor
```

### Check Safety Monitor
```bash
ps aux | grep safety_monitor
```

## 🎯 Expected Behavior

1. **Startup**: Collects all doctor IDs from the next 7 days (concurrent requests)
2. **Monitoring**: Checks all doctors' rosters simultaneously every 10 seconds
3. **Hourly Refresh**: Updates doctor list every hour (360 iterations) to detect changes
4. **Detection**: Identifies slots with `remainingNumber > 0`
5. **Notification**: Sends WeChat alert via Server Chan
6. **Logging**: Records all activity in log files
7. **Safety**: Monitors resource usage and enforces limits

## 🔒 Security & Privacy

- **No Personal Data**: Only monitors public appointment availability
- **Rate Limiting**: Built-in delays to avoid overwhelming servers
- **IP Privacy**: Uses `noip=1` parameter in notifications
- **Clean Shutdown**: Automatic log cleanup on exit

## 📞 Support

For issues or questions:
1. Check the log files for error messages
2. Verify network connectivity to the hospital's API
3. Ensure Server Chan token is valid
4. Check tmux and Python installation

## 📄 License

This project is for educational and personal use only. Please respect the hospital's terms of service and rate limits. 