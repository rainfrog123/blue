"""
Configuration settings for the West China Hospital appointment monitor.
"""
import os
from datetime import timezone, timedelta

# Timezone
CST_TZ = timezone(timedelta(hours=8))  # China Standard Time (UTC+8)

# API Configuration
API_URL = "https://hytapiv2.cd120.com/cloud/appointment/doctorListModel/selDoctorDetailsTwo"

# Default headers (tokens should be set via environment variables)
DEFAULT_HEADERS = {
    "Host": "hytapiv2.cd120.com",
    "Mac": "Not Found",
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-GB;q=1",
    "Content-Type": "application/json",
    "Connection": "keep-alive",
}

# Authentication tokens - load from environment variables with fallback defaults
# NOTE: Replace these defaults with your own tokens or use environment variables
API_TOKEN = os.environ.get(
    "HUAXITONG_TOKEN",
    "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIyNzkwODA5NTBiOWY4NzhlNjcwZTg3Y2VjOWYwNzc5YmI5ODE0NTVhZDM3YmUyMjViZjVkODkzODA4MTM5YzYwMDgwODBhIiwiaWF0IjoxNzYyMjUyMDE4LCJzdWIiOiJ7XCJ1c2VySWRcIjpcIjI3OTA4MFwiLFwiYWNjb3VudElkXCI6XCIyOTMzNjBcIixcInVzZXJUeXBlXCI6MCxcImFwcENvZGVcIjpcIkhYR1lBUFBcIixcImNoYW5uZWxDb2RlXCI6XCJQQVRJRU5UX0lPU1wiLFwiZGV2aWNlbnVtYmVyXCI6XCI5NTBiOWY4NzhlNjcwZTg3Y2VjOWYwNzc5YmI5ODE0NTVhZDM3YmUyMjViZjVkODkzODA4MTM5YzYwMDgwODBhXCIsXCJkZXZpY2VUeXBlXCI6XCJBUFBcIixcImFjY291bnROb1wiOlwiMTM4ODI5ODUxODhcIixcIm5hbWVcIjpcIumZiOS6leW3nVwiLFwiZG9jdG9ySWRcIjpudWxsLFwib3JnYW5Db2RlXCI6bnVsbH0iLCJleHAiOjE3NjQ4NDQwMTh9.uJjbbfjVPJ9s-gxmSyE94sPkiCoUMRm500ZNACnIov4***HXGYAPP"
)
API_ACCESS_TOKEN = os.environ.get(
    "HUAXITONG_ACCESS_TOKEN",
    "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiIyNzkwODA5NTBiOWY4NzhlNjcwZTg3Y2VjOWYwNzc5YmI5ODE0NTVhZDM3YmUyMjViZjVkODkzODA4MTM5YzYwMDgwODBhIiwiaWF0IjoxNzYyMjUyMDE4LCJzdWIiOiJ7XCJ1c2VySWRcIjpcIjI3OTA4MFwiLFwiYWNjb3VudElkXCI6XCIyOTMzNjBcIixcInVzZXJUeXBlXCI6MCxcImFwcENvZGVcIjpcIkhYR1lBUFBcIixcImNoYW5uZWxDb2RlXCI6XCJQQVRJRU5UX0lPU1wiLFwiZGV2aWNlbnVtYmVyXCI6XCI5NTBiOWY4NzhlNjcwZTg3Y2VjOWYwNzc5YmI5ODE0NTVhZDM3YmUyMjViZjVkODkzODA4MTM5YzYwMDgwODBhXCIsXCJkZXZpY2VUeXBlXCI6XCJBUFBcIixcImFjY291bnROb1wiOlwiMTM4ODI5ODUxODhcIixcIm5hbWVcIjpcIumZiOS6leW3nVwiLFwiZG9jdG9ySWRcIjpudWxsLFwib3JnYW5Db2RlXCI6bnVsbH0iLCJleHAiOjE3NjQ4NDQwMTh9.uJjbbfjVPJ9s-gxmSyE94sPkiCoUMRm500ZNACnIov4***HXGYAPP"
)
API_COOKIE = os.environ.get(
    "HUAXITONG_COOKIE",
    "acw_tc=1a0c39d517622521666711325e1d4a38b46413dac72c7dd846be940d0c3d7e"
)

# ServerChan notification configuration
SERVERCHAN_URL = os.environ.get(
    "SERVERCHAN_URL",
    "https://sctapi.ftqq.com/SCT282278T91zPNpvuek2817He3xtGpSLJ.send"
)
NOTIFICATION_COOLDOWN = 300  # 5 minutes in seconds

# Monitoring intervals
PEAK_HOUR_INTERVAL = 5.0  # seconds during peak hours
NORMAL_INTERVAL_MIN = 15  # seconds
NORMAL_INTERVAL_MAX = 25  # seconds
ERROR_WAIT_MIN = 30  # seconds
ERROR_WAIT_MAX = 60  # seconds

# Peak hours definition (7:59-8:04 AM/PM China time)
PEAK_WINDOWS = [
    ("07:59:00", "08:04:00"),  # Morning peak
    ("19:59:00", "20:04:00"),  # Evening peak
]

# Dynamic user agent generation data
APP_VERSIONS = ["7.0.8", "7.0.9", "7.1.0", "7.1.1", "7.1.2", "7.2.0"]

IOS_VERSIONS = [
    "15.6.1", "15.7.0", "15.7.1", "15.7.2", "15.7.3", "15.7.4", "15.7.5",
    "15.7.6", "15.7.7", "15.7.8", "15.7.9", "15.8.0", "15.8.1", "15.8.2",
    "16.0.0", "16.0.1", "16.0.2", "16.0.3", "16.1.0", "16.1.1", "16.1.2",
    "16.2.0", "16.3.0", "16.3.1", "16.4.0", "16.4.1", "16.5.0", "16.5.1",
    "16.6.0", "16.6.1", "16.7.0", "16.7.1", "16.7.2"
]

DEVICE_MODELS = [
    "iPhone13,1", "iPhone13,2", "iPhone13,3", "iPhone13,4",  # iPhone 12 series
    "iPhone14,2", "iPhone14,3", "iPhone14,4", "iPhone14,5",  # iPhone 13 series
    "iPhone14,7", "iPhone14,8",  # iPhone 13 mini/Pro Max
    "iPhone12,1", "iPhone12,3", "iPhone12,5", "iPhone12,8",  # iPhone 11 series
    "iPhone11,2", "iPhone11,4", "iPhone11,6", "iPhone11,8",  # iPhone XS series
]

SCALE_VALUES = ["2.00", "3.00"]
