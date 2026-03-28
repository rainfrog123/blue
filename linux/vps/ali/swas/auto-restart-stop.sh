#!/bin/bash

# Remove auto-restart cron job
crontab -l 2>/dev/null | grep -v "/sbin/reboot" | crontab -

echo "Auto-restart disabled."
crontab -l 2>/dev/null || echo "No cron jobs remaining."
