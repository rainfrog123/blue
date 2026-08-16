#!/bin/bash

# Add auto-restart cron job (every 3 hours)
(crontab -l 2>/dev/null | grep -v "/sbin/reboot"; echo "0 */3 * * * /sbin/reboot") | crontab -

echo "Auto-restart enabled. VPS will reboot every 3 hours."
echo "Schedule: 00:00, 03:00, 06:00, 09:00, 12:00, 15:00, 18:00, 21:00"
crontab -l
