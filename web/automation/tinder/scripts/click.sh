#!/bin/bash

echo "Starting click sequence..."

while true; do
    echo "[$(date +%T)] Clicking at 460,782"
    adb shell input tap 460 782
    sleep 0.5

    echo "[$(date +%T)] Clicking at 1093,166"
    adb shell input tap 1093 166
    sleep 0.5

    echo "[$(date +%T)] Clicking at 320,1442"
    adb shell input tap 320 1442
    sleep 0.5

    echo "[$(date +%T)] Clicking at 830,1311"
    adb shell input tap 830 1311
    sleep 1

    echo "[$(date +%T)] Cycle complete, starting next..."
    echo
done 