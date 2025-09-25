#!/bin/bash

echo "Testing ports 45000-45100..."
echo "Port | Status"
echo "----------"

for port in $(seq 45000 45100); do
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -A 'Mozilla/5.0' \
        -x "https://user-sp3j58curv-sessionduration-60-country-gb:9oOoKQ8+z8pkcUsnv0@gate.decodo.com:${port}" \
        --connect-timeout 10 \
        --max-time 15 \
        "https://www.google.com/search?q=test")
    
    echo "$port | $status"
done
